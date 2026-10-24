//! Fixed read-only commands and a bounded subprocess transport. No shell or
//! production mutation runner is exposed. Raw command output is never formatted.
use super::{HostError, Operation};
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};
use std::{
    fmt,
    io::{ErrorKind, Read},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const OUTPUT_LIMIT: usize = 1 << 20;
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release)
    }
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Query {
    Package,
    Hold,
    User,
    Group,
    Process,
    Enabled,
    Active,
    LoadState,
    Listener,
    UnitOwner,
    Clock,
    ValidateConfiguration,
}
impl Query {
    fn argv(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Package => (
                "/usr/bin/dpkg-query",
                &[
                    "--show",
                    "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}",
                    "sing-box",
                ],
            ),
            Self::Hold => ("/usr/bin/apt-mark", &["showhold"]),
            Self::User => ("/usr/bin/getent", &["passwd", "sing-box"]),
            Self::Group => ("/usr/bin/getent", &["group", "sing-box"]),
            Self::Process => ("/usr/bin/pgrep", &["--exact", "sing-box"]),
            Self::Enabled => ("/usr/bin/systemctl", &["is-enabled", "sing-box.service"]),
            Self::Active => ("/usr/bin/systemctl", &["is-active", "sing-box.service"]),
            Self::LoadState => (
                "/usr/bin/systemctl",
                &[
                    "show",
                    "--property=LoadState",
                    "--value",
                    "sing-box.service",
                ],
            ),
            Self::Listener => ("/usr/bin/ss", &["-H", "-ltnp", "sport", "=", ":443"]),
            Self::UnitOwner => (
                "/usr/bin/dpkg-query",
                &["--search", "/usr/lib/systemd/system/sing-box.service"],
            ),
            Self::Clock => (
                "/usr/bin/timedatectl",
                &["show", "--property=NTPSynchronized", "--value"],
            ),
            Self::ValidateConfiguration => (
                "/usr/bin/sing-box",
                &["-D", "/var/lib/sing-box", "-C", "/etc/sing-box", "check"],
            ),
        }
    }
}
pub struct CommandOutput {
    code: i32,
    bytes: Vec<u8>,
}
impl CommandOutput {
    pub fn completed(code: i32, bytes: Vec<u8>) -> Result<Self, HostError> {
        if code < 0 || bytes.len() > OUTPUT_LIMIT {
            return Err(HostError::OutputLimit);
        }
        Ok(Self { code, bytes })
    }
    pub fn code(&self) -> i32 {
        self.code
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn text(&self) -> Result<&str, HostError> {
        std::str::from_utf8(&self.bytes)
            .map(str::trim)
            .map_err(|_| HostError::Unsafe)
    }
}
impl fmt::Debug for CommandOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Command output (redacted)")
    }
}
/// Injection is explicit. Implementations must not treat command completion as
/// resource ownership. NativeReadOnly never implements mutation effects.
pub trait CommandRunner {
    fn query(&self, query: Query, stop: &Cancellation) -> Result<CommandOutput, HostError>;
    fn effect(&mut self, _operation: Operation, _stop: &Cancellation) -> Result<(), HostError> {
        Err(HostError::LiveUnavailable)
    }
    fn injected_effects(&self) -> bool {
        false
    }
}
pub struct NativeReadOnly;
impl CommandRunner for NativeReadOnly {
    fn query(&self, query: Query, stop: &Cancellation) -> Result<CommandOutput, HostError> {
        super::linux::require_native_environment()?;
        // Configuration validation executes a package binary and is not a read-only
        // OS observation until package/configuration authority has been established.
        if query == Query::ValidateConfiguration {
            return Err(HostError::LiveUnavailable);
        }
        let (program, args) = query.argv();
        let before = super::linux::verify_probe_executable(program)?;
        let output = run(program, args, Duration::from_secs(5), OUTPUT_LIMIT, stop)?;
        if super::linux::verify_probe_executable(program)? != before {
            return Err(HostError::Unsafe);
        }
        Ok(output)
    }
}
struct ChildGuard {
    child: Child,
    group: Pid,
    reaped: bool,
}
impl ChildGuard {
    fn terminate(&mut self) {
        if self.reaped {
            return;
        }
        let _ = kill_process_group(self.group, Signal::KILL);
        let _ = self.child.kill();
        if !self.reaped {
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate()
    }
}
fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), HostError> {
    let flags = fcntl_getfl(fd).map_err(|_| HostError::Io)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| HostError::Io)
}
fn drain(
    stream: &mut impl Read,
    bytes: &mut Vec<u8>,
    limit: usize,
    stop: &Cancellation,
    deadline: Instant,
) -> Result<bool, HostError> {
    let mut buffer = [0; 4096];
    loop {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(HostError::Timeout);
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if n > limit.saturating_sub(bytes.len()) {
                    return Err(HostError::OutputLimit);
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(HostError::Io),
        }
    }
}
fn run(
    program: &str,
    args: &[&str],
    timeout: Duration,
    limit: usize,
    stop: &Cancellation,
) -> Result<CommandOutput, HostError> {
    if stop.cancelled() {
        return Err(HostError::Cancelled);
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| HostError::Io)?;
    let group = Pid::from_raw(child.id() as i32).filter(|pid| pid.as_raw_nonzero().get() > 1);
    let Some(group) = group else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(HostError::Unsafe);
    };
    let mut child = ChildGuard {
        child,
        group,
        reaped: false,
    };
    let mut stdout = child.child.stdout.take().ok_or(HostError::Io)?;
    let mut stderr = child.child.stderr.take().ok_or(HostError::Io)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let deadline = Instant::now() + timeout;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut code = None;
    loop {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(HostError::Timeout);
        }
        let out_done = drain(
            &mut stdout,
            &mut out,
            limit.saturating_sub(err.len()),
            stop,
            deadline,
        )?;
        let err_done = drain(
            &mut stderr,
            &mut err,
            limit.saturating_sub(out.len()),
            stop,
            deadline,
        )?;
        if out.len() + err.len() > limit {
            return Err(HostError::OutputLimit);
        }
        // Keep the leader waitable until its owned process group is killed;
        // reaping early would permit PID/group-number reuse during pipe drains.
        if code.is_none()
            && let Some(status) = waitid(
                WaitId::Pid(group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| HostError::Io)?
        {
            code = Some(status.exit_status().ok_or(HostError::Io)?);
        }
        if let Some(code) = code
            && out_done
            && err_done
        {
            child.terminate();
            return CommandOutput::completed(code, out);
        }
        thread::sleep(Duration::from_millis(2));
    }
}
#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
