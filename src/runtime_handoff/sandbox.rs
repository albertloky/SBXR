//! Receiver-side observations available inside the fixed /proc-hidden sandbox.
//! No synthetic start time or current executable digest is manufactured. The
//! Owner-side Handoff independently observes and authenticates a borrowed child.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxProcess {
    pub pid: u32,
    pub uid: u32,
    pub cgroup: String,
    /// Kernel AT_EXECFN, never argv, environment, or a caller-selected path.
    pub executable_path: String,
}
impl SandboxProcess {
    pub(super) fn accepts(&self, uid: u32) -> bool {
        self.pid > 0
            && self.uid == uid
            && self.cgroup == SUBSCRIPTION_CGROUP
            && valid_execfn(&self.executable_path)
    }
}
/// Go's sandbox-side receive contract: actual kernel UID plus the exact held
/// descriptor. No receiver /proc access or claim to hash its own executable.
/// The native connector returns SO_PEERCRED UID; fixtures inject it explicitly.
pub fn acquire_serving_start(
    root: &Path,
    uid: u32,
    context: &StartContext,
    observe: impl Fn() -> Result<SandboxProcess, Error>,
    mut connect: impl FnMut() -> Result<(UnixStream, u32), Error>,
) -> Result<StartLock, Error> {
    context.check()?;
    let process = observe()?;
    if !process.accepts(uid) {
        return Err(Error::Refused);
    }
    loop {
        context.check()?;
        match StartLock::existing(root, uid) {
            Ok(lock) => {
                if observe()? != process {
                    return Err(Error::Refused);
                }
                context.check()?;
                return Ok(lock);
            }
            Err(Error::Busy) => (),
            Err(error) => return Err(error),
        }
        if let Ok((mut stream, peer_uid)) = connect() {
            let borrowed = (|| {
                if peer_uid != uid || observe()? != process {
                    return Err(Error::Refused);
                }
                stream.set_nonblocking(true).map_err(refused)?;
                write_role(&mut stream, Role::SubscriptionServing, context)?;
                let file = receive_descriptor(&stream, context)?;
                if observe()? != process {
                    return Err(Error::Refused);
                }
                let lock = StartLock {
                    file,
                    path: LockPath::open(root, uid)?,
                    borrowed: true,
                };
                lock.path.held()?;
                lock.verify()?;
                context.check()?;
                Ok(lock)
            })();
            if borrowed.is_ok() {
                return borrowed;
            }
        }
        context.pause(Duration::from_millis(25))?;
    }
}

// systemd v255 uses fexecve/execveat. Linux then reports /dev/fd/N in
// AT_EXECFN; the descriptor is usually CLOEXEC and must never be reopened or
// treated as an authority selector. Fixed unit/cgroup/build checks still apply.
fn valid_execfn(path: &str) -> bool {
    path == "/usr/local/bin/sbxr"
        || path.strip_prefix("/dev/fd/").is_some_and(|number| {
            number
                .parse::<i32>()
                .is_ok_and(|fd| fd >= 0 && fd.to_string() == number)
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_path_and_descriptor_execution_are_recognized_without_following_fd_names() {
        for name in ["/usr/local/bin/sbxr", "/dev/fd/3", "/dev/fd/2147483647"] {
            assert!(valid_execfn(name));
        }
        for name in [
            "/tmp/sbxr",
            "/dev/fd/03",
            "/dev/fd/+3",
            "/dev/fd/-1",
            "/dev/fd/2147483648",
            "/dev/fd/3/sbxr",
            "/proc/self/fd/3",
            "/dev/fd/3/../sbxr",
            "",
        ] {
            assert!(!valid_execfn(name), "{name}");
        }
    }
}
