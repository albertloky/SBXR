//! Actual Standard system command adapter. Commands have fixed executables and
//! argv; fixtures supply a transport that never executes them. CLI stays closed.
use super::{
    HostError, Operation,
    locks::HostLock,
    process::{self, Cancellation, CommandOutput, CommandRunner, Query},
};
use crate::{records::sha256_hex, server_configuration::PINNED_SING_BOX};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    program: &'static str,
    arguments: Vec<String>,
    directory: PathBuf,
    mutation: bool,
    timeout: Option<Duration>,
}
impl CommandSpec {
    pub fn program(&self) -> &str {
        self.program
    }
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn mutation(&self) -> bool {
        self.mutation
    }
    fn fixed(program: &'static str, args: &[&str], mutation: bool) -> Self {
        Self {
            program,
            arguments: args.iter().map(|s| (*s).into()).collect(),
            directory: "/".into(),
            mutation,
            timeout: None,
        }
    }
}
pub trait Transport {
    fn run(&self, command: &CommandSpec, stop: &Cancellation) -> Result<CommandOutput, HostError>;
    fn native(&self) -> bool {
        false
    }
    fn change_lock(&mut self, _lock: Option<Arc<HostLock>>) {}
}
pub struct NativeTransport {
    lock: Option<Arc<HostLock>>,
}
impl NativeTransport {
    pub fn new() -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        Ok(Self { lock: None })
    }
}
impl Transport for NativeTransport {
    fn native(&self) -> bool {
        true
    }
    fn change_lock(&mut self, lock: Option<Arc<HostLock>>) {
        self.lock = lock
    }
    fn run(&self, command: &CommandSpec, stop: &Cancellation) -> Result<CommandOutput, HostError> {
        super::linux::require_native_environment()?;
        if command.mutation {
            let lock = self.lock.as_ref().ok_or(HostError::Unsafe)?;
            if lock.root() != Path::new("/") {
                return Err(HostError::Unsafe);
            }
            lock.verify()?;
        }
        // Never permit an injected arbitrary executable, environment, cwd or shell.
        if !matches!(
            command.program,
            "/usr/bin/systemctl"
                | "/usr/bin/dpkg-query"
                | "/usr/bin/dpkg"
                | "/usr/bin/apt-get"
                | "/usr/bin/apt-mark"
                | "/usr/bin/getent"
                | "/usr/bin/pgrep"
                | "/usr/bin/find"
                | "/usr/bin/cat"
                | "/usr/bin/ss"
                | "/usr/bin/timedatectl"
                | "/usr/bin/sing-box"
                | "/usr/sbin/userdel"
                | "/usr/sbin/groupdel"
        ) {
            return Err(HostError::Unsafe);
        }
        if command.directory != Path::new("/") && command.directory != Path::new("/var/lib/sbxr") {
            return Err(HostError::Unsafe);
        }
        let before = super::linux::verify_probe_executable(command.program)?;
        let args: Vec<_> = command.arguments.iter().map(String::as_str).collect();
        // Once a managed effect starts, Go gives it its own bounded completion window.
        let completion = Cancellation::new();
        let managed = command.mutation || command.program == "/usr/bin/sing-box";
        let cancellation = if managed { &completion } else { stop };
        let result = process::run_in(
            command.program,
            &args,
            command.directory.to_str().ok_or(HostError::Unsafe)?,
            command.timeout.unwrap_or(if managed {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(5)
            }),
            process::OUTPUT_LIMIT,
            cancellation,
        )?;
        if before != super::linux::verify_probe_executable(command.program)? {
            return Err(HostError::Unsafe);
        }
        Ok(result)
    }
}
#[derive(PartialEq, Eq)]
struct GroupIdentity {
    gid: u32,
    fact: String,
}
struct Accounts {
    user: Option<(u32, u32)>,
    group: Option<GroupIdentity>,
}
pub struct SystemRunner<T> {
    root: PathBuf,
    transport: T,
    lock: Option<Arc<HostLock>>,
    configuration_sha256: String,
    package_sha256: String,
    package_size: usize,
}
impl<T: Transport> SystemRunner<T> {
    pub fn injected(
        root: &Path,
        transport: T,
        configuration_sha256: &str,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || transport.native() {
            return Err(HostError::LiveUnavailable);
        }
        super::filesystem::ProtectedFs::open(root)?;
        Self::construct(root, transport, configuration_sha256)
    }
    pub fn native(transport: T, configuration_sha256: &str) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        if !transport.native() {
            return Err(HostError::Unsafe);
        }
        Self::construct(Path::new("/"), transport, configuration_sha256)
    }
    fn construct(root: &Path, transport: T, hash: &str) -> Result<Self, HostError> {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(HostError::Unsafe);
        }
        Ok(Self {
            root: root.into(),
            transport,
            lock: None,
            configuration_sha256: hash.into(),
            package_sha256: PINNED_SING_BOX.sha256.into(),
            package_size: PINNED_SING_BOX.size as usize,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_package(mut self, bytes: &[u8]) -> Self {
        self.package_sha256 = sha256_hex(bytes);
        self.package_size = bytes.len();
        self
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    fn output(
        &self,
        program: &'static str,
        args: &[&str],
        mutation: bool,
        stop: &Cancellation,
    ) -> Result<CommandOutput, HostError> {
        if mutation {
            self.lock.as_ref().ok_or(HostError::Unsafe)?.verify()?;
        }
        self.transport
            .run(&CommandSpec::fixed(program, args, mutation), stop)
    }
    fn checked(
        &self,
        program: &'static str,
        args: &[&str],
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        if self.output(program, args, true, stop)?.code() != 0 {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    fn package(&self, stop: &Cancellation) -> Result<bool, HostError> {
        let out = self.query(Query::Package, stop)?;
        if out.code() == 1 {
            return Ok(false);
        }
        let fields: Vec<_> = out.text()?.split_whitespace().collect();
        if out.code() != 0
            || fields.len() != 3
            || fields[0] != PINNED_SING_BOX.version
            || fields[1] != "amd64"
        {
            return Err(HostError::Foreign);
        }
        Ok(true)
    }
    fn path(&self, path: &str) -> String {
        self.root
            .join(path.trim_start_matches('/'))
            .to_string_lossy()
            .into_owned()
    }
    fn accounts(&self, stop: &Cancellation) -> Result<Accounts, HostError> {
        let user = self.query(Query::User, stop)?;
        let group = self.query(Query::Group, stop)?;
        let u = if user.code() == 2 {
            None
        } else {
            let f: Vec<_> = user.text()?.split(':').collect();
            if user.code() != 0 || f.len() != 7 || f[0] != "sing-box" {
                return Err(HostError::Unsafe);
            }
            Some((
                f[2].parse().map_err(|_| HostError::Unsafe)?,
                f[3].parse().map_err(|_| HostError::Unsafe)?,
            ))
        };
        let g = if group.code() == 2 {
            None
        } else {
            let f: Vec<_> = group.text()?.split(':').collect();
            if group.code() != 0 || f.len() != 4 || f[0] != "sing-box" {
                return Err(HostError::Unsafe);
            }
            Some(GroupIdentity {
                gid: f[2].parse().map_err(|_| HostError::Unsafe)?,
                fact: group.text()?.to_owned(),
            })
        };
        Ok(Accounts { user: u, group: g })
    }
    fn pids(&self, args: &[&str], stop: &Cancellation) -> Result<BTreeSet<u32>, HostError> {
        let out = self.output("/usr/bin/pgrep", args, false, stop)?;
        if !matches!(out.code(), 0 | 1) {
            return Err(HostError::Unsafe);
        }
        out.text()?
            .split_whitespace()
            .map(|p| {
                p.parse::<u32>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or(HostError::Unsafe)
            })
            .collect()
    }
    fn group_exclusive(&self, gid: u32, stop: &Cancellation) -> Result<(), HostError> {
        self.account_files(None, gid, stop)?;
        let gid = gid.to_string();
        if self.pids(&["-G", &gid], stop)? != self.pids(&["-x", "sing-box"], stop)? {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn exclusive_accounts(&self, stop: &Cancellation) -> Result<Accounts, HostError> {
        let Accounts { user, group } = self.accounts(stop)?;
        if let (Some((uid, gid)), Some(group)) = (user, group.as_ref()) {
            if gid != group.gid {
                return Err(HostError::Unsafe);
            }
            self.account_files(Some(uid), gid, stop)?;
            let uid = uid.to_string();
            let gid = gid.to_string();
            let mut processes = self.pids(&["-u", &uid], stop)?;
            processes.extend(self.pids(&["-G", &gid], stop)?);
            if processes != self.pids(&["-x", "sing-box"], stop)? {
                return Err(HostError::Foreign);
            }
        } else if user.is_some() {
            return Err(HostError::Foreign);
        } else if let Some(group) = group.as_ref() {
            self.group_exclusive(group.gid, stop)?;
        }
        Ok(Accounts { user, group })
    }
    fn remove_identity(&self, stop: &Cancellation) -> Result<(), HostError> {
        let Accounts { user, mut group } = self.exclusive_accounts(stop)?;
        if user.is_some() {
            self.checked("/usr/sbin/userdel", &["sing-box"], stop)?;
            let current = self.accounts(stop)?.group;
            if current.is_none() {
                return Ok(());
            }
            if current != group {
                return Err(HostError::Foreign);
            }
            group = current;
        }
        if let Some(group) = group {
            self.group_exclusive(group.gid, stop)?;
            self.checked("/usr/sbin/groupdel", &["sing-box"], stop)?;
        }
        Ok(())
    }
}
impl<T: Transport> CommandRunner for SystemRunner<T> {
    fn bind_configuration(&mut self, hash: &str) -> Result<(), HostError> {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(HostError::Foreign);
        }
        self.configuration_sha256 = hash.into();
        Ok(())
    }
    fn injected_effects(&self) -> bool {
        !self.transport.native()
    }
    fn native_effects(&self) -> bool {
        self.transport.native()
    }
    fn removal_identity_safe(&self, stop: &Cancellation) -> Result<(), HostError> {
        self.exclusive_accounts(stop).map(|_| ())
    }
    fn change_lock(&mut self, lock: Option<Arc<HostLock>>) {
        self.transport.change_lock(lock.clone());
        self.lock = lock
    }
    fn query(&self, query: Query, stop: &Cancellation) -> Result<CommandOutput, HostError> {
        let _phase = super::timing::span(super::timing::Phase::Query(query));
        let (program, args) = query.argv();
        if query == Query::ValidateConfiguration {
            let fs = if self.root == Path::new("/") {
                super::filesystem::ProtectedFs::native()?
            } else {
                super::filesystem::ProtectedFs::open(&self.root)?
            };
            let (bytes, _) = fs
                .raw(
                    "etc/sing-box/config.json",
                    rustix::fs::Mode::from_raw_mode(0o640),
                    1 << 20,
                )?
                .ok_or(HostError::Unsafe)?;
            if sha256_hex(&bytes) != self.configuration_sha256 {
                return Err(HostError::Foreign);
            }
            self.output(program, args, false, stop)
        } else {
            self.output(program, args, false, stop)
        }
    }
    fn reload_units(&mut self, stop: &Cancellation) -> Result<(), HostError> {
        self.checked("/usr/bin/systemctl", &["daemon-reload"], stop)
    }
    fn effect(&mut self, operation: Operation, stop: &Cancellation) -> Result<(), HostError> {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let host = self.lock.as_ref().ok_or(HostError::Unsafe)?;
        host.verify()?;
        // Do not retain POSIX locks across commands which acquire dpkg/APT's locks.
        host.packages_available()?;
        use Operation::*;
        match operation {
            MaskService => self.checked("/usr/bin/systemctl", &["mask", "sing-box.service"], stop),
            InstallPackage => {
                let fs = if self.root == Path::new("/") {
                    super::filesystem::ProtectedFs::native()?
                } else {
                    super::filesystem::ProtectedFs::open(&self.root)?
                };
                let (bytes, _) = fs
                    .raw(
                        "var/lib/sbxr/sing-box_1.14.3_amd64.deb",
                        rustix::fs::Mode::from_raw_mode(0o600),
                        self.package_size + 1,
                    )?
                    .ok_or(HostError::Unsafe)?;
                if bytes.len() != self.package_size || sha256_hex(&bytes) != self.package_sha256 {
                    return Err(HostError::Foreign);
                }
                let path = self.path("/var/lib/sbxr/sing-box_1.14.3_amd64.deb");
                self.checked("/usr/bin/apt-get", &["update"], stop)?;
                self.checked("/usr/bin/dpkg", &["--install", &path], stop)?;
                if self.query(Query::Enabled, stop)?.text()? != "masked"
                    || self.query(Query::Active, stop)?.text()? != "inactive"
                {
                    return Err(HostError::Unsafe);
                }
                Ok(())
            }
            HoldPackage => {
                if !self.package(stop)? {
                    return Err(HostError::Unsafe);
                }
                self.checked("/usr/bin/apt-mark", &["hold", "sing-box"], stop)
            }
            UnmaskService => {
                let status = self.query(Query::Enabled, stop)?;
                if matches!(status.text()?, "not-found" | "disabled") {
                    Ok(())
                } else {
                    self.checked("/usr/bin/systemctl", &["unmask", "sing-box.service"], stop)
                }
            }
            EnableService => {
                self.checked("/usr/bin/systemctl", &["enable", "sing-box.service"], stop)
            }
            StartService => {
                self.checked("/usr/bin/systemctl", &["start", "sing-box.service"], stop)
            }
            StopDisableService => {
                let _ = self.checked(
                    "/usr/bin/systemctl",
                    &["disable", "--now", "sing-box.service"],
                    stop,
                );
                let load = self.query(Query::LoadState, stop)?;
                let enabled = self.query(Query::Enabled, stop)?;
                let active = self.query(Query::Active, stop)?;
                let pids = self.query(Query::Process, stop)?;
                let listener = self.query(Query::Listener, stop)?;
                if !(matches!(enabled.text()?, "disabled" | "masked")
                    || load.text()? == "not-found")
                    || active.text()? != "inactive"
                    || pids.code() != 1
                    || listener.code() != 0
                    || listener.text()?.contains("sing-box")
                {
                    return Err(HostError::Unsafe);
                }
                if self
                    .root
                    .join("etc/systemd/system/sbxr-mutation-lock.service")
                    .exists()
                {
                    self.checked(
                        "/usr/bin/systemctl",
                        &["stop", "sbxr-mutation-lock.service"],
                        stop,
                    )?
                }
                Ok(())
            }
            RemovePackageHold => {
                if !self.package(stop)? {
                    return Ok(());
                }
                self.checked("/usr/bin/apt-mark", &["unhold", "sing-box"], stop)?;
                let holds = self.query(Query::Hold, stop)?;
                if holds.code() != 0 || holds.text()?.split_whitespace().any(|s| s == "sing-box") {
                    return Err(HostError::Unsafe);
                }
                Ok(())
            }
            RemovePackage => {
                if !self.package(stop)? {
                    return Ok(());
                }
                if self
                    .query(Query::Hold, stop)?
                    .text()?
                    .split_whitespace()
                    .any(|s| s == "sing-box")
                {
                    self.checked("/usr/bin/apt-mark", &["unhold", "sing-box"], stop)?;
                }
                self.checked(
                    "/usr/bin/apt-get",
                    &["purge", "-y", "sing-box=1.14.3"],
                    stop,
                )
            }
            RemovePackageIdentity => self.remove_identity(stop),
            ValidateConfiguration => {
                if self.query(Query::ValidateConfiguration, stop)?.code() != 0 {
                    return Err(HostError::Unsafe);
                }
                Ok(())
            }
            _ => Err(HostError::Unsafe),
        }
    }
}
#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;

#[path = "system_mounts.rs"]
mod mounts;
