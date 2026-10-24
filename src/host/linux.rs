//! Linux observations and Standard effects over fixed commands/protected files.
//! Native construction stays unreleased; injected roots are test infrastructure.
mod effects;
mod material;
mod removal;
pub use removal::StandardRemovalHost;
pub(super) mod observation;
pub use material::SetupMaterial;
use observation::{Facts, ubuntu};
pub use observation::{NativeObserver, ProtectedConfiguration, ReadOnlyObservation};
#[cfg(test)]
use observation::{read_configuration, read_installed, read_ownership};

use super::{
    HostError, Operation, SetupHost, SetupObservation,
    filesystem::{Kind, ProtectedFs, Resource},
    process::{Cancellation, CommandOutput, CommandRunner, NativeReadOnly, Query},
};
use crate::{
    records::{InstalledRecord, OwnershipRecord, ReleaseIdentity, SetupPhase, sha256_hex},
    server_configuration::{PINNED_SING_BOX, ServerConfiguration},
};
use rustix::fs::{FileType, Mode};
#[cfg(test)]
use std::path::PathBuf;
use std::{fmt, path::Path, sync::Arc};
const APT_SOURCE:&[u8]=b"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n";
const KEY: &str = "etc/apt/keyrings/sagernet.asc";
const SOURCE: &str = "etc/apt/sources.list.d/sagernet.sources";
const CONFIG: &str = "etc/sing-box/config.json";
const ARTIFACT: &str = "var/lib/sbxr/sing-box_1.14.3_amd64.deb";
const LOCK_UNIT: &str = "etc/systemd/system/sbxr-mutation-lock.service";
const LOCK_LINK: &str = "etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service";
const UNIT: &[u8] = include_bytes!("../records/lock-provision.service");
const QUERIES: &[Query] = &[
    Query::Package,
    Query::Hold,
    Query::User,
    Query::Group,
    Query::Process,
    Query::Enabled,
    Query::Active,
    Query::LoadState,
    Query::Listener,
    Query::UnitOwner,
    Query::Clock,
];
pub fn require_native_platform() -> Result<(), HostError> {
    if !cfg!(target_os = "linux")
        || std::env::consts::ARCH != "x86_64"
        || !rustix::process::geteuid().is_root()
    {
        return Err(HostError::UnsupportedHost);
    }
    Ok(())
}
pub(super) fn require_native_environment() -> Result<(), HostError> {
    require_native_platform()?;
    let fs = ProtectedFs::native()?;
    if !ubuntu(&fs)? {
        return Err(HostError::UnsupportedHost);
    }
    Ok(())
}
pub(super) fn verify_probe_executable(
    program: &str,
) -> Result<super::filesystem::Evidence, HostError> {
    let fs = ProtectedFs::native()?;
    let path = program.strip_prefix('/').ok_or(HostError::Unsafe)?;
    let metadata = fs.metadata(path)?.ok_or(HostError::Unsafe)?;
    if metadata.gid != 0 {
        return Err(HostError::Unsafe);
    }
    let (_, evidence) = fs
        .raw(
            path,
            Mode::from_raw_mode(0o755),
            if program == "/usr/bin/sing-box" {
                256 << 20
            } else {
                16 << 20
            },
        )?
        .ok_or(HostError::Unsafe)?;
    Ok(evidence)
}
/// Explicit test-only admission inputs. Native production observations cannot
/// manufacture these values or provide an effect runner through NativeObserver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectedAdmission {
    pub public_ipv4: String,
    pub root: bool,
    pub architecture: String,
    pub destination_compatible: bool,
    pub tcp443_available: bool,
    pub host_lock_held: bool,
    pub package_locks_held: bool,
}
pub struct LinuxHost<R> {
    fs: ProtectedFs,
    runner: R,
    material: SetupMaterial,
    admission: InjectedAdmission,
    stop: Cancellation,
    interruption: Option<SetupPhase>,
    lock: Option<Arc<super::locks::HostLock>>,
    native_mode: bool,
    authenticated: Option<InstalledRecord>,
}
impl<R: CommandRunner> LinuxHost<R> {
    pub fn injected(
        root: &Path,
        runner: R,
        material: SetupMaterial,
        admission: InjectedAdmission,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || !runner.injected_effects() {
            return Err(HostError::LiveUnavailable);
        }
        let fs = ProtectedFs::open(root)?;
        Ok(Self {
            fs,
            runner,
            material,
            admission,
            stop: Cancellation::new(),
            interruption: None,
            lock: None,
            native_mode: false,
            authenticated: None,
        })
    }
    /// Authenticated installed bytes must also match this newly observed root.
    pub fn injected_authenticated(
        root: &Path,
        runner: R,
        material: SetupMaterial,
        admission: InjectedAdmission,
        authenticated: &crate::release_acquisition::AuthenticatedInstalled,
    ) -> Result<Self, HostError> {
        let mut host = Self::injected(root, runner, material, admission)?;
        let current = observation::read_installed(&host.fs)?.ok_or(HostError::Foreign)?;
        if &current != authenticated.record() {
            return Err(HostError::Foreign);
        }
        host.authenticated = Some(authenticated.record().clone());
        Ok(host)
    }
    pub fn native_authenticated_unreleased(
        runner: R,
        material: SetupMaterial,
        network: super::network::NetworkAdmission,
        authenticated: &crate::release_acquisition::AuthenticatedInstalled,
    ) -> Result<Self, HostError> {
        let mut host = Self::native_unreleased(runner, material, network)?;
        if observation::read_installed(&host.fs)?.as_ref() != Some(authenticated.record()) {
            return Err(HostError::Foreign);
        }
        host.authenticated = Some(authenticated.record().clone());
        Ok(host)
    }
    pub fn native_unreleased(
        runner: R,
        material: SetupMaterial,
        network: super::network::NetworkAdmission,
    ) -> Result<Self, HostError> {
        require_native_environment()?;
        if !runner.native_effects() || !network.bind_proved() || !network.destination().compatible()
        {
            return Err(HostError::LiveUnavailable);
        }
        Ok(Self {
            fs: ProtectedFs::native()?,
            runner,
            material,
            admission: InjectedAdmission {
                public_ipv4: network.public_ipv4().to_string(),
                root: true,
                architecture: "amd64".into(),
                destination_compatible: true,
                tcp443_available: true,
                host_lock_held: true,
                package_locks_held: true,
            },
            stop: Cancellation::new(),
            interruption: None,
            lock: None,
            native_mode: true,
            authenticated: None,
        })
    }
    pub fn runner(&self) -> &R {
        &self.runner
    }
    pub fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }
    pub fn cancellation(&self) -> Cancellation {
        self.stop.clone()
    }
    pub fn interrupt_after(&mut self, phase: Option<SetupPhase>) {
        self.interruption = phase
    }
    fn admission(&self, facts: &Facts) -> Result<(), HostError> {
        let a = &self.admission;
        if let Some(lock) = &self.lock {
            lock.verify()?;
            lock.packages_available()?;
        }
        if self.native_mode {
            let direction = observation::read_ownership(&self.fs)?.map(|r| r.recovery_direction());
            let require_bind = !matches!(
                direction,
                Some(
                    crate::records::RecoveryDirection::FinishSetup
                        | crate::records::RecoveryDirection::None
                )
            );
            let current = super::network::NetworkAdmission::native(&self.stop, require_bind)?;
            if current.public_ipv4().to_string() != a.public_ipv4
                || !current.destination().compatible()
            {
                return Err(HostError::Unsafe);
            }
        }
        if !a.root || a.architecture != "amd64" || !ubuntu(&self.fs)? {
            return Err(HostError::UnsupportedHost);
        }
        if !crate::records::ownership_public_ipv4(&a.public_ipv4)
            || !a.destination_compatible
            || !a.host_lock_held
            || !a.package_locks_held
            || !facts.clock
        {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    fn file(
        &self,
        path: &str,
        expected: &[u8],
        mode: rustix::fs::RawMode,
        fingerprint: &mut String,
    ) -> Result<bool, HostError> {
        let read = self.fs.raw(path, Mode::from_raw_mode(mode), 1 << 26)?;
        if let Some((bytes, evidence)) = read {
            if bytes != expected {
                return Err(HostError::Foreign);
            }
            fingerprint.push_str(&format!("{path}:{evidence:?}"));
            Ok(true)
        } else {
            fingerprint.push_str(&format!("{path}:absent;"));
            Ok(false)
        }
    }
    fn install(
        &self,
        path: &str,
        bytes: &[u8],
        mode: rustix::fs::RawMode,
    ) -> Result<(), HostError> {
        self.fs
            .publish_bytes(path, bytes, Mode::from_raw_mode(mode))
    }
    fn remove(&self, path: &str, bytes: &[u8], mode: rustix::fs::RawMode) -> Result<(), HostError> {
        self.fs
            .remove_bytes(path, bytes, Mode::from_raw_mode(mode))?;
        self.fs.remove_bytes(
            &format!("{path}.sbxr-next"),
            bytes,
            Mode::from_raw_mode(mode),
        )
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
