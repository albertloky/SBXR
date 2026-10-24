//! Fixed bounded service commands with retained Owner authority and joined
//! private-role lending. No arbitrary executable, argv, unit, cwd or environment.
use super::{material::RuntimeFiles, *};
use crate::runtime_handoff::{Handoff, PeerObservations};
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    StartSubscription,
    EnableSubscription,
    RestartSubscription,
    StopSubscription,
    StartProxy,
    RestartProxy,
    Reload,
    EnableFirewall,
    DisableFirewall,
    DisableSubscription,
    StopProxy,
}
impl ServiceAction {
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::StartSubscription => &["start", "sbxr-subscription.service"],
            Self::EnableSubscription => &["enable", "--now", "sbxr-subscription.service"],
            Self::RestartSubscription => &["restart", "sbxr-subscription.service"],
            Self::StopSubscription => &["stop", "sbxr-subscription.service"],
            Self::StartProxy => &["start", "sing-box.service"],
            Self::RestartProxy => &["restart", "sing-box.service"],
            Self::Reload => &["daemon-reload"],
            Self::EnableFirewall => &["enable", "--now", "sbxr-subscription-firewall.service"],
            Self::DisableFirewall => &["disable", "--now", "sbxr-subscription-firewall.service"],
            Self::DisableSubscription => &["disable", "--now", "sbxr-subscription.service"],
            Self::StopProxy => &["stop", "sing-box.service"],
        }
    }
    fn role(self) -> Result<Role, Error> {
        match self {
            Self::StartSubscription | Self::EnableSubscription | Self::RestartSubscription => {
                Ok(Role::SubscriptionServing)
            }
            Self::StartProxy | Self::RestartProxy => Ok(Role::ProxyStartAuthorize),
            _ => Err(Error::Refused),
        }
    }
}
pub trait ServiceCommands: Sync {
    fn execute(&self, action: ServiceAction, context: &StartContext) -> Result<(), Error>;
}
pub struct NativeServiceCommands {
    owner: Arc<HostLock>,
}
impl NativeServiceCommands {
    pub fn new(owner: Arc<HostLock>) -> Result<Self, HostError> {
        super::super::linux::require_native_environment()?;
        if owner.root() != Path::new("/") {
            return Err(HostError::Unsafe);
        }
        owner.verify()?;
        Ok(Self { owner })
    }
}
impl ServiceCommands for NativeServiceCommands {
    fn execute(&self, action: ServiceAction, context: &StartContext) -> Result<(), Error> {
        super::super::linux::require_native_environment().map_err(refused)?;
        self.owner.verify().map_err(refused)?;
        let before =
            super::super::linux::verify_probe_executable("/usr/bin/systemctl").map_err(refused)?;
        let output = super::command::run(context, |stop| {
            super::super::process::run_in(
                "/usr/bin/systemctl",
                action.arguments(),
                "/",
                context
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now())
                    .min(Duration::from_secs(15)),
                super::super::process::OUTPUT_LIMIT,
                stop,
            )
        })?;
        self.owner.verify().map_err(refused)?;
        if output.code() != 0
            || super::super::linux::verify_probe_executable("/usr/bin/systemctl")
                .map_err(refused)?
                != before
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
pub struct ServiceController<'a, P, C> {
    files: RuntimeFiles<'a>,
    authenticated: &'a AuthenticatedInstalled,
    owner: Arc<HostLock>,
    peers: P,
    commands: C,
    socket: Option<PathBuf>,
}
impl<'a> ServiceController<'a, runtime_handoff::LinuxPeers, NativeServiceCommands> {
    pub fn native_unreleased(
        authenticated: &'a AuthenticatedInstalled,
        owner: Arc<HostLock>,
    ) -> Result<Self, HostError> {
        let commands = NativeServiceCommands::new(owner.clone())?;
        let controller = Self {
            files: RuntimeFiles::native(authenticated)?,
            authenticated,
            owner,
            peers: runtime_handoff::LinuxPeers,
            commands,
            socket: None,
        };
        controller.verify().map_err(|_| HostError::Foreign)?;
        Ok(controller)
    }
}
impl<'a, P: PeerObservations + Sync, C: ServiceCommands> ServiceController<'a, P, C> {
    pub fn injected(
        root: &Path,
        authenticated: &'a AuthenticatedInstalled,
        owner: Arc<HostLock>,
        peers: P,
        commands: C,
        socket: PathBuf,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || socket.parent() != Some(root) {
            return Err(HostError::Unsafe);
        }
        let controller = Self {
            files: RuntimeFiles::injected(root, authenticated)?,
            authenticated,
            owner,
            peers,
            commands,
            socket: Some(socket),
        };
        controller.verify().map_err(|_| HostError::Foreign)?;
        Ok(controller)
    }
    pub(in crate::host) fn native_with_commands(
        authenticated: &'a AuthenticatedInstalled,
        owner: Arc<HostLock>,
        peers: P,
        commands: C,
    ) -> Result<Self, HostError> {
        super::super::linux::require_native_environment()?;
        let controller = Self {
            files: RuntimeFiles::native(authenticated)?,
            authenticated,
            owner,
            peers,
            commands,
            socket: None,
        };
        controller.verify().map_err(|_| HostError::Foreign)?;
        Ok(controller)
    }
    #[cfg(test)]
    pub(crate) fn into_fixture_commands(self) -> C {
        assert!(self.socket.is_some() && self.files.fs.path() != Path::new("/"));
        self.commands
    }
    fn verify(&self) -> Result<(), Error> {
        self.owner.verify().map_err(refused)?;
        if self.owner.root() != self.files.fs.path() {
            return Err(Error::Refused);
        }
        self.files.installed()?;
        let current = self.peers.current()?;
        if current.uid != self.files.fs.uid
            || current.executable_sha256 != self.files.record.executable_sha256()
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn start(&self, action: ServiceAction, context: &StartContext) -> Result<(), Error> {
        context.check()?;
        self.verify()?;
        let role = action.role()?;
        let body = self.files.ownership()?;
        let record = OwnershipRecord::decode(&body).map_err(refused)?;
        if record.release_identity() != self.files.record.release_identity() {
            return Err(Error::Refused);
        }
        if role == Role::SubscriptionServing {
            super::serving::validate_serving_footprint(&self.files)?;
            runtime_handoff::select_http_authority(&record, true)?;
            let (unit, _) = self
                .files
                .fs
                .raw(
                    "etc/systemd/system/sbxr-subscription.service",
                    Mode::from_raw_mode(0o644),
                    8192,
                )
                .map_err(refused)?
                .ok_or(Error::Refused)?;
            if unit != runtime_handoff::SERVING_UNIT.as_bytes() {
                return Err(Error::Refused);
            }
        } else if runtime_handoff::cutover_configuration(&record)?.is_some() {
            return Err(Error::Refused);
        }
        let listener = if let Some(socket) = &self.socket {
            crate::host::runtime_io::bind_fixture(self.files.fs.path(), socket)?
        } else {
            crate::host::runtime_io::bind_native(self.files.fs.path())?
        };
        let owner = self.owner.runtime_start_lock().map_err(refused)?;
        let handoff = Handoff::service(listener, owner.start_lock(), role, self.authenticated)?;
        let accepted = runtime_handoff::with_runtime_start(handoff, &self.peers, context, |ctx| {
            self.commands.execute(action, ctx).is_ok()
        });
        if !accepted || self.files.ownership()? != body {
            return Err(Error::Refused);
        }
        self.verify()?;
        context.check()
    }
    pub fn enable_subscription(&self, context: &StartContext) -> Result<(), Error> {
        self.start(ServiceAction::EnableSubscription, context)
    }
    pub fn start_subscription(&self, restart: bool, context: &StartContext) -> Result<(), Error> {
        self.start(
            if restart {
                ServiceAction::RestartSubscription
            } else {
                ServiceAction::StartSubscription
            },
            context,
        )
    }
    /// Initial VMess setup has the pinned package unit, without an identity
    /// rotation drop-in. Authorize its one fixed start in the retained Owner
    /// scope; ordinary private starts keep their existing Running-only rules.
    pub fn start_setup_proxy(&self, context: &StartContext) -> Result<(), Error> {
        context.check()?;
        self.verify()?;
        let body = self.files.ownership()?;
        let record = OwnershipRecord::decode(&body).map_err(refused)?;
        runtime_handoff::setup_start_configuration(&record)?;
        if record.release_identity() != self.files.record.release_identity() {
            return Err(Error::Refused);
        }
        let configuration = self.files.configuration()?;
        if sha256_hex(&configuration) != record.configuration_sha256()
            || crate::server_configuration::ServerConfiguration::decode_supported(&configuration)
                .map_err(refused)?
                .is_standard_only()
        {
            return Err(Error::Refused);
        }
        let unit = self
            .files
            .fs
            .raw(
                "usr/lib/systemd/system/sing-box.service",
                Mode::from_raw_mode(0o644),
                8192,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if unit.0 != include_bytes!("../owner_runtime/testdata/sing-box.service")
            || unit.1.gid != self.files.fs.gid
            || self
                .files
                .fs
                .directory_entries(
                    "etc/systemd/system/sing-box.service.d",
                    Mode::from_raw_mode(0o755),
                )
                .map_err(refused)?
                .is_some_and(|v| !v.is_empty())
        {
            return Err(Error::Refused);
        }
        let borrowed = self.owner.runtime_start_lock().map_err(refused)?;
        borrowed.start_lock().verify()?;
        if self.files.ownership()? != body {
            return Err(Error::Refused);
        }
        context.check()?;
        self.commands.execute(ServiceAction::StartProxy, context)?;
        if self.files.ownership()? != body {
            return Err(Error::Refused);
        }
        borrowed.start_lock().verify()?;
        self.verify()?;
        context.check()
    }
    pub fn start_proxy(&self, restart: bool, context: &StartContext) -> Result<(), Error> {
        self.start(
            if restart {
                ServiceAction::RestartProxy
            } else {
                ServiceAction::StartProxy
            },
            context,
        )
    }
    pub fn start_proxy_cutover(
        &self,
        gate: &CutoverGate,
        restart: bool,
        context: &StartContext,
    ) -> Result<(), Error> {
        self.verify()?;
        context.check()?;
        let authority = self.files.ownership()?;
        let action = if restart {
            ServiceAction::RestartProxy
        } else {
            ServiceAction::StartProxy
        };
        let accepted = if let Some(socket) = &self.socket {
            gate.start_fixture(socket, self.authenticated, &self.peers, context, |ctx| {
                self.commands.execute(action, ctx).is_ok()
            })
        } else {
            gate.start_native(self.authenticated, context, |ctx| {
                self.commands.execute(action, ctx).is_ok()
            })
        };
        if !accepted || self.files.ownership()? != authority {
            return Err(Error::Refused);
        }
        self.verify()?;
        context.check()
    }
    pub fn reload(&self, context: &StartContext) -> Result<(), Error> {
        self.verify()?;
        self.commands.execute(ServiceAction::Reload, context)?;
        self.verify()?;
        context.check()
    }
    /// Stop completion alone is not quiescence. The caller must separately prove
    /// cgroup population and TCP8443 absence before revocation/publication.
    pub fn stop_subscription(&self, context: &StartContext) -> Result<(), Error> {
        self.verify()?;
        context.check()?;
        let body = self.files.ownership()?;
        let record = OwnershipRecord::decode(&body).map_err(refused)?;
        if record.release_identity() != self.files.record.release_identity() {
            return Err(Error::Refused);
        }
        runtime_handoff::select_http_authority(&record, true)?;
        super::serving::validate_serving_footprint(&self.files)?;
        let (unit, _) = self
            .files
            .fs
            .raw(
                "etc/systemd/system/sbxr-subscription.service",
                Mode::from_raw_mode(0o644),
                8192,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if unit != runtime_handoff::SERVING_UNIT.as_bytes() {
            return Err(Error::Refused);
        }
        self.commands
            .execute(ServiceAction::StopSubscription, context)?;
        if self.files.ownership()? != body {
            return Err(Error::Refused);
        }
        self.verify()?;
        context.check()
    }
    /// Concrete native cgroup-v2 plus wildcard TCP8443 observation. This never
    /// treats a successful stop command or listener absence alone as quiescence.
    pub fn native_subscription_quiescent(&self, context: &StartContext) -> Result<bool, Error> {
        if self.files.fs.path() != Path::new("/") {
            return Err(Error::Refused);
        }
        super::super::linux::require_native_environment().map_err(refused)?;
        self.verify()?;
        context.check()?;
        let events = self
            .files
            .fs
            .cgroup_bytes(crate::host::owner_runtime::Unit::Subscription, true)
            .map_err(refused)?;
        if events.as_ref().is_some_and(|bytes| !quiet_events(bytes)) {
            return Ok(false);
        }
        let Ok(listener) = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8443))
        else {
            return Ok(false);
        };
        let current = self
            .files
            .fs
            .cgroup_bytes(crate::host::owner_runtime::Unit::Subscription, true)
            .map_err(refused)?;
        self.verify()?;
        context.check()?;
        drop(listener);
        Ok(current.as_ref().is_none_or(|bytes| quiet_events(bytes)))
    }
}

fn quiet_events(bytes: &[u8]) -> bool {
    bytes.len() <= 4096
        && std::str::from_utf8(bytes)
            .is_ok_and(|text| text.lines().any(|line| line == "populated 0"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quiescence_matches_exact_go_population_line_and_bound() {
        assert!(quiet_events(b"populated 0\nfrozen 0\n"));
        for bytes in [
            b"populated 1\n".as_slice(),
            b"populated 00\n",
            b"populated 0 \n",
            b"",
            &[b' '; 4097],
            b"\xffpopulated 0\n",
        ] {
            assert!(!quiet_events(bytes));
        }
    }
}
