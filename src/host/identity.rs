//! Protected injected Client Identity adapter. Fixed file effects are real;
//! native process/service/package observations must be supplied by a qualified
//! backend before production entry can exist. No native constructor is provided.
mod effects;
use super::{
    HostError,
    filesystem::{Kind, ProtectedFs, Resource},
    locks::{HostLock, PackageLocks},
    process::{Cancellation as CommandCancellation, CommandOutput, CommandRunner, Query},
    runtime::{CutoverGate, ProxyRuntimeHost},
};
use crate::{
    client_identity as ci,
    durable::OwnershipStore,
    records::{OwnershipRecord, ReleaseIdentity, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
    runtime_handoff::{self, PeerObservations, ProcessIdentity, ProxyStartHost, StartContext},
    subscription_serving::Cancellation,
};
use rustix::fs::Mode;
use std::{cell::RefCell, path::Path, sync::Arc};
pub const TARGET: &str = "var/lib/sbxr/client-identity-target.json";
pub const CONFIG: &str = "etc/sing-box/config.json";
pub const CONFIG_STAGE: &str = "etc/sing-box/.config.json.sbxr-next";
pub const STARTUP: &str = "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf";
pub const STARTUP_DIR: &str = "etc/systemd/system/sing-box.service.d";
pub const ARTIFACT: &str = "var/lib/sbxr/subscription-staging/client-artifact";
pub trait IdentityRuntime: CommandRunner + PeerObservations + Sync {
    fn reload_identity(
        &mut self,
        owner: &Arc<HostLock>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn admit_identity(&self, record: &OwnershipRecord) -> Result<(), HostError>;
    fn subscription_route(&self, record: &OwnershipRecord) -> Result<bool, HostError>;
    fn identity_quiescence(&self, record: &OwnershipRecord) -> Result<ci::Quiescence, HostError>;
    fn stop_identity_source(
        &mut self,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn start_identity_proxy(
        &mut self,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        gate: Option<&CutoverGate>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn finish_identity_subscription(
        &mut self,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn verify_identity_running(&self, record: &OwnershipRecord) -> Result<(), HostError>;
}
pub struct IdentityGuard {
    owner: Arc<HostLock>,
    packages: PackageLocks<'static>,
    writer: RefCell<OwnershipStore>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFault {
    Before(ci::Effect),
    After(ci::Effect),
}
pub struct ProtectedIdentityHost<'a, B> {
    fs: ProtectedFs,
    proof: &'a AuthenticatedInstalled,
    backend: B,
    #[cfg(test)]
    fault: Option<IdentityFault>,
}
fn refused(_: impl std::fmt::Debug) -> ci::Error {
    ci::Error::Authority
}
struct View<'a, B>(&'a B);
impl<B: PeerObservations> PeerObservations for View<'_, B> {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.0.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.0.peer(s)
    }
}
impl<B: CommandRunner> CommandRunner for View<'_, B> {
    fn query(&self, q: Query, c: &CommandCancellation) -> Result<CommandOutput, HostError> {
        self.0.query(q, c)
    }
}
impl<'a>
    ProtectedIdentityHost<
        'a,
        super::owner_runtime::OwnerRuntime<'a, super::owner_runtime::NativeIo>,
    >
{
    pub fn native_unreleased(proof: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        let host = Self {
            fs: ProtectedFs::native()?,
            proof,
            backend: super::owner_runtime::OwnerRuntime::native_unreleased(proof)?,
            #[cfg(test)]
            fault: None,
        };
        host.installed()
            .map_err(refused)
            .map_err(|_| HostError::Foreign)?;
        Ok(host)
    }
}
impl<'a, B: IdentityRuntime> ProtectedIdentityHost<'a, B> {
    pub fn injected(
        root: &Path,
        proof: &'a AuthenticatedInstalled,
        backend: B,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        let host = Self {
            fs: ProtectedFs::open(root)?,
            proof,
            backend,
            #[cfg(test)]
            fault: None,
        };
        host.installed().map_err(|_| HostError::Foreign)?;
        Ok(host)
    }
    #[cfg(test)]
    pub fn inject_fault(&mut self, fault: Option<IdentityFault>) {
        self.fault = fault;
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
    pub fn into_backend(self) -> B {
        self.backend
    }
    fn installed(&self) -> Result<(), ci::Error> {
        if !super::lifecycle::transactions_absent(&self.fs).map_err(refused)? {
            return Err(ci::Error::Authority);
        }
        if super::linux::observation::read_installed(&self.fs)
            .map_err(refused)?
            .as_ref()
            != Some(self.proof.record())
        {
            return Err(ci::Error::Authority);
        }
        let current = self.backend.current().map_err(refused)?;
        if current.uid != self.fs.uid
            || current.executable_sha256 != self.proof.record().executable_sha256()
        {
            return Err(ci::Error::Authority);
        }
        Ok(())
    }
    fn context() -> StartContext {
        StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + runtime_handoff::START_TIMEOUT,
        )
    }
    fn read_configuration(&self) -> Result<Vec<u8>, ci::Error> {
        let (body, proof) = self
            .fs
            .raw(CONFIG, Mode::from_raw_mode(0o640), 1 << 20)
            .map_err(refused)?
            .ok_or(ci::Error::Authority)?;
        let (groups, _) = self
            .fs
            .raw("etc/group", Mode::from_raw_mode(0o644), 1 << 20)
            .map_err(refused)?
            .ok_or(ci::Error::Authority)?;
        let gid = std::str::from_utf8(&groups)
            .map_err(refused)?
            .lines()
            .find(|l| l.starts_with("sing-box:"))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or(ci::Error::Authority)?;
        if proof.gid != gid {
            return Err(ci::Error::Authority);
        }
        crate::server_configuration::ServerConfiguration::decode_supported(&body)
            .map_err(refused)?;
        Ok(body)
    }
    fn gate(&self, guard: &IdentityGuard) -> Result<CutoverGate, ci::Error> {
        let proxy = ProxyRuntimeHost::injected(
            self.fs.path(),
            self.proof,
            View(&self.backend),
            View(&self.backend),
            self.fs.path().join("identity-observation.sock"),
        )
        .map_err(refused)?;
        proxy
            .prepare_cutover(&guard.owner, &Self::context())
            .map_err(refused)
    }
    fn subscription_material(&self, record: &OwnershipRecord) -> Result<(), ci::Error> {
        let Some(serving) = record.serving_authority() else {
            return Ok(());
        };
        if !serving.is_http() {
            return Err(ci::Error::Authority);
        }
        let token = self
            .fs
            .raw(super::subscription::TOKEN, Mode::from_raw_mode(0o600), 44)
            .map_err(refused)?
            .ok_or(ci::Error::Authority)?
            .0;
        let credential =
            std::str::from_utf8(token.strip_suffix(b"\n").ok_or(ci::Error::Authority)?)
                .map_err(refused)?;
        crate::subscription_artifact::SubscriptionCredential::parse(credential).map_err(refused)?;
        if sha256_hex(credential.as_bytes()) != serving.credential_sha256() {
            return Err(ci::Error::Authority);
        }
        for (path, bytes, mode) in [
            (
                super::subscription::STATE,
                serving.state_bytes().map_err(refused)?,
                0o600,
            ),
            (
                super::subscription::UNIT,
                runtime_handoff::SERVING_UNIT.as_bytes().to_vec(),
                0o644,
            ),
        ] {
            if self
                .fs
                .raw(path, Mode::from_raw_mode(mode), 1 << 20)
                .map_err(refused)?
                .map(|(b, _)| b)
                != Some(bytes)
            {
                return Err(ci::Error::Authority);
            }
        }
        Ok(())
    }
    fn inspect_record(&self, record: &OwnershipRecord) -> Result<(), ci::Error> {
        self.installed()?;
        if record.release_identity() != self.proof.record().release_identity()
            || record.serving_authority().is_some_and(|s| !s.is_http())
        {
            return Err(ci::Error::Authority);
        }
        self.subscription_material(record)?;
        let rotation = ci::rotation(record)?;
        let config = self.read_configuration()?;
        let hash = sha256_hex(&config);
        if if rotation.checkpoint == ci::Checkpoint::Revoked {
            hash != rotation.source_sha256 && hash != rotation.target_sha256
        } else {
            hash != record.configuration_sha256()
        } {
            return Err(ci::Error::Authority);
        }
        for (path, mode, digest) in [
            (TARGET, 0o600, Some(rotation.target_sha256.as_str())),
            (CONFIG_STAGE, 0o640, Some(rotation.target_sha256.as_str())),
            (
                STARTUP,
                0o644,
                Some(sha256_hex(ci::STARTUP_DROP_IN.as_bytes()).as_str()),
            ),
        ] {
            let body = self
                .fs
                .publication_or_stage_bytes(path, Mode::from_raw_mode(mode))
                .map_err(refused)?;
            if let Some(body) = body {
                if digest != Some(sha256_hex(&body).as_str()) {
                    return Err(ci::Error::Authority);
                }
                if path == CONFIG_STAGE {
                    if rotation.checkpoint.direction() != crate::records::ChangeDirection::Forward {
                        return Err(ci::Error::Authority);
                    }
                    let (_, candidate) = self
                        .fs
                        .raw(path, Mode::from_raw_mode(mode), 1 << 20)
                        .map_err(refused)?
                        .ok_or(ci::Error::Authority)?;
                    let (_, config) = self
                        .fs
                        .raw(CONFIG, Mode::from_raw_mode(mode), 1 << 20)
                        .map_err(refused)?
                        .ok_or(ci::Error::Authority)?;
                    if candidate.gid != config.gid {
                        return Err(ci::Error::Authority);
                    }
                }
            } else if path == TARGET
                && rotation.checkpoint.direction() == crate::records::ChangeDirection::Forward
                && rotation.checkpoint != ci::Checkpoint::TargetStarted
            {
                return Err(ci::Error::Authority);
            }
        }
        if let Some(hash) = rotation.target_artifact_sha256 {
            if let Some(bytes) = self
                .fs
                .publication_or_stage_bytes(ARTIFACT, Mode::from_raw_mode(0o600))
                .map_err(refused)?
                && sha256_hex(&bytes) != hash
            {
                return Err(ci::Error::Authority);
            }
            let serving = record.serving_authority().ok_or(ci::Error::Authority)?;
            if let Some(bytes) = self
                .fs
                .publication_or_stage_bytes(
                    super::subscription::CANDIDATE_STATE,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(refused)?
                && bytes != serving.state_bytes().map_err(refused)?
            {
                return Err(ci::Error::Authority);
            }
        }
        for (directory, mode, allowed) in [
            (
                STARTUP_DIR,
                0o755,
                &[
                    "sbxr-client-identity.conf",
                    "sbxr-client-identity.conf.sbxr-next",
                ][..],
            ),
            (
                super::subscription::STAGING,
                0o700,
                &[
                    "client-artifact",
                    "client-artifact.sbxr-next",
                    "serving.json",
                    "serving.json.sbxr-next",
                ][..],
            ),
        ] {
            if self
                .fs
                .directory_entries(directory, Mode::from_raw_mode(mode))
                .map_err(refused)?
                .is_some_and(|names| names.iter().any(|n| !allowed.contains(&n.as_str())))
            {
                return Err(ci::Error::Authority);
            }
        }
        Ok(())
    }
}
impl<B: IdentityRuntime> ci::Host for ProtectedIdentityHost<'_, B> {
    type Guard = IdentityGuard;
    fn native_host(&self) -> bool {
        self.fs.path() == Path::new("/")
    }
    fn acquire(&mut self) -> Result<IdentityGuard, ci::Error> {
        let owner = Arc::new(HostLock::existing(self.fs.path(), self.fs.uid).map_err(refused)?);
        let packages = owner.retain_packages().map_err(refused)?;
        let writer = RefCell::new(
            OwnershipStore::open(&self.fs.path().join("var/lib/sbxr"), self.fs.uid)
                .map_err(refused)?,
        );
        let guard = IdentityGuard {
            owner,
            packages,
            writer,
        };
        self.verify_guard(&guard)?;
        Ok(guard)
    }
    fn verify_guard(&mut self, g: &IdentityGuard) -> Result<(), ci::Error> {
        if g.owner.root() != self.fs.path() {
            return Err(ci::Error::Authority);
        }
        g.owner.verify().map_err(refused)?;
        g.packages.verify().map_err(refused)?;
        self.installed()
    }
    fn installed_release(&mut self, g: &IdentityGuard) -> Result<ReleaseIdentity, ci::Error> {
        self.verify_guard(g)?;
        Ok(self.proof.record().release_identity())
    }
    fn snapshot(&mut self, g: &IdentityGuard) -> Result<ci::Snapshot, ci::Error> {
        self.verify_guard(g)?;
        let s = g.writer.borrow().load().map_err(refused)?;
        let current = s.current.ok_or(ci::Error::Authority)?;
        Ok(ci::Snapshot {
            current: current.bytes().to_vec(),
            staged: s.staged.map(|s| s.bytes().to_vec()),
        })
    }
    fn synchronize(&mut self, g: &IdentityGuard, expected: &[u8]) -> Result<(), ci::Error> {
        self.verify_guard(g)?;
        g.writer.borrow().synchronize(expected).map_err(refused)
    }
    fn admit(
        &mut self,
        g: &IdentityGuard,
        record: &OwnershipRecord,
    ) -> Result<ci::StartupAuthority, ci::Error> {
        self.verify_guard(g)?;
        if record.pending_change().is_some()
            || record.release_identity() != self.proof.record().release_identity()
            || record.serving_authority().is_some_and(|s| !s.is_http())
        {
            return Err(ci::Error::Authority);
        }
        if sha256_hex(&self.read_configuration()?) != record.configuration_sha256() {
            return Err(ci::Error::Authority);
        }
        for path in [
            TARGET,
            &format!("{TARGET}.sbxr-next"),
            CONFIG_STAGE,
            ARTIFACT,
            &format!("{ARTIFACT}.sbxr-next"),
        ] {
            if self.fs.metadata(path).map_err(refused)?.is_some() {
                return Err(ci::Error::Authority);
            }
        }
        let directory = self
            .fs
            .directory_entries(STARTUP_DIR, Mode::from_raw_mode(0o755))
            .map_err(refused)?;
        if directory
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| name != "sbxr-client-identity.conf"))
        {
            return Err(ci::Error::Authority);
        }
        if let Some((bytes, _)) = self
            .fs
            .raw(STARTUP, Mode::from_raw_mode(0o644), 4096)
            .map_err(refused)?
            && bytes != ci::STARTUP_DROP_IN.as_bytes()
        {
            return Err(ci::Error::Authority);
        }
        self.subscription_material(record)?;
        if self
            .fs
            .directory_entries(super::subscription::STAGING, Mode::from_raw_mode(0o700))
            .map_err(refused)?
            .is_some_and(|names| !names.is_empty())
        {
            return Err(ci::Error::Authority);
        }
        self.backend.admit_identity(record).map_err(refused)?;
        self.verify_guard(g)?;
        Ok(ci::StartupAuthority {
            directory_created: directory.is_none(),
        })
    }
    fn inspect(&mut self, g: &IdentityGuard, record: &OwnershipRecord) -> Result<(), ci::Error> {
        self.verify_guard(g)?;
        self.inspect_record(record)
    }
    fn configuration(&mut self, g: &IdentityGuard) -> Result<Vec<u8>, ci::Error> {
        self.verify_guard(g)?;
        self.read_configuration()
    }
    fn publish(
        &mut self,
        g: &IdentityGuard,
        expected: &[u8],
        next: &OwnershipRecord,
    ) -> Result<(), ci::Error> {
        self.verify_guard(g)?;
        g.writer
            .borrow_mut()
            .publish(Some(expected), next)
            .map_err(|_| ci::Error::Publication)?;
        self.verify_guard(g)
    }
    fn routes(
        &mut self,
        g: &IdentityGuard,
        record: &OwnershipRecord,
    ) -> Result<ci::StartupRoutes, ci::Error> {
        self.verify_guard(g)?;
        let proxy = ProxyRuntimeHost::injected(
            self.fs.path(),
            self.proof,
            View(&self.backend),
            View(&self.backend),
            self.fs.path().join("identity-observation.sock"),
        )
        .map_err(refused)?;
        let route = proxy.verify_startup(record, &Self::context()).is_ok();
        let subscription = record.serving_authority().is_none()
            || self.backend.subscription_route(record).map_err(refused)?;
        Ok(ci::StartupRoutes {
            proxy: route,
            subscription,
        })
    }
    fn quiescence(
        &mut self,
        g: &IdentityGuard,
        record: &OwnershipRecord,
    ) -> Result<ci::Quiescence, ci::Error> {
        self.verify_guard(g)?;
        self.inspect_record(record)?;
        self.backend.identity_quiescence(record).map_err(refused)
    }
    fn effect(
        &mut self,
        g: &IdentityGuard,
        effect: ci::Effect,
        record: &OwnershipRecord,
        material: Option<&ci::Material>,
    ) -> Result<(), ci::Error> {
        self.verify_guard(g)?;
        #[cfg(test)]
        if self.fault == Some(IdentityFault::Before(effect)) {
            return Err(ci::Error::Effect);
        }
        let native = self.fs.path() == Path::new("/");
        if native {
            self.fs
                .authorize_native_writes(Some(g.owner.clone()))
                .map_err(refused)?;
        }
        let applied = self.apply(g, effect, record, material);
        if native {
            self.fs.authorize_native_writes(None).map_err(refused)?;
        }
        applied?;
        #[cfg(test)]
        if self.fault == Some(IdentityFault::After(effect)) {
            return Err(ci::Error::Effect);
        }
        self.verify_guard(g)
    }
    fn verify_running(
        &mut self,
        g: &IdentityGuard,
        record: &OwnershipRecord,
    ) -> Result<(), ci::Error> {
        self.verify_guard(g)?;
        if sha256_hex(&self.read_configuration()?) != record.configuration_sha256() {
            return Err(ci::Error::Authority);
        }
        self.backend
            .verify_identity_running(record)
            .map_err(refused)
    }
}
