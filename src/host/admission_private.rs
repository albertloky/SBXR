//! Ordinary private startup is offline local ownership, never delivery trust.
use super::admission::{EXECUTABLE, LIMIT, NativeAdmission, Snapshot, refused};
use super::{
    HostError,
    filesystem::{Evidence, ProtectedFs},
};
use crate::{
    host::runtime::ServingEnvironment,
    private_roles::Role,
    runtime_handoff::{SandboxProcess, StartContext, StartLock},
};
use crate::{
    records::InstalledRecord,
    release_identity::{self, Architecture},
    subscription_serving::Cancellation,
};
use rustix::fs::Mode;
use std::path::Path;
/// Deliberately does not implement InstalledEvidence. Protected structural local
/// startup cannot become authenticated candidate/stable acquisition authority.
pub(in crate::host) struct OfflinePrivateAdmission {
    fs: ProtectedFs,
    record: InstalledRecord,
    record_bytes: Vec<u8>,
    record_named: Evidence,
    bytes: Vec<u8>,
    named: Evidence,
    loaded: Vec<u8>,
    role: Role,
    stop: Cancellation,
    current: Option<Snapshot>,
    serving: Option<SandboxProcess>,
}
impl OfflinePrivateAdmission {
    pub(in crate::host) fn native(role: Role, context: &StartContext) -> Result<Self, HostError> {
        context.check().map_err(refused)?;
        super::linux::require_native_environment()?;
        let loaded = crate::build_identity::compiled_statement()
            .ok_or(HostError::LiveUnavailable)?
            .to_vec();
        let mut admission =
            Self::capture(ProtectedFs::native()?, loaded, role, context.stop.clone())?;
        if role == Role::SubscriptionServing {
            let sandbox = super::runtime::NativeServingEnvironment
                .sandbox()
                .map_err(refused)?;
            sandbox.validate().map_err(refused)?;
            admission.serving = Some(sandbox.process);
        } else {
            admission.current = Some(NativeAdmission::snapshot(context.stop.clone())?);
        }
        admission.verify()?;
        context.check().map_err(refused)?;
        Ok(admission)
    }
    fn capture(
        fs: ProtectedFs,
        loaded: Vec<u8>,
        role: Role,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        if !matches!(
            role,
            Role::SubscriptionServing | Role::ProxyStartAuthorize | Role::ProvisionMutationLock
        ) {
            return Err(HostError::Foreign);
        }
        let record = super::linux::observation::read_installed(&fs)?.ok_or(HostError::Foreign)?;
        let (record_bytes, record_named) = fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        let (bytes, named) = fs
            .raw(EXECUTABLE, Mode::from_raw_mode(0o755), LIMIT)?
            .ok_or(HostError::Foreign)?;
        let value = Self {
            fs,
            record,
            record_bytes,
            record_named,
            bytes,
            named,
            loaded,
            role,
            stop,
            current: None,
            serving: None,
        };
        value.pair()?;
        Ok(value)
    }
    fn pair(&self) -> Result<(), HostError> {
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        if super::linux::observation::read_installed(&self.fs)?.as_ref() != Some(&self.record)
            || !super::lifecycle::transactions_absent(&self.fs)?
        {
            return Err(HostError::Foreign);
        }
        let retained_record = self
            .fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        if retained_record.0 != self.record_bytes || retained_record.1 != self.record_named {
            return Err(HostError::Foreign);
        }
        let (bytes, named) = self
            .fs
            .raw(EXECUTABLE, Mode::from_raw_mode(0o755), LIMIT)?
            .ok_or(HostError::Foreign)?;
        let arch = match self.record.architecture() {
            "amd64" => Architecture::Amd64,
            "arm64" => Architecture::Arm64,
            _ => return Err(HostError::Foreign),
        };
        if named != self.named
            || bytes != self.bytes
            || release_identity::inspect_linux_artifact(&bytes, arch)
                .map_err(refused)?
                .kind()
                != release_identity::ArtifactKind::Rust
            || self.loaded
                != release_identity::rust_artifact_metadata(
                    self.record.release_identity().commit(),
                    arch,
                )
                .map_err(refused)?
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(in crate::host) fn verify(&self) -> Result<(), HostError> {
        self.pair()?;
        if let Some(current) = &self.current {
            current.verify()?;
        }
        if let Some(serving) = &self.serving {
            let sandbox = super::runtime::NativeServingEnvironment
                .sandbox()
                .map_err(refused)?;
            sandbox.validate().map_err(refused)?;
            if &sandbox.process != serving {
                return Err(HostError::Foreign);
            }
        }
        if self.fs.path() == Path::new("/") && self.current.is_none() && self.serving.is_none() {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(in crate::host) fn record(&self) -> &InstalledRecord {
        &self.record
    }
    pub(in crate::host) fn require_role(&self, role: Role) -> Result<(), HostError> {
        self.verify()?;
        if role != self.role {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(in crate::host) fn verify_start(
        &self,
        role: Role,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<(), HostError> {
        context.check().map_err(refused)?;
        self.require_role(role)?;
        lock.verify().map_err(refused)?;
        if lock.root() != self.fs.path() {
            return Err(HostError::Foreign);
        }
        self.verify()?;
        context.check().map_err(refused)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_pair_is_not_crypto_and_needs_exact_role_start_lock_and_uncancelled_context() {
        let f = super::super::admission::tests::Fixture::new();
        let proof = OfflinePrivateAdmission::capture(
            ProtectedFs::open(&f.0).unwrap(),
            release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64).unwrap(),
            Role::ProxyStartAuthorize,
            Cancellation::new(),
        )
        .unwrap();
        assert!(StartLock::existing(&f.0, proof.fs.uid).is_err());
        let owner = std::sync::Arc::new(
            super::super::locks::HostLock::acquire(&f.0, proof.fs.uid).unwrap(),
        );
        let lent = owner.runtime_start_lock().unwrap();
        let context = StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + crate::runtime_handoff::START_TIMEOUT,
        );
        proof
            .verify_start(Role::ProxyStartAuthorize, lent.start_lock(), &context)
            .unwrap();
        assert!(
            proof
                .verify_start(Role::SubscriptionServing, lent.start_lock(), &context)
                .is_err()
        );
        context.stop.cancel();
        assert!(
            proof
                .verify_start(Role::ProxyStartAuthorize, lent.start_lock(), &context)
                .is_err()
        );
        let other = super::super::admission::tests::Fixture::new();
        let wrong = super::super::locks::HostLock::acquire(&other.0, proof.fs.uid).unwrap();
        let wrong_lock = wrong.runtime_start_lock().unwrap();
        let context = StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + crate::runtime_handoff::START_TIMEOUT,
        );
        assert!(
            proof
                .verify_start(Role::ProxyStartAuthorize, wrong_lock.start_lock(), &context)
                .is_err()
        );
        drop(wrong_lock);
        drop(wrong);
        drop(lent);
        owner.verify().unwrap();
        f.write(EXECUTABLE, b"changed", 0o755);
        assert!(proof.verify().is_err());
    }
}
#[cfg(test)]
mod refusal_tests {
    use super::*;
    #[test]
    fn stale_start_lock_inode_refuses_and_missing_lender_does_not_fall_back_to_ordinary() {
        use crate::runtime_handoff::{self, PeerObservations, ProcessIdentity};
        struct Peers(ProcessIdentity);
        impl PeerObservations for Peers {
            fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
                Ok(self.0.clone())
            }
            fn peer(
                &self,
                _: &std::os::unix::net::UnixStream,
            ) -> Result<ProcessIdentity, runtime_handoff::Error> {
                panic!("fixture never opens sockets")
            }
        }
        let f = super::super::admission::tests::Fixture::new();
        let proof = OfflinePrivateAdmission::capture(
            ProtectedFs::open(&f.0).unwrap(),
            release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64).unwrap(),
            Role::ProxyStartAuthorize,
            Cancellation::new(),
        )
        .unwrap();
        let owner = super::super::locks::HostLock::acquire(&f.0, proof.fs.uid).unwrap();
        let context = StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + std::time::Duration::from_millis(25),
        );
        let peers = Peers(
            ProcessIdentity::new(
                600,
                1,
                100,
                proof.fs.uid,
                proof.record.executable_sha256(),
                runtime_handoff::PROXY_CGROUP,
            )
            .unwrap(),
        );
        let mut attempts = 0;
        assert!(
            runtime_handoff::acquire_runtime_start(
                &f.0,
                proof.fs.uid,
                Role::ProxyStartAuthorize,
                &peers,
                &context,
                || {
                    attempts += 1;
                    Err(runtime_handoff::Error::Refused)
                }
            )
            .is_err()
        );
        assert!(attempts > 0);
        owner.verify().unwrap();
        let lent = owner.runtime_start_lock().unwrap();
        let replacement = f.0.join("replacement");
        std::fs::write(&replacement, []).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, f.0.join("run/lock/sbxr.lock")).unwrap();
        let context = StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + runtime_handoff::START_TIMEOUT,
        );
        assert!(
            proof
                .verify_start(Role::ProxyStartAuthorize, lent.start_lock(), &context)
                .is_err()
        );
    }
}
