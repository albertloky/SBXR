//! Concrete bridge from tunnel orchestration to the existing Standard effects.
use super::*;
use crate::{
    host::tunnel_native::StandardHost, package_acquisition::ProbeImage,
    runtime_handoff::StartContext, tunnel_setup,
};
pub struct TunnelRuntimeFacts {
    pub fingerprint: String,
    pub loopback_empty: bool,
    pub running: bool,
}
pub trait TunnelRuntime {
    fn root(&self) -> &Path;
    fn public_ipv4(&self, owner: &Arc<super::super::locks::HostLock>) -> Result<String, HostError>;
    fn observe(
        &self,
        record: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<TunnelRuntimeFacts, HostError>;
    fn start(
        &self,
        owner: &Arc<super::super::locks::HostLock>,
        context: &StartContext,
    ) -> Result<(), HostError>;
}
pub struct TunnelStandard<R, B> {
    host: LinuxHost<R>,
    runtime: B,
    probe: Option<ProbeImage>,
}
impl<R: CommandRunner, B: TunnelRuntime> TunnelStandard<R, B> {
    pub fn new(
        host: LinuxHost<R>,
        runtime: B,
        probe: Option<ProbeImage>,
    ) -> Result<Self, HostError> {
        if host.fs.path() != runtime.root() || !host.material.offline && probe.is_none() {
            return Err(HostError::Foreign);
        }
        Ok(Self {
            host,
            runtime,
            probe,
        })
    }
    pub fn host(&self) -> &LinuxHost<R> {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut LinuxHost<R> {
        &mut self.host
    }
    fn bind(
        &mut self,
        record: &OwnershipRecord,
        configuration: Option<&ServerConfiguration>,
    ) -> Result<(), HostError> {
        if !(record.schema() == 1
            || record.schema() == 2
                && record.phase() == SetupPhase::Running
                && record.recovery_direction() == crate::records::RecoveryDirection::None
                && record.pending_change().is_none())
            || record.tunnel_authority().is_none()
            || record.recovery_direction() == crate::records::RecoveryDirection::Removal
        {
            return Err(HostError::Foreign);
        }
        if self.host.material.configuration_digest != record.configuration_sha256() {
            self.host.material.configuration = None;
            self.host.material.configuration_digest = record.configuration_sha256().into();
        }
        if let Some(config) = configuration {
            if self.host.material.offline
                || config.sha256_hex() != record.configuration_sha256()
                || config.is_standard_only()
            {
                return Err(HostError::Foreign);
            }
            self.host.material.configuration = Some(
                ServerConfiguration::decode_supported(config.as_bytes())
                    .map_err(|_| HostError::Foreign)?,
            );
        } else if !self.host.material.offline
            && self.host.material.configuration.is_none()
            && let Some((bytes, _)) =
                self.host
                    .fs
                    .raw(CONFIG, Mode::from_raw_mode(0o640), 1 << 20)?
        {
            if sha256_hex(&bytes) != record.configuration_sha256() {
                return Err(HostError::Foreign);
            }
            self.host.material.configuration = Some(
                ServerConfiguration::decode_supported(&bytes).map_err(|_| HostError::Foreign)?,
            );
        }
        self.host
            .runner
            .bind_configuration(record.configuration_sha256())
    }
    fn verify_probe(&self, stop: &Cancellation) -> Result<String, HostError> {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let image = self.probe.as_ref().ok_or(HostError::Foreign)?;
        let (bytes, evidence) = self
            .host
            .fs
            .raw("usr/bin/sing-box", Mode::from_raw_mode(0o755), 128 << 20)?
            .ok_or(HostError::Foreign)?;
        if evidence.gid != self.host.fs.gid {
            return Err(HostError::Foreign);
        }
        image
            .verify_bytes(
                &bytes,
                &crate::artifact_trust::SelectionBudget::new().with_cancellation(stop.shared()),
            )
            .map_err(|_| HostError::Foreign)?;
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        Ok(image.sha256().into())
    }
}
impl<R: CommandRunner, B: TunnelRuntime> StandardHost for TunnelStandard<R, B> {
    fn effects_available(&self) -> bool {
        self.host.effects_available()
    }
    fn root(&self) -> &Path {
        self.host.fs.path()
    }
    fn verify_installed(
        &mut self,
        proof: &dyn crate::release_acquisition::InstalledEvidence,
    ) -> Result<(), HostError> {
        if self.host.authenticated.as_ref() != Some(proof.record())
            || observation::read_installed(&self.host.fs)?.as_ref() != Some(proof.record())
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn public_ipv4(
        &mut self,
        owner: &Arc<super::super::locks::HostLock>,
    ) -> Result<String, HostError> {
        owner.verify()?;
        if owner.root() != self.root() {
            return Err(HostError::Foreign);
        }
        let ip = self.runtime.public_ipv4(owner)?;
        if ip != self.host.admission.public_ipv4 {
            return Err(HostError::Foreign);
        }
        Ok(ip)
    }
    fn inspect(
        &mut self,
        owner: &Arc<super::super::locks::HostLock>,
        record: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<tunnel_setup::Inspection, HostError> {
        owner.verify()?;
        if owner.root() != self.root() {
            return Err(HostError::Foreign);
        }
        if let Some(record) = record {
            self.bind(record, None)?;
        }
        if !self.host.material.offline && self.host.fs.metadata("usr/bin/sing-box")?.is_some() {
            self.verify_probe(stop)?;
        }
        let release = self
            .host
            .authenticated
            .as_ref()
            .ok_or(HostError::Foreign)?
            .release_identity();
        let base = self.host.inspect_setup_profile(&release, true)?;
        let runtime = self.runtime.observe(record, stop)?;
        if !base.running && !runtime.loopback_empty {
            return Err(HostError::Foreign);
        }
        Ok(tunnel_setup::Inspection {
            fingerprint: sha256_hex(
                format!("{}:{}", base.fingerprint, runtime.fingerprint).as_bytes(),
            ),
            empty: base.empty && runtime.loopback_empty,
            ready: base.ready,
            stopped: base.stopped && runtime.loopback_empty,
            running: base.running && runtime.running,
        })
    }
    fn effect(
        &mut self,
        owner: &Arc<super::super::locks::HostLock>,
        op: Operation,
        record: &OwnershipRecord,
        config: Option<&ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        owner.verify()?;
        if owner.root() != self.root() || self.host.lock.is_some() {
            return Err(HostError::Foreign);
        }
        if observation::read_ownership(&self.host.fs)?.as_ref() != Some(record) {
            return Err(HostError::Foreign);
        }
        self.bind(record, config)?;
        if !self.host.material.offline && self.host.fs.metadata("usr/bin/sing-box")?.is_some() {
            self.verify_probe(stop)?;
        }
        self.host.lock = Some(owner.clone());
        self.host.runner.change_lock(Some(owner.clone()));
        let result = (|| {
            if self.host.native_mode {
                self.host.fs.authorize_native_writes(Some(owner.clone()))?;
            }
            self.host.apply_setup_profile(op, record, true)
        })();
        self.host.end_change();
        result
    }
    fn start_proxy(
        &mut self,
        owner: &Arc<super::super::locks::HostLock>,
        record: &OwnershipRecord,
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        owner.verify()?;
        if owner.root() != self.root()
            || observation::read_ownership(&self.host.fs)?.as_ref() != Some(record)
        {
            return Err(HostError::Foreign);
        }
        if !self.host.effects_available() {
            return Err(HostError::LiveUnavailable);
        }
        crate::runtime_handoff::setup_start_configuration(record)
            .map_err(|_| HostError::Foreign)?;
        self.verify_probe(stop)?;
        super::super::tunnel_native::retained_start(stop, |context| {
            self.runtime
                .start(owner, context)
                .map_err(|_| crate::runtime_handoff::Error::Refused)
        })
        .map_err(|_| HostError::Foreign)?;
        Ok(())
    }
    fn probe_sha256(
        &mut self,
        owner: &Arc<super::super::locks::HostLock>,
        stop: &Cancellation,
    ) -> Result<String, HostError> {
        owner.verify()?;
        if owner.root() != self.root() {
            return Err(HostError::Foreign);
        }
        crate::package_acquisition::inspect_installed(&self.host.runner, stop).and_then(|p| {
            if p.present && p.exact_held_package && p.apt_hold {
                Ok(())
            } else {
                Err(HostError::Foreign)
            }
        })?;
        self.verify_probe(stop)
    }
}
