//! Current HTTP protected effects. Only an explicit injected root is admitted;
//! native Owner dispatch remains closed pending full host qualification.
mod effects;
pub(in crate::host) mod material;
use super::{
    HostError,
    filesystem::{Kind, ProtectedFs, Resource},
    locks::HostLock,
};
use crate::{
    records::{HttpOperation, OwnershipRecord, ServingAuthority, sha256_hex},
    release_acquisition::InstalledEvidence,
    runtime_handoff::StartContext,
    subscription_artifact::{HttpSubscriptionLink, SubscriptionCredential},
};
pub use material::http_firewall_unit;
use rustix::fs::Mode;
use std::{path::Path, sync::Arc};
pub const TOKEN: &str = "var/lib/sbxr/subscription-token";
pub const STATE: &str = "var/lib/sbxr/subscription-serving.json";
pub const STAGING: &str = "var/lib/sbxr/subscription-staging";
pub const CANDIDATE_TOKEN: &str = "var/lib/sbxr/subscription-staging/credential";
pub const CANDIDATE_STATE: &str = "var/lib/sbxr/subscription-staging/serving.json";
pub const UNIT: &str = "etc/systemd/system/sbxr-subscription.service";
pub const LINK: &str = "etc/systemd/system/multi-user.target.wants/sbxr-subscription.service";
pub const FIREWALL: &str = "etc/systemd/system/sbxr-subscription-firewall.service";
pub const FIREWALL_LINK: &str =
    "etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFacts {
    pub public_ipv4: String,
    pub proxy_running: bool,
    pub firewall_rules: String,
    pub serving_running: bool,
    pub quiescent: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemEffect {
    Reload,
    EnableFirewall,
    DisableFirewall,
    ActivateServing,
    StopServing,
    DisableServing,
}
/// Fixed external effects/observations only. The concrete host independently
/// validates all protected bytes and authority. Tests use real local serving.
pub trait HttpRuntime {
    fn facts(&self) -> Result<RuntimeFacts, HostError>;
    fn effect(
        &mut self,
        effect: SystemEffect,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn probe(
        &self,
        record: &OwnershipRecord,
        authority: &ServingAuthority,
        credential: &SubscriptionCredential,
        context: &StartContext,
    ) -> Result<(), HostError>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpObservation {
    pub fingerprint: String,
    pub absent: bool,
    pub material: bool,
    pub serving: bool,
    pub proxy: bool,
    pub public_ipv4: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpEffect {
    Enable(u32),
    CleanupEnable,
    PrepareRotation,
    StopSource,
    PublishTarget,
    RestoreSource,
    Activate,
    Verify,
    FinishRepairState,
}
pub trait SubscriptionHost {
    fn root(&self) -> &Path;
    fn uid(&self) -> u32;
    fn inspect(&self, record: &OwnershipRecord) -> Result<HttpObservation, HostError>;
    fn begin_change(&mut self) -> Result<(), HostError>;
    fn end_change(&mut self);
    fn effect(
        &mut self,
        effect: HttpEffect,
        record: &OwnershipRecord,
        credential: Option<&SubscriptionCredential>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn link(&self, record: &OwnershipRecord) -> Result<HttpSubscriptionLink, HostError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpFault {
    Before(HttpEffect),
    After(HttpEffect),
}
pub struct ProtectedHttpHost<'a, B> {
    fs: ProtectedFs,
    authenticated: &'a dyn InstalledEvidence,
    backend: B,
    owner: Option<Arc<HostLock>>,
    fault: Option<HttpFault>,
}
impl<'a>
    ProtectedHttpHost<'a, super::owner_runtime::OwnerRuntime<'a, super::owner_runtime::NativeIo>>
{
    pub fn with_native_cancellation(
        mut self,
        stop: crate::subscription_serving::Cancellation,
    ) -> Self {
        self.backend = self.backend.with_cancellation(stop);
        self
    }
    pub fn native_unreleased(authenticated: &'a dyn InstalledEvidence) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        let host = Self {
            fs: ProtectedFs::native()?,
            authenticated,
            backend: super::owner_runtime::OwnerRuntime::native_unreleased(authenticated)?,
            owner: None,
            fault: None,
        };
        host.installed()?;
        Ok(host)
    }
}
impl<'a, B: HttpRuntime> ProtectedHttpHost<'a, B> {
    pub fn injected(
        root: &Path,
        authenticated: &'a dyn InstalledEvidence,
        backend: B,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        let host = Self {
            fs: ProtectedFs::open(root)?,
            authenticated,
            backend,
            owner: None,
            fault: None,
        };
        host.installed()?;
        Ok(host)
    }
    pub fn inject_fault(&mut self, fault: Option<HttpFault>) {
        self.fault = fault;
    }
    pub fn into_backend(self) -> B {
        self.backend
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
    fn installed(&self) -> Result<(), HostError> {
        if super::linux::observation::read_installed(&self.fs)?.as_ref()
            != Some(self.authenticated.record())
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn authority(&self, record: &OwnershipRecord) -> Result<(), HostError> {
        self.installed()?;
        if record.release_identity() != self.authenticated.record().release_identity()
            || record.phase() != crate::records::SetupPhase::Running
            || record.recovery_direction() != crate::records::RecoveryDirection::None
        {
            return Err(HostError::Foreign);
        }
        let (configuration, proof) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if sha256_hex(&configuration) != record.configuration_sha256() {
            return Err(HostError::Foreign);
        }
        let (groups, _) = self
            .fs
            .raw("etc/group", Mode::from_raw_mode(0o644), 1 << 20)?
            .ok_or(HostError::Foreign)?;
        let gid = std::str::from_utf8(&groups)
            .map_err(|_| HostError::Foreign)?
            .lines()
            .find(|line| line.starts_with("sing-box:"))
            .and_then(|line| line.split(':').nth(2))
            .and_then(|id| id.parse::<u32>().ok())
            .ok_or(HostError::Foreign)?;
        if proof.gid != gid {
            return Err(HostError::Foreign);
        }
        for path in [
            "var/lib/.sbxr-removal.json",
            "var/lib/sbxr/update.json",
            "var/lib/sbxr/.update.json.next",
            "var/lib/sbxr/.installed.json.prior",
            "var/lib/sbxr/.installed.json.candidate",
            "usr/local/bin/.sbxr-update-prior",
            "usr/local/bin/.sbxr-update-candidate",
        ] {
            if self.fs.metadata(path)?.is_some() {
                return Err(HostError::Foreign);
            }
        }

        let configuration =
            crate::server_configuration::ServerConfiguration::decode_supported(&configuration)
                .map_err(|_| HostError::Foreign)?;
        // HTTP changes own no connector resources. Retain the fully validated
        // record/digest/profile binding without requiring connector reacquisition
        // or changing its independent authority during subscription recovery.
        if record.tunnel_authority().is_some() && configuration.is_standard_only() {
            return Err(HostError::Foreign);
        }
        record.http_operation().map_err(|_| HostError::Foreign)?;
        Ok(())
    }
    fn owner(&self) -> Result<Arc<HostLock>, HostError> {
        let owner = self.owner.as_ref().ok_or(HostError::Unsafe)?;
        owner.verify()?;
        Ok(owner.clone())
    }
    fn system(
        &mut self,
        effect: SystemEffect,
        record: &OwnershipRecord,
        context: &StartContext,
    ) -> Result<(), HostError> {
        let owner = self.owner()?;
        self.backend.effect(effect, record, &owner, context)?;
        owner.verify()
    }
}
