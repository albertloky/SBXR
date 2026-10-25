//! Forward-only Complete removal and exact-release recovery orchestration.
//! Effects are injected: this module grants no native installation or migration
//! capability. Adapters must prove exact ownership immediately before each effect.
use crate::{
    domain::Confirmation,
    host::{HostError, Operation},
    records::{OwnershipRecord, RecordError, RecoveryDirection, ReleaseIdentity},
};
use serde_json::{Value, json};
use std::{fmt, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalError {
    Authority,
    PreparedAction,
    Safety,
    ExactRelease,
    Host(HostError),
}
impl fmt::Display for RemovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Removal authority or exact owned resources could not be verified.")
    }
}
impl std::error::Error for RemovalError {}
impl From<RecordError> for RemovalError {
    fn from(_: RecordError) -> Self {
        Self::Authority
    }
}
impl From<HostError> for RemovalError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}
fn wire(record: &OwnershipRecord) -> Result<Value, RemovalError> {
    serde_json::from_slice(&record.encode()?).map_err(|_| RemovalError::Authority)
}
fn validated(value: Value) -> Result<OwnershipRecord, RemovalError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| RemovalError::Authority)?;
    Ok(OwnershipRecord::decode(&bytes)?)
}
fn release_wire(release: &ReleaseIdentity) -> Value {
    json!({"Repository": release.repository(), "Tag": release.tag(),
        "Commit": release.commit(), "IndexSHA256": release.index_sha256()})
}

/// Confirmed removal is the only conversion here. Inspection never changes the
/// schema, and already-committed historical authority is never rebound.
/// This is record construction, not permission to remove a Go installation.
pub fn commit_removal(
    source: Option<&OwnershipRecord>,
    finisher: &ReleaseIdentity,
) -> Result<OwnershipRecord, RemovalError> {
    let mut value = if let Some(source) = source {
        if source.recovery_direction() == RecoveryDirection::Removal {
            return Err(RemovalError::Authority);
        }
        let mut value = wire(source)?;
        if value.get("subscription_transport_migration").is_some() {
            return Err(RemovalError::Authority);
        }
        if source.schema() == 1 {
            value["schema"] = 2.into();
            value["permitted_resources"][0] =
                "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into();
            value["resource_creating_releases"] = Value::Array(
                source
                    .permitted_resources()
                    .iter()
                    .map(|_| release_wire(&source.release_identity()))
                    .collect(),
            );
        }
        value
    } else {
        let resources = json!([
            "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2",
            "/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority",
            "/usr/local/bin/sbxr exact committed Release Identity",
            "/var/lib/sbxr/installed.json exact committed Release Identity"
        ]);
        json!({"schema":2, "release_identity":release_wire(finisher),
            "proxy_package_identity":"", "public_ipv4":"", "destination_address":"",
            "destination_server_name":"", "configuration_sha256":"", "permitted_resources": resources,
            "resource_creating_releases": vec![release_wire(finisher); 4]})
    };
    value["phase"] = "Removal committed".into();
    value["unfinished_direction"] = "removal required".into();
    value["cleanup_checkpoint"] = 0.into();
    value["removal_checkpoint"] = 0.into();
    value["finishing_release_identity"] = release_wire(finisher);
    validated(value)
}

pub fn checkpoint(record: &OwnershipRecord) -> Result<u32, RemovalError> {
    if record.recovery_direction() != RecoveryDirection::Removal {
        return Err(RemovalError::Authority);
    }
    let value = wire(record)?;
    value["removal_checkpoint"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(RemovalError::Authority)
}
pub fn checkpoint_limit(record: &OwnershipRecord) -> Result<u32, RemovalError> {
    checkpoint(record)?;
    Ok(if wire(record)?["proxy_package_identity"] == "" {
        3
    } else {
        11
    })
}
pub fn next_checkpoint(record: &OwnershipRecord) -> Result<OwnershipRecord, RemovalError> {
    let current = checkpoint(record)?;
    if current >= checkpoint_limit(record)? {
        return Err(RemovalError::Authority);
    }
    let mut value = wire(record)?;
    value["removal_checkpoint"] = (current + 1).into();
    validated(value)
}
pub fn finishing_release(record: &OwnershipRecord) -> Result<ReleaseIdentity, RemovalError> {
    checkpoint(record)?;
    if record.schema() == 1 {
        return Ok(record.release_identity());
    }
    let value = wire(record)?;
    let release = &value["finishing_release_identity"];
    let text = |key| release[key].as_str().ok_or(RemovalError::Authority);
    let identity = ReleaseIdentity::new(text("Tag")?, text("Commit")?, text("IndexSHA256")?)?;
    if text("Repository")? != identity.repository() {
        return Err(RemovalError::Authority);
    }
    Ok(identity)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalAction {
    Complete,
    Finish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityLocation {
    Current,
    Finalizer,
}
/// Adapters read these three fixed paths through protected no-follow descriptors.
/// Staging is never an alternative source of removal commitment.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub current: Option<Vec<u8>>,
    pub staged: Option<Vec<u8>>,
    pub finalizer: Option<Vec<u8>>,
}
impl fmt::Debug for AuthoritySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthoritySnapshot")
            .field("current", &self.current.is_some())
            .field("staged", &self.staged.is_some())
            .field("finalizer", &self.finalizer.is_some())
            .finish()
    }
}
struct SelectedAuthority {
    record: OwnershipRecord,
    bytes: Vec<u8>,
    location: AuthorityLocation,
}
impl AuthoritySnapshot {
    /// Select only the exact committed finisher; no Latest or creator fallback.
    pub fn restoration_release(&self) -> Result<ReleaseIdentity, RemovalError> {
        finishing_release(&self.selected()?.ok_or(RemovalError::Authority)?.record)
    }
    fn selected(&self) -> Result<Option<SelectedAuthority>, RemovalError> {
        let (bytes, location) = match (&self.current, &self.finalizer) {
            (Some(bytes), None) => (bytes, AuthorityLocation::Current),
            (None, Some(bytes)) if self.staged.is_none() => (bytes, AuthorityLocation::Finalizer),
            (None, None) if self.staged.is_none() => return Ok(None),
            _ => return Err(RemovalError::Authority),
        };
        let record = OwnershipRecord::decode(bytes)?;
        if location == AuthorityLocation::Finalizer
            && checkpoint(&record)? != checkpoint_limit(&record)?
        {
            return Err(RemovalError::Authority);
        }
        if let Some(staged) = &self.staged {
            OwnershipRecord::decode(staged)?;
            if staged != bytes
                && next_checkpoint(&record)
                    .and_then(|r| Ok(r.encode()?))
                    .as_ref()
                    != Ok(staged)
            {
                return Err(RemovalError::Authority);
            }
        }
        Ok(Some(SelectedAuthority {
            record,
            bytes: bytes.clone(),
            location,
        }))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalFacts {
    /// Hash of complete fresh ownership/service/account/directory observations.
    pub fingerprint: [u8; 32],
    /// Includes complete provenance, idle writers, safe shared renewal route,
    /// exclusive package identity/process use and compatible finishing executable.
    pub accepted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleFacts {
    pub release: ReleaseIdentity,
    /// Existing members must be the exact authenticated, committed release pair.
    pub valid: bool,
    pub executable_present: bool,
    pub installed_record_present: bool,
    /// Ownership/installed records aside, every owned state entry is absent.
    pub state_directory_empty: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectState {
    Absent,
    ExactOwned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalEffect {
    DedicatedTunnel,
    ClientIdentitySubscription,
    ClientIdentityTarget,
    PreparedSubscription,
    SubscriptionRotation,
    SubscriptionRepair,
    ServingRuntime,
    RenewalIntegration,
    SubscriptionResources,
    RetiredHttps,
    ProxyStartup,
    StopDisableProxy,
    PackageArtifact,
    PackageHold,
    Package,
    ConfigurationState,
    PackageIdentity,
    AptSource,
    AptKey,
    Executable,
    InstalledRecord,
}
const PROXY_EFFECTS: [RemovalEffect; 8] = [
    RemovalEffect::StopDisableProxy,
    RemovalEffect::PackageArtifact,
    RemovalEffect::PackageHold,
    RemovalEffect::Package,
    RemovalEffect::ConfigurationState,
    RemovalEffect::PackageIdentity,
    RemovalEffect::AptSource,
    RemovalEffect::AptKey,
];
impl RemovalEffect {
    fn failed_check(self) -> &'static str {
        use RemovalEffect::*;
        match self {
            DedicatedTunnel => "Dedicated tunnel connector removal",
            ClientIdentitySubscription => "Client Identity subscription removal",
            ClientIdentityTarget => "Interrupted Client Identity rotation removal",
            PreparedSubscription => "Interrupted subscription enablement removal",
            SubscriptionRotation => "Interrupted Subscription Link rotation removal",
            SubscriptionRepair => "Interrupted subscription repair removal",
            ServingRuntime => "Subscription Serving removal",
            RenewalIntegration => "Renewal recorder removal",
            SubscriptionResources => "Subscription owned-resource removal",
            RetiredHttps => "Retired HTTPS owned-resource removal",
            ProxyStartup => "Proxy startup integration removal",
            StopDisableProxy => "Stop and disable service",
            PackageArtifact => "Remove package artifact",
            PackageHold => "Remove package hold",
            Package => "Remove package",
            ConfigurationState => "Remove configuration and state",
            PackageIdentity => "Remove package identity",
            AptSource => "Remove APT source",
            AptKey => "Remove APT key",
            Executable => "SBXR executable removal",
            InstalledRecord => "Installed Record removal",
        }
    }
    /// Reuse fixed host operations; hold removal is a separate Go checkpoint.
    pub fn host_operation(self) -> Option<Operation> {
        use RemovalEffect::*;
        Some(match self {
            StopDisableProxy => Operation::StopDisableService,
            PackageArtifact => Operation::RemovePackageArtifact,
            Package => Operation::RemovePackage,
            PackageHold => Operation::RemovePackageHold,
            ConfigurationState => Operation::RemoveConfigurationState,
            PackageIdentity => Operation::RemovePackageIdentity,
            AptSource => Operation::RemoveAptSource,
            AptKey => Operation::RemoveAptKey,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizationError {
    Interrupted,
    SynchronizationUnknown,
}

/// Narrow injected effects contract. There is deliberately no blanket SetupHost
/// implementation: setup cleanup alone cannot prove Complete removal ownership.
/// Every method must be bounded, preserve foreign/shared resources, and never
/// depend on CA, Cloudflare, network access or a tunnel token/binary for removal.
pub trait RemovalHost {
    fn is_native_system(&self) -> bool {
        false
    }
    fn effects_available(&self) -> bool {
        false
    }
    /// Verified identity of this running executable; no Latest/creator fallback.
    fn executing_release(&self) -> Result<ReleaseIdentity, HostError>;
    fn read_authority(&self) -> Result<AuthoritySnapshot, HostError>;
    fn inspect_removal(
        &self,
        record: Option<&OwnershipRecord>,
        release: &ReleaseIdentity,
    ) -> Result<RemovalFacts, HostError>;
    fn inspect_lifecycle(&self, release: &ReleaseIdentity) -> Result<LifecycleFacts, HostError>;
    /// Acquire and retain whole-host, package, and applicable writer/Certbot
    /// exclusion, checking exact lock identities. Failure retains no partial lock.
    fn begin_change(&mut self, record: Option<&OwnershipRecord>) -> Result<(), HostError>;
    /// Retain whole-host/writer exclusion while APT/dpkg takes its own locks.
    fn release_package_locks(&mut self);
    fn end_change(&mut self);
    /// Exact-source/target CAS, protected fixed paths, file+parent fsync. The
    /// record codec's removal transitions must be admitted by the adapter.
    fn publish(
        &mut self,
        expected: Option<&[u8]>,
        target: &OwnershipRecord,
    ) -> Result<(), HostError>;
    fn synchronize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), HostError>;
    /// Absent or exact recorded identity only; unknown and foreign return Err.
    /// Compound steps include quiescence/recreation barriers and exact firewall
    /// contributions. DedicatedTunnel excludes token/binary/DNS/account resources.
    fn inspect_effect(
        &self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<EffectState, HostError>;
    /// Recheck exact identity at mutation, including no-follow/inode/link/owner/
    /// mode/digest and empty-directory checks. Never recurse or adopt resources.
    fn apply(&mut self, effect: RemovalEffect, record: &OwnershipRecord) -> Result<(), HostError>;
    /// Fresh complete owned proxy/subscription/tunnel absence, including skipped
    /// checkpoints, plus a safe retained shared-renewal route.
    fn proxy_absent(&self, record: &OwnershipRecord) -> Result<bool, HostError>;
    /// Move the exact final record, no-replace, to /var/lib/.sbxr-removal.json;
    /// remove only an exact matching stage, fsync both parents, remove only the
    /// empty state directory, then unlink finalizer and fsync its parent. Support retry with exactly one authority.
    /// A post-unlink sync error is SynchronizationUnknown, never success.
    fn finalize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), FinalizationError>;
    /// UI cancellation is checked between durable effects; a started bounded
    /// effect completes first. Committed removal always keeps forward direction.
    fn cancelled(&self) -> bool {
        false
    }
}

pub struct PreparedRemoval {
    owner: Arc<()>,
    action: RemovalAction,
    snapshot: AuthoritySnapshot,
    facts: RemovalFacts,
    release: ReleaseIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalOutcome {
    Completed,
    Declined,
    Refused(RemovalError),
    NeedsCompletion(&'static str),
    FinalSynchronizationUnknown,
}
impl RemovalOutcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::Completed => "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED",
            Self::Declined => "PROXY-INSTALLATION-ACTION-CANCELLED",
            Self::Refused(_) => "PROXY-INSTALLATION-ACTION-REFUSED",
            Self::NeedsCompletion(_) | Self::FinalSynchronizationUnknown => {
                "PROXY-INSTALLATION-REMOVAL-COMPLETION-REQUIRED"
            }
        }
    }
}

/// Separate integration surface until the shared Interface exposes removal.
/// Its caller must invalidate on *every* later Review, including Status/details,
/// and map Complete removal's exact "REMOVE SBXR" prompt to Approved.
pub struct Removal<H> {
    host: H,
    owner: Arc<()>,
}
impl<H: RemovalHost> Removal<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            owner: Arc::new(()),
        }
    }
    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        self.invalidate();
        &mut self.host
    }
    pub fn into_host(self) -> H {
        self.host
    }
    pub fn invalidate(&mut self) {
        // Retained tokens keep their allocation alive, so identity cannot recur.
        self.owner = Arc::new(());
    }
    pub fn review(&mut self, action: RemovalAction) -> Result<PreparedRemoval, RemovalError> {
        self.invalidate();
        if !self.host.effects_available() {
            return Err(RemovalError::Host(HostError::LiveUnavailable));
        }
        let snapshot = self.host.read_authority()?;
        let selected = snapshot.selected()?;
        let executing = self.host.executing_release()?;
        let release = match (action, &selected) {
            (RemovalAction::Complete, Some(s))
                if s.record.recovery_direction() == RecoveryDirection::Removal =>
            {
                return Err(RemovalError::Authority);
            }
            (RemovalAction::Complete, _) => executing.clone(),
            (RemovalAction::Finish, Some(s)) => finishing_release(&s.record)?,
            _ => return Err(RemovalError::Authority),
        };
        if release != executing {
            return Err(RemovalError::ExactRelease);
        }
        let lifecycle = self.host.inspect_lifecycle(&release)?;
        if !lifecycle.valid
            || lifecycle.release != release
            || action == RemovalAction::Complete
                && (!lifecycle.executable_present || !lifecycle.installed_record_present)
        {
            return Err(RemovalError::ExactRelease);
        }
        let facts = self
            .host
            .inspect_removal(selected.as_ref().map(|s| &s.record), &release)?;
        if !facts.accepted {
            return Err(RemovalError::Safety);
        }
        if action == RemovalAction::Complete {
            commit_removal(selected.as_ref().map(|s| &s.record), &release)?;
        }
        Ok(PreparedRemoval {
            owner: self.owner.clone(),
            action,
            snapshot,
            facts,
            release,
        })
    }
    pub fn execute(
        &mut self,
        prepared: PreparedRemoval,
        confirmation: Confirmation,
    ) -> RemovalOutcome {
        if !Arc::ptr_eq(&self.owner, &prepared.owner) {
            return RemovalOutcome::Refused(RemovalError::PreparedAction);
        }
        self.invalidate();
        if confirmation == Confirmation::Declined {
            return RemovalOutcome::Declined;
        }
        if !self.host.effects_available() {
            return RemovalOutcome::Refused(RemovalError::Host(HostError::LiveUnavailable));
        }
        let selected = match prepared.snapshot.selected() {
            Ok(value) => value,
            Err(error) => return RemovalOutcome::Refused(error),
        };
        if self.host.cancelled() {
            return RemovalOutcome::Refused(RemovalError::Host(HostError::Cancelled));
        }
        if let Err(error) = self.host.begin_change(selected.as_ref().map(|s| &s.record)) {
            return RemovalOutcome::Refused(error.into());
        }
        let result = self.execute_locked(prepared, selected);
        self.host.end_change();
        result
    }
    fn execute_locked(
        &mut self,
        prepared: PreparedRemoval,
        selected: Option<SelectedAuthority>,
    ) -> RemovalOutcome {
        let revalidate = || -> Result<(), RemovalError> {
            if self.host.cancelled() {
                return Err(RemovalError::Host(HostError::Cancelled));
            }
            if self.host.read_authority()? != prepared.snapshot {
                return Err(RemovalError::PreparedAction);
            }
            if self.host.executing_release()? != prepared.release {
                return Err(RemovalError::ExactRelease);
            }
            let lifecycle = self.host.inspect_lifecycle(&prepared.release)?;
            if !lifecycle.valid || lifecycle.release != prepared.release {
                return Err(RemovalError::ExactRelease);
            }
            if prepared.action == RemovalAction::Complete {
                if !lifecycle.executable_present || !lifecycle.installed_record_present {
                    return Err(RemovalError::ExactRelease);
                }
                let facts = self
                    .host
                    .inspect_removal(selected.as_ref().map(|s| &s.record), &prepared.release)?;
                if !facts.accepted || facts != prepared.facts {
                    return Err(RemovalError::Safety);
                }
            } else if selected
                .as_ref()
                .is_some_and(|s| checkpoint(&s.record) == Ok(0))
            {
                let facts = self
                    .host
                    .inspect_removal(selected.as_ref().map(|s| &s.record), &prepared.release)?;
                if !facts.accepted {
                    return Err(RemovalError::Safety);
                }
            }
            Ok(())
        };
        if let Err(error) = revalidate() {
            return RemovalOutcome::Refused(error);
        }
        let authority = if prepared.action == RemovalAction::Complete {
            let record =
                match commit_removal(selected.as_ref().map(|s| &s.record), &prepared.release) {
                    Ok(record) => record,
                    Err(error) => return RemovalOutcome::Refused(error),
                };
            let expected = selected.as_ref().map(|s| s.bytes.as_slice());
            if !self.publish_verified(expected, &record) {
                return match self
                    .host
                    .read_authority()
                    .ok()
                    .and_then(|s| s.selected().ok())
                    .flatten()
                {
                    Some(current) if current.record == record => {
                        RemovalOutcome::NeedsCompletion("Removal commitment synchronization")
                    }
                    _ => RemovalOutcome::Refused(RemovalError::Authority),
                };
            }
            SelectedAuthority {
                bytes: record.encode().expect("validated authority"),
                record,
                location: AuthorityLocation::Current,
            }
        } else {
            selected.expect("Finish review requires authority")
        };
        self.host.release_package_locks();
        self.finish(authority)
    }
    fn publish_verified(&mut self, expected: Option<&[u8]>, target: &OwnershipRecord) -> bool {
        // Any publication error has uncertain outcome: inspect exact target,
        // never repeat commitment against an assumed old source.
        let _published = self.host.publish(expected, target);
        let Ok(bytes) = target.encode() else {
            return false;
        };
        let Ok(snapshot) = self.host.read_authority() else {
            return false;
        };
        let Ok(Some(selected)) = snapshot.selected() else {
            return false;
        };
        selected.location == AuthorityLocation::Current
            && selected.bytes == bytes
            && self
                .host
                .synchronize(AuthorityLocation::Current, &bytes)
                .is_ok()
    }
    fn perform(&mut self, effect: RemovalEffect, record: &OwnershipRecord) -> bool {
        if !matches!(self.host.read_authority().ok().and_then(|s| s.selected().ok()).flatten(), Some(current) if current.record == *record)
        {
            return false;
        }
        match self.host.inspect_effect(effect, record) {
            Ok(EffectState::Absent) => true,
            Ok(EffectState::ExactOwned) => {
                self.host.apply(effect, record).is_ok()
                    && self.host.inspect_effect(effect, record) == Ok(EffectState::Absent)
            }
            Err(_) => false,
        }
    }
    fn advance(&mut self, selected: &mut SelectedAuthority) -> bool {
        let Ok(next) = next_checkpoint(&selected.record) else {
            return false;
        };
        if !self.publish_verified(Some(&selected.bytes), &next) {
            return false;
        }
        selected.bytes = next.encode().expect("validated authority");
        selected.record = next;
        true
    }
    fn finish(&mut self, mut selected: SelectedAuthority) -> RemovalOutcome {
        use RemovalOutcome::NeedsCompletion as Incomplete;
        if self
            .host
            .synchronize(selected.location, &selected.bytes)
            .is_err()
        {
            return Incomplete("Removal authority synchronization");
        }
        let Ok(value) = wire(&selected.record) else {
            return Incomplete("Removal authority");
        };
        let mut auxiliary = Vec::new();
        if value.get("tunnel").is_some() {
            auxiliary.push(RemovalEffect::DedicatedTunnel);
        }
        let mut serving_removed = false;
        if let Some(client) = value.get("client_identity_rotation") {
            if client.get("subscription").is_some() {
                auxiliary.extend([
                    RemovalEffect::ClientIdentitySubscription,
                    RemovalEffect::SubscriptionRepair,
                ]);
                serving_removed = true;
            }
            auxiliary.push(RemovalEffect::ClientIdentityTarget);
        }
        if value.get("subscription_enablement").is_some() {
            auxiliary.push(RemovalEffect::PreparedSubscription);
        }
        if value.get("subscription_rotation").is_some() {
            auxiliary.push(RemovalEffect::SubscriptionRotation);
        }
        if value
            .get("subscription_repair")
            .and_then(|r| r.get("target"))
            .is_some()
        {
            auxiliary.push(RemovalEffect::SubscriptionRepair);
            serving_removed = true;
        }
        if value.get("serving").is_some() && !serving_removed {
            auxiliary.push(RemovalEffect::ServingRuntime);
        }
        if value.get("renewal").is_some() {
            auxiliary.push(RemovalEffect::RenewalIntegration);
        }
        if value.get("subscription_resources").is_some() {
            auxiliary.push(RemovalEffect::SubscriptionResources);
        }
        if value.get("https_retirement").is_some() {
            auxiliary.push(RemovalEffect::RetiredHttps);
        }
        for effect in auxiliary {
            if !self.perform(effect, &selected.record) {
                return Incomplete(effect.failed_check());
            }
            if self.host.cancelled() {
                return Incomplete("Managed termination");
            }
        }
        let proxy_count = checkpoint_limit(&selected.record).expect("committed authority") - 3;
        let startup = value.get("proxy_startup").is_some();
        if startup
            && checkpoint(&selected.record).unwrap_or(0) > 0
            && !self.perform(RemovalEffect::ProxyStartup, &selected.record)
        {
            return Incomplete("Proxy startup integration removal");
        }
        for (index, effect) in PROXY_EFFECTS
            .into_iter()
            .take(proxy_count as usize)
            .enumerate()
        {
            if checkpoint(&selected.record).unwrap_or(0) > index as u32 {
                continue;
            }
            if !self.perform(effect, &selected.record) {
                return Incomplete(effect.failed_check());
            }
            if !self.advance(&mut selected) {
                return Incomplete("Removal checkpoint");
            }
            if index == 0 && startup && !self.perform(RemovalEffect::ProxyStartup, &selected.record)
            {
                return Incomplete("Proxy startup integration removal");
            }
            if self.host.cancelled() {
                return Incomplete("Managed termination");
            }
        }
        if checkpoint(&selected.record).unwrap_or(0) <= proxy_count {
            if self.host.proxy_absent(&selected.record) != Ok(true) {
                return Incomplete("Final proxy absence inspection");
            }
            if !self.advance(&mut selected) {
                return Incomplete("Proxy absence checkpoint");
            }
        }
        let release = finishing_release(&selected.record).expect("committed authority");
        let facts = match self.host.inspect_lifecycle(&release) {
            Ok(facts) if facts.valid && facts.release == release && facts.state_directory_empty => {
                facts
            }
            _ => return Incomplete("SBXR state directory inspection"),
        };
        // Restored exact-release members must be removed again even when their
        // prior deletion checkpoint is already durable.
        for (effect, present, limit) in [
            (
                RemovalEffect::Executable,
                facts.executable_present,
                proxy_count + 1,
            ),
            (
                RemovalEffect::InstalledRecord,
                facts.installed_record_present,
                proxy_count + 2,
            ),
        ] {
            if (present || checkpoint(&selected.record).unwrap_or(0) <= limit)
                && !self.perform(effect, &selected.record)
            {
                return Incomplete(effect.failed_check());
            }
            if checkpoint(&selected.record).unwrap_or(0) <= limit && !self.advance(&mut selected) {
                return Incomplete("Installed product removal checkpoint");
            }
            if self.host.cancelled() {
                return Incomplete("Managed termination");
            }
        }
        if self.host.proxy_absent(&selected.record) != Ok(true) {
            return Incomplete("Final proxy absence inspection");
        }
        match self.host.inspect_lifecycle(&release) {
            Ok(facts)
                if facts.valid
                    && facts.release == release
                    && facts.state_directory_empty
                    && !facts.executable_present
                    && !facts.installed_record_present => {}
            _ => return Incomplete("Final installed-product absence inspection"),
        }
        match self.host.finalize(selected.location, &selected.bytes) {
            Ok(()) => match self.host.read_authority() {
                Ok(snapshot) if snapshot == AuthoritySnapshot::default() => {
                    RemovalOutcome::Completed
                }
                _ => Incomplete("Ownership Record finalization"),
            },
            Err(FinalizationError::Interrupted) => Incomplete("Ownership Record finalization"),
            Err(FinalizationError::SynchronizationUnknown) => {
                RemovalOutcome::FinalSynchronizationUnknown
            }
        }
    }
}

/// Recovery may restore only missing members of the exact bound release. The
/// lifecycle adapter must authenticate bytes before installation and must never
/// restore proxy state, select Latest, or replace an existing conflicting member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactRestoration {
    pub release: ReleaseIdentity,
    pub restore_executable: bool,
    pub restore_installed_record: bool,
}
pub fn exact_restoration(
    snapshot: &AuthoritySnapshot,
    facts: LifecycleFacts,
) -> Result<Option<ExactRestoration>, RemovalError> {
    let selected = snapshot.selected()?.ok_or(RemovalError::Authority)?;
    let release = finishing_release(&selected.record)?;
    if !facts.valid || facts.release != release {
        return Err(RemovalError::ExactRelease);
    }
    if facts.executable_present && facts.installed_record_present {
        return Ok(None);
    }
    Ok(Some(ExactRestoration {
        release,
        restore_executable: !facts.executable_present,
        restore_installed_record: !facts.installed_record_present,
    }))
}
