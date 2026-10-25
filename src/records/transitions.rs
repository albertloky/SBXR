//! Pure current HTTP authority transitions, not Owner confirmation or host proof.
//! Every generated target is revalidated and bound to exact creating provenance.
use super::{
    OwnershipRecord, RecordError, RecoveryDirection, ReleaseIdentity, ServingAuthority, SetupPhase,
    SubscriptionResources, TunnelAuthority,
    operations::*,
    ownership::WireOwnershipRecord,
    resources::{creator_identity, resources},
};
use crate::subscription_artifact::SubscriptionCredential;
use std::collections::BTreeMap;
pub const HTTP_ENABLEMENT_CHECKPOINTS: &[u32] = &[0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 22, 23];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeDirection {
    Cleanup,
    Forward,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingChange {
    Enablement {
        checkpoint: u32,
    },
    LinkRotation {
        checkpoint: String,
        direction: ChangeDirection,
    },
    RuntimeOrCertificateRepair {
        checkpoint: String,
        correction: String,
        direction: ChangeDirection,
    },
    ClientIdentityRotation {
        checkpoint: String,
        direction: ChangeDirection,
    },
    HistoricalCertificateActivation {
        checkpoint: String,
    },
    HistoricalTransportMigration,
    Removal {
        checkpoint: u32,
    },
}
impl PendingChange {
    pub fn direction(&self) -> Option<ChangeDirection> {
        match self {
            Self::Enablement { .. } => Some(ChangeDirection::Cleanup),
            Self::LinkRotation { direction, .. }
            | Self::RuntimeOrCertificateRepair { direction, .. }
            | Self::ClientIdentityRotation { direction, .. } => Some(*direction),
            Self::Removal { .. } => Some(ChangeDirection::Forward),
            _ => None,
        }
    }
}
impl OwnershipRecord {
    pub fn schema(&self) -> u32 {
        self.0.schema
    }
    pub fn tunnel_authority(&self) -> Option<TunnelAuthority> {
        self.0.tunnel.clone().map(TunnelAuthority)
    }
    pub fn serving_authority(&self) -> Option<ServingAuthority> {
        self.0.serving.clone().map(ServingAuthority)
    }
    pub fn creating_releases(&self) -> Vec<ReleaseIdentity> {
        self.0
            .resource_creating_releases
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .cloned()
            .map(ReleaseIdentity)
            .collect()
    }
    pub fn pending_change(&self) -> Option<PendingChange> {
        if self.recovery_direction() == RecoveryDirection::Removal {
            return Some(PendingChange::Removal {
                checkpoint: self.0.removal_checkpoint,
            });
        }
        if self.0.subscription_transport_migration {
            return Some(PendingChange::HistoricalTransportMigration);
        }
        let direction = |v: &str| {
            if v == "forward" {
                ChangeDirection::Forward
            } else {
                ChangeDirection::Cleanup
            }
        };
        if let Some(v) = &self.0.subscription_enablement {
            return Some(PendingChange::Enablement {
                checkpoint: v.checkpoint,
            });
        }
        if let Some(v) = &self.0.subscription_rotation {
            return Some(PendingChange::LinkRotation {
                checkpoint: v.checkpoint.clone(),
                direction: direction(&v.direction),
            });
        }
        if let Some(v) = &self.0.subscription_repair {
            return Some(PendingChange::RuntimeOrCertificateRepair {
                checkpoint: v.checkpoint.clone(),
                correction: v.correction.clone(),
                direction: direction(&v.direction),
            });
        }
        if let Some(v) = &self.0.client_identity_rotation {
            return Some(PendingChange::ClientIdentityRotation {
                checkpoint: v.checkpoint.clone(),
                direction: direction(&v.direction),
            });
        }
        self.0.certificate_activation.as_ref().map(|v| {
            PendingChange::HistoricalCertificateActivation {
                checkpoint: v.checkpoint.clone(),
            }
        })
    }
    pub fn new_tunnel_setup(
        release: ReleaseIdentity,
        ipv4: &str,
        configuration_sha256: &str,
        tunnel: TunnelAuthority,
    ) -> Result<Self, RecordError> {
        let mut record = Self::new_standard(release, ipv4, configuration_sha256)?;
        record.0.tunnel = Some(tunnel.0);
        record.0.permitted_resources = resources(&record.0);
        Self::validated(record.0)
    }
    fn current_running(&self) -> bool {
        self.0.phase == SetupPhase::Running
            && self.0.unfinished_direction == RecoveryDirection::None
            && !self.0.subscription_transport_migration
            && self.0.finishing_release_identity.is_none()
            && self.0.client_identity_rotation.is_none()
            && self.0.certificate_activation.is_none()
    }
    fn idle_http(&self) -> bool {
        self.current_running()
            && self.0.schema == 2
            && self.pending_change().is_none()
            && self.0.serving.as_ref().is_some_and(|s| s.http)
    }
    fn with_resources(&self, mut next: WireOwnershipRecord) -> Result<Self, RecordError> {
        let old: BTreeMap<_, _> = self
            .0
            .permitted_resources
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    creator_identity(r),
                    self.0
                        .resource_creating_releases
                        .as_ref()
                        .and_then(|v| v.get(i))
                        .unwrap_or(&self.0.release_identity)
                        .clone(),
                )
            })
            .collect();
        next.permitted_resources = resources(&next);
        next.resource_creating_releases = Some(
            next.permitted_resources
                .iter()
                .map(|r| {
                    old.get(&creator_identity(r))
                        .unwrap_or(&self.0.release_identity)
                        .clone()
                })
                .collect(),
        );
        Self::validated(next)
    }
    /// Call only after reviewed confirmation and fresh host admission. This stores
    /// credential hashes, never credential bytes, and does not migrate transport.
    pub fn begin_http_enablement(
        &self,
        link_id: &str,
        credential: &SubscriptionCredential,
        recorder_id: &str,
        firewall_sha256: &str,
    ) -> Result<Self, RecordError> {
        if !self.current_running()
            || self.pending_change().is_some()
            || self.0.serving.is_some()
            || self.0.renewal.is_some()
            || self.0.subscription_resources.is_some()
            || self.0.https_retirement.is_some()
        {
            return Err(RecordError);
        }
        let serving = ServingAuthority::http(link_id, credential)?;
        let resources = SubscriptionResources::http(&self.0.public_ipv4, firewall_sha256)?;
        let mut next = self.0.clone();
        next.schema = 2;
        next.subscription_enablement = Some(WireEnablement {
            checkpoint: 0,
            link_id: serving.0.link_id,
            credential_sha256: serving.0.credential_sha256,
            recorder_id: recorder_id.into(),
            serving: None,
            renewal: None,
            resources: Some(resources.0),
        });
        self.with_resources(next)
    }
    pub fn advance_http_enablement(&self) -> Result<Self, RecordError> {
        if !self.current_running() {
            return Err(RecordError);
        }
        let e = self.0.subscription_enablement.as_ref().ok_or(RecordError)?;
        if !e.resources.as_ref().is_some_and(|r| r.http) {
            return Err(RecordError);
        }
        let index = HTTP_ENABLEMENT_CHECKPOINTS
            .iter()
            .position(|cp| *cp == e.checkpoint)
            .ok_or(RecordError)?;
        let checkpoint = *HTTP_ENABLEMENT_CHECKPOINTS
            .get(index + 1)
            .ok_or(RecordError)?;
        let mut next = self.0.clone();
        let e = next.subscription_enablement.as_mut().expect("present");
        e.checkpoint = checkpoint;
        if checkpoint >= 8 {
            e.serving = Some(ServingAuthority::http_digest(&e.link_id, &e.credential_sha256)?.0)
        }
        self.with_resources(next)
    }
    /// Caller must prove the exact prepared generation active, serving locally,
    /// proxy healthy, and staging empty before final commitment/disclosure.
    pub fn commit_http_enablement(&self) -> Result<Self, RecordError> {
        if !self.current_running() {
            return Err(RecordError);
        }
        let e = self.0.subscription_enablement.as_ref().ok_or(RecordError)?;
        if e.checkpoint != 23
            || !e.serving.as_ref().is_some_and(|s| s.http)
            || !e.resources.as_ref().is_some_and(|r| r.http)
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.serving = e.serving.clone();
        next.subscription_resources = e.resources.clone();
        next.subscription_enablement = None;
        self.with_resources(next)
    }
    /// No checkpoint grants final commitment by itself. After proved cleanup,
    /// every unfinished HTTP enablement returns to absent subscription authority.
    pub fn cleanup_http_enablement(&self) -> Result<Self, RecordError> {
        if !self.current_running()
            || !self
                .0
                .subscription_enablement
                .as_ref()
                .is_some_and(|e| e.resources.as_ref().is_some_and(|r| r.http))
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_enablement = None;
        self.with_resources(next)
    }
    pub fn begin_http_link_rotation(
        &self,
        operation_id: &str,
        new_link_id: &str,
        credential: &SubscriptionCredential,
    ) -> Result<Self, RecordError> {
        if !self.idle_http() {
            return Err(RecordError);
        }
        let source = self.0.serving.clone().ok_or(RecordError)?;
        let target = ServingAuthority::http(new_link_id, credential)?.0;
        let mut next = self.0.clone();
        next.subscription_rotation = Some(WireRotation {
            operation_id: operation_id.into(),
            kind: "rotate subscription link".into(),
            direction: "cleanup".into(),
            effects: strings(ROTATION_EFFECTS),
            completed_effects: None,
            source,
            target,
            checkpoint: "target authorized".into(),
        });
        self.with_resources(next)
    }
    /// Stop-authorization follows proved target preparation; commitment follows
    /// proved source-request quiescence. Committed selection never restores source.
    pub fn advance_http_link_rotation(&self) -> Result<Self, RecordError> {
        if !self.current_running() {
            return Err(RecordError);
        }
        let old = self.0.subscription_rotation.as_ref().ok_or(RecordError)?;
        if !old.source.http {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        let r = next.subscription_rotation.as_mut().expect("present");
        match r.checkpoint.as_str() {
            "target authorized" => {
                r.checkpoint = "stop authorized".into();
                r.completed_effects = Some(strings(&["target prepared"]));
            }
            "stop authorized" => {
                r.checkpoint = "committed".into();
                r.direction = "forward".into();
                r.completed_effects = Some(strings(&["target prepared", "source stopped"]));
                next.serving = Some(r.target.clone());
            }
            _ => return Err(RecordError),
        }
        self.with_resources(next)
    }
    pub fn cleanup_http_link_rotation(&self) -> Result<Self, RecordError> {
        if !self.current_running()
            || !self
                .0
                .subscription_rotation
                .as_ref()
                .is_some_and(|r| r.source.http && r.checkpoint != "committed")
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_rotation = None;
        self.with_resources(next)
    }
    pub fn complete_http_link_rotation(&self) -> Result<Self, RecordError> {
        if !self.current_running()
            || !self
                .0
                .subscription_rotation
                .as_ref()
                .is_some_and(|r| r.target.http && r.checkpoint == "committed")
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_rotation = None;
        next.subscription_compromised = false;
        self.with_resources(next)
    }
    pub fn mark_subscription_compromised(&self) -> Result<Self, RecordError> {
        if !self.current_running() || !self.0.serving.as_ref().is_some_and(|s| s.http) {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_compromised = true;
        self.with_resources(next)
    }
    pub fn begin_http_runtime_repair(&self, operation_id: &str) -> Result<Self, RecordError> {
        if !self.idle_http() {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_repair = Some(WireRepair {
            operation_id: operation_id.into(),
            kind: "repair subscription".into(),
            direction: "cleanup".into(),
            correction: "restart owned serving runtime".into(),
            effects: strings(&["restart owned serving runtime"]),
            completed_effects: None,
            checkpoint: "prepared".into(),
            source: self.0.serving.clone().ok_or(RecordError)?,
            target: None,
        });
        self.with_resources(next)
    }
    pub fn advance_http_runtime_repair(&self) -> Result<Self, RecordError> {
        if !self.current_running() {
            return Err(RecordError);
        }
        let old = self.0.subscription_repair.as_ref().ok_or(RecordError)?;
        if !old.source.http || old.correction != "restart owned serving runtime" {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        let repair = next.subscription_repair.as_mut().expect("present");
        match repair.checkpoint.as_str() {
            "prepared" => {
                repair.checkpoint = "committed".into();
                repair.direction = "forward".into();
            }
            "committed" if repair.target.is_none() => repair.target = Some(repair.source.clone()),
            "committed" => {
                repair.checkpoint = "accepted".into();
                repair.completed_effects = Some(repair.effects.clone());
                next.serving = repair.target.clone();
            }
            _ => return Err(RecordError),
        }
        self.with_resources(next)
    }
    pub fn cleanup_http_runtime_repair(&self) -> Result<Self, RecordError> {
        if !self.current_running()
            || !self.0.subscription_repair.as_ref().is_some_and(|r| {
                r.source.http
                    && r.correction == "restart owned serving runtime"
                    && r.checkpoint == "prepared"
            })
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_repair = None;
        self.with_resources(next)
    }
    pub fn complete_http_runtime_repair(&self) -> Result<Self, RecordError> {
        if !self.current_running()
            || !self.0.subscription_repair.as_ref().is_some_and(|r| {
                r.source.http
                    && r.correction == "restart owned serving runtime"
                    && r.checkpoint == "accepted"
            })
        {
            return Err(RecordError);
        }
        let mut next = self.0.clone();
        next.subscription_repair = None;
        self.with_resources(next)
    }
    pub(super) fn http_successor(&self, next: &Self) -> bool {
        let same = |v: Result<Self, RecordError>| v.as_ref() == Ok(next);
        if let Some(e) = &next.0.subscription_enablement
            && self.0.subscription_enablement.is_none()
            && e.checkpoint == 0
            && e.resources
                .as_ref()
                .is_some_and(|r| r.http && r.public_ipv4 == self.0.public_ipv4)
            && e.serving.is_none()
            && e.renewal.is_none()
        {
            let mut candidate = self.0.clone();
            candidate.schema = 2;
            candidate.subscription_enablement = Some(e.clone());
            if self.current_running()
                && self.pending_change().is_none()
                && self.0.serving.is_none()
                && self.0.renewal.is_none()
                && self.0.subscription_resources.is_none()
                && self.0.https_retirement.is_none()
                && same(self.with_resources(candidate))
            {
                return true;
            }
        }
        if self.0.subscription_enablement.is_some()
            && (same(self.advance_http_enablement())
                || same(self.commit_http_enablement())
                || same(self.cleanup_http_enablement()))
        {
            return true;
        }
        if let Some(r) = &next.0.subscription_rotation
            && self.0.subscription_rotation.is_none()
            && self.idle_http()
            && r.source.http
            && r.checkpoint == "target authorized"
            && r.completed_effects.is_none()
            && self.0.serving.as_ref() == Some(&r.source)
        {
            let mut candidate = self.0.clone();
            candidate.subscription_rotation = Some(r.clone());
            if same(self.with_resources(candidate)) {
                return true;
            }
        }
        if self.0.subscription_rotation.is_some()
            && (same(self.advance_http_link_rotation())
                || same(self.cleanup_http_link_rotation())
                || same(self.complete_http_link_rotation()))
        {
            return true;
        }
        if let Some(r) = &next.0.subscription_repair
            && self.0.subscription_repair.is_none()
            && self.idle_http()
            && r.source.http
            && r.correction == "restart owned serving runtime"
            && r.checkpoint == "prepared"
            && r.completed_effects.is_none()
            && self.0.serving.as_ref() == Some(&r.source)
        {
            let mut candidate = self.0.clone();
            candidate.subscription_repair = Some(r.clone());
            if same(self.with_resources(candidate)) {
                return true;
            }
        }
        self.0.subscription_repair.is_some()
            && (same(self.advance_http_runtime_repair())
                || same(self.cleanup_http_runtime_repair())
                || same(self.complete_http_runtime_repair()))
            || !self.0.subscription_compromised && same(self.mark_subscription_compromised())
    }
}
