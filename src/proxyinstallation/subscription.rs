//! Owner Review/Execute for current HTTP enablement, link rotation and runtime
//! repair. Durable state chooses cleanup/forward; no recovery generates secrets.
use super::*;
use crate::{
    durable::{OwnershipStore, Snapshot},
    host::{
        HostError,
        subscription::{HttpEffect, HttpObservation, SubscriptionHost, http_firewall_unit},
    },
    identity_generation::{Entropy, GenerationId, OsEntropy, SubscriptionGeneration},
    records::{
        ChangeDirection, HTTP_ENABLEMENT_CHECKPOINTS, HttpOperation, OwnershipRecord,
        ReleaseIdentity, SetupPhase, sha256_hex,
    },
    runtime_handoff::{START_TIMEOUT, StartContext},
    subscription_artifact::HttpSubscriptionLink,
    subscription_serving::Cancellation,
};
use std::result::Result as HostResult;
use std::time::Instant;
pub(super) struct HttpPrepared {
    current: Vec<u8>,
    observation: HttpObservation,
}
struct State {
    record: OwnershipRecord,
    bytes: Vec<u8>,
    observation: HttpObservation,
    actions: Vec<Action>,
}
pub struct HttpInstallation<H: SubscriptionHost> {
    owner: RefCell<Rc<()>>,
    host: H,
    store: OwnershipStore,
    release: ReleaseIdentity,
    entropy: Box<dyn Entropy>,
    stop: Cancellation,
    last_link: Option<HttpSubscriptionLink>,
}
impl<H: SubscriptionHost> HttpInstallation<H> {
    pub fn new(host: H, release: ReleaseIdentity) -> HostResult<Self, HostError> {
        Self::with_entropy(host, release, Box::new(OsEntropy))
    }
    pub fn with_entropy(
        host: H,
        release: ReleaseIdentity,
        entropy: Box<dyn Entropy>,
    ) -> HostResult<Self, HostError> {
        Self::open(host, release, entropy, false)
    }
    fn open(
        host: H,
        release: ReleaseIdentity,
        entropy: Box<dyn Entropy>,
        native: bool,
    ) -> HostResult<Self, HostError> {
        if host.root() == std::path::Path::new("/") && !native {
            return Err(HostError::LiveUnavailable);
        }
        let store = OwnershipStore::open(&host.root().join("var/lib/sbxr"), host.uid())
            .map_err(|_| HostError::Unsafe)?;
        Ok(Self {
            owner: RefCell::new(Rc::new(())),
            host,
            store,
            release,
            entropy,
            stop: Cancellation::new(),
            last_link: None,
        })
    }
    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        *self.owner.get_mut() = Rc::new(());
        self.last_link = None;
        &mut self.host
    }
    pub fn into_host(self) -> H {
        self.host
    }
    fn mode(&self) -> ExecutionMode {
        if self.host.root() == std::path::Path::new("/") {
            ExecutionMode::native_unreleased()
        } else {
            ExecutionMode::InjectedHost
        }
    }
    pub fn with_cancellation(mut self, stop: Cancellation) -> Self {
        self.stop = stop;
        *self.owner.get_mut() = Rc::new(());
        self.last_link = None;
        self
    }
    pub fn cancellation(&self) -> Cancellation {
        self.stop.clone()
    }
    fn state(&self) -> HostResult<State, HostError> {
        let Snapshot { current, staged } = self.store.load().map_err(|_| HostError::Foreign)?;
        if staged.is_some() {
            return Err(HostError::Foreign);
        }
        let current = current.ok_or(HostError::Foreign)?;
        let bytes = current.bytes().to_vec();
        let record = current.record;
        if record.phase() != SetupPhase::Running
            || record.recovery_direction() != crate::records::RecoveryDirection::None
            || record.release_identity() != self.release
        {
            return Err(HostError::Foreign);
        }
        let op = record.http_operation().map_err(|_| HostError::Foreign)?;
        let observation = self.host.inspect(&record)?;
        if !observation.proxy || observation.public_ipv4 != record.public_ipv4() {
            return Err(HostError::Foreign);
        }
        let mut actions = vec![Action::ViewDetails];
        if op.is_some() {
            actions.push(Action::FinishSubscriptionChange);
        } else if record.serving_authority().is_none() && observation.absent {
            actions.push(Action::EnableSubscription);
        } else if record.serving_authority().is_some_and(|a| a.is_http()) && observation.material {
            actions.push(Action::RotateSubscriptionLink);
            if !observation.serving {
                actions.insert(1, Action::RepairSubscription);
            }
        }
        Ok(State {
            record,
            bytes,
            observation,
            actions,
        })
    }
    fn status_for(state: &State) -> &'static str {
        if state.record.pending_change().is_some() {
            "Change incomplete"
        } else if state.record.subscription_compromised() {
            "Problem detected"
        } else if state.record.serving_authority().is_none() {
            "Not enabled"
        } else if state.observation.material && state.observation.serving {
            "Available"
        } else {
            "Problem detected"
        }
    }
    fn context(&self) -> StartContext {
        StartContext::new(self.stop.clone(), Instant::now() + START_TIMEOUT)
    }
    fn publish(
        &mut self,
        current: &mut OwnershipRecord,
        next: OwnershipRecord,
    ) -> HostResult<(), HostError> {
        let before = current.encode().map_err(|_| HostError::Foreign)?;
        let bytes = next.encode().map_err(|_| HostError::Foreign)?;
        if self.store.publish(Some(&before), &next).is_err() {
            let fresh = self.store.load().map_err(|_| HostError::Foreign)?;
            if fresh.staged.is_some()
                || fresh.current.as_ref().map(|r| r.bytes()) != Some(bytes.as_slice())
                || self.store.synchronize(&bytes).is_err()
            {
                return Err(HostError::Foreign);
            }
        }
        *current = next;
        Ok(())
    }
    fn apply(
        &mut self,
        effect: HttpEffect,
        record: &OwnershipRecord,
        credential: Option<&crate::subscription_artifact::SubscriptionCredential>,
    ) -> HostResult<(), HostError> {
        self.context().check().map_err(|_| HostError::Cancelled)?;
        self.host
            .effect(effect, record, credential, &self.context())
    }
    fn enable(&mut self, record: &mut OwnershipRecord) -> HostResult<Outcome, HostError> {
        let generation = SubscriptionGeneration::generate_with_entropy(self.entropy.as_mut())
            .map_err(|_| HostError::Io)?;
        let id = GenerationId::generate_with_entropy(self.entropy.as_mut())
            .map_err(|_| HostError::Io)?;
        let hash = sha256_hex(&http_firewall_unit(record.public_ipv4())?);
        self.publish(
            record,
            record
                .begin_http_enablement(
                    generation.link_id().as_str(),
                    generation.credential(),
                    id.as_str(),
                    &hash,
                )
                .map_err(|_| HostError::Foreign)?,
        )?;
        for checkpoint in HTTP_ENABLEMENT_CHECKPOINTS.iter().copied().skip(1) {
            self.publish(
                record,
                record
                    .advance_http_enablement()
                    .map_err(|_| HostError::Foreign)?,
            )?;
            self.apply(
                HttpEffect::Enable(checkpoint),
                record,
                Some(generation.credential()),
            )?;
        }
        self.apply(HttpEffect::Verify, record, None)?;
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        self.publish(
            record,
            record
                .commit_http_enablement()
                .map_err(|_| HostError::Foreign)?,
        )?;
        self.disclose(record, Outcome::SubscriptionEnabled)
    }
    fn rotate(&mut self, record: &mut OwnershipRecord) -> HostResult<Outcome, HostError> {
        let generation = SubscriptionGeneration::generate_with_entropy(self.entropy.as_mut())
            .map_err(|_| HostError::Io)?;
        let id = GenerationId::generate_with_entropy(self.entropy.as_mut())
            .map_err(|_| HostError::Io)?;
        self.publish(
            record,
            record
                .begin_http_link_rotation(
                    id.as_str(),
                    generation.link_id().as_str(),
                    generation.credential(),
                )
                .map_err(|_| HostError::Foreign)?,
        )?;
        self.apply(
            HttpEffect::PrepareRotation,
            record,
            Some(generation.credential()),
        )?;
        self.publish(
            record,
            record
                .advance_http_link_rotation()
                .map_err(|_| HostError::Foreign)?,
        )?;
        self.apply(HttpEffect::StopSource, record, None)?;
        self.publish(
            record,
            record
                .advance_http_link_rotation()
                .map_err(|_| HostError::Foreign)?,
        )?;
        self.finish_rotation(record)
    }
    fn finish_rotation(&mut self, record: &mut OwnershipRecord) -> HostResult<Outcome, HostError> {
        self.apply(HttpEffect::PublishTarget, record, None)?;
        self.apply(HttpEffect::Activate, record, None)?;
        self.apply(HttpEffect::Verify, record, None)?;
        self.publish(
            record,
            record
                .complete_http_link_rotation()
                .map_err(|_| HostError::Foreign)?,
        )?;
        self.disclose(record, Outcome::SubscriptionLinkRotated)
    }
    fn repair(
        &mut self,
        record: &mut OwnershipRecord,
        finishing: bool,
    ) -> HostResult<Outcome, HostError> {
        if record
            .http_operation()
            .map_err(|_| HostError::Foreign)?
            .is_none()
        {
            let id = GenerationId::generate_with_entropy(self.entropy.as_mut())
                .map_err(|_| HostError::Io)?;
            self.publish(
                record,
                record
                    .begin_http_runtime_repair(id.as_str())
                    .map_err(|_| HostError::Foreign)?,
            )?;
        }
        if matches!(record.http_operation(),Ok(Some(HttpOperation::Repair{checkpoint,..})) if checkpoint=="prepared")
        {
            if finishing {
                self.publish(
                    record,
                    record
                        .cleanup_http_runtime_repair()
                        .map_err(|_| HostError::Foreign)?,
                )?;
                return Ok(Outcome::SubscriptionChangeCleanedUp);
            }
            self.publish(
                record,
                record
                    .advance_http_runtime_repair()
                    .map_err(|_| HostError::Foreign)?,
            )?;
        }
        if matches!(
            record.http_operation(),
            Ok(Some(HttpOperation::Repair { target: None, .. }))
        ) {
            self.publish(
                record,
                record
                    .advance_http_runtime_repair()
                    .map_err(|_| HostError::Foreign)?,
            )?;
        }
        if matches!(record.http_operation(),Ok(Some(HttpOperation::Repair{checkpoint,..})) if checkpoint=="committed")
        {
            self.apply(HttpEffect::Activate, record, None)?;
            self.apply(HttpEffect::Verify, record, None)?;
            self.publish(
                record,
                record
                    .advance_http_runtime_repair()
                    .map_err(|_| HostError::Foreign)?,
            )?;
        }
        self.apply(HttpEffect::FinishRepairState, record, None)?;
        self.publish(
            record,
            record
                .complete_http_runtime_repair()
                .map_err(|_| HostError::Foreign)?,
        )?;
        Ok(if finishing {
            Outcome::SubscriptionChangeFinished
        } else {
            Outcome::SubscriptionRepaired
        })
    }
    fn finish(&mut self, record: &mut OwnershipRecord) -> HostResult<Outcome, HostError> {
        match record
            .http_operation()
            .map_err(|_| HostError::Foreign)?
            .ok_or(HostError::Foreign)?
        {
            HttpOperation::Enablement { .. } => {
                self.apply(HttpEffect::CleanupEnable, record, None)?;
                self.publish(
                    record,
                    record
                        .cleanup_http_enablement()
                        .map_err(|_| HostError::Foreign)?,
                )?;
                Ok(Outcome::SubscriptionChangeCleanedUp)
            }
            HttpOperation::Rotation {
                direction: ChangeDirection::Cleanup,
                ..
            } => {
                self.apply(HttpEffect::RestoreSource, record, None)?;
                self.publish(
                    record,
                    record
                        .cleanup_http_link_rotation()
                        .map_err(|_| HostError::Foreign)?,
                )?;
                Ok(Outcome::SubscriptionChangeCleanedUp)
            }
            HttpOperation::Rotation {
                direction: ChangeDirection::Forward,
                ..
            } => self.finish_rotation(record),
            HttpOperation::Repair { .. } => self.repair(record, true),
        }
    }
    fn disclose(
        &mut self,
        record: &OwnershipRecord,
        success: Outcome,
    ) -> HostResult<Outcome, HostError> {
        match self.host.link(record) {
            Ok(link) => {
                self.last_link = Some(link);
                Ok(success)
            }
            Err(_) => Ok(Outcome::SubscriptionLinkDisplayIncomplete),
        }
    }
    fn result(&self, outcome: Outcome, message: &'static str) -> crate::domain::Result {
        let proxy = self
            .store
            .load()
            .ok()
            .and_then(|s| s.current)
            .is_some_and(|c| self.host.inspect(&c.record).is_ok_and(|o| o.proxy));
        crate::domain::Result {
            outcome,
            status: Status::Running,
            proxy_traffic: if proxy {
                Availability::ProvedWorking
            } else {
                Availability::CannotBeVerified
            },
            message,
        }
    }
}
impl<'a>
    HttpInstallation<
        crate::host::subscription::ProtectedHttpHost<
            'a,
            crate::host::owner_runtime::OwnerRuntime<'a, crate::host::owner_runtime::NativeIo>,
        >,
    >
{
    pub fn with_native_cancellation(mut self, stop: Cancellation) -> Self {
        self.host = self.host.with_native_cancellation(stop.clone());
        self.stop = stop;
        *self.owner.get_mut() = Rc::new(());
        self.last_link = None;
        self
    }
    pub fn native_unreleased(
        proof: &'a crate::release_acquisition::AuthenticatedInstalled,
    ) -> HostResult<Self, HostError> {
        Self::open(
            crate::host::subscription::ProtectedHttpHost::native_unreleased(proof)?,
            proof.record().release_identity(),
            Box::new(OsEntropy),
            true,
        )
    }
}
impl<H: SubscriptionHost> Interface for HttpInstallation<H> {
    fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let state = self.state();
        let Ok(state) = state else {
            return Review{mode:self.mode(),status:Status::ProblemDetected,details:vec!["HTTP authority or protected host facts could not be verified; preserve unknown resources.".into()],legal_actions:vec![Action::ViewDetails],plan:vec![],refusal:Some("HTTP subscription authority cannot be verified."),prepared:None};
        };
        let subscription_status = Self::status_for(&state);
        let prepared = if state.actions.contains(&action) && action != Action::ViewDetails {
            Some(PreparedAction {
                owner: Rc::clone(&self.owner.borrow()),
                action,
                basis: PreparedBasis::Subscription(HttpPrepared {
                    current: state.bytes.clone(),
                    observation: state.observation,
                }),
            })
        } else {
            None
        };
        let plan=match action {
            Action::EnableSubscription=>vec![format!("Serve HTTP on recorded IPv4 {} TCP 8443; preserve the REALITY proxy on TCP 443.",state.record.public_ipv4()),"HTTP exposes the Subscription Link credential and downloaded proxy credentials to network interception and permits response tampering. Token authentication does not protect the transport.".into(),"Create only exact owned HTTP units, protected token/state and the IPv4 TCP8443 firewall contribution. No Certbot or TCP80 effect.".into(),"Disclose only after durable commitment and local verification. Local checks do not establish Karing or outside reachability.".into()],
            Action::RotateSubscriptionLink=>vec!["Prepare one replacement while source remains authoritative; stop old accepted requests before commitment. No overlap.".into(),"After commitment finish only the selected replacement; never restore or regenerate source. Replace the old link in Karing; copied proxy credentials are not revoked by link rotation.".into()],
            Action::RepairSubscription=>vec!["Restart only the exact owned HTTP serving runtime; preserve Client Identity, credential and proxy configuration.".into()],
            Action::FinishSubscriptionChange=>vec![format!("Finish the recorded {:?} direction; never generate another credential.",state.record.pending_change().and_then(|p|p.direction()))],
            _=>vec![],
        };
        Review {
            mode: self.mode(),
            status: Status::Running,
            details: vec![format!(
                "HTTP subscription: {}. Proxy configuration remains bound to its Ownership Record.",
                subscription_status
            )],
            legal_actions: state.actions,
            plan,
            refusal: None,
            prepared,
        }
    }
    fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
    ) -> crate::domain::Result {
        self.last_link = None;
        let PreparedBasis::Subscription(basis) = prepared.basis else {
            return self.result(
                Outcome::Refused,
                "Prepared authority belongs to another adapter.",
            );
        };
        let unchanged = self.store.load().is_ok_and(|s| {
            s.staged.is_none()
                && s.current.as_ref().map(|r| r.bytes()) == Some(basis.current.as_slice())
        });
        if !Rc::ptr_eq(&self.owner.borrow(), &prepared.owner)
            || !unchanged
            || self.stop.is_cancelled()
        {
            return self.result(
                Outcome::Refused,
                "Reviewed HTTP facts changed or expired. Review again.",
            );
        }
        *self.owner.borrow_mut() = Rc::new(());
        if confirmation == Confirmation::Declined {
            return self.result(
                Outcome::Cancelled,
                "Subscription action cancelled. No changes were made.",
            );
        }
        if self.host.begin_change().is_err() {
            return self.result(
                Outcome::Refused,
                "Whole-host exclusion could not be retained.",
            );
        }
        let state = match self.state() {
            Ok(s)
                if s.bytes == basis.current
                    && s.observation == basis.observation
                    && s.actions.contains(&prepared.action) =>
            {
                s
            }
            _ => {
                self.host.end_change();
                return self.result(
                    Outcome::Refused,
                    "Reviewed HTTP facts changed under exclusion. Review again.",
                );
            }
        };
        let mut record = state.record;
        let result = match prepared.action {
            Action::EnableSubscription => self.enable(&mut record),
            Action::RotateSubscriptionLink => self.rotate(&mut record),
            Action::RepairSubscription => self.repair(&mut record, false),
            Action::FinishSubscriptionChange => self.finish(&mut record),
            _ => Err(HostError::Foreign),
        };
        self.host.end_change();
        match result {
            Ok(outcome)=>self.result(outcome,"Subscription action completed through the recorded direction; outside connectivity is not established by local checks."),
            Err(_)=>{
                let outcome=self.store.load().map_or(Outcome::SubscriptionProblemDetected,|s|{
                    if s.staged.is_some() || s.current.as_ref().is_some_and(|c|c.record.pending_change().is_some()){Outcome::SubscriptionChangeIncomplete}
                    else if s.current.as_ref().map(|c|c.bytes())==Some(basis.current.as_slice()){Outcome::Refused}else{Outcome::SubscriptionProblemDetected}
                });
                self.result(outcome,"The subscription action did not complete. Reinspect exact durable authority before further effects.")
            }
        }
    }
    fn subscription_status(&self) -> &'static str {
        self.state()
            .map_or("Problem detected", |state| Self::status_for(&state))
    }
    fn take_subscription_link(&mut self) -> Option<HttpSubscriptionLink> {
        self.last_link.take()
    }
}

#[cfg(test)]
#[path = "subscription_tests.rs"]
mod tests;
