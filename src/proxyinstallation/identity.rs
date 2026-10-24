//! Shared Owner Interface for the strict Client Identity state machine.
use super::*;
use crate::{
    client_identity as ci,
    identity_generation::{Entropy, OsEntropy},
    records::OwnershipRecord,
    subscription_serving::Cancellation,
};
use std::result::Result as HostResult;
pub(super) enum ClientPrepared {
    Rotate(Box<ci::PreparedRotation>),
    Finish(ci::PreparedFinish),
}
pub struct ClientIdentityInstallation<H: ci::Host> {
    host: RefCell<H>,
    owner: RefCell<Rc<()>>,
    entropy: RefCell<Box<dyn Entropy>>,
    stop: Cancellation,
}
impl<H: ci::Host> ClientIdentityInstallation<H> {
    pub fn new(host: H) -> Self {
        Self::with_entropy(host, Box::new(OsEntropy))
    }
    pub fn with_entropy(host: H, entropy: Box<dyn Entropy>) -> Self {
        Self {
            host: RefCell::new(host),
            owner: RefCell::new(Rc::new(())),
            entropy: RefCell::new(entropy),
            stop: Cancellation::new(),
        }
    }
    pub fn host_mut(&mut self) -> &mut H {
        *self.owner.get_mut() = Rc::new(());
        self.host.get_mut()
    }
    pub fn into_host(self) -> H {
        self.host.into_inner()
    }
    pub fn cancellation(&self) -> Cancellation {
        self.stop.clone()
    }
    fn mode(&self) -> ExecutionMode {
        if self.host.borrow().native_host() {
            ExecutionMode::NativeUnavailable
        } else {
            ExecutionMode::InjectedHost
        }
    }
    fn state(&self) -> HostResult<OwnershipRecord, ci::Error> {
        let mut host = self.host.borrow_mut();
        let guard = host.acquire()?;
        host.verify_guard(&guard)?;
        host.installed_release(&guard)?;
        let snapshot = host.snapshot(&guard)?;
        snapshot.publication_target()?;
        let record =
            OwnershipRecord::decode(&snapshot.current).map_err(|_| ci::Error::Authority)?;
        if ci::rotation(&record).is_ok() {
            host.inspect(&guard, &record)?;
        } else {
            host.admit(&guard, &record)?;
        }
        Ok(record)
    }
    fn result(&self, outcome: Outcome) -> crate::domain::Result {
        let state = self.state();
        let pending = state.as_ref().is_ok_and(|r| ci::rotation(r).is_ok());
        crate::domain::Result {
            outcome,
            status: if pending {
                Status::ChangeIncomplete
            } else if state.is_ok() {
                Status::Running
            } else {
                Status::ProblemDetected
            },
            proxy_traffic: if !pending && state.is_ok() {
                Availability::ProvedWorking
            } else {
                Availability::CannotBeVerified
            },
            message: "Client Identity result follows exact durable direction. Refresh client configuration after rotation; local checks do not establish Karing connectivity.",
        }
    }
}
impl<H: ci::Host> Interface for ClientIdentityInstallation<H> {
    fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let Ok(record) = self.state() else {
            return Review {
                mode: self.mode(),
                status: Status::ProblemDetected,
                details: vec![
                    "Client Identity host or durable authority could not be verified.".into(),
                ],
                legal_actions: vec![Action::ViewDetails],
                plan: vec![],
                refusal: Some("Client Identity authority cannot be verified."),
                prepared: None,
            };
        };
        let pending = ci::rotation(&record).is_ok();
        let selected = if pending {
            Action::FinishClientIdentityRotation
        } else {
            Action::RotateClientIdentity
        };
        let mut prepared = None;
        if action == selected {
            let mut host = self.host.borrow_mut();
            let token = if pending {
                ci::review_finish(&mut *host, &self.stop).map(ClientPrepared::Finish)
            } else {
                ci::review(&mut *host, self.entropy.borrow_mut().as_mut(), &self.stop)
                    .map(|p| ClientPrepared::Rotate(Box::new(p)))
            };
            if let Ok(token) = token {
                prepared = Some(PreparedAction {
                    owner: Rc::clone(&self.owner.borrow()),
                    action,
                    basis: PreparedBasis::ClientIdentity(token),
                });
            }
        }
        Review{mode:self.mode(),status:if pending{Status::ChangeIncomplete}else{Status::Running},details:vec!["Client Identity material stays redacted. A newer Review expires all earlier prepared authority.".into()],legal_actions:vec![Action::ViewDetails,selected],plan:vec![if pending{"Finish only the durably selected cleanup/forward direction; never regenerate or restore a revoked identity.".into()}else{"Change both protocol UUIDs sequentially with no overlap. Preserve REALITY keys and independent Subscription Link credential. Stop descendants and accepted work before revocation.".into()}],refusal:if action==selected&&prepared.is_none(){Some("Fresh Client Identity admission failed.")}else{None},prepared}
    }
    fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
    ) -> crate::domain::Result {
        if !Rc::ptr_eq(&self.owner.borrow(), &prepared.owner) {
            return self.result(Outcome::Refused);
        }
        *self.owner.get_mut() = Rc::new(());
        let PreparedBasis::ClientIdentity(token) = prepared.basis else {
            return self.result(Outcome::Refused);
        };
        let result = match token {
            ClientPrepared::Rotate(p) if prepared.action == Action::RotateClientIdentity => {
                ci::execute(self.host.get_mut(), *p, confirmation, &self.stop)
            }
            ClientPrepared::Finish(p)
                if prepared.action == Action::FinishClientIdentityRotation =>
            {
                ci::finish(self.host.get_mut(), p, confirmation, &self.stop)
            }
            _ => Err(ci::Error::StaleReview),
        };
        let outcome = match result {
            Ok(ci::Outcome::Declined) => Outcome::Cancelled,
            Ok(ci::Outcome::Rotated) => Outcome::ClientIdentityRotated,
            Ok(ci::Outcome::Finished) => Outcome::ClientIdentityRotationFinished,
            Ok(ci::Outcome::CleanedUp) => Outcome::ClientIdentityRotationCleanedUp,
            Err(ci::Error::StaleReview) => Outcome::Refused,
            Err(_) => {
                if self.state().is_ok_and(|r| ci::rotation(&r).is_ok()) {
                    Outcome::ClientIdentityRotationIncomplete
                } else {
                    Outcome::ClientIdentityRotationFailed
                }
            }
        };
        self.result(outcome)
    }
    fn subscription_status(&self) -> &'static str {
        match self.state() {
            Err(_) => "Problem detected",
            Ok(record) if record.pending_change().is_some() => "Change incomplete",
            Ok(record) if record.subscription_compromised() => "Problem detected",
            Ok(record) if record.serving_authority().is_some() => "Available",
            Ok(_) => "Not enabled",
        }
    }
}
