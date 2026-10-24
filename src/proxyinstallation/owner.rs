//! Composes existing Owner journeys. Only the selected module retains prepared
//! authority/writer exclusion; a later Review drops it before opening another.
use super::*;
use crate::{host::HostError, subscription_artifact::HttpSubscriptionLink};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Journey {
    Standard,
    Http,
    Identity,
    Removal,
}
impl Journey {
    fn accepts(self, action: Action) -> bool {
        match self {
            Self::Standard => matches!(
                action,
                Action::StartSetup | Action::FinishCleanup | Action::FinishSetup
            ),
            Self::Http => matches!(
                action,
                Action::EnableSubscription
                    | Action::RotateSubscriptionLink
                    | Action::RepairSubscription
                    | Action::FinishSubscriptionChange
            ),
            Self::Identity => matches!(
                action,
                Action::RotateClientIdentity | Action::FinishClientIdentityRotation
            ),
            Self::Removal => matches!(action, Action::CompleteRemoval | Action::FinishRemoval),
        }
    }
}
/// Closed product journeys, backed by the existing concrete adapters. This is
/// not a protocol plug-in boundary. Native sources must authenticate current bytes.
pub trait OwnerSources<'a> {
    fn journeys(&self) -> std::result::Result<Vec<Journey>, HostError>;
    fn open(&self, journey: Journey) -> std::result::Result<Box<dyn Interface + 'a>, HostError>;
    fn mode(&self) -> ExecutionMode;
}
pub(super) struct OwnerPrepared {
    inner: PreparedAction,
    journey: Journey,
}
pub struct OwnerInstallation<'a, S: OwnerSources<'a>> {
    sources: S,
    active: RefCell<Option<(Journey, Box<dyn Interface + 'a>)>>,
    owner: RefCell<Rc<()>>,
    link: Option<HttpSubscriptionLink>,
}
impl<'a, S: OwnerSources<'a>> OwnerInstallation<'a, S> {
    pub fn new(sources: S) -> Self {
        Self {
            sources,
            active: RefCell::new(None),
            owner: RefCell::new(Rc::new(())),
            link: None,
        }
    }
    pub fn sources(&self) -> &S {
        &self.sources
    }
    fn refusal(&self) -> Review {
        Review {
            mode: self.sources.mode(),
            status: Status::ProblemDetected,
            details: vec![
                "Owner authority or the selected concrete adapter could not be verified.".into(),
            ],
            legal_actions: vec![Action::ViewDetails],
            plan: vec![],
            refusal: Some(
                "Preserve the exact installation and review again after the missing prerequisite is restored.",
            ),
            prepared: None,
        }
    }
    fn refused_result() -> crate::domain::Result {
        crate::domain::Result {
            outcome: Outcome::Refused,
            status: Status::ProblemDetected,
            proxy_traffic: Availability::CannotBeVerified,
            message: "Prepared Owner authority expired or belongs to another journey. Review again.",
        }
    }
}
impl<'a, S: OwnerSources<'a>> Interface for OwnerInstallation<'a, S> {
    fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        self.active.borrow_mut().take();
        let Ok(journeys) = self.sources.journeys() else {
            return self.refusal();
        };
        let mut legal = Vec::new();
        let mut primary = None;
        for (i, journey) in journeys.iter().copied().enumerate() {
            let module = match self.sources.open(journey) {
                Ok(m) => m,
                Err(_) if i > 0 => continue,
                Err(_) => return self.refusal(),
            };
            let reviewed = module.review(Action::Status);
            for a in reviewed
                .legal_actions
                .iter()
                .copied()
                .filter(|a| journey.accepts(*a))
            {
                if !legal.contains(&a) {
                    legal.push(a);
                }
            }
            if i == 0 {
                primary = Some(reviewed);
            }
        }
        let Some(mut reviewed) = primary else {
            return self.refusal();
        };
        legal.push(Action::ViewDetails);
        reviewed.legal_actions = legal;
        reviewed.mode = self.sources.mode();
        reviewed.prepared = None;
        if matches!(action, Action::Status | Action::ViewDetails) {
            if action == Action::ViewDetails {
                let Ok(module) = self.sources.open(journeys[0]) else {
                    return self.refusal();
                };
                reviewed.details = module.review(action).details;
            }
            return reviewed;
        }
        if !reviewed.legal_actions.contains(&action) {
            reviewed.refusal = Some("The action is unavailable for the observed Owner state.");
            return reviewed;
        }
        let Some(journey) = journeys.into_iter().find(|j| j.accepts(action)) else {
            return self.refusal();
        };
        let Ok(module) = self.sources.open(journey) else {
            return self.refusal();
        };
        let mut selected = module.review(action);
        selected.mode = self.sources.mode();
        if let Some(inner) = selected.prepared.take() {
            selected.prepared = Some(PreparedAction {
                owner: self.owner.borrow().clone(),
                action,
                basis: PreparedBasis::Owner(Box::new(OwnerPrepared { inner, journey })),
            });
            *self.active.borrow_mut() = Some((journey, module));
        }
        selected
    }
    fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
    ) -> crate::domain::Result {
        self.link = None;
        if !Rc::ptr_eq(self.owner.get_mut(), &prepared.owner) {
            return Self::refused_result();
        }
        *self.owner.get_mut() = Rc::new(());
        let PreparedBasis::Owner(p) = prepared.basis else {
            return Self::refused_result();
        };
        let Some((journey, mut module)) = self.active.get_mut().take() else {
            return Self::refused_result();
        };
        if journey != p.journey || !journey.accepts(prepared.action) {
            return Self::refused_result();
        }
        let result = module.execute(p.inner, confirmation);
        self.link = module.take_subscription_link();
        result
    }
    fn subscription_status(&self) -> &'static str {
        if let Some((_, m)) = self.active.borrow().as_ref() {
            return m.subscription_status();
        }
        let Ok(journeys) = self.sources.journeys() else {
            return "Problem detected";
        };
        let j = if journeys.first() == Some(&Journey::Identity) {
            Journey::Identity
        } else {
            Journey::Http
        };
        self.sources
            .open(j)
            .map_or("Problem detected", |m| m.subscription_status())
    }
    fn take_subscription_link(&mut self) -> Option<HttpSubscriptionLink> {
        self.link.take()
    }
}
