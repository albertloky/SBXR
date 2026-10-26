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
    Disclosure,
    Tunnel,
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
            Self::Tunnel => matches!(
                action,
                Action::StartSetup
                    | Action::FinishSetup
                    | Action::FinishCleanup
                    | Action::CheckVmessTunnel
            ),
            Self::Disclosure => matches!(
                action,
                Action::ShowClientConfiguration | Action::MarkSubscriptionCompromised
            ),
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
    fn apply(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
        output: Option<&mut dyn std::io::Write>,
    ) -> std::io::Result<crate::domain::Result> {
        self.link = None;
        if !Rc::ptr_eq(self.owner.get_mut(), &prepared.owner) {
            return Ok(Self::refused_result());
        }
        *self.owner.get_mut() = Rc::new(());
        let PreparedBasis::Owner(p) = prepared.basis else {
            return Ok(Self::refused_result());
        };
        let Some((journey, mut module)) = self.active.get_mut().take() else {
            return Ok(Self::refused_result());
        };
        if journey != p.journey || !journey.accepts(prepared.action) {
            return Ok(Self::refused_result());
        }
        let result = if let Some(output) = output {
            module.execute_output(p.inner, confirmation, output)?
        } else {
            module.execute(p.inner, confirmation)
        };
        self.link = module.take_subscription_link();
        Ok(result)
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
    fn supports_tunnel(&self) -> bool {
        self.sources
            .journeys()
            .is_ok_and(|j| j.contains(&Journey::Tunnel))
    }
    fn review_tunnel_setup(&self, hostname: &str) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        self.active.borrow_mut().take();
        if !self
            .sources
            .journeys()
            .is_ok_and(|j| j.contains(&Journey::Tunnel))
        {
            return self.refusal();
        }
        let Ok(module) = self.sources.open(Journey::Tunnel) else {
            return self.refusal();
        };
        let mut reviewed = module.review_tunnel_setup(hostname);
        reviewed.mode = self.sources.mode();
        if let Some(inner) = reviewed.prepared.take() {
            reviewed.prepared = Some(PreparedAction {
                owner: self.owner.borrow().clone(),
                action: Action::StartSetup,
                basis: PreparedBasis::Owner(Box::new(OwnerPrepared {
                    inner,
                    journey: Journey::Tunnel,
                })),
            });
            *self.active.borrow_mut() = Some((Journey::Tunnel, module));
        }
        reviewed
    }

    fn review(&self, action: Action) -> Review {
        use crate::host::timing::{Phase, span};
        let _phase = span(match action {
            Action::Status => Phase::ReviewStatus,
            Action::ViewDetails => Phase::ReviewDetails,
            _ => Phase::ReviewAction,
        });
        *self.owner.borrow_mut() = Rc::new(());
        self.active.borrow_mut().take();
        let Ok(journeys) = self.sources.journeys() else {
            return self.refusal();
        };
        let mut legal = Vec::new();
        let mut routes = Vec::new();
        let mut primary = None;
        for journey in journeys.iter().copied() {
            let Ok(module) = self.sources.open(journey) else {
                continue;
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
                    routes.push((a, journey));
                }
            }
            if primary.is_none() {
                primary = Some((journey, reviewed));
            }
        }
        let Some((primary_journey, mut reviewed)) = primary else {
            return self.refusal();
        };
        legal.push(Action::ViewDetails);
        reviewed.legal_actions = legal;
        reviewed.mode = self.sources.mode();
        reviewed.prepared = None;
        if matches!(action, Action::Status | Action::ViewDetails) {
            if action == Action::ViewDetails {
                match self.sources.open(primary_journey) {
                    Ok(module) => reviewed.details = module.review(action).details,
                    Err(_) => {
                        reviewed.status = Status::ProblemDetected;
                        reviewed.details = vec!["The primary details adapter became unavailable; independently observed actions must be reviewed before execution.".into()];
                    }
                }
            }
            return reviewed;
        }
        if !reviewed.legal_actions.contains(&action) {
            reviewed.refusal = Some("The action is unavailable for the observed Owner state.");
            return reviewed;
        }
        let Some((_, journey)) = routes.into_iter().find(|(a, _)| *a == action) else {
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
    fn execute(&mut self, p: PreparedAction, c: Confirmation) -> crate::domain::Result {
        self.apply(p, c, None)
            .unwrap_or_else(|_| Self::refused_result())
    }
    fn execute_output(
        &mut self,
        p: PreparedAction,
        c: Confirmation,
        output: &mut dyn std::io::Write,
    ) -> std::io::Result<crate::domain::Result> {
        self.apply(p, c, Some(output))
    }
    fn write_details(&mut self, output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let _phase = crate::host::timing::span(crate::host::timing::Phase::Details);
        let reviewed = self.review(Action::ViewDetails);
        for line in reviewed.details {
            writeln!(output, "{line}")?;
        }
        if self
            .sources
            .journeys()
            .is_ok_and(|j| j.contains(&Journey::Disclosure))
        {
            let mut module = self
                .sources
                .open(Journey::Disclosure)
                .map_err(|_| std::io::Error::other("Protected details adapter is unavailable."))?;
            module.write_details(output)?;
        }
        Ok(())
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

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
