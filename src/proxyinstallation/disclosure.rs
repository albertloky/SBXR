//! Confirmed streaming disclosure through the shared Owner Interface. Secret
//! artifacts never enter generic Review details or a durable serialized value.
use super::*;
use crate::disclosure as d;
use std::io::{self, Write};
pub struct DisclosureInstallation<H: d::Host> {
    session: RefCell<d::Session<H>>,
    owner: RefCell<Rc<()>>,
    mode: ExecutionMode,
}
impl<H: d::Host> DisclosureInstallation<H> {
    pub fn new(host: H, mode: ExecutionMode) -> Self {
        Self {
            session: RefCell::new(d::Session::new(host)),
            owner: RefCell::new(Rc::new(())),
            mode,
        }
    }
    pub fn into_host(self) -> H {
        self.session.into_inner().into_host()
    }
    fn result(outcome: Outcome, message: &'static str) -> crate::domain::Result {
        crate::domain::Result {
            outcome,
            status: if matches!(
                outcome,
                Outcome::Refused | Outcome::SubscriptionProblemDetected
            ) {
                Status::ProblemDetected
            } else {
                Status::Running
            },
            proxy_traffic: Availability::CannotBeVerified,
            message,
        }
    }
    fn apply(
        &mut self,
        p: PreparedAction,
        c: Confirmation,
        output: Option<&mut dyn Write>,
    ) -> io::Result<crate::domain::Result> {
        if !Rc::ptr_eq(self.owner.get_mut(), &p.owner) {
            return Ok(Self::result(
                Outcome::Refused,
                "Disclosure review expired. Review again.",
            ));
        }
        *self.owner.get_mut() = Rc::new(());
        let PreparedBasis::Disclosure(token) = p.basis else {
            return Ok(Self::result(
                Outcome::Refused,
                "Prepared authority belongs to another journey.",
            ));
        };
        let result = self.session.get_mut().execute(*token, c, output);
        Ok(match result {
            Ok(d::Outcome::Declined) => Self::result(
                Outcome::Cancelled,
                "Disclosure action cancelled; no protected material was displayed.",
            ),
            Ok(d::Outcome::ClientConfigurationDisclosed) => Self::result(
                Outcome::ClientConfigurationDisclosed,
                "Client Configuration was disclosed.",
            ),
            Ok(d::Outcome::SubscriptionCompromised) => Self::result(
                Outcome::SubscriptionCompromised,
                "Subscription Link compromise recorded. Rotate the link separately to revoke it.",
            ),
            Err(d::Error::Output) => {
                return Err(io::Error::other(
                    "Disclosure output failed; no successful display is established.",
                ));
            }
            Err(d::Error::Publication) => Self::result(
                Outcome::SubscriptionProblemDetected,
                "Compromise record publication is uncertain. Inspect exact durable authority before retrying.",
            ),
            Err(_) => Self::result(
                Outcome::Refused,
                "Disclosure authority could not be freshly verified. Review again.",
            ),
        })
    }
}
impl<H: d::Host> Interface for DisclosureInstallation<H> {
    fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let mut session = self.session.borrow_mut();
        session.expire();
        let summary = session.status();
        let mut actions = vec![Action::ViewDetails];
        let mut prepared = None;
        let mut plan = vec![];
        if let Ok(s) = summary.as_ref() {
            if s.client_configuration_available {
                actions.push(Action::ShowClientConfiguration)
            }
            if s.mark_compromise_available {
                actions.push(Action::MarkSubscriptionCompromised)
            }
        }
        let selected = match action {
            Action::ShowClientConfiguration => Some(d::Action::ShowClientConfiguration),
            Action::MarkSubscriptionCompromised => Some(d::Action::MarkSubscriptionCompromised),
            _ => None,
        };
        if let Some(selected) = selected {
            plan = selected.plan().iter().map(|s| (*s).into()).collect();
            if let Ok(token) = session.review(selected) {
                prepared = Some(PreparedAction {
                    owner: self.owner.borrow().clone(),
                    action,
                    basis: PreparedBasis::Disclosure(Box::new(token)),
                });
            }
        }
        Review{mode:self.mode,status:if summary.as_ref().is_ok_and(|s|s.client_configuration_available){Status::Running}else{Status::ProblemDetected},details:vec!["Client material remains redacted until explicit confirmation. View details can redisclose only a consistently proved existing link.".into()],legal_actions:actions,plan,refusal:if summary.is_err()||selected.is_some()&&prepared.is_none(){Some("Protected disclosure authority cannot be verified.")}else{None},prepared}
    }
    fn execute(&mut self, p: PreparedAction, c: Confirmation) -> crate::domain::Result {
        self.apply(p, c, None).unwrap_or_else(|_| {
            Self::result(
                Outcome::Refused,
                "No valid disclosure output sink was supplied.",
            )
        })
    }
    fn execute_output(
        &mut self,
        p: PreparedAction,
        c: Confirmation,
        output: &mut dyn Write,
    ) -> io::Result<crate::domain::Result> {
        self.apply(p, c, Some(output))
    }
    fn subscription_status(&self) -> &'static str {
        *self.owner.borrow_mut() = Rc::new(());
        match self.session.borrow_mut().status() {
            Ok(s) if !s.has_subscription => "Not enabled",
            _ => "Problem detected",
        }
    }
    fn write_details(&mut self, output: &mut dyn Write) -> io::Result<()> {
        *self.owner.get_mut() = Rc::new(());
        let details = self
            .session
            .get_mut()
            .view_details()
            .map_err(|_| io::Error::other("Protected Subscription Link cannot be verified."))?;
        if details.compromised {
            writeln!(
                output,
                "Subscription Link is marked compromised; the current credential remains active until successful rotation."
            )?;
        }
        if let Some(link) = details.subscription_link {
            d::write_link(output, &link)
                .map_err(|_| io::Error::other("Subscription Link output failed."))?;
        }
        Ok(())
    }
}
