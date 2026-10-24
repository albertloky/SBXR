//! Shared Interface bridge for the concrete, explicitly injected removal host.
use super::*;
use crate::removal::{Removal, RemovalAction, RemovalHost, RemovalOutcome};
pub struct RemovalInstallation<H: RemovalHost> {
    inner: RefCell<Removal<H>>,
    owner: RefCell<Rc<()>>,
}
impl<H: RemovalHost> RemovalInstallation<H> {
    pub fn new(host: H) -> Self {
        Self {
            inner: RefCell::new(Removal::new(host)),
            owner: RefCell::new(Rc::new(())),
        }
    }
    pub fn host_mut(&mut self) -> &mut H {
        *self.owner.get_mut() = Rc::new(());
        self.inner.get_mut().host_mut()
    }
    pub fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let mut module = self.inner.borrow_mut();
        module.invalidate();
        let snapshot = module.host().read_authority();
        let mut status = Status::ProblemDetected;
        let mut selected = None;
        if let Ok(snapshot) = snapshot {
            let committed = snapshot.finalizer.is_some()
                || snapshot
                    .current
                    .as_ref()
                    .and_then(|b| crate::records::OwnershipRecord::decode(b).ok())
                    .is_some_and(|r| {
                        r.recovery_direction() == crate::records::RecoveryDirection::Removal
                    });
            let candidate = if committed {
                RemovalAction::Finish
            } else {
                RemovalAction::Complete
            };
            if let Ok(prepared) = module.review(candidate) {
                status = if committed {
                    Status::RemovalIncomplete
                } else {
                    snapshot
                        .current
                        .as_ref()
                        .and_then(|b| crate::records::OwnershipRecord::decode(b).ok())
                        .map_or(Status::NotSetUp, |r| {
                            if r.phase() == crate::records::SetupPhase::Running {
                                Status::Running
                            } else {
                                Status::SetupIncomplete
                            }
                        })
                };
                selected = Some((candidate, prepared));
            } else if snapshot == crate::removal::AuthoritySnapshot::default()
                && let Ok(release) = module.host().executing_release()
                && module.host().inspect_lifecycle(&release).is_ok_and(|f| {
                    f.valid
                        && !f.executable_present
                        && !f.installed_record_present
                        && f.state_directory_empty
                })
            {
                status = Status::NotInstalled;
            }
        }
        let mut legal_actions = vec![Action::ViewDetails];
        let mut prepared = None;
        if let Some((candidate, token)) = selected {
            let expected = match candidate {
                RemovalAction::Complete => Action::CompleteRemoval,
                RemovalAction::Finish => Action::FinishRemoval,
            };
            legal_actions.push(expected);
            if expected == action {
                prepared = Some(PreparedAction {
                    owner: Rc::clone(&self.owner.borrow()),
                    action,
                    basis: PreparedBasis::Removal(token),
                });
            }
        }
        Review {
            mode:ExecutionMode::InjectedHost,
            status,legal_actions,prepared,
            details:vec!["Injected Standard removal; no native deployment or exact-release restoration is enabled.".into()],
            plan:vec!["Remove only the proved exact Standard resources and installed pair. Preserve unknown/shared resources. Committed removal finishes forward only.".into()],
            refusal:if status==Status::ProblemDetected {Some("Removal ownership, exact release or host effects cannot be safely verified.")} else {None},
        }
    }
    pub fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> Result {
        if !Rc::ptr_eq(&self.owner.borrow(), &prepared.owner) {
            return result(
                Outcome::Refused,
                Status::ProblemDetected,
                "Prepared removal expired. Review again.",
            );
        }
        let PreparedBasis::Removal(token) = prepared.basis else {
            return result(
                Outcome::Refused,
                Status::ProblemDetected,
                "Prepared action belongs to another adapter.",
            );
        };
        *self.owner.get_mut() = Rc::new(());
        let outcome = self.inner.get_mut().execute(token, confirmation);
        let declined_status = if outcome == RemovalOutcome::Declined {
            self.review(Action::Status).status
        } else {
            Status::ProblemDetected
        };
        match outcome {
            RemovalOutcome::Completed => result(
                Outcome::RemovalComplete,
                Status::NotInstalled,
                "Exact owned removal completed in the injected root.",
            ),
            RemovalOutcome::Declined => result(
                Outcome::Cancelled,
                declined_status,
                "Removal cancelled. No change was authorized.",
            ),
            RemovalOutcome::Refused(_) => result(
                Outcome::Refused,
                Status::ProblemDetected,
                "Removal authority or ownership could not be verified. Review again.",
            ),
            RemovalOutcome::NeedsCompletion(_) => result(
                Outcome::RemovalNeedsCompletion,
                Status::RemovalIncomplete,
                "Committed removal requires forward completion with the exact finishing release.",
            ),
            RemovalOutcome::FinalSynchronizationUnknown => result(
                Outcome::RemovalNeedsCompletion,
                Status::ProblemDetected,
                "Final synchronization is unknown. Inspect fresh state before further action.",
            ),
        }
    }
}
fn result(outcome: Outcome, status: Status, message: &'static str) -> Result {
    Result {
        outcome,
        status,
        proxy_traffic: Availability::CannotBeVerified,
        message,
    }
}
impl<H: RemovalHost> Interface for RemovalInstallation<H> {
    fn review(&self, action: Action) -> Review {
        Self::review(self, action)
    }
    fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> Result {
        Self::execute(self, prepared, confirmation)
    }
}
