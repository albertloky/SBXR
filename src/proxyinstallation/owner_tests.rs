//! Socket-free Owner admission regressions using the existing simulation only
//! for an independently selected Standard action. No native adapters execute.
use super::*;
struct Sources {
    removal: bool,
    standard: bool,
}
struct RemovalStatus;
impl Interface for RemovalStatus {
    fn review(&self, _: Action) -> Review {
        Review {
            mode: ExecutionMode::InjectedHost,
            status: Status::Running,
            details: vec!["Independent removal observation".into()],
            legal_actions: vec![Action::CompleteRemoval],
            plan: vec![],
            refusal: None,
            prepared: None,
        }
    }
    fn execute(&mut self, _: PreparedAction, _: Confirmation) -> crate::domain::Result {
        panic!("read-only removal fixture cannot execute")
    }
}
impl OwnerSources<'_> for Sources {
    fn journeys(&self) -> std::result::Result<Vec<Journey>, HostError> {
        Ok(vec![Journey::Tunnel, Journey::Standard, Journey::Removal])
    }
    fn open(&self, journey: Journey) -> std::result::Result<Box<dyn Interface>, HostError> {
        match journey {
            Journey::Removal if self.removal => Ok(Box::new(RemovalStatus)),
            Journey::Standard if self.standard => Ok(Box::new(Installation::simulation())),
            _ => Err(HostError::LiveUnavailable),
        }
    }
    fn mode(&self) -> ExecutionMode {
        ExecutionMode::InjectedHost
    }
}
#[test]
fn unavailable_first_journey_does_not_hide_independent_removal() {
    let owner = OwnerInstallation::new(Sources {
        removal: true,
        standard: false,
    });
    for action in [Action::Status, Action::ViewDetails, Action::CompleteRemoval] {
        let review = owner.review(action);
        assert!(review.legal_actions.contains(&Action::CompleteRemoval));
        assert!(!review.legal_actions.contains(&Action::StartSetup));
        assert_eq!(review.status, Status::Running);
    }
    let owner = OwnerInstallation::new(Sources {
        removal: false,
        standard: false,
    });
    assert_eq!(
        owner.review(Action::Status).legal_actions,
        vec![Action::ViewDetails]
    );
}
#[test]
fn action_routes_to_its_admitting_journey_and_later_review_revokes_it() {
    let mut owner = OwnerInstallation::new(Sources {
        removal: true,
        standard: true,
    });
    let old = owner
        .review(Action::StartSetup)
        .prepared
        .expect("Standard can admit while Tunnel is unavailable");
    owner.review(Action::ViewDetails);
    assert_eq!(
        owner.execute(old, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let fresh = owner.review(Action::StartSetup).prepared.unwrap();
    let mut other = OwnerInstallation::new(Sources {
        removal: true,
        standard: true,
    });
    assert_eq!(
        other.execute(fresh, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let fresh = owner.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        owner.execute(fresh, Confirmation::Approved).outcome,
        Outcome::SetupComplete
    );
}

#[test]
fn details_reopen_failure_keeps_independently_observed_removal_visible() {
    struct Transient(std::cell::Cell<usize>);
    impl OwnerSources<'_> for Transient {
        fn journeys(&self) -> std::result::Result<Vec<Journey>, HostError> {
            Ok(vec![Journey::Standard, Journey::Removal])
        }
        fn open(&self, j: Journey) -> std::result::Result<Box<dyn Interface>, HostError> {
            if j == Journey::Standard {
                let count = self.0.get();
                self.0.set(count + 1);
                if count == 0 {
                    return Ok(Box::new(Installation::simulation()));
                }
                return Err(HostError::LiveUnavailable);
            }
            Ok(Box::new(RemovalStatus))
        }
        fn mode(&self) -> ExecutionMode {
            ExecutionMode::InjectedHost
        }
    }
    let owner = OwnerInstallation::new(Transient(std::cell::Cell::new(0)));
    let review = owner.review(Action::ViewDetails);
    assert_eq!(review.status, Status::ProblemDetected);
    assert!(review.legal_actions.contains(&Action::CompleteRemoval));
    assert!(review.prepared.is_none());
}
