use crate::domain::{Action, Availability, Confirmation, Outcome, Phase, Status};
use crate::proxyinstallation::{Installation, SimulationFault};

#[test]
fn only_explicit_approval_starts_simulated_setup() {
    let mut installation = Installation::simulation();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    let result = installation.execute(prepared, Confirmation::Declined);
    assert_eq!(result.outcome, Outcome::Cancelled);
    assert_eq!(installation.phase(), Phase::Absent);
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    let result = installation.execute(prepared, Confirmation::Approved);
    assert_eq!(result.outcome, Outcome::SetupComplete);
    assert_eq!(result.status, Status::Running);
    assert_eq!(result.proxy_traffic, Availability::CannotBeVerified);
}

#[test]
fn authority_is_bound_to_the_reviewed_installation_and_facts() {
    let mut first = Installation::simulation();
    let mut second = Installation::simulation();
    let prepared = first.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        second.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let prepared = first.review(Action::StartSetup).prepared.unwrap();
    first.host_mut().facts.port_443_available = false;
    assert_eq!(
        first.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert_eq!(first.phase(), Phase::Absent);
}

#[test]
fn only_cleanup_is_legal_before_activation_commit() {
    let mut installation = Installation::simulation();
    installation.host_mut().fault = Some(SimulationFault::BeforeActivation);
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    assert!(installation.review(Action::StartSetup).prepared.is_none());
    assert!(installation.review(Action::FinishSetup).prepared.is_none());
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::CleanedUp
    );
    assert_eq!(installation.phase(), Phase::Absent);
}

#[test]
fn activation_commit_allows_only_forward_completion() {
    let mut installation = Installation::simulation();
    installation.host_mut().fault = Some(SimulationFault::AfterActivation);
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCompletion
    );
    assert!(
        installation
            .review(Action::FinishCleanup)
            .prepared
            .is_none()
    );
    assert!(installation.review(Action::StartSetup).prepared.is_none());
    assert_eq!(installation.phase(), Phase::ActivationCommitted);
    installation.host_mut().fault = None;
    let prepared = installation.review(Action::FinishSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::SetupComplete
    );
}

#[test]
fn review_is_read_only_and_refuses_unproved_safety_facts() {
    for change in 0..7 {
        let mut installation = Installation::simulation();
        let facts = &mut installation.host_mut().facts;
        match change {
            0 => facts.root = false,
            1 => facts.ubuntu_24_04 = false,
            2 => facts.amd64 = false,
            3 => facts.owned_paths_absent = false,
            4 => facts.port_443_available = false,
            5 => facts.mutation_idle = false,
            _ => facts.destination_compatible = false,
        }
        let review = installation.review(Action::StartSetup);
        assert!(
            review.prepared.is_none(),
            "unsafe fact {change} was admitted"
        );
        assert_eq!(installation.phase(), Phase::Absent);
        assert_eq!(installation.host().effects, 0);
    }
}

#[test]
fn old_authority_stays_invalid_after_cleanup_returns_to_the_same_phase() {
    let mut installation = Installation::simulation();
    let old = installation.review(Action::StartSetup).prepared.unwrap();
    let current = installation.review(Action::StartSetup).prepared.unwrap();
    installation.host_mut().fault = Some(SimulationFault::BeforeActivation);
    installation.execute(current, Confirmation::Approved);
    let cleanup = installation.review(Action::FinishCleanup).prepared.unwrap();
    installation.execute(cleanup, Confirmation::Approved);
    assert_eq!(installation.phase(), Phase::Absent);
    installation.host_mut().fault = None;
    assert_eq!(
        installation.execute(old, Confirmation::Approved).outcome,
        Outcome::Refused
    );
}
