use super::*;
use crate::domain::{Action, Availability, Confirmation, Outcome, Status};
use crate::host::{FixtureFault, FixtureHost, Operation, planned_commands};
use crate::records::{RecoveryDirection, ReleaseIdentity, SetupPhase};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("TMPDIR").expect("workspace TMPDIR required"))
            .join(format!(
                "host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn create(&self) -> FixtureInstallation {
        FixtureInstallation::new(FixtureHost::create(&self.0, release()).unwrap(), release())
            .unwrap()
    }
    fn reopen(&self) -> FixtureInstallation {
        FixtureInstallation::new(FixtureHost::open(&self.0).unwrap(), release()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
    }
}
fn release() -> ReleaseIdentity {
    ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap()
}
fn perform(journey: &mut FixtureInstallation, action: Action) -> crate::domain::Result {
    let prepared = journey
        .review(action)
        .prepared
        .expect("legal fixture action");
    journey.execute(prepared, Confirmation::Approved)
}

#[test]
fn standard_setup_reaches_a_persisted_fixture_running_state() {
    let root = Fixture::new();
    let mut journey = root.create();
    let before = journey.host().inspect(&release()).unwrap();
    assert_eq!(journey.review(Action::Status).status, Status::NotSetUp);
    assert_eq!(journey.host().inspect(&release()).unwrap(), before);
    let declined = journey.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        journey.execute(declined, Confirmation::Declined).outcome,
        Outcome::Cancelled
    );
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    let result = perform(&mut journey, Action::StartSetup);
    assert_eq!(result.outcome, Outcome::SetupComplete);
    assert_eq!(result.status, Status::Running);
    assert_eq!(result.proxy_traffic, Availability::CannotBeVerified);
    assert!(result.message.contains("Fixture"));
    assert!(root.0.join("etc/sing-box/config.json").is_file());
    drop(journey);
    let reopened = root.reopen();
    assert_eq!(reopened.review(Action::Status).status, Status::Running);
    assert!(reopened.review(Action::FinishCleanup).prepared.is_none());
    assert!(reopened.review(Action::StartSetup).prepared.is_none());
}

#[test]
fn every_interrupted_checkpoint_keeps_the_correct_durable_direction() {
    let mut record = crate::records::OwnershipRecord::new_standard(
        release(),
        "8.8.8.8",
        &crate::records::sha256_hex(crate::host::FIXTURE_CONFIGURATION),
    )
    .unwrap();
    loop {
        if record.phase() == SetupPhase::Running {
            break;
        }
        let root = Fixture::new();
        let mut journey = root.create();
        journey
            .host_mut()
            .set_fault(Some(FixtureFault::InterruptAfter(record.phase())));
        let result = perform(&mut journey, Action::StartSetup);
        let precommit = record.recovery_direction() == RecoveryDirection::Cleanup;
        assert_eq!(
            result.outcome,
            if precommit {
                Outcome::NeedsCleanup
            } else {
                Outcome::NeedsCompletion
            },
            "{:?}",
            record.phase()
        );
        drop(journey);
        let mut reopened = root.reopen();
        let action = if precommit {
            Action::FinishCleanup
        } else {
            Action::FinishSetup
        };
        let wrong = if precommit {
            Action::FinishSetup
        } else {
            Action::FinishCleanup
        };
        assert!(reopened.review(wrong).prepared.is_none());
        let result = perform(&mut reopened, action);
        assert_eq!(
            result.outcome,
            if precommit {
                Outcome::CleanedUp
            } else {
                Outcome::SetupComplete
            }
        );
        assert_eq!(
            result.status,
            if precommit {
                Status::NotSetUp
            } else {
                Status::Running
            }
        );
        record = record.next_setup_checkpoint().unwrap();
    }
}

#[test]
fn precommit_effect_failure_cleans_up_and_postcommit_failure_only_finishes_forward() {
    for fault in [
        FixtureFault::FailBefore(Operation::InstallAptSource),
        FixtureFault::FailAfter(Operation::InstallPackage),
    ] {
        let root = Fixture::new();
        let mut journey = root.create();
        journey.host_mut().set_fault(Some(fault));
        assert_eq!(
            perform(&mut journey, Action::StartSetup).outcome,
            Outcome::CleanedUp
        );
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    }
    let root = Fixture::new();
    let mut journey = root.create();
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::FailBefore(Operation::StartService)));
    assert_eq!(
        perform(&mut journey, Action::StartSetup).outcome,
        Outcome::NeedsCompletion
    );
    assert!(journey.review(Action::FinishCleanup).prepared.is_none());
    journey.host_mut().set_fault(None);
    assert_eq!(
        perform(&mut journey, Action::FinishSetup).outcome,
        Outcome::SetupComplete
    );
}

#[test]
fn changed_facts_or_later_review_refuse_old_prepared_authority_without_effects() {
    let root = Fixture::new();
    let mut journey = root.create();
    let prepared = journey.review(Action::StartSetup).prepared.unwrap();
    journey.review(Action::Status);
    assert_eq!(
        journey.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let prepared = journey.review(Action::StartSetup).prepared.unwrap();
    fs::write(root.0.join("var/lib/sbxr/installed.json"), b"foreign").unwrap();
    assert_eq!(
        journey.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}

#[test]
fn cleanup_preserves_foreign_files_and_never_recursively_erases_residue() {
    let root = Fixture::new();
    let mut journey = root.create();
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::InterruptAfter(
            SetupPhase::ConfigurationInstalled,
        )));
    assert_eq!(
        perform(&mut journey, Action::StartSetup).outcome,
        Outcome::NeedsCleanup
    );
    let foreign = root.0.join("var/lib/sing-box/foreign");
    fs::write(&foreign, b"keep me").unwrap();
    journey.host_mut().set_fault(None);
    assert_eq!(
        perform(&mut journey, Action::FinishCleanup).outcome,
        Outcome::NeedsCleanup
    );
    assert_eq!(fs::read(&foreign).unwrap(), b"keep me");
    assert!(root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    fs::remove_file(&foreign).unwrap();
    assert_eq!(
        perform(&mut journey, Action::FinishCleanup).outcome,
        Outcome::CleanedUp
    );
}

#[test]
fn unknown_configuration_is_refused_and_preserved_after_commit() {
    let root = Fixture::new();
    let mut journey = root.create();
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::InterruptAfter(
            SetupPhase::ActivationCommitted,
        )));
    assert_eq!(
        perform(&mut journey, Action::StartSetup).outcome,
        Outcome::NeedsCompletion
    );
    let config = root.0.join("etc/sing-box/config.json");
    fs::write(&config, b"foreign config").unwrap();
    let review = journey.review(Action::FinishSetup);
    assert_eq!(review.status, Status::ProblemDetected);
    assert!(review.prepared.is_none());
    assert!(journey.review(Action::FinishCleanup).prepared.is_none());
    assert_eq!(fs::read(config).unwrap(), b"foreign config");
}

#[test]
fn command_plans_are_fixed_data_and_live_deployment_is_unavailable() {
    let commands = planned_commands(Operation::InstallPackage);
    assert_eq!(commands[0].program, "apt-get");
    assert_eq!(commands[0].arguments, ["update"]);
    assert_eq!(commands[1].arguments, ["download", "sing-box=1.14.3"]);
    assert_eq!(commands[1].working_directory, Some("/var/lib/sbxr"));
    assert_eq!(commands[2].program, "dpkg");
    assert_eq!(
        planned_commands(Operation::ValidateConfiguration)[0].arguments,
        ["-D", "/var/lib/sing-box", "-C", "/etc/sing-box", "check"]
    );
    assert!(crate::host::require_live_adapter().is_err());
}

#[test]
fn numbered_wizard_uses_the_same_durable_fixture_journey() {
    let root = Fixture::new();
    let mut journey = root.create();
    let mut output = Vec::new();
    crate::terminal::run(
        &mut std::io::Cursor::new(b"2\n\ny\n0\n"),
        &mut output,
        &mut journey,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("filesystem fixture only"));
    assert!(output.contains("Apply fixture install and check"));
    assert!(output.contains("Proxy status: Running (fixture)"));
    assert!(!output.contains("All host facts and setup effects are in memory"));
    assert!(!output.contains("Proxy status: Running (simulated)"));
    drop(journey);
    assert_eq!(root.reopen().review(Action::Status).status, Status::Running);
}

#[test]
fn interrupted_cleanup_resumes_its_recorded_checkpoint() {
    let root = Fixture::new();
    let mut journey = root.create();
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::InterruptAfter(
            SetupPhase::ConfigurationInstalled,
        )));
    assert_eq!(
        perform(&mut journey, Action::StartSetup).outcome,
        Outcome::NeedsCleanup
    );
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::FailBefore(Operation::RemovePackage)));
    assert_eq!(
        perform(&mut journey, Action::FinishCleanup).outcome,
        Outcome::NeedsCleanup
    );
    let bytes = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
    assert_eq!(
        crate::records::OwnershipRecord::decode(&bytes)
            .unwrap()
            .cleanup_checkpoint(),
        3
    );
    drop(journey);
    let mut reopened = root.reopen();
    assert_eq!(
        perform(&mut reopened, Action::FinishCleanup).outcome,
        Outcome::CleanedUp
    );
    assert!(root.0.join("var/lib/sbxr/installed.json").exists());
}

#[test]
fn mismatched_release_or_unsafe_links_never_grant_effect_authority() {
    use std::os::unix::fs::symlink;
    let root = Fixture::new();
    let mut journey = root.create();
    journey
        .host_mut()
        .set_fault(Some(FixtureFault::InterruptAfter(
            SetupPhase::ActivationCommitted,
        )));
    assert_eq!(
        perform(&mut journey, Action::StartSetup).outcome,
        Outcome::NeedsCompletion
    );
    drop(journey);
    let other = ReleaseIdentity::new("v3.1.119", &"d".repeat(40), &"e".repeat(64)).unwrap();
    let mismatched = FixtureInstallation::new(FixtureHost::open(&root.0).unwrap(), other).unwrap();
    assert_eq!(
        mismatched.review(Action::Status).status,
        Status::ProblemDetected
    );
    assert!(mismatched.review(Action::FinishSetup).prepared.is_none());
    drop(mismatched);
    let config = root.0.join("etc/sing-box/config.json");
    let foreign = root.0.join("foreign-config");
    fs::rename(&config, &foreign).unwrap();
    symlink(&foreign, &config).unwrap();
    let unsafe_host =
        FixtureInstallation::new(FixtureHost::open(&root.0).unwrap(), release()).unwrap();
    assert_eq!(
        unsafe_host.review(Action::ViewDetails).status,
        Status::ProblemDetected
    );
    assert!(unsafe_host.review(Action::FinishSetup).prepared.is_none());
    assert_eq!(
        fs::read(&foreign).unwrap(),
        crate::host::FIXTURE_CONFIGURATION
    );
}

#[test]
fn fixture_roots_and_foreign_ancestors_are_never_adopted_implicitly() {
    use std::os::unix::fs::symlink;
    let root = Fixture::new();
    fs::write(root.0.join("foreign"), b"keep me").unwrap();
    assert!(FixtureHost::create(&root.0, release()).is_err());
    assert_eq!(fs::read(root.0.join("foreign")).unwrap(), b"keep me");
    assert!(!root.0.join(".sbxr-fixture-root").exists());
    let root2 = Fixture::new();
    let journey = root2.create();
    let outside = Fixture::new();
    fs::write(outside.0.join("foreign"), b"outside").unwrap();
    symlink(&outside.0, root2.0.join("etc")).unwrap();
    assert_eq!(
        journey.review(Action::StartSetup).status,
        Status::ProblemDetected
    );
    assert!(journey.review(Action::StartSetup).prepared.is_none());
    assert!(!root2.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    assert_eq!(fs::read(outside.0.join("foreign")).unwrap(), b"outside");
}

#[test]
fn prepared_authority_cannot_cross_adapter_or_fixture_boundaries() {
    let root = Fixture::new();
    let mut fixture = root.create();
    let mut simulation = crate::proxyinstallation::Installation::simulation();
    let prepared = simulation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        fixture.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let prepared = fixture.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        simulation.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let root2 = Fixture::new();
    let mut fixture2 = root2.create();
    let prepared = fixture.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        fixture2.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    assert!(!root2.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}
