//! Independent behavioral checks against the preserved Go abbe4d7 contract.
//! See testdata/parity/README.md for provenance and the deliberately bounded scope.
use sbxr::domain::{Action, Availability, Confirmation, Phase, Result as ActionResult, Status};
use sbxr::proxyinstallation::{Facts, Installation, PreparedAction, SimulationFault};
use std::io::{Cursor, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn code(key: &str) -> &'static str {
    include_str!("testdata/parity/result-codes.tsv")
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once('\t').unwrap();
            (name == key).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing independent outcome fixture: {key}"))
}

fn assert_result(result: &ActionResult, expected: &str, status: Status) {
    assert_eq!(result.outcome.code(), code(expected), "{result:?}");
    assert_eq!(result.status, status, "{result:?}");
    assert_eq!(result.proxy_traffic, Availability::CannotBeVerified);
}

fn prepared(installation: &Installation, action: Action) -> PreparedAction {
    installation
        .review(action)
        .prepared
        .unwrap_or_else(|| panic!("{action:?} was not prepared"))
}

fn execute(installation: &mut Installation, action: Action) -> ActionResult {
    let authority = prepared(installation, action);
    installation.execute(authority, Confirmation::Approved)
}

fn executable(input: &[u8], arguments: &[&str]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sbxr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let written = child.stdin.take().unwrap().write_all(input);
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        panic!("failed to feed the test's child: {error}");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                child.kill().unwrap();
                break true;
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("failed to wait for the test's child: {error}");
            }
        }
    };
    let output = child.wait_with_output().unwrap();
    assert!(!timed_out, "executable timed out: {output:?}");
    (
        output.status.code().unwrap(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn successful_session(input: &[u8]) -> String {
    terminal_session(&mut Installation::simulation(), input)
}

fn menu_number(output: &str, action: &str) -> String {
    output
        .lines()
        .filter_map(|line| line.split_once(". "))
        .find_map(|(number, label)| (label == action).then_some(number.to_owned()))
        .unwrap_or_else(|| panic!("missing menu action {action}: {output}"))
}

fn terminal_session(installation: &mut Installation, input: &[u8]) -> String {
    let mut output = Vec::new();
    sbxr::terminal::run(&mut Cursor::new(input), &mut output, installation).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn explicit_simulator_opens_an_honestly_labeled_numbered_menu_and_eof_exits() {
    for input in [b"0\n".as_slice(), b""] {
        let output = successful_session(input);
        for label in [
            "local simulation only",
            "Proxy status: Not set up",
            "Subscription status: Not enabled",
            "Software Lifecycle status: Not inspected",
            "cannot be verified",
            "0. Exit",
        ] {
            assert!(output.contains(label), "missing {label}: {output}");
        }
        assert_ne!(menu_number(&output, "Start setup"), "0");
        assert_ne!(menu_number(&output, "View details"), "0");
        assert!(!output.contains("Setup 1 —"));
        assert!(!output.contains("Code: PROXY-INSTALLATION-SETUP-COMPLETE"));
    }
}

#[test]
fn public_arguments_are_refused_before_the_menu() {
    for argument in ["setup", "--help", "--simulate"] {
        let (status, output, error) = executable(b"", &[argument]);
        assert_ne!(status, 0, "accepted {argument}");
        assert!(output.is_empty(), "{output}");
        assert!(error.contains("SBXR accepts no arguments"), "{error}");
    }
}

#[test]
fn standard_wizard_matches_the_reference_input_cases_in_the_explicit_terminal() {
    let start = menu_number(&successful_session(b"0\n"), "Start setup");
    for line in include_str!("testdata/parity/wizard-cases.tsv").lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5, "invalid fixture: {line}");
        let [name, input, outcome, reviews, choices] = fields.as_slice() else {
            unreachable!()
        };
        let input = input.replace("\\r", "\r").replace("\\n", "\n");
        let output = successful_session(format!("{start}\n{input}").as_bytes());
        assert_eq!(
            output.matches("Setup 2 — Review").count(),
            reviews.parse::<usize>().unwrap(),
            "{name}: {output}"
        );
        assert_eq!(
            output.matches("Setup 1 — Choose connection").count(),
            choices.parse::<usize>().unwrap(),
            "{name}: {output}"
        );
        let expected = format!("Code: {}", code(outcome));
        assert_eq!(output.matches(&expected).count(), 1, "{name}: {output}");
        assert!(
            !output.contains("2. Standard + Cloudflare"),
            "{name}: {output}"
        );
        if *outcome == "complete" {
            assert!(output.contains("Proxy status: Running"), "{name}: {output}");
            assert!(
                output.contains("No software was installed"),
                "{name}: {output}"
            );
            assert!(!output.contains(code("cancelled")), "{name}: {output}");
        } else {
            assert!(
                !output.contains("Proxy status: Running"),
                "{name}: {output}"
            );
            assert!(!output.contains(code("complete")), "{name}: {output}");
        }
        let mut installation = Installation::simulation();
        terminal_session(&mut installation, format!("{start}\n{input}").as_bytes());
        if *outcome == "complete" {
            assert_eq!(installation.phase(), Phase::Running, "{name}");
        } else {
            assert_eq!(installation.phase(), Phase::Absent, "{name}");
            assert_eq!(installation.host().effects, 0, "{name}");
        }
    }
}

#[test]
fn malformed_menu_numbers_do_not_select_an_action() {
    let output = successful_session(b"01\n+1\n 1\n1 \n-1\n0\n");
    assert_eq!(
        output
            .matches("Enter one of the displayed numbers.")
            .count(),
        5
    );
    assert!(!output.contains("Setup 1 —"));
    assert!(!output.contains("Simulation phase:"));
}

#[test]
fn overlong_confirmation_is_drained_without_echo_or_approval() {
    let start = menu_number(&successful_session(b"0\n"), "Start setup");
    let secret_like_input = format!("y{}", "private-input".repeat(30));
    let output = successful_session(format!("{start}\n\n{secret_like_input}\nn\n0\n").as_bytes());
    assert!(output.contains("Input is too long"), "{output}");
    assert!(!output.contains("private-input"), "{output}");
    assert!(output.contains(code("cancelled")), "{output}");
    assert!(!output.contains(code("complete")), "{output}");
}

#[test]
fn public_execute_returns_exact_cancel_complete_and_foreign_authority_codes() {
    let mut installation = Installation::simulation();
    let authority = prepared(&installation, Action::StartSetup);
    let result = installation.execute(authority, Confirmation::Declined);
    assert_result(&result, "cancelled", Status::NotSetUp);
    assert_eq!(installation.host().effects, 0);
    let mut foreign = Installation::simulation();
    let authority = prepared(&installation, Action::StartSetup);
    let result = foreign.execute(authority, Confirmation::Approved);
    assert_result(&result, "refused", Status::NotSetUp);
    assert_eq!(foreign.host().effects, 0);
    let result = execute(&mut installation, Action::StartSetup);
    assert_result(&result, "complete", Status::Running);
    assert!(installation.review(Action::StartSetup).prepared.is_none());
}

type FactChange = (&'static str, fn(&mut Facts));
const UNSAFE_FACTS: [FactChange; 7] = [
    ("root", |facts| facts.root = false),
    ("Ubuntu", |facts| facts.ubuntu_24_04 = false),
    ("architecture", |facts| facts.amd64 = false),
    ("footprint", |facts| facts.owned_paths_absent = false),
    ("port", |facts| facts.port_443_available = false),
    ("mutation lock", |facts| facts.mutation_idle = false),
    ("destination", |facts| facts.destination_compatible = false),
];

#[test]
fn review_and_details_are_read_only_and_unsafe_setup_never_gets_authority() {
    let mut installation = Installation::simulation();
    let frame = terminal_session(&mut installation, b"0\n");
    let details = menu_number(&frame, "View details");
    terminal_session(&mut installation, format!("{details}\n0\n").as_bytes());
    for action in [Action::Status, Action::ViewDetails, Action::StartSetup] {
        installation.review(action);
    }
    assert_eq!(installation.phase(), Phase::Absent);
    assert_eq!(installation.host().effects, 0);
    for (name, change) in UNSAFE_FACTS {
        let mut installation = Installation::simulation();
        change(&mut installation.host_mut().facts);
        let review = installation.review(Action::StartSetup);
        assert!(review.prepared.is_none(), "{name}");
        assert!(review.refusal.is_some(), "{name}");
        assert!(
            !review.legal_actions.contains(&Action::StartSetup),
            "{name}"
        );
        assert_eq!(installation.phase(), Phase::Absent, "{name}");
        assert_eq!(installation.host().effects, 0, "{name}");
    }
}

#[test]
fn execute_rechecks_each_safety_fact_after_review_and_has_no_refused_effect() {
    for (name, change) in UNSAFE_FACTS {
        let mut installation = Installation::simulation();
        let authority = prepared(&installation, Action::StartSetup);
        change(&mut installation.host_mut().facts);
        let result = installation.execute(authority, Confirmation::Approved);
        assert_result(&result, "refused", Status::NotSetUp);
        assert_eq!(installation.phase(), Phase::Absent, "{name}");
        assert_eq!(installation.host().effects, 0, "{name}");
    }
}

fn assert_later_review_invalidates_authority(action: Action) {
    // Go TestExecuteRefusesUntrustedPreparedAuthority: "stale after a later review".
    let mut installation = Installation::simulation();
    let authority = prepared(&installation, Action::StartSetup);
    installation.review(action);
    let result = installation.execute(authority, Confirmation::Approved);
    assert_result(&result, "refused", Status::NotSetUp);
    assert_eq!(installation.phase(), Phase::Absent, "later {action:?}");
    assert_eq!(installation.host().effects, 0, "later {action:?}");
}

#[test]
fn later_status_review_invalidates_prepared_authority() {
    assert_later_review_invalidates_authority(Action::Status);
}

#[test]
fn later_details_review_invalidates_prepared_authority() {
    assert_later_review_invalidates_authority(Action::ViewDetails);
}

#[test]
fn later_setup_review_invalidates_prepared_authority() {
    assert_later_review_invalidates_authority(Action::StartSetup);
}

fn assert_direction(installation: &Installation, legal: Action, illegal: Action) {
    let review = installation.review(Action::Status);
    assert_eq!(review.status, Status::SetupIncomplete);
    assert!(review.legal_actions.contains(&Action::ViewDetails));
    assert!(review.legal_actions.contains(&legal));
    assert!(!review.legal_actions.contains(&illegal));
    assert!(!review.legal_actions.contains(&Action::StartSetup));
    assert!(installation.review(illegal).prepared.is_none());
    assert!(installation.review(Action::StartSetup).prepared.is_none());
}

#[test]
fn interruption_before_commit_allows_only_cleanup_and_returns_the_go_codes() {
    let mut installation = Installation::simulation();
    installation.host_mut().fault = Some(SimulationFault::BeforeActivation);
    let result = execute(&mut installation, Action::StartSetup);
    assert_result(&result, "cleanup_required", Status::SetupIncomplete);
    assert_eq!(installation.phase(), Phase::Preparing);
    assert_direction(&installation, Action::FinishCleanup, Action::FinishSetup);
    let effects = installation.host().effects;
    let authority = prepared(&installation, Action::FinishCleanup);
    let result = installation.execute(authority, Confirmation::Declined);
    assert_result(&result, "cancelled", Status::SetupIncomplete);
    assert_eq!(installation.host().effects, effects);
    assert_eq!(installation.phase(), Phase::Preparing);
    let result = execute(&mut installation, Action::FinishCleanup);
    assert_result(&result, "cleaned_up", Status::NotSetUp);
    assert_eq!(installation.phase(), Phase::Absent);
    assert!(installation.review(Action::StartSetup).prepared.is_some());
}

#[test]
fn interruption_after_commit_allows_only_forward_completion() {
    let mut installation = Installation::simulation();
    installation.host_mut().fault = Some(SimulationFault::AfterActivation);
    let result = execute(&mut installation, Action::StartSetup);
    assert_result(&result, "completion_required", Status::SetupIncomplete);
    assert_eq!(installation.phase(), Phase::ActivationCommitted);
    assert_direction(&installation, Action::FinishSetup, Action::FinishCleanup);
    let authority = prepared(&installation, Action::FinishSetup);
    let effects = installation.host().effects;
    let result = installation.execute(authority, Confirmation::Declined);
    assert_result(&result, "cancelled", Status::SetupIncomplete);
    assert_eq!(installation.host().effects, effects);
    assert_eq!(installation.phase(), Phase::ActivationCommitted);
    let result = execute(&mut installation, Action::FinishSetup);
    assert_result(&result, "completion_required", Status::SetupIncomplete);
    assert_eq!(installation.phase(), Phase::ActivationCommitted);
    installation.host_mut().fault = None;
    let result = execute(&mut installation, Action::FinishSetup);
    assert_result(&result, "complete", Status::Running);
    assert!(
        installation
            .review(Action::FinishCleanup)
            .prepared
            .is_none()
    );
}

#[test]
fn stale_authority_cannot_be_revived_by_cleanup_returning_to_the_same_phase() {
    let mut installation = Installation::simulation();
    let old = prepared(&installation, Action::StartSetup);
    installation.host_mut().fault = Some(SimulationFault::BeforeActivation);
    execute(&mut installation, Action::StartSetup);
    execute(&mut installation, Action::FinishCleanup);
    installation.host_mut().fault = None;
    assert_eq!(installation.phase(), Phase::Absent);
    let effects = installation.host().effects;
    let result = installation.execute(old, Confirmation::Approved);
    assert_result(&result, "refused", Status::NotSetUp);
    assert_eq!(installation.host().effects, effects);
    assert_eq!(installation.phase(), Phase::Absent);
}

#[test]
fn numbered_recovery_menu_uses_the_committed_direction_and_defaults_to_no() {
    for (fault, legal, illegal, outcome, final_phase, final_status) in [
        (
            SimulationFault::BeforeActivation,
            Action::FinishCleanup,
            Action::FinishSetup,
            "cleaned_up",
            Phase::Absent,
            Status::NotSetUp,
        ),
        (
            SimulationFault::AfterActivation,
            Action::FinishSetup,
            Action::FinishCleanup,
            "complete",
            Phase::Running,
            Status::Running,
        ),
    ] {
        let mut installation = Installation::simulation();
        installation.host_mut().fault = Some(fault);
        execute(&mut installation, Action::StartSetup);
        installation.host_mut().fault = None;
        let frame = terminal_session(&mut installation, b"0\n");
        let number = menu_number(&frame, &legal.to_string());
        assert!(!frame.contains(&format!(". {illegal}\n")), "{frame}");
        let phase = installation.phase();
        let effects = installation.host().effects;
        let output = terminal_session(&mut installation, format!("{number}\n\n0\n").as_bytes());
        assert!(output.contains(code("cancelled")), "{output}");
        assert_eq!(installation.phase(), phase);
        assert_eq!(installation.host().effects, effects);
        let output = terminal_session(&mut installation, format!("{number}\ny\n0\n").as_bytes());
        assert!(output.contains(&format!("{legal}? [y/N]")), "{output}");
        assert!(!output.contains(&format!("{illegal}? [y/N]")), "{output}");
        assert!(output.contains(code(outcome)), "{output}");
        assert!(
            output.contains(&format!("Proxy status: {final_status}")),
            "{output}"
        );
        assert_eq!(installation.phase(), final_phase);
    }
}
