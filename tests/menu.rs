use std::process::{Command, Stdio};

#[test]
fn explicit_library_simulation_keeps_the_wizard_contract() {
    let mut installation = sbxr::proxyinstallation::Installation::simulation();
    let mut output = Vec::new();
    sbxr::terminal::run(
        &mut std::io::Cursor::new(b"2\n\ny\n0\n"),
        &mut output,
        &mut installation,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Proxy status: Running"));
    assert!(output.contains("No software was installed"));
}

#[test]
fn executable_refuses_arguments_before_opening_the_menu() {
    let result = Command::new(env!("CARGO_BIN_EXE_sbxr"))
        .arg("setup")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("SBXR accepts no arguments")
    );
}

#[test]
fn fixed_private_roles_refuse_silently_without_native_prerequisites() {
    for (role, code) in [
        ("--provision-mutation-lock", 1),
        ("--proxy-start-authorize", 1),
        ("--subscription-serving", 1),
        ("--certbot-recorder", 125),
        ("--certbot-deploy-hook", 1),
        ("--certbot-post-hook", 1),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_sbxr"))
            .arg(role)
            .env("SBXR_RENEWAL_ATTEMPT_ID", "synthetic-untrusted")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(code));
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
    let result = Command::new(env!("CARGO_BIN_EXE_sbxr"))
        .args(["--provision-mutation-lock", "extra"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn native_entry_never_automatically_substitutes_the_simulator() {
    let result = Command::new(env!("CARGO_BIN_EXE_sbxr"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let out = String::from_utf8(result.stdout).unwrap();
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(out.is_empty());
    assert!(!error.is_empty());
    assert!(!out.contains("simulation") && !out.contains("Start setup"));
}

// Presentation seam only. No native host, prepared action or effect is created.
struct ReadOnlyOwner(sbxr::proxyinstallation::ExecutionMode);
impl sbxr::proxyinstallation::Interface for ReadOnlyOwner {
    fn review(&self, _: sbxr::domain::Action) -> sbxr::proxyinstallation::Review {
        sbxr::proxyinstallation::Review {
            mode: self.0,
            status: sbxr::domain::Status::NotSetUp,
            details: vec!["Read-only presentation fixture".into()],
            legal_actions: vec![sbxr::domain::Action::ViewDetails],
            plan: vec![],
            refusal: None,
            prepared: None,
        }
    }
    fn execute(
        &mut self,
        _: sbxr::proxyinstallation::PreparedAction,
        _: sbxr::domain::Confirmation,
    ) -> sbxr::domain::Result {
        panic!("presentation fixture cannot execute")
    }
}
struct ReadOnlyLifecycle;
impl ReadOnlyLifecycle {
    fn result(code: sbxr::software_lifecycle::Code) -> sbxr::software_lifecycle::Result {
        sbxr::software_lifecycle::Result {
            state: sbxr::software_lifecycle::State::Ready,
            installed: None,
            latest: None,
            code,
            message: "Read-only lifecycle fixture",
            recovery_direction: None,
        }
    }
}
impl sbxr::software_lifecycle::Interface for ReadOnlyLifecycle {
    fn status(&mut self) -> sbxr::software_lifecycle::Result {
        Self::result(sbxr::software_lifecycle::Code::StatusReady)
    }
    fn check(&mut self) -> sbxr::software_lifecycle::Result {
        Self::result(sbxr::software_lifecycle::Code::CheckAlreadyCurrent)
    }
    fn update(&mut self) -> sbxr::software_lifecycle::Result {
        panic!("Update is excluded")
    }
    fn review_recover(&mut self) -> sbxr::software_lifecycle::Result {
        Self::result(sbxr::software_lifecycle::Code::RecoverNotRequired)
    }
    fn recover(&mut self, _: sbxr::domain::Confirmation) -> sbxr::software_lifecycle::Result {
        panic!("ready lifecycle must not mutate")
    }
}
fn native_presentation(input: &[u8]) -> String {
    let mut output = Vec::new();
    sbxr::terminal::run_with_lifecycle(
        &mut std::io::Cursor::new(input),
        &mut output,
        &mut ReadOnlyOwner(sbxr::proxyinstallation::ExecutionMode::Native),
        &mut ReadOnlyLifecycle,
    )
    .unwrap();
    String::from_utf8(output).unwrap()
}
#[test]
fn native_frames_are_consumed_by_the_retained_qualification_driver() {
    // Execute only the real driver's finite transcript parser methods. Bypass
    // its process-owning constructor: no subprocess/session cleanup, ps, native
    // signalling, socket or system adapter from that module can run here.
    const PARSER: &str = r#"
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('driver',sys.argv[1]);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
data=json.load(sys.stdin)
class Lines:
 def __init__(self):self.items=iter(data['transcript'].splitlines())
 def line(self,_):return next(self.items,None)
s=object.__new__(driver.MenuSession);s.stream=Lines();s.deadline=0
writes=[];s.write=writes.append
s.choose(data['label'])
if data['label']=='View details':
 s.wait_unconfirmed_marker(driver.DETAILS_PROMPT);s.write('\n');s.return_to_menu()
elif data['label']=='Recover':
 s.wait_unconfirmed_marker('No recovery is available. If a change is in progress, wait for it to finish.');s.return_to_menu()
else:s.wait_code('SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT')
assert writes==data['writes'],writes
print('retained parser accepted')
"#;
    for (input, label, writes) in [
        (b"2\n0\n".as_slice(), "Check", vec!["2\n", "0\n"]),
        (b"3\n0\n".as_slice(), "Recover", vec!["3\n", "0\n"]),
        (
            b"1\n\n0\n".as_slice(),
            "View details",
            vec!["1\n", "\n", "0\n"],
        ),
    ] {
        let text = native_presentation(input);
        let data = serde_json::json!({"transcript":text,"label":label,"writes":writes});
        let mut child = Command::new("python3")
            .args([
                "-B",
                "-c",
                PARSER,
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/.github/scripts/v3-menu-session.py"
                ),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&data).unwrap())
            .unwrap();
        let parsed = child.wait_with_output().unwrap();
        assert!(
            parsed.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&parsed.stderr)
        );
        assert_eq!(text.lines().filter(|l| *l == "SBXR V3").count(), 2);
        assert_eq!(
            text.lines()
                .filter(|l| *l == "Proxy status: Not set up")
                .count(),
            2
        );
        assert!(text.contains("Subscription status: Not enabled\n"));
        assert!(text.contains("Software Lifecycle: Ready\n"));
        assert!(text.contains("Code: SOFTWARE-LIFECYCLE-STATUS-READY\n"));
        assert!(!text.contains("Check SBXR") && !text.contains("Recover SBXR"));
    }
    let eof = native_presentation(b"1\n");
    assert!(eof.contains("Press Enter to return to the menu."));
    assert_eq!(eof.lines().filter(|l| *l == "SBXR V3").count(), 1);
}
#[test]
fn unavailable_and_fixture_modes_never_impersonate_a_native_driver_frame() {
    use sbxr::proxyinstallation::ExecutionMode;
    for mode in [
        ExecutionMode::Simulation,
        ExecutionMode::Fixture,
        ExecutionMode::InjectedHost,
        ExecutionMode::NativeUnavailable,
    ] {
        let mut output = Vec::new();
        sbxr::terminal::run(
            &mut std::io::Cursor::new(b"0\n"),
            &mut output,
            &mut ReadOnlyOwner(mode),
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.lines().any(|l| l == "SBXR V3"));
        assert!(!text.lines().any(|l| l == "Proxy status: Not set up"));
    }
}

#[test]
fn native_setup_recovery_uses_the_retained_confirmation_prompts_without_mutation() {
    use sbxr::{
        domain::{Action, Confirmation},
        proxyinstallation::{
            ExecutionMode, Installation, Interface, PreparedAction, Review, SimulationFault,
        },
    };
    // Explicit in-memory setup states supply real prepared authority; this
    // presentation wrapper permits only Declined execution, never host effects.
    struct DeclineOnly(Installation);
    impl Interface for DeclineOnly {
        fn review(&self, a: Action) -> Review {
            let mut r = self.0.review(a);
            r.mode = ExecutionMode::Native;
            r
        }
        fn execute(&mut self, p: PreparedAction, c: Confirmation) -> sbxr::domain::Result {
            assert_eq!(c, Confirmation::Declined);
            self.0.execute(p, c)
        }
    }
    const PARSER: &str = r#"
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('driver',sys.argv[1]);d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
data=json.load(sys.stdin)
class Lines:
 def __init__(self):self.items=iter(data['text'].splitlines())
 def line(self,_):return next(self.items,None)
s=object.__new__(d.MenuSession);s.stream=Lines();s.deadline=0
writes=[];s.write=writes.append
s.choose(data['label']);s.expect_prompt(d.PROMPTS[data['label']]);s.write('n\n');s.wait_code('PROXY-INSTALLATION-ACTION-CANCELLED')
assert writes==['2\n','n\n','0\n'],writes
"#;
    for (fault, label) in [
        (SimulationFault::BeforeActivation, "Finish cleanup"),
        (SimulationFault::AfterActivation, "Finish setup"),
    ] {
        let mut model = Installation::simulation();
        model.host_mut().fault = Some(fault);
        let prepared = model.review(Action::StartSetup).prepared.unwrap();
        model.execute(prepared, Confirmation::Approved);
        model.host_mut().fault = None;
        let phase = model.phase();
        let effects = model.host().effects;
        let mut owner = DeclineOnly(model);
        let mut out = Vec::new();
        sbxr::terminal::run(
            &mut std::io::Cursor::new(b"2\nn\n0\n"),
            &mut out,
            &mut owner,
        )
        .unwrap();
        assert_eq!(owner.0.phase(), phase);
        assert_eq!(owner.0.host().effects, effects);
        let data = serde_json::json!({"text":String::from_utf8(out).unwrap(),"label":label});
        let mut child = Command::new("python3")
            .args([
                "-B",
                "-c",
                PARSER,
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/.github/scripts/v3-menu-session.py"
                ),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&data).unwrap())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[path = "menu/setup_retry.rs"]
mod setup_retry;

#[test]
fn candidate_arguments_and_ambient_overrides_cannot_bypass_protected_zero_argument_entry() {
    // These names are deliberately unsupported input. No process-wide environment
    // changes, protected-root writes or native effects occur in this regression.
    for args in [vec![], vec!["--candidate"], vec!["--ca", "synthetic.pem"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_sbxr"))
            .args(&args)
            .env("SBXR_CHANNEL", "candidate")
            .env("SBXR_CANDIDATE_MANIFEST", "synthetic.json")
            .env("SBXR_CANDIDATE_CA_SHA256", "a".repeat(64))
            .env("SSL_CERT_FILE", "synthetic.pem")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        if args.is_empty() {
            assert!(!error.is_empty());
            assert!(!error.contains("synthetic") && !error.contains(&"a".repeat(64)));
        } else {
            assert!(error.contains("SBXR accepts no arguments"));
        }
    }
}
