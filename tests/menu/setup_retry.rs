//! Explicit in-memory state for native presentation only; no host/credentials.
use sbxr::{
    domain::{Action, Confirmation, Phase},
    proxyinstallation::{ExecutionMode, Installation, Interface, PreparedAction, Review},
};
use std::{
    cell::{Cell, RefCell},
    io::{self, BufRead, Cursor, Read},
};
struct Scripted {
    inner: RefCell<Installation>,
    failures: Cell<usize>,
    reviews: Cell<usize>,
}
impl Scripted {
    fn new(failures: usize) -> Self {
        Self {
            inner: RefCell::new(Installation::simulation()),
            failures: Cell::new(failures),
            reviews: Cell::new(0),
        }
    }
}
impl Interface for Scripted {
    fn review(&self, action: Action) -> Review {
        if action == Action::StartSetup {
            self.reviews.set(self.reviews.get() + 1);
            let failed = self.failures.get() > 0;
            self.failures.set(self.failures.get().saturating_sub(1));
            self.inner
                .borrow_mut()
                .host_mut()
                .facts
                .destination_compatible = !failed;
        }
        let mut review = self.inner.borrow().review(action);
        review.mode = ExecutionMode::Native;
        review
    }
    fn execute(&mut self, p: PreparedAction, c: Confirmation) -> sbxr::domain::Result {
        self.inner.get_mut().execute(p, c)
    }
}
fn run(input: impl BufRead, owner: &mut Scripted) -> (io::Result<()>, String) {
    let mut out = Vec::new();
    let result = sbxr::terminal::run(&mut { input }, &mut out, owner);
    (result, String::from_utf8(out).unwrap())
}
#[test]
fn retry_rechecks_without_reusing_authority_and_back_returns_to_connection() {
    for (input, reviews, choices) in [("2\n1\nr\nn\n0\n", 2, 1), ("2\n1\nb\nc\n0\n", 1, 2)] {
        let mut owner = Scripted::new(1);
        let (result, text) = run(Cursor::new(input), &mut owner);
        result.unwrap();
        assert_eq!(owner.reviews.get(), reviews);
        assert_eq!(owner.inner.borrow().host().effects, 0);
        assert_eq!(
            text.matches("Connection [1] (h Help, c Cancel):").count(),
            choices
        );
        assert!(text.contains("Code: PROXY-INSTALLATION-ACTION-REFUSED\n"));
        assert!(text.contains("Setup is not ready. r Retry checks, b Back, c Cancel:"));
        assert!(text.contains("Code: PROXY-INSTALLATION-ACTION-CANCELLED\n"));
    }
    let mut pending = Scripted::new(2);
    let (result, _) = run(Cursor::new("2\n1\nr\nc\n0\n"), &mut pending);
    result.unwrap();
    assert_eq!(pending.reviews.get(), 2);
    assert_eq!(pending.inner.borrow().host().effects, 0);
    let mut owner = Scripted::new(1);
    let (result, _) = run(Cursor::new("2\n1\nr\ny\n0\n"), &mut owner);
    result.unwrap();
    assert_eq!(owner.reviews.get(), 2);
    assert_eq!(owner.inner.borrow().phase(), Phase::Running);
    // Every later Review revokes a separately held action, including retry UI.
    let mut owner = Scripted::new(0);
    let old = owner.review(Action::StartSetup).prepared.unwrap();
    owner.failures.set(1);
    run(Cursor::new("2\n1\nc\n0\n"), &mut owner).0.unwrap();
    assert_eq!(
        owner.execute(old, Confirmation::Approved).outcome,
        sbxr::domain::Outcome::Refused
    );
    assert_eq!(owner.inner.borrow().host().effects, 0);
}
#[test]
fn refusal_cannot_treat_yes_blank_eof_or_interrupted_input_as_approval() {
    for input in ["2\n1\nc\n0\n", "2\n1\ny\n\nc\n0\n", "2\n1\n"] {
        let mut owner = Scripted::new(2);
        let (result, text) = run(Cursor::new(input), &mut owner);
        result.unwrap();
        assert_eq!(owner.reviews.get(), 1);
        assert_eq!(owner.inner.borrow().host().effects, 0);
        assert!(text.contains("Code: PROXY-INSTALLATION-ACTION-CANCELLED\n"));
    }
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture interrupted input"))
        }
    }
    impl BufRead for Broken {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("fixture interrupted input"))
        }
        fn consume(&mut self, _: usize) {}
    }
    let mut owner = Scripted::new(1);
    let (result, _) = run(Cursor::new(b"2\n1\n").chain(Broken), &mut owner);
    assert!(result.is_err());
    assert_eq!(owner.reviews.get(), 1);
    assert_eq!(owner.inner.borrow().host().effects, 0);
}
#[test]
fn retained_driver_can_cancel_the_actual_native_failed_review_transcript() {
    let mut owner = Scripted::new(1);
    let (result, text) = run(Cursor::new("2\n1\nc\n0\n"), &mut owner);
    result.unwrap();
    const PARSER: &str = r#"
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('driver',sys.argv[1]);d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
data=json.load(sys.stdin)
class Lines:
 def __init__(self):self.it=iter(data.splitlines())
 def line(self,_):return next(self.it,None)
s=object.__new__(d.MenuSession);s.stream=Lines();s.deadline=0
writes=[];s.write=writes.append
s.choose('Start setup');s.expect_prompt(d.SETUP_CHOICE_PROMPT);s.write('1\n');s.expect_prompt(d.SETUP_REFUSAL_PROMPT,review_code='PROXY-INSTALLATION-ACTION-REFUSED');s.write('c\n');s.wait_code('PROXY-INSTALLATION-ACTION-CANCELLED')
assert writes==['2\n','1\n','c\n','0\n'],writes
"#;
    use std::io::Write;
    use std::process::{Command, Stdio};
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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&text).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
