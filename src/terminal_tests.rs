use super::run;
use crate::domain::{Action, Confirmation, Phase};
use crate::proxyinstallation::{Installation, SimulationFault};
use std::io::{self, Cursor, Write};

fn session(input: &[u8], installation: &mut Installation) -> String {
    let mut output = Vec::new();
    run(&mut Cursor::new(input), &mut output, installation).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn standard_setup_reaches_simulated_running_through_the_wizard() {
    let mut installation = Installation::simulation();
    let output = session(b"2\n\ny\n0\n", &mut installation);
    for expected in [
        "local simulation only",
        "Setup 1 — Choose connection",
        "1. Standard (default; no domain needed)",
        "Setup 2 — Review",
        "Apply setup? [y/N]",
        "Simulation complete",
        "Proxy status: Running",
        "cannot be verified",
        "Code: PROXY-INSTALLATION-SETUP-COMPLETE",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
    assert_eq!(installation.phase(), Phase::Running);
    assert!(!output.contains("Installed: Standard proxy is locally verified"));
    assert!(!output.contains("2. Standard + Cloudflare"));
    assert!(!output.contains("Update"));
}

#[test]
fn decline_cancel_eof_and_unterminated_approval_leave_setup_absent() {
    for input in [
        "2\n\n\n0\n",
        "2\n\nn\n0\n",
        "2\nc\n0\n",
        "2\n\nc\n0\n",
        "2\n\n",
        "2\n\ny",
    ] {
        let mut installation = Installation::simulation();
        session(input.as_bytes(), &mut installation);
        assert_eq!(installation.phase(), Phase::Absent, "input {input:?}");
        assert_eq!(installation.host().effects, 0);
    }
}

#[test]
fn help_back_and_invalid_confirmation_do_not_bypass_review() {
    let mut installation = Installation::simulation();
    let output = session(b"2\nh\n2\n1\nb\n1\nY\nyes\n y\ny\n0\n", &mut installation);
    assert_eq!(installation.phase(), Phase::Running);
    assert!(output.contains("Standard uses VLESS REALITY Vision"));
    assert_eq!(output.matches("Setup 2 — Review").count(), 2);
    assert_eq!(output.matches("Enter y to apply").count(), 3);
}

#[test]
fn long_input_is_drained_and_never_becomes_approval() {
    let mut installation = Installation::simulation();
    let input = format!("2\n\ny{}\nn\n0\n", "x".repeat(10000));
    let output = session(input.as_bytes(), &mut installation);
    assert!(output.contains("Input is too long"));
    assert!(!output.contains(&"x".repeat(100)));
    assert_eq!(installation.host().effects, 0);
}

#[test]
fn details_are_read_only_and_recovery_uses_the_reviewed_direction() {
    let mut installation = Installation::simulation();
    session(b"1\n0\n", &mut installation);
    assert_eq!(installation.host().effects, 0);
    installation.host_mut().fault = Some(SimulationFault::AfterActivation);
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    installation.execute(prepared, Confirmation::Approved);
    installation.host_mut().fault = None;
    let output = session(b"2\ny\n0\n", &mut installation);
    assert!(output.contains("Finish setup? [y/N]"));
    assert!(!output.contains("Finish cleanup? [y/N]"));
    assert_eq!(installation.phase(), Phase::Running);
}

struct FailingWriter {
    at: &'static str,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains(self.at) {
            Err(io::Error::other("fixture output failure"))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failure_before_confirmation_cannot_mutate() {
    let mut installation = Installation::simulation();
    assert!(
        run(
            &mut Cursor::new(b"2\n\ny\n"),
            &mut FailingWriter { at: "Apply setup?" },
            &mut installation
        )
        .is_err()
    );
    assert_eq!(installation.host().effects, 0);
}

#[test]
fn failed_result_display_does_not_undo_or_repeat_commitment() {
    let mut installation = Installation::simulation();
    assert!(
        run(
            &mut Cursor::new(b"2\n\ny\n"),
            &mut FailingWriter {
                at: "Simulation complete"
            },
            &mut installation
        )
        .is_err()
    );
    assert_eq!(installation.phase(), Phase::Running);
    assert_eq!(installation.host().effects, 3);
}

#[test]
fn malformed_utf8_cannot_mutate() {
    let mut installation = Installation::simulation();
    let mut output = Vec::new();
    assert!(
        run(
            &mut Cursor::new(b"2\n\n\xff\n"),
            &mut output,
            &mut installation
        )
        .is_err()
    );
    assert_eq!(installation.host().effects, 0);
}

struct FailingReader;
impl io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture input failure"))
    }
}
impl io::BufRead for FailingReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::other("fixture input failure"))
    }
    fn consume(&mut self, _: usize) {}
}

#[test]
fn failed_input_cannot_mutate() {
    let mut installation = Installation::simulation();
    assert!(run(&mut FailingReader, &mut Vec::new(), &mut installation).is_err());
    assert_eq!(installation.host().effects, 0);
}
