use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn real_executable_runs_the_local_simulation() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sbxr"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"2\n\ny\n0\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).unwrap();
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
