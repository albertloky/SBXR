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
