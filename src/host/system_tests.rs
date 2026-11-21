use super::*;
struct NoCommands;
impl Transport for NoCommands {
    fn run(&self, _: &CommandSpec, _: &Cancellation) -> Result<CommandOutput, HostError> {
        panic!("unapproved command")
    }
}
#[test]
fn commands_cannot_run_without_retained_exclusion() {
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            std::fs::remove_dir(&self.0).unwrap()
        }
    }
    use std::os::unix::fs::PermissionsExt;
    let root = Root(
        std::path::PathBuf::from(std::env::var_os("TMPDIR").unwrap())
            .join(format!("system-no-lock-{}", std::process::id())),
    );
    std::fs::create_dir(&root.0).unwrap();
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut runner = SystemRunner::injected(&root.0, NoCommands, &"a".repeat(64)).unwrap();
    assert!(matches!(
        runner.effect(Operation::MaskService, &Cancellation::new()),
        Err(HostError::Unsafe)
    ));
}
#[test]
fn native_transport_and_runner_refuse_mac_before_effects() {
    if !cfg!(target_os = "linux") {
        assert!(matches!(
            NativeTransport::new(),
            Err(HostError::UnsupportedHost)
        ));
        assert!(matches!(
            SystemRunner::native(NoCommands, &"a".repeat(64)),
            Err(HostError::UnsupportedHost)
        ))
    }
}

#[test]
fn qualification_purge_matches_only_the_fixed_guarded_mutation() {
    let purge = ["/usr/bin/apt-get", "purge", "-y", "sing-box=1.14.3"];
    let fixed = CommandSpec::fixed(purge[0], &purge[1..], true);
    assert!(fixed.is_proxy_package_purge());
    let transport = NativeTransport {
        lock: None,
        standard_removal: None,
    };
    assert!(!transport.list_only_purge(&fixed).unwrap());
    let mut wrong_directory = fixed;
    wrong_directory.directory = "/var/lib/sbxr".into();
    assert!(!wrong_directory.is_proxy_package_purge());
    for unqualified in [
        CommandSpec::fixed(purge[0], &purge[1..], false),
        CommandSpec::fixed(purge[0], &["update"], true),
        CommandSpec::fixed(purge[0], &["purge", "-y", "openssh-server"], true),
        CommandSpec::fixed("/usr/bin/dpkg", &purge[1..], true),
    ] {
        assert!(!unqualified.is_proxy_package_purge());
    }
}
