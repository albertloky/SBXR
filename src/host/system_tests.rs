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
