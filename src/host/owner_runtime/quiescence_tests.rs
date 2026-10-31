use super::*;
struct QuietIo {
    state: &'static str,
    main: &'static str,
    control: &'static str,
    group: String,
    listener: &'static str,
}
impl PeerObservations for QuietIo {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        panic!("not needed")
    }
    fn peer(
        &self,
        _: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        panic!("not needed")
    }
}
impl OwnerIo for QuietIo {
    fn query(&self, q: Observation, _: &StartContext) -> Result<CommandOutput, HostError> {
        let text = match q {
            Observation::Property(Unit::Subscription, Property::ActiveState) => self.state,
            Observation::Property(Unit::Subscription, Property::MainPid) => self.main,
            Observation::Property(Unit::Subscription, Property::ControlPid) => self.control,
            Observation::Property(Unit::Subscription, Property::ControlGroup) => &self.group,
            Observation::Listener8443 => self.listener,
            _ => panic!("unexpected query: {q:?}"),
        };
        CommandOutput::completed(0, text.as_bytes().to_vec())
    }
    fn service(
        &self,
        _: ServiceAction,
        _: &Arc<HostLock>,
        _: Option<&Path>,
        _: &StartContext,
    ) -> Result<(), HostError> {
        panic!("read only")
    }
    fn port_available(&self, _: u16, _: &StartContext) -> Result<bool, HostError> {
        panic!("caller separately checks bind")
    }
    fn process(&self, _: u32) -> Result<runtime_handoff::ProcessIdentity, HostError> {
        panic!("no live process")
    }
    fn public_ipv4(&self, _: &StartContext) -> Result<std::net::Ipv4Addr, HostError> {
        panic!("no network")
    }
    fn validate_configuration(
        &self,
        _: &Arc<HostLock>,
        _: &str,
        _: &StartContext,
    ) -> Result<bool, HostError> {
        panic!("no effect")
    }
}
#[test]
fn failed_subscription_removal_requires_actual_quiescence() {
    let root = Root::new();
    let events = "sys/fs/cgroup/system.slice/sbxr-subscription.service/cgroup.events";
    root.write(events, b"populated 0\nfrozen 0\n", 0o444);
    fs::set_permissions(
        root.0.join("sys/fs/cgroup/system.slice"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let archive = crate::release_acquisition::fixture_archive();
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut runtime = OwnerRuntime {
        fs: ProtectedFs::open(&root.0).unwrap(),
        proof: &proof,
        io: QuietIo {
            state: "failed",
            main: "0",
            control: "0",
            group: Unit::Subscription.cgroup().into(),
            listener: "",
        },
        probe: None,
        stop: Cancellation::new(),
    };
    assert!(
        !runtime
            .quiescence(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    assert!(
        runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    for state in [
        "active",
        "activating",
        "deactivating",
        "reloading",
        "unknown",
    ] {
        runtime.io.state = state;
        assert!(
            !runtime
                .quiescence_for_removal(Unit::Subscription, &runtime.context())
                .unwrap()
        );
    }
    runtime.io.state = "failed";
    runtime.io.main = "123";
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.main = "0";
    runtime.io.control = "124";
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.control = "0";
    runtime.io.listener = "LISTEN 0 128 0.0.0.0:8443";
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.listener = "";
    runtime.io.group = "/foreign".into();
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.group = Unit::Subscription.cgroup().into();
    fs::set_permissions(root.0.join(events), fs::Permissions::from_mode(0o644)).unwrap();
    root.write(events, b"populated 1\nfrozen 0\n", 0o444);
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    fs::remove_file(root.0.join(events)).unwrap();
    assert!(
        !runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.group.clear();
    assert!(
        runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
    runtime.io.state = "inactive";
    assert!(
        runtime
            .quiescence_for_removal(Unit::Subscription, &runtime.context())
            .unwrap()
    );
}
