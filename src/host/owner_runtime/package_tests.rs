//! Fixed observations only. All process, service and network methods panic.
use super::*;
struct PackageFacts {
    status: &'static str,
    hold: &'static str,
    owner: &'static str,
}
impl PeerObservations for PackageFacts {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        panic!("not needed")
    }
    fn peer(
        &self,
        _: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        panic!("no sockets")
    }
}
impl OwnerIo for PackageFacts {
    fn query(&self, q: Observation, _: &StartContext) -> Result<CommandOutput, HostError> {
        let body = match q {
            Observation::Package => self.status,
            Observation::Hold => self.hold,
            Observation::UnitOwner => self.owner,
            _ => panic!("unexpected observation"),
        };
        CommandOutput::completed(0, body.as_bytes().to_vec())
    }
    fn service(
        &self,
        _: ServiceAction,
        _: &Arc<HostLock>,
        _: Option<&Path>,
        _: &StartContext,
    ) -> Result<(), HostError> {
        panic!("no effects")
    }
    fn port_available(&self, _: u16, _: &StartContext) -> Result<bool, HostError> {
        panic!("no bind")
    }
    fn process(&self, _: u32) -> Result<runtime_handoff::ProcessIdentity, HostError> {
        panic!("no ps or proc")
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
        panic!("no execution")
    }
}
#[test]
fn running_package_requires_healthy_dpkg_hold_and_independent_apt_hold() {
    let root = Root::new();
    let proof = crate::release_acquisition::fixture_authenticated().0;
    let mut runtime = OwnerRuntime {
        fs: ProtectedFs::open(&root.0).unwrap(),
        proof: &proof,
        io: PackageFacts {
            status: "1.14.3 amd64 hi",
            hold: "sing-box",
            owner: "sing-box: /usr/lib/systemd/system/sing-box.service",
        },
        probe: None,
        stop: Cancellation::new(),
    };
    assert!(
        runtime.package(&runtime.context()).is_ok(),
        "setup holds the installed package"
    );
    for status in [
        "1.14.3 amd64 ii",
        "1.14.3 amd64 hF",
        "1.14.3 amd64 iU",
        "1.14.3 amd64 hiR",
        "1.14.4 amd64 hi",
        "1.14.3 arm64 hi",
        "1.14.3 amd64 hi extra",
    ] {
        runtime.io.status = status;
        assert!(runtime.package(&runtime.context()).is_err(), "{status}");
    }
    runtime.io.status = "1.14.3 amd64 hi";
    for hold in ["", "sing-box-beta", "sing-box\nsing-box"] {
        runtime.io.hold = hold;
        assert!(runtime.package(&runtime.context()).is_err());
    }
    runtime.io.hold = "sing-box";
    runtime.io.owner = "foreign: /usr/lib/systemd/system/sing-box.service";
    assert!(runtime.package(&runtime.context()).is_err());
}
