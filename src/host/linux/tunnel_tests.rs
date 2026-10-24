use super::*;

const TUNNEL_IMAGE: &[u8] = b"synthetic pinned package executable; never executed";
#[derive(Clone)]
struct TunnelRunner {
    root: PathBuf,
    state: Arc<std::sync::Mutex<Fake>>,
    corrupt: Arc<std::sync::atomic::AtomicBool>,
    package_default: bool,
}
impl CommandRunner for TunnelRunner {
    fn bind_configuration(&mut self, hash: &str) -> Result<(), HostError> {
        self.state.lock().unwrap().bind_configuration(hash)
    }
    fn query(&self, q: Query, c: &Cancellation) -> Result<CommandOutput, HostError> {
        let mut s = self.state.lock().unwrap();
        s.active = self.root.join("fixture-running").exists();
        s.query(q, c)
    }
    fn effect(&mut self, op: Operation, c: &Cancellation) -> Result<(), HostError> {
        self.state.lock().unwrap().effect(op, c)?;
        if op == Operation::InstallPackage {
            fs::write(
                self.root.join("usr/lib/systemd/system/sing-box.service"),
                include_bytes!("../owner_runtime/testdata/sing-box.service"),
            )
            .unwrap();
            let gid = fs::metadata(&self.root).unwrap().gid();
            fs::write(self.root.join("etc/group"), format!("sing-box:x:{gid}:\n")).unwrap();
            fs::set_permissions(
                self.root.join("etc/group"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            let path = self.root.join("usr/bin/sing-box");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let body = if self.corrupt.load(Ordering::SeqCst) {
                vec![b'X'; TUNNEL_IMAGE.len()]
            } else {
                TUNNEL_IMAGE.to_vec()
            };
            fs::write(&path, body).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            if self.package_default {
                fs::write(
                    self.root.join(CONFIG),
                    include_bytes!("../../../tests/testdata/tunnel_native/package-default.json"),
                )
                .unwrap();
                fs::set_permissions(self.root.join(CONFIG), fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
        }
        if op == Operation::RemovePackage {
            let path = self.root.join("usr/bin/sing-box");
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        if op == Operation::StopDisableService {
            let path = self.root.join("fixture-running");
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        Ok(())
    }
    fn removal_identity_safe(&self, _: &Cancellation) -> Result<(), HostError> {
        Ok(())
    }
    fn injected_effects(&self) -> bool {
        true
    }
}
#[derive(Clone)]
struct TunnelBackend {
    root: PathBuf,
    proof: Arc<crate::release_acquisition::AuthenticatedInstalled>,
    fail_start: Arc<std::sync::atomic::AtomicBool>,
}
struct TunnelPeers {
    proof: Arc<crate::release_acquisition::AuthenticatedInstalled>,
    uid: u32,
}
impl crate::runtime_handoff::PeerObservations for TunnelPeers {
    fn current(
        &self,
    ) -> Result<crate::runtime_handoff::ProcessIdentity, crate::runtime_handoff::Error> {
        crate::runtime_handoff::ProcessIdentity::new(
            100,
            1,
            1,
            self.uid,
            self.proof.record().executable_sha256(),
            "/owner.scope",
        )
    }
    fn peer(
        &self,
        _: &std::os::unix::net::UnixStream,
    ) -> Result<crate::runtime_handoff::ProcessIdentity, crate::runtime_handoff::Error> {
        Err(crate::runtime_handoff::Error::Refused)
    }
}
struct TunnelCommands {
    root: PathBuf,
    owner: Arc<crate::host::locks::HostLock>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl crate::host::runtime::ServiceCommands for TunnelCommands {
    fn execute(
        &self,
        action: crate::host::runtime::ServiceAction,
        c: &crate::runtime_handoff::StartContext,
    ) -> Result<(), crate::runtime_handoff::Error> {
        c.check()?;
        self.owner
            .verify()
            .map_err(|_| crate::runtime_handoff::Error::Refused)?;
        assert!(matches!(
            crate::host::locks::HostLock::existing(
                &self.root,
                fs::metadata(&self.root).unwrap().uid()
            ),
            Err(HostError::Busy)
        ));
        assert_eq!(action, crate::host::runtime::ServiceAction::StartProxy);
        if self.fail.load(Ordering::SeqCst) {
            return Err(crate::runtime_handoff::Error::Refused);
        }
        fs::write(
            self.root.join("fixture-running"),
            b"owned simulated process",
        )
        .unwrap();
        Ok(())
    }
}
impl TunnelRuntime for TunnelBackend {
    fn root(&self) -> &Path {
        &self.root
    }
    fn public_ipv4(&self, o: &Arc<crate::host::locks::HostLock>) -> Result<String, HostError> {
        o.verify()?;
        Ok("8.8.8.8".into())
    }
    fn observe(
        &self,
        _: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<TunnelRuntimeFacts, HostError> {
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let running = self.root.join("fixture-running").exists();
        Ok(TunnelRuntimeFacts {
            fingerprint: format!("fixture:{running}"),
            loopback_empty: !running,
            running,
        })
    }
    fn start(
        &self,
        o: &Arc<crate::host::locks::HostLock>,
        c: &crate::runtime_handoff::StartContext,
    ) -> Result<(), HostError> {
        let uid = fs::metadata(&self.root).unwrap().uid();
        let controller = crate::host::runtime::ServiceController::injected(
            &self.root,
            &self.proof,
            o.clone(),
            TunnelPeers {
                proof: self.proof.clone(),
                uid,
            },
            TunnelCommands {
                root: self.root.clone(),
                owner: o.clone(),
                fail: self.fail_start.clone(),
            },
            self.root.join("start.sock"),
        )?;
        controller
            .start_setup_proxy(c)
            .map_err(|_| HostError::Foreign)
    }
}
#[derive(Clone)]
struct ConnectorFixture {
    root: PathBuf,
    active: Arc<std::sync::atomic::AtomicBool>,
}
impl crate::host::tunnel_native::ConnectorIo for ConnectorFixture {
    fn query(
        &self,
        q: crate::host::tunnel_native::ConnectorQuery,
        _: &Cancellation,
        _: std::time::Duration,
    ) -> Result<CommandOutput, HostError> {
        use crate::host::tunnel_native::ConnectorQuery as Q;
        let unit = self
            .root
            .join("etc/systemd/system/sbxr-tunnel.service")
            .exists();
        let active = self.active.load(Ordering::SeqCst);
        let body=match q {
            Q::Version=>"cloudflared version 2025.4.0".into(),Q::Listener(_)=>String::new(),
            Q::Properties if !unit=>"LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n".into(),
            Q::Properties=>format!("LoadState=loaded\nActiveState={}\nMainPID={}\nControlPID=0\nControlGroup={}\nFragmentPath=/etc/systemd/system/sbxr-tunnel.service\nDropInPaths=\nExecCondition=\nExecStartPre=\nExecStartPost=\nExecReload=\nExecStop=\nExecStopPost=\nKillMode=control-group\nDynamicUser=yes\nLoadCredential=tunnel-token:/etc/cloudflared/sbxr.token\nExecStart={{ path=/usr/bin/cloudflared ; argv[]=/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file /run/credentials/sbxr-tunnel.service/tunnel-token ; ignore_errors=no }}\n",if active{"active"}else{"inactive"},if active{"300"}else{"0"},if active{"/system.slice/sbxr-tunnel.service"}else{""}),
        };
        CommandOutput::completed(0, body.into_bytes())
    }
    fn command(
        &self,
        a: crate::host::tunnel_native::ConnectorAction,
        o: &Arc<crate::host::locks::HostLock>,
        _: &Cancellation,
    ) -> Result<(), HostError> {
        o.verify()?;
        use crate::host::tunnel_native::ConnectorAction as A;
        match a {
            A::Reload => {}
            A::Start => self.active.store(true, Ordering::SeqCst),
            A::StopDisable => self.active.store(false, Ordering::SeqCst),
        };
        Ok(())
    }
    fn process(&self, pid: u32) -> Result<crate::runtime_handoff::ProcessIdentity, HostError> {
        crate::runtime_handoff::ProcessIdentity::new(
            pid,
            1,
            2,
            2000,
            &sha256_hex(&fs::read(self.root.join("usr/bin/cloudflared")).unwrap()),
            "/system.slice/sbxr-tunnel.service",
        )
        .map_err(|_| HostError::Foreign)
    }
    fn quiescent(&self, _: &Cancellation) -> Result<bool, HostError> {
        Ok(!self.active.load(Ordering::SeqCst))
    }
}
type TunnelFixture<'a> = crate::host::tunnel_native::ProtectedTunnelHost<
    'a,
    TunnelStandard<TunnelRunner, TunnelBackend>,
    ConnectorFixture,
>;
struct TunnelEntropy(u8);
impl crate::identity_generation::Entropy for TunnelEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crate::identity_generation::IdentityError> {
        for b in bytes {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}
fn tunnel_fixture<'a>(
    root: &Root,
    reference: &'a crate::release_acquisition::AuthenticatedInstalled,
    package_default: bool,
) -> (
    TunnelFixture<'a>,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    use base64::Engine;
    let (authenticated, exe) = crate::release_acquisition::fixture_authenticated();
    let proof = Arc::new(authenticated);
    root.write("usr/local/bin/sbxr", &exe, 0o755);
    root.write(
        "var/lib/sbxr/installed.json",
        &proof.record().encode().unwrap(),
        0o600,
    );
    let token = base64::engine::general_purpose::STANDARD.encode(include_bytes!(
        "../../../tests/testdata/tunnel_setup/token-claims.json"
    ));
    root.write("etc/cloudflared/sbxr.token", token.as_bytes(), 0o600);
    root.write("usr/bin/cloudflared", b"owner synthetic cloudflared", 0o755);
    fs::create_dir_all(root.0.join("run/lock")).unwrap();
    fs::set_permissions(root.0.join("run/lock"), fs::Permissions::from_mode(0o755)).unwrap();
    drop(
        crate::host::locks::HostLock::provision(&root.0, fs::metadata(&root.0).unwrap().uid())
            .unwrap(),
    );
    let base = root.host();
    let corrupt = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runner = TunnelRunner {
        root: root.0.clone(),
        state: Arc::new(std::sync::Mutex::new(base.runner)),
        corrupt: corrupt.clone(),
        package_default,
    };
    let host =
        LinuxHost::injected_authenticated(&root.0, runner, base.material, admission(), &proof)
            .unwrap();
    let runtime = TunnelBackend {
        root: root.0.clone(),
        proof,
        fail_start: fail.clone(),
    };
    let bridge = TunnelStandard::new(
        host,
        runtime,
        Some(crate::package_acquisition::ProbeImage::fixture(
            TUNNEL_IMAGE,
        )),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::Cursor::new(include_bytes!(
        "../../../tests/testdata/tunnel_native/ca.pem"
    ))) {
        roots.add(c.unwrap()).unwrap();
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    drop(listener);
    let network = crate::host::tunnel_native::ProbeNetwork::injected(
        roots,
        crate::host::tunnel_native::LoopbackNetwork {
            local_origin: address,
            public_hostname: "fixture.example.com".into(),
            public_address: address,
        },
    )
    .unwrap();
    let fixture = crate::host::tunnel_native::ProtectedTunnelHost::injected(
        &root.0,
        reference,
        bridge,
        ConnectorFixture {
            root: root.0.clone(),
            active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        network,
    )
    .unwrap();
    (fixture, fail, corrupt)
}

#[test]
fn composed_tunnel_recovery_retains_owner_and_never_restarts_precommit_source() {
    use crate::proxyinstallation::{ExecutionMode, Interface, TunnelOwnerInstallation};
    let root = Root::new();
    let proof = crate::release_acquisition::fixture_authenticated().0;
    let (host, fail, _) = tunnel_fixture(&root, &proof, false);
    fail.store(true, Ordering::SeqCst);
    let mut module = TunnelOwnerInstallation::with_entropy(
        host,
        ExecutionMode::InjectedHost,
        Box::new(TunnelEntropy(1)),
    );
    let prepared = module
        .review_tunnel_setup("fixture.example.com")
        .prepared
        .unwrap();
    let result = module.execute(prepared, Confirmation::Approved);
    assert_eq!(
        result.outcome,
        Outcome::NeedsCompletion,
        "{result:?}; {}",
        tunnel_debug(&mut module, &root)
    );
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(record.phase(), SetupPhase::ServiceEnabled);
    assert_eq!(
        record.recovery_direction(),
        crate::records::RecoveryDirection::FinishSetup
    );
    let config = fs::read(root.0.join(CONFIG)).unwrap();
    let token = fs::read(root.0.join("etc/cloudflared/sbxr.token")).unwrap();
    assert!(module.review(Action::FinishCleanup).prepared.is_none());
    fail.store(false, Ordering::SeqCst);
    let prepared = module.review(Action::FinishSetup).prepared.unwrap();
    let result = module.execute(prepared, Confirmation::Approved);
    assert_eq!(
        result.outcome,
        Outcome::VmessConnectionPending,
        "{result:?}"
    );
    assert_eq!(result.status, Status::Running);
    assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), config);
    assert_eq!(
        fs::read(root.0.join("etc/cloudflared/sbxr.token")).unwrap(),
        token
    );
    assert!(module.review(Action::CheckVmessTunnel).prepared.is_some());
}
#[test]
fn composed_tunnel_status_and_changed_prerequisites_expire_prepared_authority() {
    use crate::proxyinstallation::{ExecutionMode, Interface, TunnelOwnerInstallation};
    for later_status in [false, true] {
        let root = Root::new();
        let proof = crate::release_acquisition::fixture_authenticated().0;
        let (host, _, _) = tunnel_fixture(&root, &proof, false);
        let mut module = TunnelOwnerInstallation::with_entropy(
            host,
            ExecutionMode::InjectedHost,
            Box::new(TunnelEntropy(1)),
        );
        let prepared = module
            .review_tunnel_setup("fixture.example.com")
            .prepared
            .unwrap();
        if later_status {
            module.review(Action::Status);
        } else {
            root.write("usr/bin/cloudflared", b"changed reviewed connector", 0o755);
        }
        assert_eq!(
            module.execute(prepared, Confirmation::Approved).outcome,
            Outcome::Refused
        );
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
        assert!(!root.0.join("fixture-running").exists());
    }
}
#[test]
fn composed_tunnel_mismatched_probe_and_package_default_refuse_before_activation() {
    use crate::proxyinstallation::{ExecutionMode, Interface, TunnelOwnerInstallation};
    for package_default in [false, true] {
        let root = Root::new();
        let proof = crate::release_acquisition::fixture_authenticated().0;
        let (host, _, corrupt) = tunnel_fixture(&root, &proof, package_default);
        corrupt.store(!package_default, Ordering::SeqCst);
        let mut module = TunnelOwnerInstallation::with_entropy(
            host,
            ExecutionMode::InjectedHost,
            Box::new(TunnelEntropy(1)),
        );
        let prepared = module
            .review_tunnel_setup("fixture.example.com")
            .prepared
            .unwrap();
        assert_eq!(
            module.execute(prepared, Confirmation::Approved).outcome,
            Outcome::Refused
        );
        let record = OwnershipRecord::decode(
            &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record.phase(), SetupPhase::PackageInstalled);
        assert_eq!(
            record.recovery_direction(),
            crate::records::RecoveryDirection::Cleanup
        );
        assert!(!root.0.join("fixture-running").exists());
        if package_default {
            assert_eq!(
                fs::read(root.0.join(CONFIG)).unwrap(),
                include_bytes!("../../../tests/testdata/tunnel_native/package-default.json")
            );
        } else {
            assert_eq!(
                fs::read(root.0.join("usr/bin/sing-box")).unwrap(),
                vec![b'X'; TUNNEL_IMAGE.len()]
            );
        }
    }
}
#[test]
fn composed_tunnel_interruption_reopens_cleanup_without_owner_prerequisites() {
    use crate::proxyinstallation::{ExecutionMode, Interface, TunnelOwnerInstallation};
    let root = Root::new();
    let proof = crate::release_acquisition::fixture_authenticated().0;
    let (host, _, _) = tunnel_fixture(&root, &proof, false);
    host.standard().host().runner().state.lock().unwrap().fail = Some(Operation::HoldPackage);
    let mut module = TunnelOwnerInstallation::with_entropy(
        host,
        ExecutionMode::InjectedHost,
        Box::new(TunnelEntropy(1)),
    );
    let prepared = module
        .review_tunnel_setup("fixture.example.com")
        .prepared
        .unwrap();
    let result = module.execute(prepared, Confirmation::Approved);
    assert_eq!(
        result.outcome,
        Outcome::NeedsCleanup,
        "{result:?}; {}",
        tunnel_debug(&mut module, &root)
    );
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    let old = module.host_mut().standard().host().runner().clone();
    drop(module);
    fs::remove_file(root.0.join("etc/cloudflared/sbxr.token")).unwrap();
    fs::remove_file(root.0.join("usr/bin/cloudflared")).unwrap();
    old.state.lock().unwrap().fail = None;
    let base = root.host();
    let mut material = SetupMaterial::tunnel_cleanup(&record).unwrap();
    material.key_sha256 = base.material.key_sha256;
    material.package_sha256 = base.material.package_sha256;
    let host =
        LinuxHost::injected_authenticated(&root.0, old, material, admission(), &proof).unwrap();
    let bridge = TunnelStandard::new(
        host,
        TunnelBackend {
            root: root.0.clone(),
            proof: Arc::new(crate::release_acquisition::fixture_authenticated().0),
            fail_start: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        None,
    )
    .unwrap();
    let roots = rustls::RootCertStore::empty();
    let network = crate::host::tunnel_native::ProbeNetwork::injected(
        roots,
        crate::host::tunnel_native::LoopbackNetwork {
            local_origin: "127.0.0.1:9".parse().unwrap(),
            public_hostname: "fixture.example.com".into(),
            public_address: "127.0.0.1:9".parse().unwrap(),
        },
    )
    .unwrap();
    let host = crate::host::tunnel_native::ProtectedTunnelHost::injected(
        &root.0,
        &proof,
        bridge,
        ConnectorFixture {
            root: root.0.clone(),
            active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        network,
    )
    .unwrap();
    let mut module = TunnelOwnerInstallation::new(host, ExecutionMode::InjectedHost);
    let prepared = module.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        module.execute(prepared, Confirmation::Approved).outcome,
        Outcome::CleanedUp
    );
    assert!(!root.0.join(CONFIG).exists());
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    assert!(!root.0.join("usr/bin/cloudflared").exists());
}

fn tunnel_debug(
    module: &mut crate::proxyinstallation::TunnelOwnerInstallation<TunnelFixture<'_>>,
    root: &Root,
) -> String {
    use crate::host::tunnel_native::StandardHost;
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    let owner = Arc::new(
        crate::host::locks::HostLock::existing(&root.0, fs::metadata(&root.0).unwrap().uid())
            .unwrap(),
    );
    let host = module.host_mut().standard_mut();
    let obs = host.host().inspect_setup_profile(
        &host
            .host()
            .authenticated
            .as_ref()
            .unwrap()
            .release_identity(),
        true,
    );
    let inspection = host.inspect(&owner, Some(&record), &Cancellation::new());
    format!(
        "phase {:?}; base {obs:?}; bridge {inspection:?}",
        record.phase()
    )
}

#[test]
fn setup_start_selector_keeps_ordinary_private_starts_and_other_checkpoints_closed() {
    let mut record = OwnershipRecord::new_tunnel_setup(
        release(),
        "8.8.8.8",
        &"1".repeat(64),
        crate::records::TunnelAuthority::new(
            "12345678-1234-1234-1234-123456789abc",
            &"2".repeat(64),
            &"3".repeat(64),
        )
        .unwrap(),
    )
    .unwrap();
    loop {
        assert_eq!(
            crate::runtime_handoff::setup_start_configuration(&record).is_ok(),
            record.phase() == SetupPhase::ServiceEnabled,
            "{:?}",
            record.phase()
        );
        if record.phase() != SetupPhase::Running {
            assert!(crate::runtime_handoff::cutover_configuration(&record).is_err());
        }
        if record.phase() == SetupPhase::Running {
            break;
        }
        record = record.next_setup_checkpoint().unwrap();
    }
}
struct SharedTunnel<'a>(
    std::rc::Rc<
        std::cell::RefCell<crate::proxyinstallation::TunnelOwnerInstallation<TunnelFixture<'a>>>,
    >,
);
impl crate::proxyinstallation::Interface for SharedTunnel<'_> {
    fn supports_tunnel(&self) -> bool {
        true
    }
    fn review(&self, a: Action) -> crate::proxyinstallation::Review {
        self.0.borrow().review(a)
    }
    fn review_tunnel_setup(&self, h: &str) -> crate::proxyinstallation::Review {
        self.0.borrow().review_tunnel_setup(h)
    }
    fn execute(
        &mut self,
        p: crate::proxyinstallation::PreparedAction,
        c: Confirmation,
    ) -> crate::domain::Result {
        self.0.borrow_mut().execute(p, c)
    }
}
impl<'a> crate::proxyinstallation::OwnerSources<'a> for SharedTunnel<'a> {
    fn journeys(&self) -> Result<Vec<crate::proxyinstallation::Journey>, HostError> {
        Ok(vec![crate::proxyinstallation::Journey::Tunnel])
    }
    fn open(
        &self,
        j: crate::proxyinstallation::Journey,
    ) -> Result<Box<dyn crate::proxyinstallation::Interface + 'a>, HostError> {
        if j != crate::proxyinstallation::Journey::Tunnel {
            return Err(HostError::Foreign);
        }
        Ok(Box::new(SharedTunnel(self.0.clone())))
    }
    fn mode(&self) -> crate::proxyinstallation::ExecutionMode {
        crate::proxyinstallation::ExecutionMode::InjectedHost
    }
}
#[test]
fn owner_tunnel_wizard_keeps_default_no_back_cancel_and_invalid_input_secret_safe() {
    use crate::proxyinstallation::{ExecutionMode, OwnerInstallation, TunnelOwnerInstallation};
    for input in [
        "1\n2\ny\nfixture.example.com\n\n0\n",
        "1\n2\ny\nfixture.example.com\nb\nupdated.example.com\nn\n0\n",
        "1\n2\nb\nc\n0\n",
        "1\n2\ny\nNEVER_ECHO_THIS_CREDENTIAL\nfixture.example.com\nn\n0\n",
    ] {
        let root = Root::new();
        let proof = crate::release_acquisition::fixture_authenticated().0;
        let (host, _, _) = tunnel_fixture(&root, &proof, false);
        let module = TunnelOwnerInstallation::with_entropy(
            host,
            ExecutionMode::InjectedHost,
            Box::new(TunnelEntropy(1)),
        );
        let source = SharedTunnel(std::rc::Rc::new(std::cell::RefCell::new(module)));
        let mut owner = OwnerInstallation::new(source);
        let mut output = vec![];
        crate::terminal::run(&mut std::io::Cursor::new(input), &mut output, &mut owner).unwrap();
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
        assert!(!root.0.join("fixture-running").exists());
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("NEVER_ECHO_THIS_CREDENTIAL"));
        assert!(output.contains("ACTION-CANCELLED"));
    }
}
#[test]
fn owner_tunnel_review_authority_expires_on_later_details() {
    use crate::proxyinstallation::{
        ExecutionMode, Interface, OwnerInstallation, TunnelOwnerInstallation,
    };
    let root = Root::new();
    let proof = crate::release_acquisition::fixture_authenticated().0;
    let (host, _, _) = tunnel_fixture(&root, &proof, false);
    let module = TunnelOwnerInstallation::with_entropy(
        host,
        ExecutionMode::InjectedHost,
        Box::new(TunnelEntropy(1)),
    );
    let mut owner = OwnerInstallation::new(SharedTunnel(std::rc::Rc::new(
        std::cell::RefCell::new(module),
    )));
    let prepared = owner
        .review_tunnel_setup("fixture.example.com")
        .prepared
        .unwrap();
    owner.review(Action::ViewDetails);
    assert_eq!(
        owner.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}
