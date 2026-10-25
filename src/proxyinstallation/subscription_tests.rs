use super::*;
use crate::{
    host::{
        locks::HostLock,
        runtime::{
            ServiceAction, ServiceCommands, ServiceController, ServingEnvironment,
            ServingRuntimeHost,
        },
        subscription::{
            HttpFault, HttpRuntime, LINK, ProtectedHttpHost, RuntimeFacts, STAGING, STATE,
            SystemEffect, TOKEN, UNIT,
        },
    },
    release_acquisition::{AuthenticatedArchive, AuthenticatedInstalled},
    runtime_handoff::{
        self, PathAccess, PeerObservations, ProcessIdentity, SandboxProcess, ServingSandbox,
    },
    subscription_artifact::SubscriptionCredential,
    subscription_serving::{Code, Module},
};
use std::result::Result;
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "ho-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn write(&self, path: &str, body: &[u8], mode: u32) {
        let p = self.0.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn setup(&self, a: &AuthenticatedArchive) -> OwnershipRecord {
        let config = include_bytes!("../../tests/testdata/server_configuration/standard.json");
        let mut r = OwnershipRecord::new_standard(
            a.record().release_identity(),
            "8.8.8.8",
            &sha256_hex(config),
        )
        .unwrap();
        while r.phase() != SetupPhase::Running {
            r = r.next_setup_checkpoint().unwrap();
        }
        self.write("usr/local/bin/sbxr", a.executable(), 0o755);
        self.write(
            "var/lib/sbxr/installed.json",
            &a.record().encode().unwrap(),
            0o600,
        );
        self.write(
            "var/lib/sbxr/proxy-ownership.json",
            &r.encode().unwrap(),
            0o600,
        );
        fs::set_permissions(
            self.0.join("var/lib/sbxr"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        self.write("etc/sing-box/config.json", config, 0o640);
        self.write(
            "etc/group",
            format!(
                "root:x:0:\nsing-box:x:{}:\n",
                fs::metadata(&self.0).unwrap().gid()
            )
            .as_bytes(),
            0o644,
        );
        fs::create_dir_all(self.0.join("run/lock")).unwrap();
        drop(HostLock::provision(&self.0, self.uid()).unwrap());
        r
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct EntropyCounter(u8);
impl Entropy for EntropyCounter {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crate::identity_generation::IdentityError> {
        for b in bytes {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}
struct Active {
    stop: Cancellation,
    join: JoinHandle<Code>,
    address: SocketAddr,
}
struct Peers {
    uid: u32,
    hash: String,
}
impl PeerObservations for Peers {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        ProcessIdentity::new(100, 1, 1, self.uid, &self.hash, "/owner.scope")
    }
    fn peer(&self, _: &UnixStream) -> Result<ProcessIdentity, runtime_handoff::Error> {
        ProcessIdentity::new(
            123,
            100,
            2,
            self.uid,
            &self.hash,
            runtime_handoff::SUBSCRIPTION_CGROUP,
        )
    }
}
struct Environment {
    uid: u32,
    ready: Mutex<Option<std::sync::mpsc::SyncSender<SocketAddr>>>,
}
impl ServingEnvironment for Environment {
    fn process(&self) -> Result<SandboxProcess, runtime_handoff::Error> {
        Ok(SandboxProcess {
            pid: 123,
            uid: self.uid,
            cgroup: runtime_handoff::SUBSCRIPTION_CGROUP.into(),
            executable_path: "/usr/local/bin/sbxr".into(),
        })
    }
    fn sandbox(&self) -> Result<ServingSandbox, runtime_handoff::Error> {
        let mut p = self.process()?;
        p.uid = 0;
        Ok(ServingSandbox {
            effective_uid: 0,
            process: p,
            capabilities: [0; 4],
            no_new_privileges: true,
            inaccessible: [PathAccess::PermissionDenied; 5],
            cgroup_procs: b"123\n".to_vec(),
        })
    }
    fn lender_uid(&self, _: &UnixStream) -> Result<u32, runtime_handoff::Error> {
        Ok(self.uid)
    }
    fn public_ipv4(&self, ctx: &StartContext) -> Result<Ipv4Addr, runtime_handoff::Error> {
        ctx.check()?;
        Ok(Ipv4Addr::new(8, 8, 8, 8))
    }
    fn bind_listener(
        &self,
        ip: Ipv4Addr,
        port: u16,
    ) -> Result<TcpListener, runtime_handoff::Error> {
        let listener =
            TcpListener::bind((ip, port)).map_err(|_| runtime_handoff::Error::Refused)?;
        if let Some(sender) = self.ready.lock().unwrap().take() {
            sender
                .send(listener.local_addr().unwrap())
                .map_err(|_| runtime_handoff::Error::Refused)?;
        }
        Ok(listener)
    }
}
struct Launch {
    root: PathBuf,
    archive: Arc<AuthenticatedArchive>,
    socket: PathBuf,
    advance_rate_clock: bool,
    active: Mutex<Option<Active>>,
}
impl ServiceCommands for Launch {
    fn execute(
        &self,
        action: ServiceAction,
        ctx: &StartContext,
    ) -> Result<(), runtime_handoff::Error> {
        assert_eq!(action, ServiceAction::EnableSubscription);
        ctx.check()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let root = self.root.clone();
        let a = self.archive.clone();
        let socket = self.socket.clone();
        let advance_rate_clock = self.advance_rate_clock;
        let stop = Cancellation::new();
        let childstop = stop.clone();
        let join = thread::spawn(move || {
            let uid = fs::metadata(&root).unwrap().uid();
            let host = ServingRuntimeHost::injected(
                &root,
                &a,
                Environment {
                    uid,
                    ready: Mutex::new(Some(tx)),
                },
                socket,
            )
            .unwrap();
            let ctx = StartContext::new(childstop, Instant::now() + Duration::from_secs(2));
            let ticks = AtomicUsize::new(0);
            let origin = Instant::now();
            let module = if advance_rate_clock {
                Module::with_clock(move || {
                    origin + Duration::from_secs(60 * ticks.fetch_add(1, Ordering::Relaxed) as u64)
                })
            } else {
                Module::new()
            };
            runtime_handoff::serve_subscription_loopback_fixture(&host, &module, &ctx)
        });
        let address = match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(a) => a,
            Err(_) => {
                stop.cancel();
                let _ = join.join();
                return Err(runtime_handoff::Error::Refused);
            }
        };
        *self.active.lock().unwrap() = Some(Active {
            stop,
            join,
            address,
        });
        Ok(())
    }
}
struct Backend {
    root: PathBuf,
    archive: Arc<AuthenticatedArchive>,
    proof: Arc<AuthenticatedInstalled>,
    active: Option<Active>,
    rules: String,
    proxy: bool,
    ip: String,
    trace: Vec<SystemEffect>,
    quiescence_blocked: bool,
    probe_blocked: bool,
    advance_rate_clock: bool,
    cancel_on_reload: Option<Cancellation>,
}
impl Backend {
    fn new(
        root: &Root,
        archive: Arc<AuthenticatedArchive>,
        proof: Arc<AuthenticatedInstalled>,
    ) -> Self {
        Self {
            root: root.0.clone(),
            archive,
            proof,
            active: None,
            rules: "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
                .into(),
            proxy: true,
            ip: "8.8.8.8".into(),
            trace: Vec::new(),
            quiescence_blocked: false,
            probe_blocked: false,
            advance_rate_clock: false,
            cancel_on_reload: None,
        }
    }
    fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            active.stop.cancel();
            assert_eq!(active.join.join().unwrap(), Code::Stopped);
            assert!(TcpListener::bind(active.address).is_ok());
        }
    }
    fn request(&self, token: &str) -> Vec<u8> {
        let mut socket = TcpStream::connect(self.active.as_ref().unwrap().address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket
            .write_all(format!("GET /s/{token} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .unwrap();
        let mut b = Vec::new();
        socket.read_to_end(&mut b).unwrap();
        b
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}
impl HttpRuntime for Backend {
    fn facts(&self) -> Result<RuntimeFacts, HostError> {
        Ok(RuntimeFacts {
            public_ipv4: self.ip.clone(),
            proxy_running: self.proxy,
            firewall_rules: self.rules.clone(),
            serving_running: self.active.is_some(),
            quiescent: self.active.is_none() && !self.quiescence_blocked,
        })
    }
    fn effect(
        &mut self,
        effect: SystemEffect,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        owner.verify()?;
        self.trace.push(effect);
        if effect == SystemEffect::Reload
            && let Some(stop) = self.cancel_on_reload.take()
        {
            stop.cancel();
            ctx.check().map_err(|_| HostError::Cancelled)?;
        }
        match effect {
            SystemEffect::Reload => {}
            SystemEffect::EnableFirewall => {
                let rule = format!(
                    "-A INPUT -d {}/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n",
                    record.public_ipv4()
                );
                self.rules = self.rules.replace("COMMIT\n", &(rule + "COMMIT\n"));
            }
            SystemEffect::DisableFirewall => {
                self.rules = self
                    .rules
                    .lines()
                    .filter(|l| !l.contains("--comment sbxr-subscription"))
                    .map(|l| format!("{l}\n"))
                    .collect()
            }
            SystemEffect::StopServing | SystemEffect::DisableServing => self.stop(),
            SystemEffect::ActivateServing => {
                let authority = runtime_handoff::select_http_authority(record, true)
                    .map_err(|_| HostError::Foreign)?;
                let token = fs::read_to_string(self.root.join(TOKEN)).unwrap();
                let credential = SubscriptionCredential::parse(token.trim_end()).unwrap();
                if self.active.is_some() && self.probe(record, &authority, &credential, ctx).is_ok()
                {
                    return Ok(());
                }
                self.stop();
                let socket = self.root.join(format!("start-{}.sock", self.trace.len()));
                let commands = Launch {
                    root: self.root.clone(),
                    archive: self.archive.clone(),
                    socket: socket.clone(),
                    advance_rate_clock: self.advance_rate_clock,
                    active: Mutex::new(None),
                };
                let peers = Peers {
                    uid: fs::metadata(&self.root).unwrap().uid(),
                    hash: self.proof.record().executable_sha256().into(),
                };
                let controller = ServiceController::injected(
                    &self.root,
                    &self.proof,
                    owner.clone(),
                    peers,
                    commands,
                    socket,
                )
                .map_err(|_| HostError::Foreign)?;
                controller
                    .enable_subscription(ctx)
                    .map_err(|_| HostError::Foreign)?;
                self.active = controller
                    .into_fixture_commands()
                    .active
                    .into_inner()
                    .unwrap();
            }
        }
        owner.verify()
    }
    fn probe(
        &self,
        _: &OwnershipRecord,
        _: &crate::records::ServingAuthority,
        credential: &SubscriptionCredential,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        ctx.check().map_err(|_| HostError::Cancelled)?;
        if self.active.is_none() || self.probe_blocked {
            return Err(HostError::Foreign);
        }
        let bytes = self.request(credential.as_str());
        let configuration = fs::read(self.root.join("etc/sing-box/config.json")).unwrap();
        let artifact =
            crate::server_configuration::ServerConfiguration::decode_supported(&configuration)
                .unwrap()
                .connection_facts("127.0.0.1")
                .unwrap()
                .subscription_artifact()
                .unwrap();
        if !bytes.starts_with(b"HTTP/1.1 200 OK\r\n") || !bytes.ends_with(artifact.as_bytes()) {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
fn module<'a>(
    root: &Root,
    proof: &'a AuthenticatedInstalled,
    archive: Arc<AuthenticatedArchive>,
) -> HttpInstallation<ProtectedHttpHost<'a, Backend>> {
    let proof_arc = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let backend = Backend::new(root, archive, proof_arc);
    let host = ProtectedHttpHost::injected(&root.0, proof, backend).unwrap();
    HttpInstallation::with_entropy(
        host,
        proof.record().release_identity(),
        Box::new(EntropyCounter(0)),
    )
    .unwrap()
}
fn execute<H: SubscriptionHost>(
    m: &mut HttpInstallation<H>,
    action: Action,
) -> crate::domain::Result {
    let review = m.review(action);
    assert!(review.prepared.is_some(), "{action}: {:?}", review.refusal);
    m.execute(review.prepared.unwrap(), Confirmation::Approved)
}
#[test]
fn enable_rotate_and_runtime_repair_are_real_owner_and_serving_journeys() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let initial = root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let config = fs::read(root.0.join("etc/sing-box/config.json")).unwrap();
    let mut m = module(&root, &proof, archive);
    assert_eq!(m.subscription_status(), "Not enabled");
    assert_eq!(
        execute(&mut m, Action::EnableSubscription).outcome,
        Outcome::SubscriptionEnabled
    );
    let old = m.take_subscription_link().unwrap();
    assert!(m.take_subscription_link().is_none());
    assert_eq!(m.subscription_status(), "Available");
    let rotated = execute(&mut m, Action::RotateSubscriptionLink);
    assert_eq!(
        rotated.outcome,
        Outcome::SubscriptionLinkRotated,
        "pending={:?}; effects={:?}",
        OwnershipRecord::decode(
            &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
        )
        .unwrap()
        .http_operation(),
        m.host().backend().trace
    );
    let new = m.take_subscription_link().unwrap();
    assert_ne!(old.as_str(), new.as_str());
    let old_token = old.as_str().split("/s/").nth(1).unwrap();
    assert!(
        m.host()
            .backend()
            .request(old_token)
            .starts_with(b"HTTP/1.1 404")
    );
    m.host_mut().backend_mut().stop();
    assert_eq!(m.subscription_status(), "Problem detected");
    assert_eq!(
        execute(&mut m, Action::RepairSubscription).outcome,
        Outcome::SubscriptionRepaired
    );
    assert_eq!(m.subscription_status(), "Available");
    let r = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(r.pending_change().is_none());
    assert_eq!(r.configuration_sha256(), initial.configuration_sha256());
    assert_eq!(
        fs::read(root.0.join("etc/sing-box/config.json")).unwrap(),
        config
    );
    assert!(m.host().backend().rules.contains("--dport 22"));
}

#[test]
fn every_enablement_effect_interruption_reopens_for_cleanup_without_disclosing() {
    for checkpoint in HTTP_ENABLEMENT_CHECKPOINTS.iter().copied().skip(1) {
        for after in [false, true] {
            let root = Root::new();
            let archive = Arc::new(crate::release_acquisition::fixture_archive());
            root.setup(&archive);
            let proof = archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap();
            let mut m = module(&root, &proof, archive);
            let effect = HttpEffect::Enable(checkpoint);
            m.host_mut().inject_fault(Some(if after {
                HttpFault::After(effect)
            } else {
                HttpFault::Before(effect)
            }));
            assert_eq!(
                execute(&mut m, Action::EnableSubscription).outcome,
                Outcome::SubscriptionChangeIncomplete,
                "checkpoint {checkpoint} after={after}"
            );
            assert!(m.take_subscription_link().is_none());
            assert_eq!(m.subscription_status(), "Change incomplete");
            let mut host = m.into_host();
            host.inject_fault(None);
            let mut reopened = HttpInstallation::with_entropy(
                host,
                proof.record().release_identity(),
                Box::new(EntropyCounter(90)),
            )
            .unwrap();
            assert_eq!(
                execute(&mut reopened, Action::FinishSubscriptionChange).outcome,
                Outcome::SubscriptionChangeCleanedUp,
                "checkpoint {checkpoint} after={after}"
            );
            assert_eq!(reopened.subscription_status(), "Not enabled");
            for path in [
                TOKEN,
                STATE,
                STAGING,
                UNIT,
                LINK,
                "etc/systemd/system/sbxr-subscription-firewall.service",
            ] {
                assert!(!root.0.join(path).exists(), "{path}");
            }
            assert!(reopened.host().backend().rules.contains("--dport 22"));
        }
    }
}
#[test]
fn interrupted_link_rotation_reopens_without_regeneration_or_source_resurrection() {
    for effect in [
        HttpEffect::PrepareRotation,
        HttpEffect::StopSource,
        HttpEffect::PublishTarget,
        HttpEffect::Activate,
        HttpEffect::Verify,
    ] {
        for after in [false, true] {
            let root = Root::new();
            let archive = Arc::new(crate::release_acquisition::fixture_archive());
            root.setup(&archive);
            let proof = archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap();
            let mut m = module(&root, &proof, archive);
            m.host_mut().backend_mut().advance_rate_clock = true;
            assert_eq!(
                execute(&mut m, Action::EnableSubscription).outcome,
                Outcome::SubscriptionEnabled
            );
            let old = m.take_subscription_link().unwrap();
            let source = fs::read(root.0.join(TOKEN)).unwrap();
            m.host_mut().inject_fault(Some(if after {
                HttpFault::After(effect)
            } else {
                HttpFault::Before(effect)
            }));
            assert_eq!(
                execute(&mut m, Action::RotateSubscriptionLink).outcome,
                Outcome::SubscriptionChangeIncomplete,
                "{effect:?} after={after}"
            );
            assert!(m.take_subscription_link().is_none());
            let record = OwnershipRecord::decode(
                &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            )
            .unwrap();
            let forward = matches!(
                record.http_operation().unwrap(),
                Some(HttpOperation::Rotation {
                    direction: ChangeDirection::Forward,
                    ..
                })
            );
            let mut host = m.into_host();
            host.inject_fault(None);
            let mut reopened = HttpInstallation::with_entropy(
                host,
                proof.record().release_identity(),
                Box::new(FailingEntropy),
            )
            .unwrap();
            let expected = if forward {
                Outcome::SubscriptionLinkRotated
            } else {
                Outcome::SubscriptionChangeCleanedUp
            };
            assert_eq!(
                execute(&mut reopened, Action::FinishSubscriptionChange).outcome,
                expected,
                "{effect:?} after={after}"
            );
            let current = fs::read(root.0.join(TOKEN)).unwrap();
            assert_eq!(current == source, !forward);
            if forward {
                let old_token = old.as_str().split("/s/").nth(1).unwrap();
                assert!(
                    reopened
                        .host()
                        .backend()
                        .request(old_token)
                        .starts_with(b"HTTP/1.1 404")
                );
            }
            assert!(root.0.join(STAGING).read_dir().unwrap().next().is_none());
        }
    }
}
struct FailingEntropy;
impl Entropy for FailingEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::identity_generation::IdentityError> {
        Err(crate::identity_generation::IdentityError::EntropyUnavailable)
    }
}
#[test]
fn entropy_decline_stale_review_and_changed_host_never_start_an_operation() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let before = root.setup(&archive).encode().unwrap();
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = module(&root, &proof, archive);
    let token = m.review(Action::EnableSubscription).prepared.unwrap();
    m.review(Action::ViewDetails);
    assert_eq!(
        m.execute(token, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let token = m.review(Action::EnableSubscription).prepared.unwrap();
    assert_eq!(
        m.execute(token, Confirmation::Declined).outcome,
        Outcome::Cancelled
    );
    let token = m.review(Action::EnableSubscription).prepared.unwrap();
    m.host.backend_mut().ip = "9.9.9.9".into();
    assert_eq!(
        m.execute(token, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    m.host.backend_mut().ip = "8.8.8.8".into();
    m.entropy = Box::new(FailingEntropy);
    assert_eq!(
        execute(&mut m, Action::EnableSubscription).outcome,
        Outcome::Refused
    );
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        before
    );
    assert!(m.host().backend().trace.is_empty());
    assert!(m.take_subscription_link().is_none());
}
#[test]
fn unknown_stage_hardlink_and_foreign_material_are_preserved() {
    for fault in [
        "staged-record",
        "foreign",
        "foreign-unit",
        "hardlink",
        "group",
    ] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        let record = root.setup(&archive);
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let m = module(&root, &proof, archive);
        match fault {
            "staged-record" => root.write(
                "var/lib/sbxr/.proxy-ownership.json.next",
                &record.encode().unwrap(),
                0o600,
            ),
            "foreign" => root.write("var/lib/sbxr/foreign", b"preserve", 0o600),
            "foreign-unit" => root.write(UNIT, b"preserve", 0o644),
            "hardlink" => {
                root.write(TOKEN, b"preserve", 0o600);
                fs::hard_link(root.0.join(TOKEN), root.0.join("foreign-link")).unwrap();
            }
            _ => root.write("etc/group", b"sing-box:x:999999:\n", 0o644),
        }
        assert!(
            m.review(Action::EnableSubscription).prepared.is_none(),
            "{fault}"
        );
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            record.encode().unwrap()
        );
        assert!(m.host().backend().trace.is_empty());
    }
}
#[test]
fn quiescence_failure_cannot_commit_rotation_and_cleanup_keeps_source() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = module(&root, &proof, archive);
    m.host_mut().backend_mut().advance_rate_clock = true;
    assert_eq!(
        execute(&mut m, Action::EnableSubscription).outcome,
        Outcome::SubscriptionEnabled
    );
    let before = fs::read(root.0.join(TOKEN)).unwrap();
    m.host_mut().backend_mut().quiescence_blocked = true;
    assert_eq!(
        execute(&mut m, Action::RotateSubscriptionLink).outcome,
        Outcome::SubscriptionChangeIncomplete
    );
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        record.http_operation().unwrap(),
        Some(HttpOperation::Rotation {
            direction: ChangeDirection::Cleanup,
            ..
        })
    ));
    m.host_mut().backend_mut().quiescence_blocked = false;
    assert_eq!(
        execute(&mut m, Action::FinishSubscriptionChange).outcome,
        Outcome::SubscriptionChangeCleanedUp
    );
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), before);
}

#[test]
fn interrupted_runtime_repair_is_forward_only_and_never_changes_credential() {
    for effect in [
        HttpEffect::Activate,
        HttpEffect::Verify,
        HttpEffect::FinishRepairState,
    ] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        root.setup(&archive);
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let mut m = module(&root, &proof, archive);
        m.host_mut().backend_mut().advance_rate_clock = true;
        assert_eq!(
            execute(&mut m, Action::EnableSubscription).outcome,
            Outcome::SubscriptionEnabled
        );
        let before = fs::read(root.0.join(TOKEN)).unwrap();
        m.host_mut().backend_mut().stop();
        m.host_mut().inject_fault(Some(HttpFault::After(effect)));
        assert_eq!(
            execute(&mut m, Action::RepairSubscription).outcome,
            Outcome::SubscriptionChangeIncomplete
        );
        let mut host = m.into_host();
        host.inject_fault(None);
        let mut reopened = HttpInstallation::with_entropy(
            host,
            proof.record().release_identity(),
            Box::new(FailingEntropy),
        )
        .unwrap();
        assert_eq!(
            execute(&mut reopened, Action::FinishSubscriptionChange).outcome,
            Outcome::SubscriptionChangeFinished
        );
        assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), before);
        assert_eq!(reopened.subscription_status(), "Available");
    }
}
#[test]
fn terminal_enablement_is_default_no_and_discloses_only_after_apply() {
    for approve in [false, true] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        root.setup(&archive);
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let mut m = module(&root, &proof, archive);
        let input = if approve {
            b"2\ny\n0\n".as_slice()
        } else {
            b"2\n\n0\n".as_slice()
        };
        let mut output = Vec::new();
        crate::terminal::run(&mut std::io::Cursor::new(input), &mut output, &mut m).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("HTTP exposes"));
        assert_eq!(
            text.contains("Subscription Link (sensitive): http://8.8.8.8:8443/s/"),
            approve
        );
        assert_eq!(root.0.join(TOKEN).exists(), approve);
    }
}
#[test]
fn canonical_staged_two_link_publication_recovers_but_foreign_alias_refuses() {
    for foreign in [false, true] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        root.setup(&archive);
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let mut m = module(&root, &proof, archive);
        m.host_mut()
            .inject_fault(Some(HttpFault::After(HttpEffect::Enable(11))));
        assert_eq!(
            execute(&mut m, Action::EnableSubscription).outcome,
            Outcome::SubscriptionChangeIncomplete
        );
        let stage = root.0.join(format!("{TOKEN}.sbxr-next"));
        fs::hard_link(
            root.0.join(TOKEN),
            if foreign {
                root.0.join("foreign-link")
            } else {
                stage.clone()
            },
        )
        .unwrap();
        let token = fs::read(root.0.join(TOKEN)).unwrap();
        m.host_mut().inject_fault(None);
        if foreign {
            assert!(
                m.review(Action::FinishSubscriptionChange)
                    .prepared
                    .is_none()
            );
            assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), token);
            assert!(root.0.join("foreign-link").exists());
        } else {
            assert_eq!(
                execute(&mut m, Action::FinishSubscriptionChange).outcome,
                Outcome::SubscriptionChangeCleanedUp
            );
            assert!(!stage.exists());
            assert!(!root.0.join(TOKEN).exists());
        }
    }
}

const CONDITION: &str = "{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }";
impl crate::host::process::CommandRunner for Backend {
    fn query(
        &self,
        query: crate::host::process::Query,
        stop: &crate::host::process::Cancellation,
    ) -> Result<crate::host::process::CommandOutput, HostError> {
        assert_eq!(query, crate::host::process::Query::ProxyStartCondition);
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let dropin = fs::read(self.root.join(crate::host::identity::STARTUP))
            .map_err(|_| HostError::Foreign)?;
        if dropin != crate::client_identity::STARTUP_DROP_IN.as_bytes() {
            return Err(HostError::Foreign);
        }
        crate::host::process::CommandOutput::completed(0, CONDITION.as_bytes().to_vec())
    }
}
impl PeerObservations for Backend {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        ProcessIdentity::new(
            100,
            1,
            1,
            fs::metadata(&self.root).unwrap().uid(),
            self.proof.record().executable_sha256(),
            "/owner.scope",
        )
    }
    fn peer(&self, _: &UnixStream) -> Result<ProcessIdentity, runtime_handoff::Error> {
        Err(runtime_handoff::Error::Refused)
    }
}
struct ProxyPeers {
    current: ProcessIdentity,
    other: ProcessIdentity,
}
impl PeerObservations for ProxyPeers {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        Ok(self.current.clone())
    }
    fn peer(&self, _: &UnixStream) -> Result<ProcessIdentity, runtime_handoff::Error> {
        Ok(self.other.clone())
    }
}
struct ProxyLaunch {
    root: PathBuf,
    proof: Arc<AuthenticatedInstalled>,
    socket: PathBuf,
}
impl ServiceCommands for ProxyLaunch {
    fn execute(
        &self,
        action: ServiceAction,
        ctx: &StartContext,
    ) -> Result<(), runtime_handoff::Error> {
        assert_eq!(action, ServiceAction::StartProxy);
        let uid = fs::metadata(&self.root).unwrap().uid();
        let hash = self.proof.record().executable_sha256();
        let host = crate::host::runtime::ProxyRuntimeHost::injected(
            &self.root,
            &self.proof,
            ProxyPeers {
                current: ProcessIdentity::new(
                    124,
                    100,
                    3,
                    uid,
                    hash,
                    runtime_handoff::PROXY_CGROUP,
                )?,
                other: ProcessIdentity::new(100, 1, 1, uid, hash, "/owner.scope")?,
            },
            ConditionRunner,
            self.socket.clone(),
        )
        .map_err(|_| runtime_handoff::Error::Refused)?;
        runtime_handoff::authorize_proxy_start(&host, ctx)
    }
}
struct ConditionRunner;
impl crate::host::process::CommandRunner for ConditionRunner {
    fn query(
        &self,
        q: crate::host::process::Query,
        _: &crate::host::process::Cancellation,
    ) -> Result<crate::host::process::CommandOutput, HostError> {
        assert_eq!(q, crate::host::process::Query::ProxyStartCondition);
        crate::host::process::CommandOutput::completed(0, CONDITION.as_bytes().to_vec())
    }
}
impl crate::host::identity::IdentityRuntime for Backend {
    fn reload_identity(
        &mut self,
        owner: &Arc<HostLock>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        owner.verify()?;
        ctx.check().map_err(|_| HostError::Cancelled)
    }
    fn admit_identity(&self, record: &OwnershipRecord) -> Result<(), HostError> {
        if !self.proxy || self.ip != record.public_ipv4() {
            return Err(HostError::Foreign);
        }
        if let Some(serving) = record.serving_authority() {
            let token =
                fs::read_to_string(self.root.join(TOKEN)).map_err(|_| HostError::Foreign)?;
            let credential =
                SubscriptionCredential::parse(token.trim_end()).map_err(|_| HostError::Foreign)?;
            if sha256_hex(credential.as_str().as_bytes()) != serving.credential_sha256() {
                return Err(HostError::Foreign);
            }
        }
        Ok(())
    }
    fn subscription_route(&self, _: &OwnershipRecord) -> Result<bool, HostError> {
        Ok(
            fs::read(self.root.join(UNIT)).map_err(|_| HostError::Foreign)?
                == runtime_handoff::SERVING_UNIT.as_bytes(),
        )
    }
    fn identity_quiescence(
        &self,
        _: &OwnershipRecord,
    ) -> Result<crate::client_identity::Quiescence, HostError> {
        Ok(crate::client_identity::Quiescence {
            inactive: !self.proxy,
            main_pid_zero: !self.proxy,
            processes_absent: !self.proxy,
            listener_absent: !self.proxy,
            descendants_empty: !self.quiescence_blocked,
            subscription_requests_drained: self.active.is_none(),
            subscription_descendants_empty: self.active.is_none(),
            subscription_listener_absent: self.active.is_none(),
            subscription_inactive: self.active.is_none(),
        })
    }
    fn stop_identity_source(
        &mut self,
        _: &OwnershipRecord,
        owner: &Arc<HostLock>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        owner.verify()?;
        ctx.check().map_err(|_| HostError::Cancelled)?;
        self.stop();
        self.proxy = false;
        Ok(())
    }
    fn start_identity_proxy(
        &mut self,
        _: &OwnershipRecord,
        owner: &Arc<HostLock>,
        gate: Option<&crate::host::runtime::CutoverGate>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        let socket = self.root.join(format!(
            "proxy-{}.sock",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let uid = fs::metadata(&self.root).unwrap().uid();
        let hash = self.proof.record().executable_sha256();
        let peers = ProxyPeers {
            current: ProcessIdentity::new(100, 1, 1, uid, hash, "/owner.scope").unwrap(),
            other: ProcessIdentity::new(124, 100, 3, uid, hash, runtime_handoff::PROXY_CGROUP)
                .unwrap(),
        };
        let commands = ProxyLaunch {
            root: self.root.clone(),
            proof: self.proof.clone(),
            socket: socket.clone(),
        };
        let controller = ServiceController::injected(
            &self.root,
            &self.proof,
            owner.clone(),
            peers,
            commands,
            socket,
        )
        .map_err(|_| HostError::Foreign)?;
        if let Some(gate) = gate {
            controller.start_proxy_cutover(gate, false, ctx)
        } else {
            controller.start_proxy(false, ctx)
        }
        .map_err(|_| HostError::Foreign)?;
        self.proxy = true;
        Ok(())
    }
    fn finish_identity_subscription(
        &mut self,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        HttpRuntime::effect(self, SystemEffect::ActivateServing, record, owner, ctx)?;
        let token = fs::read_to_string(self.root.join(TOKEN)).map_err(|_| HostError::Foreign)?;
        let credential =
            SubscriptionCredential::parse(token.trim_end()).map_err(|_| HostError::Foreign)?;
        self.probe(
            record,
            &record.serving_authority().ok_or(HostError::Foreign)?,
            &credential,
            ctx,
        )
    }
    fn verify_identity_running(&self, _: &OwnershipRecord) -> Result<(), HostError> {
        if self.proxy {
            Ok(())
        } else {
            Err(HostError::Foreign)
        }
    }
}
fn identity_module<'a>(
    root: &Root,
    proof: &'a AuthenticatedInstalled,
    archive: Arc<AuthenticatedArchive>,
) -> ClientIdentityInstallation<crate::host::identity::ProtectedIdentityHost<'a, Backend>> {
    let mut http = module(root, proof, archive);
    http.host_mut().backend_mut().advance_rate_clock = true;
    assert_eq!(
        execute(&mut http, Action::EnableSubscription).outcome,
        Outcome::SubscriptionEnabled
    );
    let backend = http.into_host().into_backend();
    let host =
        crate::host::identity::ProtectedIdentityHost::injected(&root.0, proof, backend).unwrap();
    ClientIdentityInstallation::with_entropy(host, Box::new(EntropyCounter(70)))
}
fn execute_identity<H: crate::client_identity::Host>(
    m: &mut ClientIdentityInstallation<H>,
    action: Action,
) -> crate::domain::Result {
    let r = m.review(action);
    assert!(r.prepared.is_some(), "{:?}", r.refusal);
    m.execute(r.prepared.unwrap(), Confirmation::Approved)
}
#[test]
fn http_owner_rotation_uses_concrete_identity_files_cutover_and_refreshed_response() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = identity_module(&root, &proof, archive);
    let before: serde_json::Value =
        serde_json::from_slice(&fs::read(root.0.join(crate::host::identity::CONFIG)).unwrap())
            .unwrap();
    let token = fs::read(root.0.join(TOKEN)).unwrap();
    let state = fs::read(root.0.join(STATE)).unwrap();
    let result = execute_identity(&mut m, Action::RotateClientIdentity);
    assert_eq!(
        result.outcome,
        Outcome::ClientIdentityRotated,
        "{:?}",
        crate::client_identity::rotation(
            &OwnershipRecord::decode(
                &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
            )
            .unwrap()
        )
    );
    let mut after: serde_json::Value =
        serde_json::from_slice(&fs::read(root.0.join(crate::host::identity::CONFIG)).unwrap())
            .unwrap();
    assert_ne!(
        before["inbounds"][0]["users"][0]["uuid"],
        after["inbounds"][0]["users"][0]["uuid"]
    );
    after["inbounds"][0]["users"][0]["uuid"] = before["inbounds"][0]["users"][0]["uuid"].clone();
    assert_eq!(before, after);
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), token);
    assert_eq!(fs::read(root.0.join(STATE)).unwrap(), state);
    assert!(root.0.join(crate::host::identity::STARTUP).is_file());
    assert!(!root.0.join(crate::host::identity::TARGET).exists());
    assert!(!root.0.join("run/sbxr-client-identity-start").exists());
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(record.pending_change().is_none());
    let token = std::str::from_utf8(&token).unwrap().trim_end();
    assert!(
        m.host_mut()
            .backend()
            .request(token)
            .starts_with(b"HTTP/1.1 200 OK")
    );
}
#[test]
fn concrete_identity_interruption_recovery_never_restores_revoked_configuration() {
    use crate::{client_identity as ci, host::identity::IdentityFault};
    for effect in [
        ci::Effect::PrepareTarget,
        ci::Effect::PublishStartup,
        ci::Effect::Reload,
        ci::Effect::StopSource,
        ci::Effect::PublishTarget,
        ci::Effect::StartTarget,
        ci::Effect::FinishSubscription,
        ci::Effect::RemoveTarget,
    ] {
        for after in [false, true] {
            let root = Root::new();
            let archive = Arc::new(crate::release_acquisition::fixture_archive());
            let initial = root.setup(&archive);
            let proof = archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap();
            let mut m = identity_module(&root, &proof, archive);
            m.host_mut().inject_fault(Some(if after {
                IdentityFault::After(effect)
            } else {
                IdentityFault::Before(effect)
            }));
            assert_eq!(
                execute_identity(&mut m, Action::RotateClientIdentity).outcome,
                Outcome::ClientIdentityRotationIncomplete,
                "{effect:?}/{after}"
            );
            let pending = OwnershipRecord::decode(
                &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            )
            .unwrap();
            let forward = ci::rotation(&pending).unwrap().checkpoint.direction()
                == crate::records::ChangeDirection::Forward;
            let mut host = m.into_host();
            host.inject_fault(None);
            let mut reopened =
                ClientIdentityInstallation::with_entropy(host, Box::new(FailingEntropy));
            assert_eq!(
                execute_identity(&mut reopened, Action::FinishClientIdentityRotation).outcome,
                if forward {
                    Outcome::ClientIdentityRotationFinished
                } else {
                    Outcome::ClientIdentityRotationCleanedUp
                },
                "{effect:?}/{after}"
            );
            let done = OwnershipRecord::decode(
                &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                done.configuration_sha256() == initial.configuration_sha256(),
                !forward,
                "{effect:?}/{after}"
            );
            assert!(done.pending_change().is_none());
        }
    }
}
#[test]
fn concrete_identity_decline_stale_and_remaining_descendants_preserve_source() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let initial = root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = identity_module(&root, &proof, archive);
    let r = m.review(Action::RotateClientIdentity);
    assert!(r.prepared.is_some());
    assert_eq!(
        m.execute(r.prepared.unwrap(), Confirmation::Declined)
            .outcome,
        Outcome::Cancelled
    );
    let r = m.review(Action::RotateClientIdentity);
    m.review(Action::Status);
    assert_eq!(
        m.execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::Refused
    );
    m.host_mut().backend_mut().quiescence_blocked = true;
    assert_eq!(
        execute_identity(&mut m, Action::RotateClientIdentity).outcome,
        Outcome::ClientIdentityRotationIncomplete
    );
    let pending = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crate::client_identity::rotation(&pending)
            .unwrap()
            .checkpoint,
        crate::client_identity::Checkpoint::Stopped
    );
    assert_eq!(
        sha256_hex(&fs::read(root.0.join(crate::host::identity::CONFIG)).unwrap()),
        initial.configuration_sha256()
    );
}
#[test]
fn http_owner_material_bytes_match_preserved_go_renderers() {
    assert_eq!(
        crate::host::subscription::http_firewall_unit("8.8.8.8").unwrap(),
        include_bytes!("../../tests/testdata/http_owner/firewall.service")
    );
    let credential = SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    let authority = crate::records::ServingAuthority::http(&"1".repeat(32), &credential).unwrap();
    assert_eq!(
        authority.state_bytes().unwrap(),
        include_bytes!("../../tests/testdata/http_owner/serving-state.json")
    );
}

#[test]
fn fixed_absolute_enablement_links_are_owned_but_other_links_are_preserved() {
    use crate::host::subscription::{FIREWALL, FIREWALL_LINK};
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = module(&root, &proof, archive);
    m.host_mut().backend_mut().advance_rate_clock = true;
    assert_eq!(
        execute(&mut m, Action::EnableSubscription).outcome,
        Outcome::SubscriptionEnabled
    );
    for (path, target) in [(LINK, UNIT), (FIREWALL_LINK, FIREWALL)] {
        fs::remove_file(root.0.join(path)).unwrap();
        std::os::unix::fs::symlink(format!("/{target}"), root.0.join(path)).unwrap();
    }
    assert_eq!(m.subscription_status(), "Available");
    assert_eq!(
        execute(&mut m, Action::RotateSubscriptionLink).outcome,
        Outcome::SubscriptionLinkRotated
    );
    fs::remove_file(root.0.join(FIREWALL_LINK)).unwrap();
    std::os::unix::fs::symlink(
        "/etc/systemd/system/foreign.service",
        root.0.join(FIREWALL_LINK),
    )
    .unwrap();
    assert!(m.review(Action::RotateSubscriptionLink).prepared.is_none());
    assert_eq!(
        fs::read_link(root.0.join(FIREWALL_LINK))
            .unwrap()
            .to_str()
            .unwrap(),
        "/etc/systemd/system/foreign.service"
    );
}
#[test]
fn concrete_identity_foreign_target_stage_is_preserved_without_source_reversal() {
    use crate::{
        client_identity as ci,
        host::identity::{IdentityFault, TARGET},
    };
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let initial = root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = identity_module(&root, &proof, archive);
    m.host_mut()
        .inject_fault(Some(IdentityFault::Before(ci::Effect::PrepareTarget)));
    assert_eq!(
        execute_identity(&mut m, Action::RotateClientIdentity).outcome,
        Outcome::ClientIdentityRotationIncomplete
    );
    root.write(&format!("{TARGET}.sbxr-next"), b"foreign", 0o600);
    assert!(
        m.review(Action::FinishClientIdentityRotation)
            .prepared
            .is_none()
    );
    assert_eq!(
        fs::read(root.0.join(format!("{TARGET}.sbxr-next"))).unwrap(),
        b"foreign"
    );
    assert_eq!(
        sha256_hex(&fs::read(root.0.join(crate::host::identity::CONFIG)).unwrap()),
        initial.configuration_sha256()
    );
}

#[test]
fn concrete_identity_uncommitted_configuration_candidate_has_no_replacement_authority() {
    use crate::{
        client_identity as ci,
        host::identity::{CONFIG, CONFIG_STAGE, IdentityFault, TARGET},
    };
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let initial = root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = identity_module(&root, &proof, archive);
    m.host_mut()
        .inject_fault(Some(IdentityFault::After(ci::Effect::PrepareTarget)));
    assert_eq!(
        execute_identity(&mut m, Action::RotateClientIdentity).outcome,
        Outcome::ClientIdentityRotationIncomplete
    );
    let target = fs::read(root.0.join(TARGET)).unwrap();
    root.write(CONFIG_STAGE, &target, 0o640);
    assert!(
        m.review(Action::FinishClientIdentityRotation)
            .prepared
            .is_none()
    );
    assert_eq!(fs::read(root.0.join(CONFIG_STAGE)).unwrap(), target);
    assert_eq!(
        sha256_hex(&fs::read(root.0.join(CONFIG)).unwrap()),
        initial.configuration_sha256()
    );
}

// Native runtime logic is exercised through fixed command/process observations.
// Commands are never executed; real files, lending, gates and TCP responses are.
struct OwnerIoFixture {
    service_uid: u32,
    backend: Mutex<Backend>,
    role: AtomicUsize,
    address: SocketAddr,
    bad: AtomicUsize,
}
impl OwnerIoFixture {
    fn new(
        root: &Root,
        a: Arc<AuthenticatedArchive>,
        proof: Arc<AuthenticatedInstalled>,
    ) -> Arc<Self> {
        root.write(
            "usr/bin/sing-box",
            b"inert fixture package executable\n",
            0o755,
        );
        root.write(
            "usr/lib/systemd/system/sing-box.service",
            include_bytes!("../host/owner_runtime/testdata/sing-box.service"),
            0o644,
        );
        fs::create_dir_all(root.0.join("sys/fs/cgroup/system.slice")).unwrap();
        fs::set_permissions(
            root.0.join("sys/fs/cgroup/system.slice"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let io = Arc::new(Self {
            service_uid: if root.uid() == 0 { 2000 } else { root.uid() },
            backend: Mutex::new(Backend::new(root, a, proof)),
            role: AtomicUsize::new(0),
            address,
            bad: AtomicUsize::new(0),
        });
        io.cgroup(crate::host::owner_runtime::Unit::Proxy, true);
        io.cgroup(crate::host::owner_runtime::Unit::Subscription, false);
        io
    }
    fn cgroup(&self, u: crate::host::owner_runtime::Unit, running: bool) {
        let b = self.backend.lock().unwrap();
        let path = b.root.join(format!("sys/fs/cgroup{}", u.cgroup()));
        fs::create_dir_all(&path).unwrap();
        for (name, data) in [
            (
                "cgroup.events",
                if running {
                    b"populated 1\n".as_slice()
                } else {
                    b"populated 0\n".as_slice()
                },
            ),
            (
                "cgroup.procs",
                if !running {
                    b"".as_slice()
                } else if u == crate::host::owner_runtime::Unit::Proxy {
                    b"200\n".as_slice()
                } else {
                    b"123\n".as_slice()
                },
            ),
        ] {
            let p = path.join(name);
            if p.exists() {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            }
            fs::write(&p, data).unwrap();
            fs::set_permissions(
                p,
                fs::Permissions::from_mode(if name == "cgroup.events" {
                    0o444
                } else {
                    0o644
                }),
            )
            .unwrap();
        }
    }
    fn start_http(&self, channel: &std::path::Path, c: &StartContext) -> Result<(), HostError> {
        let (root, proof) = {
            let b = self.backend.lock().unwrap();
            (b.root.clone(), b.proof.clone())
        };
        let uid = fs::metadata(&root).unwrap().uid();
        let hash = proof.record().executable_sha256();
        let owner = ProcessIdentity::new(100, 1, 1, uid, hash, "/owner.scope").unwrap();
        let peers = ProxyPeers {
            current: ProcessIdentity::new(
                123,
                100,
                2,
                uid,
                hash,
                runtime_handoff::SUBSCRIPTION_CGROUP,
            )
            .unwrap(),
            other: owner.clone(),
        };
        let lock = runtime_handoff::acquire_runtime_start(
            &root,
            uid,
            crate::private_roles::Role::SubscriptionServing,
            &peers,
            c,
            || {
                Ok((
                    crate::host::runtime_io::connect_fixture(&root, channel, c)?,
                    owner.clone(),
                ))
            },
        )
        .map_err(|_| HostError::Foreign)?;
        drop(lock);
        let r = OwnershipRecord::decode(
            &fs::read(root.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        )
        .unwrap();
        let config = crate::server_configuration::ServerConfiguration::decode_supported(
            &fs::read(root.join("etc/sing-box/config.json")).unwrap(),
        )
        .unwrap();
        let authority = runtime_handoff::select_http_authority(&r, true).unwrap();
        let token = fs::read_to_string(root.join(TOKEN)).unwrap();
        let credential = SubscriptionCredential::parse(token.trim_end()).unwrap();
        let state = crate::subscription_serving::State::prepare_http_loopback_fixture(
            &root,
            &config.connection_facts(r.public_ipv4()).unwrap(),
            crate::subscription_serving::Generation::new(authority.link_id(), credential.sha256())
                .unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind(self.address).map_err(|_| HostError::Io)?;
        let stop = Cancellation::new();
        let shutdown = stop.clone();
        let join = thread::spawn(move || Module::new().serve(Arc::new(state), listener, &shutdown));
        self.backend.lock().unwrap().active = Some(Active {
            stop,
            join,
            address: self.address,
        });
        self.cgroup(crate::host::owner_runtime::Unit::Subscription, true);
        Ok(())
    }
}
impl PeerObservations for OwnerIoFixture {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.backend.lock().unwrap().current()
    }
    fn peer(&self, _: &UnixStream) -> Result<ProcessIdentity, runtime_handoff::Error> {
        let b = self.backend.lock().unwrap();
        let role = if self.role.load(Ordering::SeqCst) == 1 {
            runtime_handoff::PROXY_CGROUP
        } else {
            runtime_handoff::SUBSCRIPTION_CGROUP
        };
        ProcessIdentity::new(
            if role == runtime_handoff::PROXY_CGROUP {
                124
            } else {
                123
            },
            100,
            if role == runtime_handoff::PROXY_CGROUP {
                3
            } else {
                2
            },
            fs::metadata(&b.root).unwrap().uid(),
            b.proof.record().executable_sha256(),
            role,
        )
    }
}
impl crate::host::owner_runtime::OwnerIo for OwnerIoFixture {
    fn query(
        &self,
        o: crate::host::owner_runtime::Observation,
        c: &StartContext,
    ) -> Result<crate::host::process::CommandOutput, HostError> {
        use crate::host::owner_runtime::{Observation as O, Property as P, Unit as U};
        c.check().map_err(|_| HostError::Cancelled)?;
        let b = self.backend.lock().unwrap();
        let mut code = 0;
        let value = match o {
            O::Listener10000 => String::new(),
            O::Architecture => "amd64".into(),
            O::Enabled => "enabled".into(),
            O::Package => "1.14.3 amd64 hi".into(),
            O::Hold => "sing-box".into(),
            O::UnitOwner => "sing-box: /usr/lib/systemd/system/sing-box.service".into(),
            O::User => format!(
                "sing-box:x:{}:{}::/var/lib/sing-box:/usr/sbin/nologin",
                self.service_uid,
                fs::metadata(&b.root).unwrap().gid()
            ),
            O::Group => format!(
                "sing-box:x:{}:",
                if self.bad.load(Ordering::SeqCst) == 8 {
                    9999
                } else {
                    fs::metadata(&b.root).unwrap().gid()
                }
            ),
            O::Firewall => b.rules.clone(),
            O::ProxyProcesses => {
                if b.proxy {
                    "200".into()
                } else {
                    code = 1;
                    String::new()
                }
            }
            O::Listener443 => {
                if b.proxy {
                    "LISTEN 0 4096 [::]:443 *:* users:((\"sing-box\",pid=200,fd=3))".into()
                } else {
                    String::new()
                }
            }
            O::Listener8443 => {
                if b.active.is_some() {
                    "LISTEN 0 4096 8.8.8.8:8443 *:* users:((\"sbxr\",pid=123,fd=3))".into()
                } else {
                    String::new()
                }
            }
            O::Property(u, p) => match p {
                P::ActiveState => if if u == U::Proxy {
                    b.proxy
                } else if u == U::Subscription {
                    b.active.is_some()
                } else {
                    b.rules.contains("sbxr-subscription")
                } {
                    "active"
                } else {
                    "inactive"
                }
                .into(),
                P::MainPid => if u == U::Proxy && b.proxy {
                    "200"
                } else if u == U::Subscription && b.active.is_some() {
                    "123"
                } else {
                    "0"
                }
                .into(),
                P::ControlPid => "0".into(),
                P::ControlGroup => u.cgroup().into(),
                P::KillMode => if self.bad.load(Ordering::SeqCst) == 1 {
                    "process"
                } else {
                    "control-group"
                }
                .into(),
                P::FragmentPath => if u == U::Proxy {
                    "/usr/lib/systemd/system/sing-box.service"
                } else if u == U::Subscription {
                    "/etc/systemd/system/sbxr-subscription.service"
                } else {
                    "/etc/systemd/system/sbxr-subscription-firewall.service"
                }
                .into(),
                P::DropInPaths => {
                    if u == U::Proxy && b.root.join(crate::host::identity::STARTUP).exists() {
                        format!("/{}", crate::host::identity::STARTUP)
                    } else {
                        String::new()
                    }
                }
                P::LoadState => "loaded".into(),
                P::ExecCondition => CONDITION.into(),
                P::ExecStart | P::ExecStop => {
                    if u == U::Proxy {
                        "{ path=/usr/bin/sing-box ; argv[]=/usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run ; ignore_errors=no }".into()
                    } else if u == U::Subscription {
                        "{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --subscription-serving ; ignore_errors=no }".to_owned()
                    } else {
                        let body =
                            crate::host::subscription::http_firewall_unit("8.8.8.8").unwrap();
                        let body = std::str::from_utf8(&body).unwrap();
                        let command = body
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix(if p == P::ExecStart {
                                    "ExecStart="
                                } else {
                                    "ExecStop="
                                })
                            })
                            .unwrap()
                            .replacen("/bin/sh -ec '", "/bin/sh -ec ", 1);
                        format!(
                            "{{ path=/bin/sh ; argv[]={} ; ignore_errors=no }}",
                            command.trim_end_matches('\'')
                        )
                    }
                }
            },
        };
        crate::host::process::CommandOutput::completed(code, value.into_bytes())
    }
    fn service(
        &self,
        a: ServiceAction,
        owner: &Arc<HostLock>,
        channel: Option<&std::path::Path>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        owner.verify()?;
        c.check().map_err(|_| HostError::Cancelled)?;
        match a {
            ServiceAction::EnableSubscription
            | ServiceAction::StartSubscription
            | ServiceAction::RestartSubscription => {
                self.backend.lock().unwrap().stop();
                self.role.store(0, Ordering::SeqCst);
                self.start_http(channel.ok_or(HostError::Unsafe)?, c)?;
            }
            ServiceAction::StartProxy | ServiceAction::RestartProxy => {
                self.role.store(1, Ordering::SeqCst);
                let b = self.backend.lock().unwrap();
                let launch = ProxyLaunch {
                    root: b.root.clone(),
                    proof: b.proof.clone(),
                    socket: channel.ok_or(HostError::Unsafe)?.into(),
                };
                drop(b);
                launch
                    .execute(ServiceAction::StartProxy, c)
                    .map_err(|_| HostError::Foreign)?;
                self.backend.lock().unwrap().proxy = true;
                self.cgroup(crate::host::owner_runtime::Unit::Proxy, true);
            }
            ServiceAction::StopSubscription | ServiceAction::DisableSubscription => {
                self.backend.lock().unwrap().stop();
                self.cgroup(crate::host::owner_runtime::Unit::Subscription, false);
            }
            ServiceAction::StopProxy => {
                self.backend.lock().unwrap().proxy = false;
                self.cgroup(crate::host::owner_runtime::Unit::Proxy, false);
            }
            ServiceAction::EnableFirewall => {
                let mut b = self.backend.lock().unwrap();
                b.rules=b.rules.replace("COMMIT\n","-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\nCOMMIT\n");
            }
            ServiceAction::DisableFirewall => {
                let mut b = self.backend.lock().unwrap();
                b.rules = b
                    .rules
                    .lines()
                    .filter(|l| !l.contains("sbxr-subscription"))
                    .map(|l| format!("{l}\n"))
                    .collect();
            }
            ServiceAction::Reload => {}
        }
        owner.verify()
    }
    fn validate_configuration(
        &self,
        owner: &Arc<HostLock>,
        expected: &str,
        c: &StartContext,
    ) -> Result<bool, HostError> {
        owner.verify()?;
        c.check().map_err(|_| HostError::Cancelled)?;
        let b = self.backend.lock().unwrap();
        let config = fs::read(b.root.join("etc/sing-box/config.json")).unwrap();
        Ok(sha256_hex(&config) == expected
            && crate::server_configuration::ServerConfiguration::decode_supported(&config).is_ok())
    }
    fn public_ipv4(&self, c: &StartContext) -> Result<Ipv4Addr, HostError> {
        c.check().map_err(|_| HostError::Cancelled)?;
        self.backend
            .lock()
            .unwrap()
            .ip
            .parse()
            .map_err(|_| HostError::Foreign)
    }
    fn port_available(&self, p: u16, _: &StartContext) -> Result<bool, HostError> {
        assert_eq!(p, 8443);
        Ok(TcpListener::bind(self.address).is_ok())
    }
    fn process(&self, p: u32) -> Result<ProcessIdentity, HostError> {
        let b = self.backend.lock().unwrap();
        let mut hash = if p == 200 {
            sha256_hex(&fs::read(b.root.join("usr/bin/sing-box")).unwrap())
        } else {
            b.proof.record().executable_sha256().into()
        };
        let bad = self.bad.load(Ordering::SeqCst);
        if bad == 3 {
            hash = "0".repeat(64);
        }
        ProcessIdentity::new(
            p,
            100,
            if p == 200 { 4 } else { 2 },
            if bad == 2 {
                0
            } else if p == 200 {
                self.service_uid
            } else {
                fs::metadata(&b.root).unwrap().uid()
            },
            &hash,
            if bad == 4 {
                "/foreign.scope"
            } else if p == 200 {
                runtime_handoff::PROXY_CGROUP
            } else {
                runtime_handoff::SUBSCRIPTION_CGROUP
            },
        )
        .map_err(|_| HostError::Foreign)
    }
}
struct ComposedSources<'a> {
    root: &'a Root,
    proof: &'a AuthenticatedInstalled,
    io: Arc<OwnerIoFixture>,
}
impl<'a> OwnerSources<'a> for ComposedSources<'a> {
    fn journeys(&self) -> Result<Vec<Journey>, HostError> {
        let r = OwnershipRecord::decode(
            &fs::read(self.root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        )
        .unwrap();
        Ok(if crate::client_identity::rotation(&r).is_ok() {
            vec![Journey::Identity]
        } else {
            vec![Journey::Http, Journey::Identity]
        })
    }
    fn open(&self, j: Journey) -> Result<Box<dyn Interface + 'a>, HostError> {
        let runtime = crate::host::owner_runtime::OwnerRuntime::injected(
            &self.root.0,
            self.proof,
            self.io.clone(),
            self.io.address,
        )?;
        match j {
            Journey::Http => Ok(Box::new(HttpInstallation::with_entropy(
                ProtectedHttpHost::injected(&self.root.0, self.proof, runtime)?,
                self.proof.record().release_identity(),
                Box::new(crate::identity_generation::OsEntropy),
            )?)),
            Journey::Identity => Ok(Box::new(ClientIdentityInstallation::with_entropy(
                crate::host::identity::ProtectedIdentityHost::injected(
                    &self.root.0,
                    self.proof,
                    runtime,
                )?,
                Box::new(crate::identity_generation::OsEntropy),
            ))),
            _ => Err(HostError::LiveUnavailable),
        }
    }
    fn mode(&self) -> ExecutionMode {
        ExecutionMode::InjectedHost
    }
}
#[test]
fn composed_owner_uses_native_runtime_logic_and_switches_writers_without_stale_authority() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    let mut owner = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    });
    let status = owner.review(Action::Status);
    assert!(status.legal_actions.contains(&Action::EnableSubscription));
    assert!(status.legal_actions.contains(&Action::RotateClientIdentity));
    let stale = owner.review(Action::EnableSubscription).prepared.unwrap();
    owner.review(Action::ViewDetails);
    assert_eq!(
        owner.execute(stale, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let selected = owner.review(Action::EnableSubscription).prepared.unwrap();
    assert_eq!(
        owner.execute(selected, Confirmation::Approved).outcome,
        Outcome::SubscriptionEnabled,
        "{:?}",
        OwnershipRecord::decode(
            &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
        )
        .unwrap()
        .http_operation()
    );
    let link = owner.take_subscription_link().unwrap();
    let token = fs::read(root.0.join(TOKEN)).unwrap();
    let selected = owner.review(Action::RotateClientIdentity).prepared.unwrap();
    assert_eq!(
        owner.execute(selected, Confirmation::Approved).outcome,
        Outcome::ClientIdentityRotated
    );
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), token);
    assert_eq!(owner.subscription_status(), "Available");
    assert!(
        io.backend
            .lock()
            .unwrap()
            .request(link.as_str().split("/s/").nth(1).unwrap())
            .starts_with(b"HTTP/1.1 200")
    );
    let selected = owner
        .review(Action::RotateSubscriptionLink)
        .prepared
        .unwrap();
    assert_eq!(
        owner.execute(selected, Confirmation::Approved).outcome,
        Outcome::SubscriptionLinkRotated
    );
}
#[test]
fn unowned_busy_serving_runtime_never_becomes_enablement_authority() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = module(&root, &proof, archive);
    m.host_mut().backend_mut().quiescence_blocked = true;
    assert!(m.review(Action::EnableSubscription).prepared.is_none());
    assert!(m.host().backend().trace.is_empty());
}

#[test]
fn composed_identity_rotation_repairs_independent_serving_fault_without_changing_link() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    let mut owner = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    });
    let r = owner.review(Action::EnableSubscription);
    assert_eq!(
        owner
            .execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::SubscriptionEnabled
    );
    let credential = fs::read(root.0.join(TOKEN)).unwrap();
    io.backend.lock().unwrap().stop();
    io.cgroup(crate::host::owner_runtime::Unit::Subscription, false);
    let r = owner.review(Action::RotateClientIdentity);
    assert!(r.prepared.is_some());
    assert_eq!(
        owner
            .execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::ClientIdentityRotated
    );
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), credential);
    assert_eq!(owner.subscription_status(), "Available");
}

#[test]
fn native_runtime_rejects_wrong_process_uid_image_and_cgroup_before_owner_effects() {
    for bad in [2, 3, 4] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        let original = root.setup(&archive).encode().unwrap();
        let proof = Arc::new(
            archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap(),
        );
        let io = OwnerIoFixture::new(&root, archive, proof.clone());
        io.bad.store(bad, Ordering::SeqCst);
        let owner = OwnerInstallation::new(ComposedSources {
            root: &root,
            proof: &proof,
            io,
        });
        assert!(
            owner.review(Action::EnableSubscription).prepared.is_none(),
            "bad proof {bad}"
        );
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            original
        );
    }
}
#[test]
fn native_identity_stop_refuses_foreign_kill_mode_without_revoking_source() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let original = root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    let mut owner = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    });
    let r = owner.review(Action::RotateClientIdentity);
    assert!(r.prepared.is_some());
    io.bad.store(1, Ordering::SeqCst);
    assert_eq!(
        owner
            .execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::ClientIdentityRotationIncomplete
    );
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crate::client_identity::rotation(&record)
            .unwrap()
            .checkpoint,
        crate::client_identity::Checkpoint::Gated
    );
    assert_eq!(
        record.configuration_sha256(),
        original.configuration_sha256()
    );
    assert!(io.backend.lock().unwrap().proxy);
}

fn disclosure_surface(root: &Root, io: &OwnerIoFixture) {
    root.write(
        "etc/os-release",
        b"ID=ubuntu\nVERSION_ID=\"24.04\"\n",
        0o644,
    );
    root.write(
        "etc/apt/keyrings/sagernet.asc",
        include_bytes!("../../tests/testdata/package_acquisition/sagernet.asc"),
        0o644,
    );
    root.write("etc/apt/sources.list.d/sagernet.sources",b"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n",0o644);
    root.write(
        "etc/systemd/system/sbxr-mutation-lock.service",
        include_bytes!("../records/lock-provision.service"),
        0o644,
    );
    let link = root
        .0
        .join("etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("../sbxr-mutation-lock.service", link).unwrap();
    let state = root.0.join("var/lib/sing-box");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    if root.uid() != io.service_uid {
        rustix::fs::chown(
            &state,
            Some(rustix::process::Uid::from_raw(io.service_uid)),
            Some(rustix::process::Gid::from_raw(
                fs::metadata(&root.0).unwrap().gid(),
            )),
        )
        .unwrap();
    }
}
struct DisclosureSources<'a>(ComposedSources<'a>);
impl<'a> OwnerSources<'a> for DisclosureSources<'a> {
    fn journeys(&self) -> Result<Vec<Journey>, HostError> {
        let mut j = self.0.journeys()?;
        j.push(Journey::Disclosure);
        Ok(j)
    }
    fn open(&self, j: Journey) -> Result<Box<dyn Interface + 'a>, HostError> {
        if j != Journey::Disclosure {
            return self.0.open(j);
        }
        let host = crate::host::disclosure::ProtectedDisclosureHost::injected(
            &self.0.root.0,
            self.0.proof,
            self.0.io.clone(),
            self.0.io.address,
        )?;
        Ok(Box::new(DisclosureInstallation::new(
            host,
            ExecutionMode::InjectedHost,
        )))
    }
    fn mode(&self) -> ExecutionMode {
        ExecutionMode::InjectedHost
    }
}
struct FailingOutput;
impl Write for FailingOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn protected_disclosure_streams_only_after_confirmation_and_preserves_output_failure() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let original = root.setup(&archive).encode().unwrap();
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    disclosure_surface(&root, &io);
    let mut owner = OwnerInstallation::new(DisclosureSources(ComposedSources {
        root: &root,
        proof: &proof,
        io,
    }));
    let r = owner.review(Action::ShowClientConfiguration);
    assert!(r.prepared.is_some(), "{:?}", r.refusal);
    let mut output = Vec::new();
    assert_eq!(
        owner
            .execute_output(r.prepared.unwrap(), Confirmation::Declined, &mut output)
            .unwrap()
            .outcome,
        Outcome::Cancelled
    );
    assert!(output.is_empty());
    let r = owner.review(Action::ShowClientConfiguration);
    let result = owner
        .execute_output(r.prepared.unwrap(), Confirmation::Approved, &mut output)
        .unwrap();
    assert_eq!(result.outcome, Outcome::ClientConfigurationDisclosed);
    assert!(output.starts_with(b"----- BEGIN SBXR CLIENT CONFIGURATION -----\n"));
    assert!(
        output
            .windows(b"12345678-1234-4234-8234-123456789abc".len())
            .any(|s| s == b"12345678-1234-4234-8234-123456789abc")
    );
    assert!(
        !output
            .windows(b"private_key".len())
            .any(|s| s == b"private_key")
    );
    let r = owner.review(Action::ShowClientConfiguration);
    assert!(
        owner
            .execute_output(
                r.prepared.unwrap(),
                Confirmation::Approved,
                &mut FailingOutput
            )
            .is_err()
    );
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        original
    );
}
#[test]
fn protected_disclosure_marks_compromise_and_rediscloses_only_canonical_agreed_link() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    disclosure_surface(&root, &io);
    let mut owner = OwnerInstallation::new(DisclosureSources(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    }));
    let r = owner.review(Action::EnableSubscription);
    assert_eq!(
        owner
            .execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::SubscriptionEnabled
    );
    let link = owner.take_subscription_link().unwrap();
    let token = fs::read(root.0.join(TOKEN)).unwrap();
    let mut details = Vec::new();
    owner.write_details(&mut details).unwrap();
    assert!(
        details
            .windows(link.as_str().len())
            .any(|s| s == link.as_str().as_bytes())
    );
    let stale = owner
        .review(Action::MarkSubscriptionCompromised)
        .prepared
        .unwrap();
    owner.review(Action::Status);
    assert_eq!(
        owner.execute(stale, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let r = owner.review(Action::MarkSubscriptionCompromised);
    assert_eq!(
        owner
            .execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::SubscriptionCompromised
    );
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), token);
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(record.subscription_compromised());
    root.write(TOKEN, b"foreign", 0o600);
    assert!(owner.write_details(&mut Vec::new()).is_err());
    // A token fault does not revoke the independent confirmed client fallback.
    assert!(
        owner
            .review(Action::ShowClientConfiguration)
            .prepared
            .is_some()
    );
}
#[test]
fn protected_disclosure_checks_independent_gid_and_terminal_default_no() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    disclosure_surface(&root, &io);
    let host = crate::host::disclosure::ProtectedDisclosureHost::injected(
        &root.0,
        &proof,
        io.clone(),
        io.address,
    )
    .unwrap();
    let mut module = DisclosureInstallation::new(host, ExecutionMode::InjectedHost);
    let mut output = Vec::new();
    crate::terminal::run(&mut &b"2\n\n0\n"[..], &mut output, &mut module).unwrap();
    assert!(
        !output
            .windows(b"BEGIN SBXR".len())
            .any(|s| s == b"BEGIN SBXR")
    );
    root.write("etc/group", b"sing-box:x:9999:\n", 0o644);
    // Runtime resolves the group independently; do not accept a file's own GID.
    io.bad.store(8, Ordering::SeqCst);
    assert!(
        module
            .review(Action::ShowClientConfiguration)
            .prepared
            .is_none()
    );
}

#[test]
fn disclosure_status_uses_metadata_without_reading_subscription_credential() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    disclosure_surface(&root, &io);
    let mut http = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    });
    let r = http.review(Action::EnableSubscription);
    assert_eq!(
        http.execute(r.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::SubscriptionEnabled
    );
    drop(http);
    let path = root.0.join(TOKEN);
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_times(
        fs::FileTimes::new().set_accessed(std::time::UNIX_EPOCH + Duration::from_secs(1000)),
    )
    .unwrap();
    drop(file);
    let before = fs::metadata(&path).unwrap().accessed().unwrap();
    let host = crate::host::disclosure::ProtectedDisclosureHost::injected(
        &root.0,
        &proof,
        io.clone(),
        io.address,
    )
    .unwrap();
    let mut session = crate::disclosure::Session::new(host);
    assert!(session.status().unwrap().client_configuration_available);
    assert_eq!(fs::metadata(path).unwrap().accessed().unwrap(), before);
}

struct OfflineOwnerIo(Arc<OwnerIoFixture>);
impl PeerObservations for OfflineOwnerIo {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.0.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.0.peer(s)
    }
}
impl crate::host::owner_runtime::OwnerIo for OfflineOwnerIo {
    fn query(
        &self,
        q: crate::host::owner_runtime::Observation,
        c: &StartContext,
    ) -> Result<crate::host::process::CommandOutput, HostError> {
        self.0.query(q, c)
    }
    fn service(
        &self,
        a: ServiceAction,
        o: &Arc<HostLock>,
        s: Option<&std::path::Path>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.0.service(a, o, s, c)
    }
    fn port_available(&self, p: u16, c: &StartContext) -> Result<bool, HostError> {
        self.0.port_available(p, c)
    }
    fn process(&self, p: u32) -> Result<ProcessIdentity, HostError> {
        self.0.process(p)
    }
    fn public_ipv4(&self, _: &StartContext) -> Result<Ipv4Addr, HostError> {
        panic!("offline removal must not request a public IP")
    }
    fn validate_configuration(
        &self,
        _: &Arc<HostLock>,
        _: &str,
        _: &StartContext,
    ) -> Result<bool, HostError> {
        panic!("offline removal must not execute sing-box")
    }
}
#[test]
fn native_removal_runtime_stops_and_joins_real_fixture_serving_without_network_probe() {
    use crate::host::{linux::AuxiliaryRuntime, owner_runtime::OwnerRuntime};
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    let mut frontend = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io: io.clone(),
    });
    let prepared = frontend
        .review(Action::EnableSubscription)
        .prepared
        .unwrap();
    assert_eq!(
        frontend.execute(prepared, Confirmation::Approved).outcome,
        Outcome::SubscriptionEnabled
    );
    drop(frontend);
    let path = "var/lib/sbxr/proxy-ownership.json";
    let source = OwnershipRecord::decode(&fs::read(root.0.join(path)).unwrap()).unwrap();
    let committed =
        crate::removal::commit_removal(Some(&source), &proof.record().release_identity()).unwrap();
    root.write(path, &committed.encode().unwrap(), 0o600);
    let mut runtime =
        OwnerRuntime::injected(&root.0, &proof, OfflineOwnerIo(io.clone()), io.address).unwrap();
    assert!(runtime.observe(&committed).unwrap().serving_running);
    let owner = Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
    runtime.disable(false, &committed, &owner).unwrap();
    let facts = runtime.observe(&committed).unwrap();
    assert!(!facts.serving_running && facts.quiescent);
    runtime.disable(true, &committed, &owner).unwrap();
    assert!(
        !runtime
            .observe(&committed)
            .unwrap()
            .firewall_rules
            .contains("sbxr-subscription")
    );
    assert!(TcpStream::connect_timeout(&io.address, Duration::from_millis(100)).is_err());
    assert_eq!(
        fs::read(root.0.join(path)).unwrap(),
        committed.encode().unwrap()
    );
    let mut checkpoint = committed;
    for _ in 0..9 {
        checkpoint = crate::removal::next_checkpoint(&checkpoint).unwrap();
    }
    root.write(path, &checkpoint.encode().unwrap(), 0o600);
    fs::remove_file(root.0.join("usr/local/bin/sbxr")).unwrap();
    runtime.observe(&checkpoint).unwrap();
    fs::remove_file(root.0.join("var/lib/sbxr/installed.json")).unwrap();
    assert!(runtime.observe(&checkpoint).is_err());
    checkpoint = crate::removal::next_checkpoint(&checkpoint).unwrap();
    root.write(path, &checkpoint.encode().unwrap(), 0o600);
    runtime.observe(&checkpoint).unwrap();
}

struct VmessOwnerIo {
    inner: Arc<OwnerIoFixture>,
    listener: String,
}
impl PeerObservations for VmessOwnerIo {
    fn current(&self) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.inner.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<ProcessIdentity, runtime_handoff::Error> {
        self.inner.peer(s)
    }
}
impl crate::host::owner_runtime::OwnerIo for VmessOwnerIo {
    fn query(
        &self,
        o: crate::host::owner_runtime::Observation,
        c: &StartContext,
    ) -> Result<crate::host::process::CommandOutput, HostError> {
        if o == crate::host::owner_runtime::Observation::Listener10000 {
            return crate::host::process::CommandOutput::completed(
                0,
                self.listener.as_bytes().to_vec(),
            );
        }
        self.inner.query(o, c)
    }
    fn service(
        &self,
        a: ServiceAction,
        o: &Arc<HostLock>,
        s: Option<&std::path::Path>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.inner.service(a, o, s, c)
    }
    fn port_available(&self, p: u16, c: &StartContext) -> Result<bool, HostError> {
        self.inner.port_available(p, c)
    }
    fn process(&self, p: u32) -> Result<ProcessIdentity, HostError> {
        self.inner.process(p)
    }
    fn public_ipv4(&self, _: &StartContext) -> Result<Ipv4Addr, HostError> {
        panic!("local VMess observation must not request Internet state")
    }
    fn validate_configuration(
        &self,
        _: &Arc<HostLock>,
        _: &str,
        _: &StartContext,
    ) -> Result<bool, HostError> {
        panic!("process observation does not execute a checker")
    }
}
#[test]
fn native_tunnel_observation_binds_loopback_to_the_same_pinned_proxy_process() {
    use crate::host::{linux::TunnelRuntime, owner_runtime::OwnerRuntime};
    for listener in [
        "LISTEN 0 128 127.0.0.1:10000 *:* users:((\"sing-box\",pid=200,fd=4))",
        "LISTEN 0 128 *:10000 *:* users:((\"sing-box\",pid=200,fd=4))",
        "LISTEN 0 128 127.0.0.1:10000 *:* users:((\"sing-box\",pid=999,fd=4))",
        "",
    ] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        root.setup(&archive);
        let proof = Arc::new(
            archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap(),
        );
        let config = crate::server_configuration::ServerConfiguration::decode_standard(
            &fs::read(root.0.join("etc/sing-box/config.json")).unwrap(),
        )
        .unwrap()
        .with_vmess_websocket("fixture.example.com")
        .unwrap();
        let mut record = OwnershipRecord::new_tunnel_setup(
            proof.record().release_identity(),
            "8.8.8.8",
            &config.sha256_hex(),
            crate::records::TunnelAuthority::new(
                "12345678-1234-1234-1234-123456789abc",
                &"1".repeat(64),
                &"2".repeat(64),
            )
            .unwrap(),
        )
        .unwrap();
        while record.phase() != crate::records::SetupPhase::Running {
            record = record.next_setup_checkpoint().unwrap();
        }
        root.write(
            "var/lib/sbxr/proxy-ownership.json",
            &record.encode().unwrap(),
            0o600,
        );
        root.write("etc/sing-box/config.json", config.as_bytes(), 0o640);
        let io = OwnerIoFixture::new(&root, archive, proof.clone());
        let runtime = OwnerRuntime::injected(
            &root.0,
            &proof,
            VmessOwnerIo {
                inner: io.clone(),
                listener: listener.into(),
            },
            io.address,
        )
        .unwrap();
        let result = runtime.observe(Some(&record), &crate::host::process::Cancellation::new());
        assert_eq!(
            result.is_ok(),
            listener.contains("127.0.0.1") && listener.contains("pid=200,")
        );
    }
}

#[test]
fn composed_owner_and_lifecycle_menu_keep_current_identity_and_never_offer_update() {
    struct Offline;
    impl crate::artifact_trust::AcquisitionTransport for Offline {
        fn get(
            &mut self,
            _: &crate::artifact_trust::AcquisitionRequest,
            _: &crate::artifact_trust::SelectionBudget,
        ) -> Result<crate::artifact_trust::AcquisitionResponse, crate::artifact_trust::TrustError>
        {
            Err(crate::artifact_trust::TrustError::Unavailable)
        }
    }
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = Arc::new(
        archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap(),
    );
    let io = OwnerIoFixture::new(&root, archive, proof.clone());
    let mut owner = OwnerInstallation::new(ComposedSources {
        root: &root,
        proof: &proof,
        io,
    });
    let before = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
    let configuration = fs::read(root.0.join("etc/sing-box/config.json")).unwrap();
    let mut life = crate::software_lifecycle::Installed::new(
        crate::host::lifecycle::LifecycleHost::injected(&root.0).unwrap(),
        Offline,
    );
    let mut output = Vec::new();
    crate::terminal::run_with_lifecycle(
        &mut std::io::Cursor::new(b"4\n5\n0\n"),
        &mut output,
        &mut owner,
        &mut life,
    )
    .unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("Software Lifecycle status: Ready"));
    assert!(text.contains(crate::software_lifecycle::Code::CheckReleaseUnavailable.as_str()));
    assert!(text.contains("No recovery is available"));
    assert!(!text.contains("Update SBXR"));
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        before
    );
    assert_eq!(
        fs::read(root.0.join("etc/sing-box/config.json")).unwrap(),
        configuration
    );
    assert!(!root.0.join(TOKEN).exists());
}

#[test]
fn owner_http_cancellation_reaches_effect_context_and_recovers_only_cleanup() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    root.setup(&archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let session = Cancellation::new();
    let mut m = module(&root, &proof, archive).with_cancellation(session.clone());
    m.host_mut().backend_mut().cancel_on_reload = Some(session.clone());
    let result = execute(&mut m, Action::EnableSubscription);
    assert!(session.is_cancelled());
    assert_ne!(result.outcome, Outcome::SubscriptionEnabled);
    assert_eq!(m.host().backend().trace, vec![SystemEffect::Reload]);
    assert!(m.take_subscription_link().is_none());
    let bytes = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
    let record = OwnershipRecord::decode(&bytes).unwrap();
    assert!(record.http_operation().unwrap().is_some());
    assert!(record.serving_authority().is_none());
    let stale = m.review(Action::FinishSubscriptionChange).prepared.unwrap();
    let mut m = m.with_cancellation(Cancellation::new());
    assert_eq!(
        m.execute(stale, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert_eq!(
        execute(&mut m, Action::FinishSubscriptionChange).outcome,
        Outcome::SubscriptionChangeCleanedUp
    );
    assert!(!root.0.join(TOKEN).exists());
    assert!(m.host().backend().active.is_none());
    let record = OwnershipRecord::decode(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    assert!(record.http_operation().unwrap().is_none());
}

#[path = "http_admission_tests.rs"]
mod http_admission_tests;
