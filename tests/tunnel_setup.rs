use base64::{Engine, engine::general_purpose::STANDARD};
use sbxr::{
    domain::Confirmation,
    durable::{OWNERSHIP_FILE, OwnershipStore, STAGED_FILE},
    host::{Operation, process::Cancellation},
    identity_generation::{Entropy, IdentityError},
    records::{OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase},
    server_configuration::{ServerConfiguration, ServerIdentity},
    tunnel_setup::*,
};
use serde_json::Value;
use std::{
    cell::RefCell,
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const HOSTNAME: &str = "fixture.example.com";
const TOKEN_ID: &str = "12345678-1234-1234-1234-123456789abc";
static NEXT: AtomicU64 = AtomicU64::new(0);
fn facts(mode: u32) -> FileFacts {
    FileFacts {
        uid: 0,
        mode,
        links: 1,
        regular: true,
        stable: true,
        protected_parents: true,
    }
}
fn token() -> Vec<u8> {
    STANDARD
        .encode(include_bytes!("testdata/tunnel_setup/token-claims.json"))
        .into_bytes()
}
fn prerequisite(bytes: &[u8]) -> Result<Prerequisites, Error> {
    Prerequisites::inspect(
        bytes,
        facts(0o600),
        b"inert synthetic binary; never execute",
        facts(0o755),
        "cloudflared version 2025.4.0",
    )
}
fn configuration(hostname: &str) -> ServerConfiguration {
    ServerConfiguration::standard(
        &ServerIdentity::from_private_key(
            "00112233-4455-4677-8899-aabbccddeeff",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "01234567",
        )
        .unwrap(),
    )
    .unwrap()
    .with_vmess_websocket(hostname)
    .unwrap()
}
fn release() -> ReleaseIdentity {
    ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap()
}
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let parent = std::env::var_os("TMPDIR").expect("isolated TMPDIR required");
        let path = PathBuf::from(parent).join(format!(
            "tn-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("only this disposable fixture root");
    }
}
#[derive(Default)]
struct State {
    events: Vec<String>,
    effects: usize,
    publications: usize,
    prereq_reads: usize,
    occupied: bool,
    standard: bool,
    ready: bool,
    proxy: bool,
    connector: bool,
    connector_running: bool,
    config: Vec<u8>,
    token: Vec<u8>,
    foreign: bool,
    interrupt_effect: Option<(usize, bool)>,
    interrupt_publication: Option<usize>,
    fail_effect: Option<Effect>,
    uncertain_publication: Option<usize>,
    ws_failure: Option<(usize, ProbeProblem)>,
    ws_calls: usize,
    ws_mutation: Option<&'static str>,
    port: u16,
    wrong_listener: bool,
    exited_after_egress: bool,
    egress_calls: usize,
    egress_body: Option<Vec<u8>>,
    egress_status: Option<u16>,
    egress_redirect: bool,
    egress_untrusted: bool,
    egress_unauthenticated: bool,
    egress_failure: bool,
    panic_egress: bool,
    fail_cleanup: bool,
    cleanup_calls: usize,
    cancel_on: Option<&'static str>,
    change_record_during_egress: bool,
    changed_process: bool,
}
struct TestHost {
    store: OwnershipStore,
    root: Rc<Root>,
    state: Rc<RefCell<State>>,
    stop: Cancellation,
    installed: ReleaseIdentity,
}
impl TestHost {
    fn new() -> Self {
        let root = Rc::new(Root::new());
        let store = OwnershipStore::open(&root.0, rustix::process::geteuid().as_raw()).unwrap();
        Self {
            store,
            root,
            state: Rc::new(RefCell::new(State {
                token: token(),
                port: 32101,
                ..State::default()
            })),
            stop: Cancellation::new(),
            installed: release(),
        }
    }
    fn record(&self) -> Option<OwnershipRecord> {
        self.store.load().unwrap().current.map(|r| r.record)
    }
    fn reopen(self) -> Self {
        let Self {
            store, root, state, ..
        } = self;
        drop(store);
        let store = OwnershipStore::open(&root.0, rustix::process::geteuid().as_raw()).unwrap();
        {
            let mut s = state.borrow_mut();
            s.interrupt_effect = None;
            s.interrupt_publication = None;
            s.uncertain_publication = None;
            s.fail_effect = None;
        }
        Self {
            store,
            root,
            state,
            stop: Cancellation::new(),
            installed: release(),
        }
    }
    fn running() -> TunnelInstallation<Self> {
        let host = Self::new();
        let stop = host.stop.clone();
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup
            .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
            .unwrap();
        assert_eq!(
            setup.execute(prepared, Confirmation::Approved, &stop),
            Ok(SetupOutcome::RunningConnectionPending)
        );
        setup
    }
}
impl Host for TestHost {
    type Guard = Rc<Root>;
    type Probe = TestProbe;
    fn acquire(&mut self, _: &Cancellation) -> Result<Self::Guard, Error> {
        self.state.borrow_mut().events.push("acquire".into());
        Ok(self.root.clone())
    }
    fn verify_guard(&mut self, guard: &Self::Guard) -> Result<(), Error> {
        if Rc::ptr_eq(guard, &self.root) {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    fn installed_release(&mut self, _: &Self::Guard) -> Result<ReleaseIdentity, Error> {
        Ok(self.installed.clone())
    }
    fn public_ipv4(&mut self, _: &Self::Guard) -> Result<String, Error> {
        Ok("8.8.8.8".into())
    }
    fn snapshot(&mut self, _: &Self::Guard) -> Result<Snapshot, Error> {
        let s = self.store.load().map_err(|_| Error::Authority)?;
        Ok(Snapshot {
            current: s.current.map(|r| r.bytes().to_vec()),
            staged: s.staged.map(|r| r.bytes().to_vec()),
        })
    }
    fn prerequisites(&mut self, _: &Self::Guard, _: &Cancellation) -> Result<Prerequisites, Error> {
        let mut s = self.state.borrow_mut();
        s.prereq_reads += 1;
        prerequisite(&s.token)
    }
    fn inspect(
        &mut self,
        _: &Self::Guard,
        record: Option<&OwnershipRecord>,
        _: &Cancellation,
    ) -> Result<Inspection, Error> {
        let s = self.state.borrow();
        if s.foreign || record.is_none() && s.occupied {
            return Err(Error::Authority);
        }
        Ok(Inspection {
            fingerprint: format!(
                "{}:{}:{}:{}:{}:{}",
                self.root.0.display(),
                s.standard,
                s.ready,
                s.proxy,
                s.connector,
                s.connector_running
            ),
            empty: !s.standard && !s.proxy && !s.connector && !s.connector_running,
            ready: s.ready && s.connector,
            stopped: !s.proxy,
            running: s.proxy && s.connector_running,
        })
    }
    fn configuration(&mut self, _: &Self::Guard, _: &OwnershipRecord) -> Result<Vec<u8>, Error> {
        Ok(self.state.borrow().config.clone())
    }
    fn synchronize(&mut self, _: &Self::Guard, expected: &[u8]) -> Result<(), Error> {
        self.store
            .synchronize(expected)
            .map_err(|_| Error::Publication)
    }
    fn publish(
        &mut self,
        _: &Self::Guard,
        expected: Option<&[u8]>,
        next: &OwnershipRecord,
    ) -> Result<(), Error> {
        self.store
            .publish(expected, next)
            .map_err(|_| Error::Publication)?;
        let mut s = self.state.borrow_mut();
        s.publications += 1;
        s.events.push(format!("publish:{:?}", next.phase()));
        if s.interrupt_publication == Some(s.publications) {
            self.stop.cancel();
        }
        if s.uncertain_publication == Some(s.publications) {
            return Err(Error::Publication);
        }
        Ok(())
    }
    fn effect(
        &mut self,
        _: &Self::Guard,
        effect: Effect,
        record: &OwnershipRecord,
        config: Option<&ServerConfiguration>,
        _: &Cancellation,
    ) -> Result<(), Error> {
        assert_eq!(
            Some(record.clone()),
            self.record(),
            "authority must precede effects"
        );
        let mut s = self.state.borrow_mut();
        s.effects += 1;
        s.events.push(format!("effect:{effect:?}"));
        if s.interrupt_effect == Some((s.effects, false)) {
            self.stop.cancel();
            return Err(Error::Interrupted);
        }
        if s.fail_effect == Some(effect) {
            return Err(Error::Effect(effect));
        }
        match effect {
            Effect::Standard(Operation::InstallAptKey) => s.standard = true,
            Effect::Standard(Operation::InstallConfiguration) => {
                s.config = config.unwrap().as_bytes().to_vec()
            }
            Effect::Standard(Operation::ValidateConfiguration) => s.ready = true,
            Effect::Standard(Operation::StartService) => s.proxy = true,
            Effect::Standard(Operation::StopDisableService) => s.proxy = false,
            Effect::Standard(Operation::RemoveAptKey) => {
                s.standard = false;
                s.ready = false;
                s.config.clear();
            }
            Effect::InstallConnector => {
                assert!(record.tunnel_authority().is_some());
                s.connector = true;
            }
            Effect::StartConnector => {
                assert_eq!(record.recovery_direction(), RecoveryDirection::FinishSetup);
                s.connector_running = true;
            }
            Effect::RemoveConnector => {
                assert_eq!(record.recovery_direction(), RecoveryDirection::Cleanup);
                s.connector = false;
                s.connector_running = false;
            }
            _ => {}
        }
        if s.interrupt_effect == Some((s.effects, true)) {
            self.stop.cancel();
        }
        Ok(())
    }
    fn remove_completed_cleanup(&mut self, _: &Self::Guard, expected: &[u8]) -> Result<(), Error> {
        assert_eq!(
            fs::read(self.root.0.join(OWNERSHIP_FILE)).unwrap(),
            expected
        );
        let r = OwnershipRecord::decode(expected).unwrap();
        assert_eq!(r.cleanup_checkpoint(), 8);
        assert_eq!(r.recovery_direction(), RecoveryDirection::Cleanup);
        fs::remove_file(self.root.0.join(OWNERSHIP_FILE)).map_err(|_| Error::Publication)?;
        fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        Ok(())
    }
    fn websocket(
        &mut self,
        _: &Self::Guard,
        request: &WebSocketRequest,
        budget: &Budget<'_>,
    ) -> Result<WebSocketReply, ProbeProblem> {
        assert!(budget.remaining().is_ok());
        let mut s = self.state.borrow_mut();
        s.ws_calls += 1;
        s.events.push(format!("ws:{}", request.url()));
        assert_eq!(
            request.url(),
            if s.ws_calls % 2 == 1 {
                "http://127.0.0.1:10000/sbxr-vmess".into()
            } else {
                format!("https://{HOSTNAME}/sbxr-vmess")
            }
        );
        assert!(!request.follows_redirects());
        assert!(!request.uses_environment_proxy());
        assert_eq!(request.max_header_bytes(), 16384);
        assert_eq!(request.timeout(), Duration::from_secs(8));
        if s.cancel_on
            == Some(if s.ws_calls % 2 == 1 {
                "local"
            } else {
                "public"
            })
        {
            self.stop.cancel();
        }
        if let Some((at, problem)) = s.ws_failure
            && at == s.ws_calls
        {
            return Err(problem);
        }
        let mut reply = WebSocketReply {
            status: 101,
            trusted_tls: true,
            redirected: false,
            headers: vec![
                ("Upgrade".into(), "WebSocket".into()),
                ("Connection".into(), "keep-alive, Upgrade".into()),
                (
                    "Sec-WebSocket-Accept".into(),
                    websocket_accept(request.key()),
                ),
            ],
        };
        match s.ws_mutation {
            Some("status") => reply.status = 403,
            Some("upgrade") => reply.headers[0].1 = "not-websocket".into(),
            Some("connection") => reply.headers[1].1 = "not-upgrade".into(),
            Some("accept") => reply.headers[2].1 = "wrong-accept-synthetic-secret".into(),
            Some("duplicate") => reply.headers.push(("upgrade".into(), "websocket".into())),
            Some("newline") => reply.headers[0].1 = "websocket\r\nsecret: synthetic".into(),
            Some("large") => reply.headers.push(("x-padding".into(), "x".repeat(16384))),
            Some("redirect") => reply.redirected = true,
            Some("tls") if request.trusted_tls_required() => reply.trusted_tls = false,
            _ => {}
        }
        Ok(reply)
    }
    fn probe_port(&mut self, _: &Self::Guard, _: &Budget<'_>) -> Result<u16, ProbeProblem> {
        Ok(self.state.borrow().port)
    }
    fn spawn_probe(
        &mut self,
        _: &Self::Guard,
        plan: &ProbePlan,
        _: &Budget<'_>,
    ) -> Result<Self::Probe, ProbeProblem> {
        let value: Value = serde_json::from_slice(plan.as_bytes()).unwrap();
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(value["outbounds"][0]["type"], "vmess");
        assert_eq!(value["outbounds"][0]["server"], HOSTNAME);
        assert_eq!(value["outbounds"][0]["server_port"], 443);
        assert_eq!(
            value["outbounds"][0]["tls"],
            serde_json::json!({"enabled":true,"server_name":HOSTNAME})
        );
        assert_eq!(
            value["outbounds"][0]["uuid"],
            "00112233-4455-4677-8899-aabbccddeeff"
        );
        assert_eq!(value["route"]["final"], "vmess-only");
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["users"][0]["username"], "sbxr-probe");
        assert_eq!(
            value["inbounds"][0]["users"][0]["password"]
                .as_str()
                .unwrap()
                .len(),
            43
        );
        assert!(!format!("{plan:?}").contains("password"));
        self.state.borrow_mut().events.push("spawn".into());
        Ok(TestProbe {
            state: self.state.clone(),
            port: plan.port(),
            stop: self.stop.clone(),
            root: self.root.clone(),
        })
    }
}
struct TestProbe {
    state: Rc<RefCell<State>>,
    port: u16,
    stop: Cancellation,
    root: Rc<Root>,
}
impl ProbeSession for TestProbe {
    fn listener(&mut self, _: &Budget<'_>) -> Result<ListenerProof, ProbeProblem> {
        let mut s = self.state.borrow_mut();
        s.events.push("listener".into());
        if s.cancel_on == Some("listener") {
            self.stop.cancel();
        }
        let process = sbxr::runtime_handoff::ProcessIdentity::new(
            4242,
            std::process::id(),
            if s.changed_process && s.egress_calls > 0 {
                2
            } else {
                1
            },
            rustix::process::geteuid().as_raw(),
            &"d".repeat(64),
            "/synthetic-probe",
        )
        .unwrap();
        Ok(ListenerProof {
            process,
            listener_pid: if s.wrong_listener { 1234 } else { 4242 },
            address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port),
            exclusive: true,
            process_alive: !(s.exited_after_egress && s.egress_calls > 0),
        })
    }
    fn egress(
        &mut self,
        request: &EgressRequest<'_>,
        budget: &Budget<'_>,
    ) -> Result<EgressReply, ProbeProblem> {
        assert!(budget.remaining().is_ok());
        assert_eq!(request.url(), "https://api.ipify.org");
        assert_eq!(
            request.proxy_address(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
        );
        assert_eq!(request.username(), "sbxr-probe");
        assert_eq!(request.password().len(), 43);
        assert_eq!(request.max_body_bytes(), 128);
        assert!(request.trusted_tls_required());
        assert!(!request.follows_redirects());
        let mut s = self.state.borrow_mut();
        s.egress_calls += 1;
        s.events.push("egress".into());
        if s.panic_egress {
            drop(s);
            panic!("synthetic probe interruption");
        }
        if s.cancel_on == Some("egress") {
            self.stop.cancel();
        }
        if s.change_record_during_egress {
            let bytes = fs::read(self.root.0.join(OWNERSHIP_FILE)).unwrap();
            let mut value: Value = serde_json::from_slice(&bytes).unwrap();
            value["public_ipv4"] = "9.9.9.9".into();
            fs::write(
                self.root.0.join(OWNERSHIP_FILE),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        }
        if s.egress_failure {
            return Err(ProbeProblem::Traffic);
        }
        Ok(EgressReply {
            status: s.egress_status.unwrap_or(200),
            body: s
                .egress_body
                .clone()
                .unwrap_or_else(|| b"8.8.8.8\n".to_vec()),
            trusted_tls: !s.egress_untrusted,
            authenticated_proxy: !s.egress_unauthenticated,
            redirected: s.egress_redirect,
        })
    }
    fn stop_and_reap(&mut self) -> Result<(), ProbeProblem> {
        let mut s = self.state.borrow_mut();
        s.cleanup_calls += 1;
        s.events.push("reap".into());
        if s.fail_cleanup {
            Err(ProbeProblem::Cleanup)
        } else {
            Ok(())
        }
    }
}
struct FixedEntropy {
    calls: usize,
    fail_at: Option<usize>,
}
impl Entropy for FixedEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), IdentityError> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(IdentityError::EntropyUnavailable);
        }
        bytes.fill(self.calls as u8);
        Ok(())
    }
}
fn check(setup: &mut TunnelInstallation<TestHost>) -> ConnectionCheck {
    let stop = setup.host().stop.clone();
    setup.check_connection_with_entropy(
        &stop,
        CHECK_TIMEOUT,
        &mut FixedEntropy {
            calls: 0,
            fail_at: None,
        },
    )
}

#[test]
fn protected_owner_prerequisites_only() {
    let token = token();
    let p = prerequisite(&token).unwrap();
    assert_eq!(p.authority().tunnel_id(), TOKEN_ID);
    assert_ne!(
        p,
        prerequisite(&[token.as_slice(), b"\n"].concat()).unwrap(),
        "review binds original bytes"
    );
    for bad in [
        facts(0o644),
        FileFacts {
            uid: 1,
            ..facts(0o600)
        },
        FileFacts {
            links: 2,
            ..facts(0o600)
        },
        FileFacts {
            regular: false,
            ..facts(0o600)
        },
        FileFacts {
            stable: false,
            ..facts(0o600)
        },
        FileFacts {
            protected_parents: false,
            ..facts(0o600)
        },
    ] {
        assert_eq!(
            Prerequisites::inspect(
                &token,
                bad,
                b"binary",
                facts(0o755),
                "cloudflared version 2025.4.0"
            ),
            Err(Error::TokenFile)
        );
    }
    for bad in [
        facts(0o700),
        FileFacts {
            links: 2,
            ..facts(0o755)
        },
        FileFacts {
            stable: false,
            ..facts(0o755)
        },
    ] {
        assert_eq!(
            Prerequisites::inspect(
                &token,
                facts(0o600),
                b"binary",
                bad,
                "cloudflared version 2025.4.0"
            ),
            Err(Error::BinaryFile)
        );
    }
    for old in [
        "cloudflared version 2025.3.9",
        "cloudflared version 2024.12.1",
        "cloudflared version 2026.13.0",
        "untrusted output",
    ] {
        assert_eq!(
            Prerequisites::inspect(&token, facts(0o600), b"binary", facts(0o755), old),
            Err(Error::BinaryVersion)
        );
    }
    assert!(!format!("{p:?}").contains("synthetic"));
    assert!(
        !p.authority()
            .resources()
            .iter()
            .any(|r| r.contains("sbxr.token") || r.contains("/usr/bin/cloudflared"))
    );
}
#[test]
fn token_claims_are_exact_and_errors_never_echo_secrets() {
    for claims in [
        r#"{"a":"synthetic-secret","t":"12345678-1234-1234-1234-123456789ABC","s":"secret"}"#,
        r#"{"a":"synthetic-secret","t":"https://bad.example","s":"secret"}"#,
        r#"{"a":"synthetic-secret","t":"12345678-1234-1234-1234-123456789abc","t":"00000000-0000-0000-0000-000000000000","s":"secret"}"#,
        r#"{"a":"","t":"12345678-1234-1234-1234-123456789abc","s":"secret"}"#,
        r#"{"a":"synthetic-secret","t":"12345678-1234-1234-1234-123456789abc","s":null}"#,
        r#"{"a":"synthetic-secret","t":"12345678-1234-1234-1234-123456789abc","s":"secret","extra":true}"#,
    ] {
        let err = prerequisite(STANDARD.encode(claims).as_bytes()).unwrap_err();
        assert_eq!(err, Error::TokenClaims);
        assert!(!format!("{err:?} {err}").contains("synthetic-secret"));
    }
    for input in [
        vec![],
        b"invalid-secret".to_vec(),
        vec![b'A'; 16385],
        [token(), b"\n\n".to_vec()].concat(),
    ] {
        assert!(prerequisite(&input).is_err());
    }
}
#[test]
fn setup_is_confirmed_bound_and_connection_pending() {
    let host = TestHost::new();
    let stop = host.stop.clone();
    let state = host.state.clone();
    let mut setup = TunnelInstallation::new(host);
    let first = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert!(setup.host().record().is_none());
    let second = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(first, Confirmation::Approved, &stop),
        Err(Error::StaleReview)
    );
    assert_eq!(
        setup.execute(second, Confirmation::Approved, &stop),
        Err(Error::StaleReview)
    );
    let declined = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(declined, Confirmation::Declined, &stop),
        Ok(SetupOutcome::Cancelled)
    );
    assert_eq!(state.borrow().effects, 0);
    assert_eq!(state.borrow().publications, 0);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Ok(SetupOutcome::RunningConnectionPending)
    );
    let record = setup.host().record().unwrap();
    assert_eq!(record.phase(), SetupPhase::Running);
    assert_eq!(record.tunnel_authority().unwrap().tunnel_id(), TOKEN_ID);
    let events = &state.borrow().events;
    assert!(
        events
            .iter()
            .position(|e| e == "effect:InstallConnector")
            .unwrap()
            < events
                .iter()
                .position(|e| e == "publish:ActivationCommitted")
                .unwrap()
    );
    assert!(!events.iter().any(|e| e.starts_with("ws:")));
}
#[test]
fn setup_refuses_hostnames_foreign_state_changed_prerequisites_and_release() {
    for name in [
        "https://fixture.example.com",
        "Fixture.example.com",
        "127.0.0.1",
        "fixture.example.com:443",
        "fixture.example.com/",
        "a..example.com",
        "token",
    ] {
        let host = TestHost::new();
        let stop = host.stop.clone();
        let mut setup = TunnelInstallation::new(host);
        assert!(
            setup
                .review_setup(name, configuration(HOSTNAME), &stop)
                .is_err()
        );
        assert_eq!(setup.host().state.borrow().effects, 0);
    }
    for change in ["token", "release", "foreign", "occupied"] {
        let host = TestHost::new();
        let stop = host.stop.clone();
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup
            .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
            .unwrap();
        match change {
            "token" => setup.host().state.borrow_mut().token.push(b'\n'),
            "release" => {
                setup.host_mut().installed =
                    ReleaseIdentity::new("v3.1.119", &"a".repeat(40), &"b".repeat(64)).unwrap()
            }
            "foreign" => setup.host().state.borrow_mut().foreign = true,
            _ => setup.host().state.borrow_mut().occupied = true,
        }
        assert!(
            setup
                .execute(prepared, Confirmation::Approved, &stop)
                .is_err()
        );
        assert_eq!(setup.host().state.borrow().effects, 0);
        assert!(setup.host().record().is_none());
    }
    let host = TestHost::new();
    let stop = host.stop.clone();
    assert!(
        TunnelInstallation::new(host)
            .review_setup("other.example.com", configuration(HOSTNAME), &stop)
            .is_err()
    );
}
#[test]
fn every_setup_effect_interruption_recovers_after_store_reopen() {
    let baseline = TestHost::running().host().state.borrow().effects;
    assert_eq!(baseline, 14);
    for at in 1..=baseline {
        for after in [false, true] {
            let host = TestHost::new();
            let stop = host.stop.clone();
            host.state.borrow_mut().interrupt_effect = Some((at, after));
            let mut setup = TunnelInstallation::new(host);
            let prepared = setup
                .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
                .unwrap();
            assert_eq!(
                setup.execute(prepared, Confirmation::Approved, &stop),
                Err(Error::Interrupted),
                "effect {at}, after={after}"
            );
            let direction = setup.host().record().unwrap().recovery_direction();
            let host = setup.into_host().reopen();
            let stop = host.stop.clone();
            if direction == RecoveryDirection::Cleanup {
                host.state.borrow_mut().token.clear();
            }
            let mut setup = TunnelInstallation::new(host);
            let prepared = setup.review_finish(&stop).unwrap();
            let reads = setup.host().state.borrow().prereq_reads;
            let result = setup
                .execute(prepared, Confirmation::Approved, &stop)
                .unwrap();
            if direction == RecoveryDirection::Cleanup {
                assert_eq!(result, SetupOutcome::CleanedUp);
                assert!(setup.host().record().is_none());
                assert_eq!(setup.host().state.borrow().prereq_reads, reads);
            } else {
                assert_eq!(direction, RecoveryDirection::FinishSetup);
                assert_eq!(result, SetupOutcome::RunningConnectionPending);
                assert!(
                    !setup
                        .host()
                        .state
                        .borrow()
                        .events
                        .iter()
                        .any(|e| e == "effect:RemoveConnector")
                );
            }
        }
    }
}
#[test]
fn every_record_checkpoint_interruption_keeps_its_direction() {
    for at in 1..=14 {
        let host = TestHost::new();
        let stop = host.stop.clone();
        host.state.borrow_mut().interrupt_publication = Some(at);
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup
            .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
            .unwrap();
        assert_eq!(
            setup.execute(prepared, Confirmation::Approved, &stop),
            Err(Error::Interrupted)
        );
        let record = setup.host().record().unwrap();
        let host = setup.into_host().reopen();
        let stop = host.stop.clone();
        let mut setup = TunnelInstallation::new(host);
        if record.phase() == SetupPhase::Running {
            assert!(setup.review_finish(&stop).is_err());
            assert!(check(&mut setup).verified());
        } else {
            let prepared = setup.review_finish(&stop).unwrap();
            assert_eq!(
                setup
                    .execute(prepared, Confirmation::Approved, &stop)
                    .unwrap(),
                if record.recovery_direction() == RecoveryDirection::Cleanup {
                    SetupOutcome::CleanedUp
                } else {
                    SetupOutcome::RunningConnectionPending
                }
            );
        }
    }
}
#[test]
fn uncertain_commit_stops_then_recovers_forward_without_cleanup() {
    let host = TestHost::new();
    let stop = host.stop.clone();
    host.state.borrow_mut().uncertain_publication = Some(11);
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Err(Error::Publication)
    );
    assert_eq!(
        setup.host().record().unwrap().phase(),
        SetupPhase::ActivationCommitted
    );
    assert!(!setup.host().state.borrow().proxy);
    let host = setup.into_host().reopen();
    let stop = host.stop.clone();
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup.review_finish(&stop).unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Ok(SetupOutcome::RunningConnectionPending)
    );
    assert!(
        !setup
            .host()
            .state
            .borrow()
            .events
            .iter()
            .any(|e| e == "effect:RemoveConnector")
    );
}
#[test]
fn connector_start_failure_retains_exact_forward_recovery() {
    let host = TestHost::new();
    let stop = host.stop.clone();
    host.state.borrow_mut().fail_effect = Some(Effect::StartConnector);
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Err(Error::Effect(Effect::StartConnector))
    );
    assert_eq!(
        setup.host().record().unwrap().phase(),
        SetupPhase::ServiceStarted
    );
    assert!(!check(&mut setup).verified());
    let host = setup.into_host().reopen();
    let stop = host.stop.clone();
    let mut setup = TunnelInstallation::new(host);
    setup.host().state.borrow_mut().token.push(b'\n');
    let prepared = setup.review_finish(&stop).unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Err(Error::PrerequisitesChanged)
    );
    setup.host().state.borrow_mut().token = token();
    let prepared = setup.review_finish(&stop).unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Ok(SetupOutcome::RunningConnectionPending)
    );
}
#[test]
fn foreign_or_staged_recovery_is_preserved_without_effects() {
    for staged in [false, true] {
        let host = TestHost::new();
        let stop = host.stop.clone();
        host.state.borrow_mut().interrupt_publication = Some(1);
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup
            .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
            .unwrap();
        assert!(
            setup
                .execute(prepared, Confirmation::Approved, &stop)
                .is_err()
        );
        let host = setup.into_host().reopen();
        let stop = host.stop.clone();
        if staged {
            fs::write(host.root.0.join(STAGED_FILE), b"unknown-synthetic-residue").unwrap();
            fs::set_permissions(
                host.root.0.join(STAGED_FILE),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        } else {
            host.state.borrow_mut().foreign = true;
        }
        let effects = host.state.borrow().effects;
        let mut setup = TunnelInstallation::new(host);
        assert!(setup.review_finish(&stop).is_err());
        assert_eq!(setup.host().state.borrow().effects, effects);
        if staged {
            assert_eq!(
                fs::read(setup.host().root.0.join(STAGED_FILE)).unwrap(),
                b"unknown-synthetic-residue"
            );
        }
    }
}
#[test]
fn websocket_challenge_matches_independent_rfc_and_hashlib_vectors() {
    let vectors: Vec<[String; 2]> = serde_json::from_slice(include_bytes!(
        "testdata/tunnel_setup/websocket-accept.json"
    ))
    .unwrap();
    for [key, expected] in vectors {
        assert_eq!(websocket_accept(&key), expected);
    }
}
#[test]
fn check_is_ordered_fresh_and_has_no_durable_effects() {
    let mut setup = TestHost::running();
    let before = setup.host().record().unwrap().encode().unwrap();
    let effects = setup.host().state.borrow().effects;
    let writes = setup.host().state.borrow().publications;
    for _ in 0..2 {
        let result = check(&mut setup);
        assert!(result.verified());
        assert_eq!(result.code(), CONNECTION_VERIFIED);
        assert_eq!(result.stage(), CheckStage::Complete);
        assert!(result.message().contains("Karing"));
    }
    let s = setup.host().state.borrow();
    assert_eq!(s.effects, effects);
    assert_eq!(s.publications, writes);
    assert_eq!(s.cleanup_calls, 2);
    assert_eq!(setup.host().record().unwrap().encode().unwrap(), before);
    let events: Vec<_> = s
        .events
        .iter()
        .filter(|e| {
            e.starts_with("ws:") || ["spawn", "listener", "egress", "reap"].contains(&e.as_str())
        })
        .map(String::as_str)
        .collect();
    assert_eq!(
        &events[..7],
        [
            "ws:http://127.0.0.1:10000/sbxr-vmess",
            "ws:https://fixture.example.com/sbxr-vmess",
            "spawn",
            "listener",
            "egress",
            "listener",
            "reap"
        ]
    );
}
#[test]
fn websocket_failures_stop_at_their_stage_and_never_verify() {
    for (mutation, stage, problem) in [
        (
            "status",
            CheckStage::LocalWebSocket,
            ProbeProblem::Http(403),
        ),
        (
            "upgrade",
            CheckStage::LocalWebSocket,
            ProbeProblem::InvalidUpgrade,
        ),
        (
            "connection",
            CheckStage::LocalWebSocket,
            ProbeProblem::InvalidConnection,
        ),
        (
            "accept",
            CheckStage::LocalWebSocket,
            ProbeProblem::InvalidAccept,
        ),
        (
            "duplicate",
            CheckStage::LocalWebSocket,
            ProbeProblem::Headers,
        ),
        ("newline", CheckStage::LocalWebSocket, ProbeProblem::Headers),
        ("large", CheckStage::LocalWebSocket, ProbeProblem::Headers),
        (
            "redirect",
            CheckStage::LocalWebSocket,
            ProbeProblem::Redirect,
        ),
        (
            "tls",
            CheckStage::PublicWebSocket,
            ProbeProblem::UntrustedTls,
        ),
    ] {
        let mut setup = TestHost::running();
        setup.host().state.borrow_mut().ws_mutation = Some(mutation);
        let result = check(&mut setup);
        assert!(!result.verified());
        assert_eq!(result.code(), CONNECTION_PENDING);
        assert!(result.local_running());
        assert_eq!(result.stage(), stage);
        assert_eq!(result.problem(), Some(problem));
        assert_eq!(setup.host().state.borrow().egress_calls, 0);
        assert_eq!(setup.host().state.borrow().cleanup_calls, 0);
        assert!(!format!("{result:?} {}", result.problem().unwrap()).contains("synthetic-secret"));
    }
    for failure in [
        ProbeProblem::Dns,
        ProbeProblem::TlsCertificate,
        ProbeProblem::TlsHandshake,
        ProbeProblem::Network,
        ProbeProblem::TimedOut,
    ] {
        let mut setup = TestHost::running();
        setup.host().state.borrow_mut().ws_failure = Some((2, failure));
        let result = check(&mut setup);
        assert_eq!(result.stage(), CheckStage::PublicWebSocket);
        assert_eq!(result.problem(), Some(failure));
        assert!(!result.verified());
    }
}
#[test]
fn traffic_failure_matrix_always_reaps_and_never_verifies() {
    for failure in [
        "owner",
        "changed-process",
        "exited",
        "wrong-ip",
        "ipv6",
        "truncated",
        "http",
        "redirect",
        "tls",
        "auth",
        "transport",
        "cleanup",
        "changed-record",
    ] {
        let mut setup = TestHost::running();
        {
            let mut s = setup.host().state.borrow_mut();
            match failure {
                "owner" => s.wrong_listener = true,
                "changed-process" => s.changed_process = true,
                "exited" => s.exited_after_egress = true,
                "wrong-ip" => s.egress_body = Some(b"9.9.9.9".to_vec()),
                "ipv6" => s.egress_body = Some(b"::ffff:8.8.8.8".to_vec()),
                "truncated" => {
                    s.egress_body = Some([b"8.8.8.8".to_vec(), vec![b' '; 128]].concat())
                }
                "http" => s.egress_status = Some(302),
                "redirect" => s.egress_redirect = true,
                "tls" => s.egress_untrusted = true,
                "auth" => s.egress_unauthenticated = true,
                "transport" => s.egress_failure = true,
                "cleanup" => s.fail_cleanup = true,
                _ => s.change_record_during_egress = true,
            }
        }
        let result = check(&mut setup);
        assert!(!result.verified(), "{failure}");
        assert_eq!(result.code(), CONNECTION_PENDING);
        assert_eq!(
            result.stage(),
            if failure == "cleanup" {
                CheckStage::ProbeCleanup
            } else {
                CheckStage::Traffic
            }
        );
        let s = setup.host().state.borrow();
        assert_eq!(s.cleanup_calls, 1, "{failure}");
        if failure == "owner" {
            assert_eq!(s.egress_calls, 0);
        }
    }
}
#[test]
fn cancellation_at_every_check_stage_reaps_only_a_started_probe() {
    for at in ["local", "public", "listener", "egress"] {
        let mut setup = TestHost::running();
        setup.host().state.borrow_mut().cancel_on = Some(at);
        let result = check(&mut setup);
        assert!(!result.verified());
        assert_eq!(result.problem(), Some(ProbeProblem::Cancelled));
        assert_eq!(
            setup.host().state.borrow().cleanup_calls,
            usize::from(["listener", "egress"].contains(&at))
        );
    }
    let mut setup = TestHost::running();
    let stop = setup.host().stop.clone();
    let result = setup.check_connection_with_entropy(
        &stop,
        Duration::ZERO,
        &mut FixedEntropy {
            calls: 0,
            fail_at: None,
        },
    );
    assert_eq!(result.problem(), Some(ProbeProblem::TimedOut));
    assert_eq!(setup.host().state.borrow().ws_calls, 0);
    for fail_at in 1..=3 {
        let mut setup = TestHost::running();
        let stop = setup.host().stop.clone();
        let result = setup.check_connection_with_entropy(
            &stop,
            CHECK_TIMEOUT,
            &mut FixedEntropy {
                calls: 0,
                fail_at: Some(fail_at),
            },
        );
        assert_eq!(result.problem(), Some(ProbeProblem::Entropy));
        assert_eq!(setup.host().state.borrow().cleanup_calls, 0);
    }
}
#[test]
fn panic_unwind_still_reaps_the_owned_probe() {
    let mut setup = TestHost::running();
    setup.host().state.borrow_mut().panic_egress = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&mut setup))).is_err());
    assert_eq!(setup.host().state.borrow().cleanup_calls, 1);
}

fn unfinished() -> TestHost {
    let host = TestHost::new();
    let stop = host.stop.clone();
    host.state.borrow_mut().interrupt_publication = Some(1);
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Err(Error::Interrupted)
    );
    setup.into_host().reopen()
}

#[test]
fn cleanup_interruption_matrix_reopens_and_never_reads_prerequisites() {
    for at in 1..=9 {
        for after in [false, true] {
            let host = unfinished();
            let stop = host.stop.clone();
            {
                let mut s = host.state.borrow_mut();
                s.token.clear();
                s.interrupt_effect = Some((at, after));
            }
            let mut setup = TunnelInstallation::new(host);
            let prepared = setup.review_finish(&stop).unwrap();
            assert_eq!(
                prepared.recovery_direction(),
                Some(RecoveryDirection::Cleanup)
            );
            assert_eq!(prepared.tunnel_id().unwrap(), TOKEN_ID);
            assert_eq!(
                setup.execute(prepared, Confirmation::Approved, &stop),
                Err(Error::Interrupted)
            );
            assert_eq!(
                setup.host().record().unwrap().recovery_direction(),
                RecoveryDirection::Cleanup
            );
            let host = setup.into_host().reopen();
            let stop = host.stop.clone();
            let reads = host.state.borrow().prereq_reads;
            let mut setup = TunnelInstallation::new(host);
            let prepared = setup.review_finish(&stop).unwrap();
            assert_eq!(
                setup.execute(prepared, Confirmation::Approved, &stop),
                Ok(SetupOutcome::CleanedUp)
            );
            assert!(setup.host().record().is_none());
            assert_eq!(setup.host().state.borrow().prereq_reads, reads);
        }
    }
    for checkpoint in 1..=8 {
        let host = unfinished();
        let stop = host.stop.clone();
        host.state.borrow_mut().interrupt_publication = Some(1 + checkpoint);
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup.review_finish(&stop).unwrap();
        assert_eq!(
            setup.execute(prepared, Confirmation::Approved, &stop),
            Err(Error::Interrupted)
        );
        assert_eq!(
            setup.host().record().unwrap().cleanup_checkpoint(),
            checkpoint as u32
        );
        let host = setup.into_host().reopen();
        let stop = host.stop.clone();
        let mut setup = TunnelInstallation::new(host);
        let prepared = setup.review_finish(&stop).unwrap();
        assert_eq!(
            setup.execute(prepared, Confirmation::Approved, &stop),
            Ok(SetupOutcome::CleanedUp)
        );
    }
}

#[test]
fn exact_precommit_stage_is_retried_only_after_confirmed_recovery() {
    let host = unfinished();
    let stop = host.stop.clone();
    let target = host.record().unwrap().next_cleanup_checkpoint().unwrap();
    let path = host.root.0.join(STAGED_FILE);
    fs::write(&path, target.encode().unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup.review_finish(&stop).unwrap();
    assert_eq!(setup.host().record().unwrap().cleanup_checkpoint(), 0);
    assert_eq!(
        setup.execute(prepared, Confirmation::Declined, &stop),
        Ok(SetupOutcome::Cancelled)
    );
    assert!(path.exists());
    let prepared = setup.review_finish(&stop).unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Ok(SetupOutcome::CleanedUp)
    );
    assert!(!path.exists());
}

#[test]
fn staged_activation_barrier_refuses_to_guess_a_recovery_direction() {
    let host = TestHost::new();
    let stop = host.stop.clone();
    host.state.borrow_mut().interrupt_publication = Some(10);
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved, &stop),
        Err(Error::Interrupted)
    );
    let host = setup.into_host().reopen();
    let stop = host.stop.clone();
    assert_eq!(host.record().unwrap().phase(), SetupPhase::ServiceUnmasked);
    let target = host.record().unwrap().next_setup_checkpoint().unwrap();
    assert_eq!(target.phase(), SetupPhase::ActivationCommitted);
    let path = host.root.0.join(STAGED_FILE);
    fs::write(&path, target.encode().unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let effects = host.state.borrow().effects;
    let mut setup = TunnelInstallation::new(host);
    assert_eq!(setup.review_finish(&stop).unwrap_err(), Error::Publication);
    assert_eq!(setup.host().state.borrow().effects, effects);
    assert!(path.exists());
}

#[test]
fn automatic_setup_check_keeps_durable_and_fresh_results_separate() {
    let host = TestHost::new();
    let stop = host.stop.clone();
    let mut setup = TunnelInstallation::new(host);
    let prepared = setup
        .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
        .unwrap();
    assert_eq!(prepared.tunnel_id().unwrap(), TOKEN_ID);
    assert_eq!(prepared.recovery_direction(), None);
    let (installation, connection) = setup
        .execute_and_check(prepared, Confirmation::Approved, &stop)
        .unwrap();
    assert_eq!(installation, SetupOutcome::RunningConnectionPending);
    assert!(connection.unwrap().verified());
    let record = setup.host().record().unwrap().encode().unwrap();
    let wire: Value = serde_json::from_slice(&record).unwrap();
    assert!(wire.get("connection_verified").is_none());
}

#[test]
fn owner_bridge_forwards_safe_check_diagnostics_without_changing_local_status() {
    use sbxr::{
        domain::{Action, Availability, Outcome, Status},
        proxyinstallation::{ExecutionMode, Interface, TunnelOwnerInstallation},
    };
    for failure in [Some(ProbeProblem::Dns), Some(ProbeProblem::Http(403)), None] {
        let host = TestHost::running().into_host();
        host.state.borrow_mut().ws_failure = failure.map(|problem| (2, problem));
        let mut bridge = TunnelOwnerInstallation::new(host, ExecutionMode::InjectedHost);
        let prepared = bridge.review(Action::CheckVmessTunnel).prepared.unwrap();
        let mut output = Vec::new();
        let result = bridge
            .execute_output(prepared, Confirmation::Approved, &mut output)
            .unwrap();
        assert_eq!(result.status, Status::Running);
        assert_eq!(result.proxy_traffic, Availability::ProvedWorking);
        assert_eq!(
            result.outcome,
            if failure.is_some() {
                Outcome::VmessConnectionPending
            } else {
                Outcome::VmessConnectionVerified
            }
        );
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains(if failure.is_some() {
                "PublicWebSocket"
            } else {
                "Complete"
            }),
            "{output}"
        );
        if let Some(problem) = failure {
            assert!(output.contains(&problem.to_string()), "{output}");
        }
        assert!(!output.contains(HOSTNAME));
        assert!(!output.contains(TOKEN_ID));
        assert!(!output.contains(&String::from_utf8(token()).unwrap()));
        let prepared = bridge.review(Action::CheckVmessTunnel).prepared.unwrap();
        let mut output = Vec::new();
        assert_eq!(
            bridge
                .execute_output(prepared, Confirmation::Declined, &mut output)
                .unwrap()
                .outcome,
            Outcome::Cancelled
        );
        assert!(output.is_empty(), "must not replay previous diagnostics");
    }
}

#[test]
fn terminal_renders_diagnostics_for_tunnel_setup_check_and_finish() {
    use sbxr::proxyinstallation::{ExecutionMode, TunnelOwnerInstallation};
    for journey in ["setup", "check", "finish"] {
        let (host, input) = match journey {
            "setup" => (TestHost::new(), format!("1\n2\ny\n{HOSTNAME}\ny\n0\n")),
            "check" => (TestHost::running().into_host(), "1\n0\n".into()),
            "finish" => {
                let host = TestHost::new();
                let stop = host.stop.clone();
                host.state.borrow_mut().fail_effect = Some(Effect::StartConnector);
                let mut setup = TunnelInstallation::new(host);
                let prepared = setup
                    .review_setup(HOSTNAME, configuration(HOSTNAME), &stop)
                    .unwrap();
                assert_eq!(
                    setup.execute(prepared, Confirmation::Approved, &stop),
                    Err(Error::Effect(Effect::StartConnector))
                );
                assert_eq!(
                    setup.host().record().unwrap().recovery_direction(),
                    RecoveryDirection::FinishSetup
                );
                (setup.into_host().reopen(), "1\ny\n0\n".into())
            }
            _ => unreachable!(),
        };
        host.state.borrow_mut().ws_failure = Some((2, ProbeProblem::Http(403)));
        let mut bridge = TunnelOwnerInstallation::new(host, ExecutionMode::InjectedHost);
        let mut output = Vec::new();
        sbxr::terminal::run(&mut input.as_bytes(), &mut output, &mut bridge).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output
                .matches("VMess connection check stage: PublicWebSocket")
                .count(),
            1,
            "{journey}: {output}"
        );
        assert_eq!(
            output
                .matches("VMess connection check problem: HTTP 403 (unexpected status)")
                .count(),
            1,
            "{journey}: {output}"
        );
        assert!(
            output.contains("VMess public connection pending"),
            "{journey}: {output}"
        );
        assert!(
            output.contains("Proxy status: Running"),
            "{journey}: {output}"
        );
        assert!(!output.contains(&String::from_utf8(token()).unwrap()));
    }
}
