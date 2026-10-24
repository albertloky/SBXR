use base64::{Engine, engine::general_purpose::STANDARD};
use sbxr::host::tunnel_native::{Connector, ConnectorAction, ConnectorIo, ConnectorQuery};
use sbxr::host::{
    HostError,
    locks::HostLock,
    process::{Cancellation, CommandOutput},
};
use sbxr::runtime_handoff::ProcessIdentity;
use sbxr::tunnel_setup::{Error, FileFacts, Prerequisites};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "tn-native-{}-{}",
            std::process::id(),
            getrandom::u64().unwrap()
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn file(&self, p: &str, b: &[u8], mode: u32) {
        let p = self.0.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Clone, Default)]
struct Io(Arc<Mutex<Vec<ConnectorAction>>>);
impl ConnectorIo for Io {
    fn query(
        &self,
        q: ConnectorQuery,
        _: &Cancellation,
        _: Duration,
    ) -> Result<CommandOutput, HostError> {
        CommandOutput::completed(0,match q {ConnectorQuery::Version=>b"cloudflared version 2025.4.0".to_vec(),ConnectorQuery::Properties=>b"LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n".to_vec(),ConnectorQuery::Listener(_)=>Vec::new()})
    }
    fn command(
        &self,
        a: ConnectorAction,
        g: &Arc<HostLock>,
        _: &Cancellation,
    ) -> Result<(), HostError> {
        g.verify()?;
        self.0.lock().unwrap().push(a);
        Ok(())
    }
    fn process(&self, _: u32) -> Result<ProcessIdentity, HostError> {
        Err(HostError::LiveUnavailable)
    }
    fn quiescent(&self, _: &Cancellation) -> Result<bool, HostError> {
        Ok(true)
    }
}
fn root() -> Root {
    let r = Root::new();
    r.file(
        "etc/cloudflared/sbxr.token",
        STANDARD
            .encode(include_bytes!("testdata/tunnel_setup/token-claims.json"))
            .as_bytes(),
        0o600,
    );
    r.file(
        "usr/bin/cloudflared",
        b"inert fixture binary, never executed",
        0o755,
    );
    r
}
#[test]
fn protected_prerequisites_read_exact_synthetic_token_and_refuse_hardlinks() {
    let r = root();
    let c = Connector::injected(&r.0, Io::default()).unwrap();
    let p = c.prerequisites(&Cancellation::new()).unwrap();
    assert_eq!(
        p.authority().tunnel_id(),
        "12345678-1234-1234-1234-123456789abc"
    );
    fs::hard_link(
        r.0.join("etc/cloudflared/sbxr.token"),
        r.0.join("token-copy"),
    )
    .unwrap();
    assert_eq!(c.prerequisites(&Cancellation::new()), Err(Error::TokenFile));
}
#[test]
fn native_constructor_refuses_injected_root_and_prerequisites_preserve_files() {
    let r = root();
    assert!(Connector::injected(Path::new("/"), Io::default()).is_err());
    let c = Connector::injected(&r.0, Io::default()).unwrap();
    let before = fs::read(r.0.join("etc/cloudflared/sbxr.token")).unwrap();
    c.prerequisites(&Cancellation::new()).unwrap();
    assert_eq!(
        fs::read(r.0.join("etc/cloudflared/sbxr.token")).unwrap(),
        before
    );
}
#[test]
fn unrecorded_or_foreign_connector_residue_refuses_without_commands() {
    let r = root();
    r.file("etc/systemd/system/sbxr-tunnel.service", b"foreign", 0o644);
    let io = Io::default();
    let c = Connector::injected(&r.0, io.clone()).unwrap();
    assert!(c.inspect(false, &Cancellation::new()).is_err());
    assert!(io.0.lock().unwrap().is_empty());
}
#[test]
fn prerequisite_pure_claims_remain_compatible() {
    let f = |mode| FileFacts {
        uid: 0,
        mode,
        links: 1,
        regular: true,
        stable: true,
        protected_parents: true,
    };
    let p = Prerequisites::inspect(
        STANDARD
            .encode(include_bytes!("testdata/tunnel_setup/token-claims.json"))
            .as_bytes(),
        f(0o600),
        b"binary",
        f(0o755),
        "cloudflared version 2025.4.0",
    );
    assert!(p.is_ok());
}

use sbxr::host::tunnel_native::{
    LoopbackNetwork, NativeProbeSession, ProbeNetwork, ProbeObservations,
};
use sbxr::tunnel_setup::{
    self as t, Budget, ProbePlan, ProbeProblem, WebSocketReply, WebSocketRequest,
};
use sbxr::{
    records::{OwnershipRecord, ReleaseIdentity, sha256_hex},
    server_configuration::{ServerConfiguration, ServerIdentity},
};
use std::{
    io::{Read, Write},
    net::{SocketAddrV4, TcpListener, TcpStream},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread,
    time::Instant,
};
fn config() -> ServerConfiguration {
    ServerConfiguration::standard(
        &ServerIdentity::from_private_key(
            "00112233-4455-4677-8899-aabbccddeeff",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "01234567",
        )
        .unwrap(),
    )
    .unwrap()
    .with_vmess_websocket("fixture.example.com")
    .unwrap()
}
fn release() -> ReleaseIdentity {
    ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap()
}
fn running_record() -> OwnershipRecord {
    let mut r = OwnershipRecord::new_tunnel_setup(
        release(),
        "8.8.8.8",
        &config().sha256_hex(),
        Prerequisites::inspect(
            STANDARD
                .encode(include_bytes!("testdata/tunnel_setup/token-claims.json"))
                .as_bytes(),
            FileFacts {
                uid: 0,
                mode: 0o600,
                links: 1,
                regular: true,
                stable: true,
                protected_parents: true,
            },
            b"binary",
            FileFacts {
                uid: 0,
                mode: 0o755,
                links: 1,
                regular: true,
                stable: true,
                protected_parents: true,
            },
            "cloudflared version 2025.4.0",
        )
        .unwrap()
        .authority()
        .clone(),
    )
    .unwrap();
    while r.phase() != sbxr::records::SetupPhase::Running {
        r = r.next_setup_checkpoint().unwrap();
    }
    r
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &include_bytes!("testdata/tunnel_native/ca.pem")[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    roots
}
fn server_tls() -> rustls::ServerConfig {
    let cert = rustls_pemfile::certs(&mut &include_bytes!("testdata/tunnel_native/server.pem")[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(
        &mut &include_bytes!("testdata/tunnel_native/server-key.pem")[..],
    )
    .unwrap()
    .unwrap();
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap()
}
fn read_header(s: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut b = [0];
    while bytes.len() < 20000 && !bytes.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => bytes.push(b[0]),
            _ => break,
        }
    }
    bytes
}
#[derive(Clone, Copy)]
enum ReplyMode {
    Upgrade,
    Redirect,
    Oversized,
    Duplicate,
    Stall,
    StallTls,
}
fn ws_server(tls: bool, mode: ReplyMode) -> (SocketAddrV4, thread::JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let std::net::SocketAddr::V4(addr) = l.local_addr().unwrap() else {
        unreachable!()
    };
    let join = thread::spawn(move || {
        let (socket, _) = l.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if matches!(mode, ReplyMode::StallTls) {
            thread::sleep(Duration::from_millis(180));
            return Vec::new();
        }
        let mut s: Box<dyn ReadWrite> = if tls {
            Box::new(rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(server_tls())).unwrap(),
                socket,
            ))
        } else {
            Box::new(socket)
        };
        let request = read_header(&mut s);
        if matches!(mode, ReplyMode::Stall) {
            thread::sleep(Duration::from_millis(180));
            return request;
        }
        let text = String::from_utf8_lossy(&request);
        let key = text
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap_or("");
        let response = match mode {
            ReplyMode::Upgrade => format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                t::websocket_accept(key)
            ),
            ReplyMode::Redirect => {
                "HTTP/1.1 302 Found\r\nLocation: https://foreign.invalid\r\n\r\n".into()
            }
            ReplyMode::Oversized => format!(
                "HTTP/1.1 101 Switching Protocols\r\nX-Oversized: {}\r\n\r\n",
                "a".repeat(17000)
            ),
            ReplyMode::Duplicate => format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                t::websocket_accept(key),
                t::websocket_accept(key)
            ),
            _ => unreachable!(),
        };
        let _ = s.write_all(response.as_bytes());
        let _ = s.flush();
        request
    });
    (addr, join)
}
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
#[derive(Clone)]
struct Observations {
    hash: String,
    port: u16,
    sabotage: bool,
    observed: Arc<Mutex<usize>>,
}
impl ProbeObservations for Observations {
    fn process(&self, pid: u32) -> Result<ProcessIdentity, ProbeProblem> {
        let mut n = self.observed.lock().unwrap();
        *n += 1;
        ProcessIdentity::new(
            pid,
            std::process::id(),
            if self.sabotage && *n > 2 { 2 } else { 1 },
            rustix::process::geteuid().as_raw(),
            &self.hash,
            "/fixture/probe",
        )
        .map_err(|_| ProbeProblem::Listener)
    }
    fn listeners(&self, port: u16, _: &Budget<'_>) -> Result<String, ProbeProblem> {
        assert_eq!(port, self.port);
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(20),
        )
        .is_err()
        {
            return Ok(String::new());
        }
        let n = *self.observed.lock().unwrap();
        let _ = n;
        Ok(format!(
            "LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:* users:((\"probe\",pid={},fd=3))",
            CHILD_PID.with(|p| p.get())
        ))
    }
}
thread_local! {static CHILD_PID:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};}
struct Harness {
    root: Root,
    network: ProbeNetwork,
    record: OwnershipRecord,
    spawned: Arc<Mutex<Option<u32>>>,
    child_mode: String,
    sabotage: bool,
    stop_after_spawn: bool,
    skip_ws: bool,
    bad_root: bool,
}
impl Harness {
    fn new(network: ProbeNetwork) -> Self {
        Self {
            root: root(),
            network,
            record: running_record(),
            spawned: Arc::new(Mutex::new(None)),
            child_mode: "valid".into(),
            sabotage: false,
            stop_after_spawn: false,
            skip_ws: false,
            bad_root: false,
        }
    }
}
impl t::Host for Harness {
    type Guard = ();
    type Probe = NativeProbeSession<Observations>;
    fn acquire(&mut self, _: &Cancellation) -> Result<(), Error> {
        Ok(())
    }
    fn verify_guard(&mut self, _: &()) -> Result<(), Error> {
        Ok(())
    }
    fn installed_release(&mut self, _: &()) -> Result<ReleaseIdentity, Error> {
        Ok(release())
    }
    fn public_ipv4(&mut self, _: &()) -> Result<String, Error> {
        Ok("8.8.8.8".into())
    }
    fn snapshot(&mut self, _: &()) -> Result<t::Snapshot, Error> {
        Ok(t::Snapshot {
            current: Some(self.record.encode().unwrap()),
            staged: None,
        })
    }
    fn prerequisites(&mut self, _: &(), _: &Cancellation) -> Result<Prerequisites, Error> {
        Err(Error::Authority)
    }
    fn inspect(
        &mut self,
        _: &(),
        _: Option<&OwnershipRecord>,
        _: &Cancellation,
    ) -> Result<t::Inspection, Error> {
        Ok(t::Inspection {
            fingerprint: "fixture".into(),
            empty: false,
            ready: true,
            stopped: false,
            running: true,
        })
    }
    fn configuration(&mut self, _: &(), _: &OwnershipRecord) -> Result<Vec<u8>, Error> {
        Ok(config().as_bytes().to_vec())
    }
    fn synchronize(&mut self, _: &(), _: &[u8]) -> Result<(), Error> {
        Err(Error::Authority)
    }
    fn publish(&mut self, _: &(), _: Option<&[u8]>, _: &OwnershipRecord) -> Result<(), Error> {
        Err(Error::Authority)
    }
    fn effect(
        &mut self,
        _: &(),
        _: t::Effect,
        _: &OwnershipRecord,
        _: Option<&ServerConfiguration>,
        _: &Cancellation,
    ) -> Result<(), Error> {
        Err(Error::Authority)
    }
    fn remove_completed_cleanup(&mut self, _: &(), _: &[u8]) -> Result<(), Error> {
        Err(Error::Authority)
    }
    fn websocket(
        &mut self,
        _: &(),
        r: &WebSocketRequest,
        b: &Budget<'_>,
    ) -> Result<WebSocketReply, ProbeProblem> {
        if self.skip_ws {
            Ok(WebSocketReply {
                status: 101,
                headers: vec![
                    ("Upgrade".into(), "websocket".into()),
                    ("Connection".into(), "Upgrade".into()),
                    ("Sec-WebSocket-Accept".into(), t::websocket_accept(r.key())),
                ],
                trusted_tls: r.trusted_tls_required(),
                redirected: false,
            })
        } else {
            self.network.websocket(r, b)
        }
    }
    fn probe_port(&mut self, _: &(), _: &Budget<'_>) -> Result<u16, ProbeProblem> {
        Ok(TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port())
    }
    fn spawn_probe(
        &mut self,
        _: &(),
        plan: &ProbePlan,
        b: &Budget<'_>,
    ) -> Result<Self::Probe, ProbeProblem> {
        let value: serde_json::Value = serde_json::from_slice(plan.as_bytes()).unwrap();
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(value["outbounds"][0]["type"], "vmess");
        assert_eq!(value["route"]["final"], "vmess-only");
        assert!(value["outbounds"][0]["tls"]["insecure"].is_null());
        let executable = std::env::current_exe().unwrap();
        let hash = sha256_hex(&fs::read(&executable).unwrap());
        let child = Command::new(&executable)
            .args(["--exact", "synthetic_probe_child", "--nocapture"])
            .env_clear()
            .env("SBXR_TUNNEL_FIXTURE_CHILD", &self.child_mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        CHILD_PID.with(|p| p.set(pid));
        *self.spawned.lock().unwrap() = Some(pid);
        let obs = Observations {
            hash: hash.clone(),
            port: plan.port(),
            sabotage: self.sabotage,
            observed: Arc::new(Mutex::new(0)),
        };
        let session = NativeProbeSession::injected(
            if self.bad_root {
                Path::new("/")
            } else {
                &self.root.0
            },
            child,
            plan,
            &hash,
            obs,
            self.network.clone(),
            b,
        )?;
        if self.stop_after_spawn {
            b.cancellation().cancel();
        }
        Ok(session)
    }
}
#[test]
fn synthetic_probe_child() {
    let Ok(mode) = std::env::var("SBXR_TUNNEL_FIXTURE_CHILD") else {
        return;
    };
    if mode == "exit" {
        return;
    }
    if mode == "blocked-stdin" {
        thread::sleep(Duration::from_secs(20));
        return;
    }
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let port = value["inbounds"][0]["listen_port"].as_u64().unwrap() as u16;
    let password = value["inbounds"][0]["users"][0]["password"]
        .as_str()
        .unwrap();
    let expected = format!(
        "Proxy-Authorization: Basic {}",
        STANDARD.encode(format!("sbxr-probe:{password}"))
    );
    if mode == "descendant" {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "synthetic_descendant_child"])
            .env("SBXR_TUNNEL_DESCENDANT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::spawn(move || {
            let _ = child.wait();
        });
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    for socket in listener.incoming() {
        let mut socket = socket.unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = read_header(&mut socket);
        if request.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("CONNECT api.ipify.org:443 HTTP/1.1\r\n"));
        assert!(text.lines().any(|l| l == expected));
        if mode == "auth-refuse" {
            socket
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .unwrap();
            continue;
        }
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(server_tls())).unwrap(),
            socket,
        );
        let request = read_header(&mut tls);
        if request.is_empty() {
            continue;
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\n"));
        assert!(
            !String::from_utf8_lossy(&request)
                .to_lowercase()
                .contains("authorization")
        );
        let body = if mode == "wrong-egress" {
            "1.1.1.1"
        } else {
            "8.8.8.8"
        };
        let response = if mode == "oversized-egress" {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n{}",
                "a".repeat(128)
            )
        } else if mode == "redirect-egress" {
            "HTTP/1.1 302 Found\r\nLocation: https://foreign.invalid\r\n\r\n".into()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let _ = tls.write_all(response.as_bytes());
        let _ = tls.flush();
    }
}
fn network(local: SocketAddrV4, public: SocketAddrV4) -> ProbeNetwork {
    ProbeNetwork::injected(
        roots(),
        LoopbackNetwork {
            local_origin: local,
            public_hostname: "fixture.example.com".into(),
            public_address: public,
        },
    )
    .unwrap()
}
fn assert_reaped(pid: u32) {
    let p = rustix::process::Pid::from_raw(pid as i32).unwrap();
    assert_eq!(
        rustix::process::test_kill_process(p),
        Err(rustix::io::Errno::SRCH)
    );
}
#[test]
fn actual_loopback_tls_ws_and_authenticated_connect_complete_without_direct_fallback() {
    let (local, a) = ws_server(false, ReplyMode::Upgrade);
    let (public, b) = ws_server(true, ReplyMode::Upgrade);
    let h = Harness::new(network(local, public));
    let spawned = h.spawned.clone();
    let mut t = t::TunnelInstallation::new(h);
    let result = t.check_connection(&Cancellation::new());
    assert!(
        result.verified(),
        "{:?}: {:?}",
        result.stage(),
        result.problem()
    );
    assert_reaped(spawned.lock().unwrap().unwrap());
    let local = String::from_utf8(a.join().unwrap()).unwrap();
    assert!(local.contains("GET /sbxr-vmess HTTP/1.1"));
    assert!(!local.to_lowercase().contains("authorization"));
    assert!(
        String::from_utf8(b.join().unwrap())
            .unwrap()
            .contains("Host: fixture.example.com")
    );
}
#[test]
fn actual_ws_rejects_redirect_duplicates_and_header_overflow() {
    for (mode, expected) in [
        (ReplyMode::Redirect, ProbeProblem::Redirect),
        (ReplyMode::Duplicate, ProbeProblem::Headers),
        (ReplyMode::Oversized, ProbeProblem::Headers),
    ] {
        let (local, a) = ws_server(false, mode);
        let mut t = t::TunnelInstallation::new(Harness::new(network(local, local)));
        let result = t.check_connection(&Cancellation::new());
        assert_eq!(result.problem(), Some(expected));
        assert_eq!(result.stage(), t::CheckStage::LocalWebSocket);
        a.join().unwrap();
    }
}
#[test]
fn ws_deadline_and_cancellation_interrupt_a_stalled_read() {
    for cancel in [false, true] {
        let (local, a) = ws_server(false, ReplyMode::Stall);
        let mut t = t::TunnelInstallation::new(Harness::new(network(local, local)));
        let stop = Cancellation::new();
        let started = Instant::now();
        thread::scope(|scope| {
            if cancel {
                let stop = stop.clone();
                scope.spawn(move || {
                    thread::sleep(Duration::from_millis(40));
                    stop.cancel();
                });
            }
            let result = t.check_connection_with_entropy(
                &stop,
                Duration::from_millis(if cancel { 1000 } else { 60 }),
                &mut sbxr::identity_generation::OsEntropy,
            );
            assert_eq!(
                result.problem(),
                Some(if cancel {
                    ProbeProblem::Cancelled
                } else {
                    ProbeProblem::TimedOut
                })
            );
        });
        assert!(started.elapsed() < Duration::from_millis(160));
        a.join().unwrap();
    }
}
#[test]
fn vmess_probe_rejects_changed_identity_wrong_egress_auth_failure_and_redirects_then_reaps() {
    for (mode, sabotage, expected) in [
        ("valid", true, ProbeProblem::Listener),
        ("wrong-egress", false, ProbeProblem::Egress),
        ("auth-refuse", false, ProbeProblem::Traffic),
        ("oversized-egress", false, ProbeProblem::Egress),
        ("redirect-egress", false, ProbeProblem::Redirect),
    ] {
        let address = "127.0.0.1:12345".parse().unwrap();
        let mut h = Harness::new(network(address, address));
        h.skip_ws = true;
        h.child_mode = mode.into();
        h.sabotage = sabotage;
        let spawned = h.spawned.clone();
        let mut t = t::TunnelInstallation::new(h);
        let result = t.check_connection(&Cancellation::new());
        assert_eq!(
            result.problem(),
            Some(expected),
            "mode={mode} stage={:?}",
            result.stage()
        );
        assert_reaped(spawned.lock().unwrap().unwrap());
    }
}
#[test]
fn cancelled_session_uses_independent_process_group_cleanup() {
    let address = "127.0.0.1:12345".parse().unwrap();
    let mut h = Harness::new(network(address, address));
    h.skip_ws = true;
    h.stop_after_spawn = true;
    h.child_mode = "blocked-stdin".into();
    let spawned = h.spawned.clone();
    let mut t = t::TunnelInstallation::new(h);
    let result = t.check_connection(&Cancellation::new());
    assert_eq!(result.problem(), Some(ProbeProblem::Cancelled));
    assert_reaped(spawned.lock().unwrap().unwrap());
}

#[derive(Clone)]
struct SystemIo {
    root: PathBuf,
    state: Arc<Mutex<SystemState>>,
}
#[derive(Default)]
struct SystemState {
    active: bool,
    effective_override: Option<(&'static str, &'static str)>,
    commands: Vec<ConnectorAction>,
    replace_binary: bool,
}
impl SystemIo {
    fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            state: Arc::default(),
        }
    }
}
impl ConnectorIo for SystemIo {
    fn query(
        &self,
        q: ConnectorQuery,
        _: &Cancellation,
        _: Duration,
    ) -> Result<CommandOutput, HostError> {
        let state = self.state.lock().unwrap();
        let bytes = match q {
            ConnectorQuery::Version => {
                if state.replace_binary {
                    fs::write(self.root.join("usr/bin/cloudflared"), b"changed-binary").unwrap();
                }
                b"cloudflared version 2025.4.0".to_vec()
            }
            ConnectorQuery::Listener(_) => Vec::new(),
            ConnectorQuery::Properties => {
                let exists = self
                    .root
                    .join("etc/systemd/system/sbxr-tunnel.service")
                    .exists();
                let mut props = std::collections::BTreeMap::from([
                    (
                        "LoadState",
                        if exists { "loaded" } else { "not-found" }.to_owned(),
                    ),
                    (
                        "ActiveState",
                        if state.active { "active" } else { "inactive" }.into(),
                    ),
                    ("MainPID", if state.active { "42" } else { "0" }.into()),
                    ("ControlPID", "0".into()),
                    (
                        "ControlGroup",
                        if state.active {
                            "/system.slice/sbxr-tunnel.service"
                        } else {
                            ""
                        }
                        .into(),
                    ),
                ]);
                if exists {
                    for (k, v) in [
                        ("FragmentPath", "/etc/systemd/system/sbxr-tunnel.service"),
                        ("DropInPaths", ""),
                        ("ExecCondition", ""),
                        ("ExecStartPre", ""),
                        ("ExecStartPost", ""),
                        ("ExecReload", ""),
                        ("ExecStop", ""),
                        ("ExecStopPost", ""),
                        ("KillMode", "control-group"),
                        ("DynamicUser", "yes"),
                        ("LoadCredential", "tunnel-token:/etc/cloudflared/sbxr.token"),
                        (
                            "ExecStart",
                            "/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file /run/credentials/sbxr-tunnel.service/tunnel-token",
                        ),
                    ] {
                        props.insert(k, v.into());
                    }
                }
                if let Some((k, v)) = state.effective_override {
                    props.insert(k, v.into());
                }
                props
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}\n"))
                    .collect::<String>()
                    .into_bytes()
            }
        };
        CommandOutput::completed(0, bytes)
    }
    fn command(
        &self,
        a: ConnectorAction,
        g: &Arc<HostLock>,
        _: &Cancellation,
    ) -> Result<(), HostError> {
        g.verify()?;
        assert!(HostLock::existing(&self.root, rustix::process::geteuid().as_raw()).is_err());
        let mut state = self.state.lock().unwrap();
        state.commands.push(a);
        match a {
            ConnectorAction::Start => state.active = true,
            ConnectorAction::Stop => state.active = false,
            ConnectorAction::Reload => {}
        }
        Ok(())
    }
    fn process(&self, pid: u32) -> Result<ProcessIdentity, HostError> {
        ProcessIdentity::new(
            pid,
            1,
            10,
            42,
            &sha256_hex(b"inert fixture binary, never executed"),
            "/system.slice/sbxr-tunnel.service",
        )
        .map_err(|_| HostError::Foreign)
    }
    fn quiescent(&self, _: &Cancellation) -> Result<bool, HostError> {
        Ok(!self.state.lock().unwrap().active)
    }
}
#[test]
fn exact_connector_install_start_and_cleanup_retain_guard_and_preserve_prerequisites() {
    let r = root();
    let stop = Cancellation::new();
    let io = SystemIo::new(&r.0);
    let mut c = Connector::injected(&r.0, io.clone()).unwrap();
    let authority = c.prerequisites(&stop).unwrap().authority().clone();
    let lock = Arc::new(HostLock::acquire(&r.0, rustix::process::geteuid().as_raw()).unwrap());
    assert!(c.inspect(false, &stop).unwrap().empty);
    c.install(&lock, &stop).unwrap();
    assert!(c.inspect(true, &stop).unwrap().installed);
    assert_eq!(
        fs::read(r.0.join("etc/systemd/system/sbxr-tunnel.service")).unwrap(),
        sbxr::server_configuration::tunnel_unit().as_bytes()
    );
    assert_eq!(
        fs::read_link(r.0.join("etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"))
            .unwrap(),
        Path::new("../sbxr-tunnel.service")
    );
    c.start(&lock, &stop).unwrap();
    assert!(c.inspect(true, &stop).unwrap().running);
    // Removing missing prerequisites must still use durable binary ownership.
    fs::remove_file(r.0.join("etc/cloudflared/sbxr.token")).unwrap();
    fs::remove_file(r.0.join("usr/bin/cloudflared")).unwrap();
    c.remove(&lock, &authority, &stop).unwrap();
    assert!(c.inspect(false, &stop).unwrap().empty);
    assert_eq!(
        io.state.lock().unwrap().commands,
        [
            ConnectorAction::Reload,
            ConnectorAction::Start,
            ConnectorAction::Stop,
            ConnectorAction::Reload
        ]
    );
}
#[test]
fn connector_refuses_foreign_dropins_aliases_links_effective_commands_and_version_replacement() {
    for path in [
        "run/systemd/system/sbxr-tunnel.service",
        "etc/systemd/system/sbxr-tunnel.service.d/foreign.conf",
        "usr/lib/systemd/system/multi-user.target.requires/sbxr-tunnel.service",
    ] {
        let r = root();
        r.file(path, b"foreign", 0o644);
        let c = Connector::injected(&r.0, SystemIo::new(&r.0)).unwrap();
        assert!(c.inspect(false, &Cancellation::new()).is_err());
    }
    for (key, value) in [
        ("ExecStart", "/usr/bin/cloudflared --token secret"),
        ("ExecStartPre", "/bin/true"),
        ("LoadCredential", "foreign:/tmp/token"),
        ("DynamicUser", "no"),
        ("KillMode", "process"),
        ("FragmentPath", "/run/systemd/system/sbxr-tunnel.service"),
        ("DropInPaths", "/etc/foreign.conf"),
    ] {
        let r = root();
        let io = SystemIo::new(&r.0);
        let mut c = Connector::injected(&r.0, io.clone()).unwrap();
        let lock = Arc::new(HostLock::acquire(&r.0, rustix::process::geteuid().as_raw()).unwrap());
        c.install(&lock, &Cancellation::new()).unwrap();
        io.state.lock().unwrap().effective_override = Some((key, value));
        assert!(c.start(&lock, &Cancellation::new()).is_err(), "{key}");
        assert_eq!(io.state.lock().unwrap().commands, [ConnectorAction::Reload]);
    }
    let r = root();
    let io = SystemIo::new(&r.0);
    io.state.lock().unwrap().replace_binary = true;
    let c = Connector::injected(&r.0, io).unwrap();
    assert_eq!(
        c.prerequisites(&Cancellation::new()),
        Err(Error::PrerequisitesChanged)
    );
}
#[test]
fn protected_reads_refuse_symlinks_insecure_parents_and_incorrect_modes() {
    for change in [0, 1, 2] {
        let r = root();
        match change {
            0 => {
                fs::rename(r.0.join("etc/cloudflared/sbxr.token"), r.0.join("token")).unwrap();
                std::os::unix::fs::symlink("../../token", r.0.join("etc/cloudflared/sbxr.token"))
                    .unwrap();
            }
            1 => fs::set_permissions(
                r.0.join("etc/cloudflared"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap(),
            _ => fs::set_permissions(
                r.0.join("usr/bin/cloudflared"),
                fs::Permissions::from_mode(0o775),
            )
            .unwrap(),
        };
        let c = Connector::injected(&r.0, SystemIo::new(&r.0)).unwrap();
        assert!(c.prerequisites(&Cancellation::new()).is_err());
    }
}
#[test]
fn trusted_public_ws_rejects_untrusted_certificate_and_tls_stall() {
    for stall in [false, true] {
        let (local, a) = ws_server(false, ReplyMode::Upgrade);
        let (public, b) = ws_server(
            true,
            if stall {
                ReplyMode::StallTls
            } else {
                ReplyMode::Upgrade
            },
        );
        let network = if stall {
            network(local, public)
        } else {
            ProbeNetwork::injected(
                rustls::RootCertStore::empty(),
                LoopbackNetwork {
                    local_origin: local,
                    public_hostname: "fixture.example.com".into(),
                    public_address: public,
                },
            )
            .unwrap()
        };
        let mut t = t::TunnelInstallation::new(Harness::new(network));
        let result = t.check_connection_with_entropy(
            &Cancellation::new(),
            Duration::from_millis(if stall { 100 } else { 1000 }),
            &mut sbxr::identity_generation::OsEntropy,
        );
        assert_eq!(result.stage(), t::CheckStage::PublicWebSocket);
        assert_eq!(
            result.problem(),
            Some(if stall {
                ProbeProblem::TimedOut
            } else {
                ProbeProblem::TlsCertificate
            })
        );
        a.join().unwrap();
        b.join().unwrap();
    }
}

#[test]
fn synthetic_descendant_child() {
    if std::env::var_os("SBXR_TUNNEL_DESCENDANT").is_some() {
        thread::sleep(Duration::from_secs(20));
    }
}
#[test]
fn spawn_refusal_and_early_exit_drop_the_owned_process_group() {
    for bad_root in [false, true] {
        let address = "127.0.0.1:12345".parse().unwrap();
        let mut h = Harness::new(network(address, address));
        h.skip_ws = true;
        h.bad_root = bad_root;
        h.child_mode = "exit".into();
        let spawned = h.spawned.clone();
        let mut installation = t::TunnelInstallation::new(h);
        let result = installation.check_connection(&Cancellation::new());
        assert!(!result.verified());
        assert!(
            matches!(
                result.problem(),
                Some(ProbeProblem::Authority | ProbeProblem::Exited | ProbeProblem::Spawn)
            ),
            "bad_root={bad_root} actual={:?} stage={:?}",
            result.problem(),
            result.stage()
        );
        assert_reaped(spawned.lock().unwrap().unwrap());
    }
}
#[test]
fn cleanup_kills_the_probe_group_including_owned_descendants() {
    let address = "127.0.0.1:12345".parse().unwrap();
    let mut h = Harness::new(network(address, address));
    h.skip_ws = true;
    h.child_mode = "descendant".into();
    let spawned = h.spawned.clone();
    let mut installation = t::TunnelInstallation::new(h);
    let result = installation.check_connection(&Cancellation::new());
    assert!(result.verified(), "{:?}", result.problem());
    let pid = rustix::process::Pid::from_raw(spawned.lock().unwrap().unwrap() as i32).unwrap();
    assert_eq!(
        rustix::process::test_kill_process_group(pid),
        Err(rustix::io::Errno::SRCH)
    );
}
