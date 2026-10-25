#![forbid(unsafe_code)]

use sbxr::{private_roles::Role, runtime_handoff::*, subscription_serving::Cancellation};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = base.join(format!(
            "handoff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path.join("run")).unwrap();
        fs::create_dir(path.join("run/lock")).unwrap();
        fs::write(path.join("run/lock/sbxr.lock"), []).unwrap();
        fs::set_permissions(
            path.join("run/lock/sbxr.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self(path)
    }
    // Relative socket names stay inside the same owned fixture directory and
    // avoid Darwin SUN_LEN limits with a long workspace-local TMPDIR.
    fn socket(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        let cwd = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        path.strip_prefix(cwd).unwrap_or(&path).to_path_buf()
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn lock(&self) -> StartLock {
        StartLock::existing(&self.0, self.uid()).unwrap()
    }
    fn context(&self) -> StartContext {
        StartContext::new(Cancellation::new(), Instant::now() + Duration::from_secs(2))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn process(pid: u32, cgroup: &str, uid: u32) -> ProcessIdentity {
    ProcessIdentity::new(pid, 1, 123, uid, &"a".repeat(64), cgroup).unwrap()
}
struct Peers {
    current: ProcessIdentity,
    peer: ProcessIdentity,
}
impl PeerObservations for Peers {
    fn current(&self) -> Result<ProcessIdentity, Error> {
        Ok(self.current.clone())
    }
    fn peer(&self, _: &UnixStream) -> Result<ProcessIdentity, Error> {
        Ok(self.peer.clone())
    }
}

#[test]
fn ordinary_starts_serialize_without_creating_or_trusting_unsafe_locks() {
    let f = Fixture::new();
    let owner = f.lock();
    assert!(matches!(
        StartLock::existing(&f.0, f.uid()),
        Err(Error::Busy)
    ));
    drop(owner);
    drop(f.lock());
    fs::set_permissions(
        f.0.join("run/lock/sbxr.lock"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(matches!(
        StartLock::existing(&f.0, f.uid()),
        Err(Error::Refused)
    ));
    fs::remove_file(f.0.join("run/lock/sbxr.lock")).unwrap();
    assert!(StartLock::existing(&f.0, f.uid()).is_err());
    assert!(!f.0.join("run/lock/sbxr.lock").exists());
}

#[test]
fn descriptor_handoff_is_one_use_and_borrower_never_unlocks_owner() {
    let f = Fixture::new();
    let owner = f.lock();
    let lender = process(100, "/user.slice/owner.scope", f.uid());
    let child = process(101, SUBSCRIPTION_CGROUP, f.uid());
    let socket = f.socket("one.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let context = f.context();
    thread::scope(|scope| {
        let offer =
            Handoff::new(listener, &owner, Role::SubscriptionServing, child.clone()).unwrap();
        let lender_observations = Peers {
            current: lender.clone(),
            peer: child.clone(),
        };
        let context_ref = &context;
        let accepting = scope.spawn(move || offer.accept(&lender_observations, context_ref));
        let client_observations = Peers {
            current: child,
            peer: lender.clone(),
        };
        let borrowed = borrow(
            UnixStream::connect(&socket).unwrap(),
            &f.0,
            Role::SubscriptionServing,
            &lender,
            &client_observations,
            &context,
        )
        .unwrap();
        assert!(borrowed.is_borrowed());
        assert!(
            borrowed.descriptor().is_err(),
            "borrower must not lend onward"
        );
        drop(borrowed);
        assert_eq!(accepting.join().unwrap(), Ok(()));
        assert!(
            UnixStream::connect(&socket).is_err(),
            "consumed listener remained open"
        );
    });
    owner.verify().unwrap();
    assert!(matches!(
        StartLock::existing(&f.0, f.uid()),
        Err(Error::Busy)
    ));
}

#[test]
fn arbitrary_cli_process_and_wrong_role_do_not_authorize_start() {
    let f = Fixture::new();
    let owner = f.lock();
    let arbitrary = process(100, "/user.slice/interactive.scope", f.uid());
    let (stream, _other) = UnixStream::pair().unwrap();
    let observations = Peers {
        current: arbitrary.clone(),
        peer: arbitrary.clone(),
    };
    assert!(
        borrow(
            stream,
            &f.0,
            Role::SubscriptionServing,
            &arbitrary,
            &observations,
            &f.context()
        )
        .is_err()
    );
    let listener = UnixListener::bind(f.socket("invalid.sock")).unwrap();
    assert!(Handoff::new(listener, &owner, Role::RenewalDeploy, arbitrary.clone()).is_err());
    let listener = UnixListener::bind(f.socket("outside.sock")).unwrap();
    assert!(Handoff::new(listener, &owner, Role::SubscriptionServing, arbitrary).is_err());
}

#[test]
fn refused_peer_consumes_handoff_and_cannot_receive_a_descriptor() {
    let f = Fixture::new();
    let owner = f.lock();
    let expected = process(200, SUBSCRIPTION_CGROUP, f.uid());
    let mut stale = expected.clone();
    stale.start_ticks += 1;
    let observations = Peers {
        current: process(201, "/owner.scope", f.uid()),
        peer: stale,
    };
    let socket = f.socket("refuse.sock");
    let offer = Handoff::new(
        UnixListener::bind(&socket).unwrap(),
        &owner,
        Role::SubscriptionServing,
        expected,
    )
    .unwrap();
    let context = f.context();
    thread::scope(|scope| {
        let accepting = scope.spawn(|| offer.accept(&observations, &context));
        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let _ = client.write_all(b"--subscription-serving\n");
        let mut byte = [0];
        assert!(!matches!(client.read(&mut byte), Ok(1)));
        assert_eq!(accepting.join().unwrap(), Err(Error::Refused));
        assert!(UnixStream::connect(&socket).is_err());
    });
    assert!(matches!(
        StartLock::existing(&f.0, f.uid()),
        Err(Error::Busy)
    ));
}

#[test]
fn stalled_handoff_obeys_cancellation_and_absolute_deadline() {
    let f = Fixture::new();
    let lender = process(300, "/owner.scope", f.uid());
    let observations = Peers {
        current: process(301, SUBSCRIPTION_CGROUP, f.uid()),
        peer: lender.clone(),
    };
    for cancel in [false, true] {
        let stop = Cancellation::new();
        let context = StartContext::new(stop.clone(), Instant::now() + Duration::from_millis(100));
        let (client, _stalled) = UnixStream::pair().unwrap();
        let began = Instant::now();
        thread::scope(|scope| {
            if cancel {
                scope.spawn(|| {
                    thread::sleep(Duration::from_millis(20));
                    stop.cancel();
                });
            }
            let result = borrow(
                client,
                &f.0,
                Role::SubscriptionServing,
                &lender,
                &observations,
                &context,
            );
            assert!(
                matches!(result, Err(Error::Cancelled)) && cancel
                    || matches!(result, Err(Error::Deadline)) && !cancel
            );
        });
        assert!(began.elapsed() < Duration::from_secs(1));
    }
}

#[test]
fn inode_replacement_invalidates_retained_authority() {
    let f = Fixture::new();
    let owner = f.lock();
    fs::rename(f.0.join("run/lock/sbxr.lock"), f.0.join("run/lock/prior")).unwrap();
    fs::write(f.0.join("run/lock/sbxr.lock"), []).unwrap();
    fs::set_permissions(
        f.0.join("run/lock/sbxr.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(owner.verify(), Err(Error::Refused));
    assert!(owner.descriptor().is_err());
}

#[test]
fn cancellation_stops_busy_start_and_preserves_owner() {
    let f = Fixture::new();
    let owner = f.lock();
    let stop = Cancellation::new();
    let context = StartContext::new(stop.clone(), Instant::now() + Duration::from_secs(1));
    let current = process(101, PROXY_CGROUP, f.uid());
    let observations = Peers {
        current: current.clone(),
        peer: current,
    };
    thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(30));
            stop.cancel();
        });
        let result = acquire_runtime_start(
            &f.0,
            f.uid(),
            Role::ProxyStartAuthorize,
            &observations,
            &context,
            || Err(Error::Refused),
        );
        assert!(matches!(result, Err(Error::Cancelled)));
    });
    owner.verify().unwrap();
}

#[test]
fn native_peer_proof_fails_closed_off_linux() {
    if cfg!(target_os = "linux") {
        return;
    }
    let (stream, _) = UnixStream::pair().unwrap();
    assert_eq!(LinuxPeers.peer(&stream), Err(Error::Refused));
}

use sbxr::{
    records::{HTTP_ENABLEMENT_CHECKPOINTS, OwnershipRecord, ReleaseIdentity, SetupPhase},
    server_configuration::ServerConfiguration,
    subscription_artifact::SubscriptionCredential,
    subscription_serving::{Code, Module},
};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize},
    },
};

const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn running_http() -> (OwnershipRecord, Vec<u8>) {
    let configuration = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/server_configuration/standard.json"
    ))
    .to_vec();
    let identity = ReleaseIdentity::new("v3.0.0", &"a".repeat(40), &"b".repeat(64)).unwrap();
    let mut record = OwnershipRecord::new_standard(
        identity,
        "8.8.8.8",
        &ServerConfiguration::decode_standard(&configuration)
            .unwrap()
            .sha256_hex(),
    )
    .unwrap();
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    record = record
        .begin_http_enablement(
            &"1".repeat(32),
            &SubscriptionCredential::parse(TOKEN).unwrap(),
            &"2".repeat(32),
            &"c".repeat(64),
        )
        .unwrap();
    for _ in 1..HTTP_ENABLEMENT_CHECKPOINTS.len() {
        record = record.advance_http_enablement().unwrap();
    }
    (record.commit_http_enablement().unwrap(), configuration)
}
fn sandbox() -> ServingSandbox {
    ServingSandbox {
        effective_uid: 0,
        process: SandboxProcess {
            pid: 123,
            uid: 0,
            cgroup: SUBSCRIPTION_CGROUP.into(),
            executable_path: "/usr/local/bin/sbxr".into(),
        },
        capabilities: [0; 4],
        no_new_privileges: true,
        inaccessible: [PathAccess::PermissionDenied; 5],
        cgroup_procs: b"123\n".to_vec(),
    }
}
struct ServingFixture {
    fixture: Fixture,
    record: OwnershipRecord,
    configuration: Vec<u8>,
    fault: &'static str,
    reads: AtomicUsize,
    binds: AtomicUsize,
    address: Mutex<Option<SocketAddr>>,
    watcher_started: AtomicBool,
    watcher_ended: AtomicBool,
    fail_public: AtomicBool,
}
impl ServingFixture {
    fn new(fault: &'static str) -> Self {
        let (record, configuration) = running_http();
        Self {
            fixture: Fixture::new(),
            record,
            configuration,
            fault,
            reads: AtomicUsize::new(0),
            binds: AtomicUsize::new(0),
            address: Mutex::new(None),
            watcher_started: AtomicBool::new(false),
            watcher_ended: AtomicBool::new(false),
            fail_public: AtomicBool::new(false),
        }
    }
}
impl ServingHost for ServingFixture {
    fn acquire_start(&self, _: &StartContext) -> Result<StartLock, Error> {
        StartLock::existing(&self.fixture.0, self.fixture.uid())
    }
    fn installed_identity(
        &self,
        _: &StartLock,
        _: &StartContext,
    ) -> Result<ReleaseIdentity, Error> {
        if self.fault == "installed" {
            ReleaseIdentity::new("v3.0.1", &"a".repeat(40), &"b".repeat(64))
                .map_err(|_| Error::Refused)
        } else {
            Ok(self.record.release_identity())
        }
    }
    fn ownership(&self) -> Result<Vec<u8>, Error> {
        let nth = self.reads.fetch_add(1, Ordering::SeqCst);
        let mut body = self.record.encode().unwrap();
        if self.fault == "changed" && nth > 0 {
            body.push(b' ');
        }
        Ok(body)
    }
    fn pending_and_final_absent(&self) -> Result<bool, Error> {
        Ok(self.fault != "pending")
    }
    fn validate_material(
        &self,
        _: &OwnershipRecord,
        _: &sbxr::records::ServingAuthority,
    ) -> Result<(), Error> {
        if self.fault == "material" {
            Err(Error::Refused)
        } else {
            Ok(())
        }
    }
    fn unit(&self) -> Result<Vec<u8>, Error> {
        let mut unit = SERVING_UNIT.as_bytes().to_vec();
        if self.fault == "unit" {
            unit.push(b' ');
        }
        Ok(unit)
    }
    fn sandbox(&self) -> Result<ServingSandbox, Error> {
        let mut proof = sandbox();
        if self.fault == "sandbox" {
            proof.inaccessible[2] = PathAccess::Missing;
        }
        Ok(proof)
    }
    fn public_ipv4(&self, _: &StartContext) -> Result<Ipv4Addr, Error> {
        Ok(if self.fault == "public" {
            Ipv4Addr::new(8, 8, 4, 4)
        } else {
            Ipv4Addr::new(8, 8, 8, 8)
        })
    }
    fn configuration(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.configuration.clone();
        if self.fault == "config" {
            bytes.push(b' ');
        }
        Ok(bytes)
    }
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<TcpListener, Error> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        assert!(
            matches!(
                StartLock::existing(&self.fixture.0, self.fixture.uid()),
                Err(Error::Busy)
            ),
            "startup released lock before bind"
        );
        assert_eq!(address, Ipv4Addr::LOCALHOST);
        assert_eq!(port, 0);
        let listener = TcpListener::bind((address, port)).map_err(|_| Error::Refused)?;
        *self.address.lock().unwrap() = Some(listener.local_addr().unwrap());
        Ok(listener)
    }
    fn watch_public_ipv4(&self, expected: Ipv4Addr, stop: &Cancellation) -> WatchOutcome {
        assert_eq!(expected, Ipv4Addr::new(8, 8, 8, 8));
        self.watcher_started.store(true, Ordering::SeqCst);
        if self.fault == "watch-panic" {
            panic!("synthetic watcher failure");
        }
        while !stop.is_cancelled() && !self.fail_public.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(2));
        }
        self.watcher_ended.store(true, Ordering::SeqCst);
        if self.fail_public.load(Ordering::SeqCst) {
            WatchOutcome::PublicIpv4Failed
        } else {
            WatchOutcome::Cancelled
        }
    }
}

#[test]
fn fixed_service_unit_matches_the_go_reference_bytes() {
    assert_eq!(
        SERVING_UNIT.as_bytes(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/runtime_handoff/sbxr-subscription.service"
        ))
    );
}
#[test]
fn sandbox_requires_every_independent_observation() {
    sandbox().validate().unwrap();
    for fault in 0..13 {
        let mut proof = sandbox();
        match fault {
            0 => proof.effective_uid = 1000,
            1 => proof.process.cgroup.push_str("/foreign"),
            2..=5 => proof.capabilities[fault - 2] = 1,
            6 => proof.no_new_privileges = false,
            7 => proof.cgroup_procs = b"123\n456\n".to_vec(),
            8 => proof.cgroup_procs = vec![b' '; 4096],
            9 => proof.inaccessible[0] = PathAccess::Missing,
            10 => proof.inaccessible[1] = PathAccess::Accessible,
            11 => proof.inaccessible[3] = PathAccess::Unknown,
            _ => proof.inaccessible[4] = PathAccess::Missing,
        }
        assert_eq!(proof.validate(), Err(Error::Refused), "fault {fault}");
    }
}
#[test]
fn every_failed_startup_proof_refuses_before_binding_or_serving() {
    for fault in [
        "installed",
        "pending",
        "material",
        "unit",
        "sandbox",
        "public",
        "config",
        "changed",
    ] {
        let host = ServingFixture::new(fault);
        let result =
            serve_subscription_loopback_fixture(&host, &Module::new(), &host.fixture.context());
        assert_eq!(result, Code::Refused, "fault {fault}");
        assert_eq!(host.binds.load(Ordering::SeqCst), 0, "fault {fault}");
        assert!(!host.watcher_started.load(Ordering::SeqCst));
        drop(host.fixture.lock());
    }
}
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(Instant::now() < deadline, "fixture did not reach boundary");
        thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn serving_wiring_releases_start_lock_serves_and_joins_on_owner_cancel() {
    let host = ServingFixture::new("");
    let context = host.fixture.context();
    let module = Module::new();
    thread::scope(|scope| {
        let _stop_on_failure = StopOnDrop(context.stop.clone());
        let worker = scope.spawn(|| serve_subscription_loopback_fixture(&host, &module, &context));
        wait_until(|| host.watcher_started.load(Ordering::SeqCst));
        drop(host.fixture.lock());
        let address = host.address.lock().unwrap().unwrap();
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket
            .write_all(format!("GET /s/{TOKEN} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            response.contains("@127.0.0.1:443?"),
            "fixture must expose only its synthetic loopback profile"
        );
        let mut stalled = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        context.stop.cancel();
        assert_eq!(worker.join().unwrap(), Code::Stopped);
        let mut byte = [0];
        assert!(!matches!(stalled.read(&mut byte), Ok(1)));
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
        assert!(host.watcher_ended.load(Ordering::SeqCst));
    });
}
#[test]
fn periodic_public_ip_failure_is_failed_and_all_runtime_work_ends() {
    let host = ServingFixture::new("");
    let context = host.fixture.context();
    let module = Module::new();
    thread::scope(|scope| {
        let _stop_on_failure = StopOnDrop(context.stop.clone());
        let worker = scope.spawn(|| serve_subscription_loopback_fixture(&host, &module, &context));
        wait_until(|| host.watcher_started.load(Ordering::SeqCst));
        host.fail_public.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Code::Failed);
        assert!(context.stop.is_cancelled());
        assert!(host.watcher_ended.load(Ordering::SeqCst));
        assert!(
            TcpStream::connect_timeout(
                &host.address.lock().unwrap().unwrap(),
                Duration::from_millis(100)
            )
            .is_err()
        );
    });
}
#[test]
fn selected_generation_tracks_current_enablement_rotation_and_repair() {
    let (record, _) = running_http();
    assert_eq!(
        select_http_authority(&record, false).unwrap().link_id(),
        "1".repeat(32)
    );
    let next_token =
        SubscriptionCredential::parse("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE").unwrap();
    let mut rotation = record
        .begin_http_link_rotation(&"3".repeat(32), &"4".repeat(32), &next_token)
        .unwrap();
    assert!(select_http_authority(&rotation, false).is_err());
    assert_eq!(
        select_http_authority(&rotation, true).unwrap().link_id(),
        "1".repeat(32)
    );
    rotation = rotation
        .advance_http_link_rotation()
        .unwrap()
        .advance_http_link_rotation()
        .unwrap();
    assert!(select_http_authority(&rotation, false).is_err());
    assert_eq!(
        select_http_authority(&rotation, true).unwrap().link_id(),
        "4".repeat(32)
    );
    let prepared = record.begin_http_runtime_repair(&"5".repeat(32)).unwrap();
    assert!(select_http_authority(&prepared, false).is_ok());
    let committed = prepared.advance_http_runtime_repair().unwrap();
    assert!(
        select_http_authority(&committed, false).is_err(),
        "committed repair without a selected target must refuse"
    );
}

struct StopOnDrop(Cancellation);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn watcher_panic_fails_and_stops_serving_without_a_leaked_thread() {
    let host = ServingFixture::new("watch-panic");
    let result =
        serve_subscription_loopback_fixture(&host, &Module::new(), &host.fixture.context());
    assert_eq!(result, Code::Failed);
    assert!(
        TcpStream::connect_timeout(
            &host.address.lock().unwrap().unwrap(),
            Duration::from_millis(100)
        )
        .is_err()
    );
}

#[test]
fn malformed_ancillary_data_and_wrong_inodes_close_every_received_descriptor() {
    use rustix::{
        io::IoSlice,
        net::{self, SendAncillaryBuffer, SendAncillaryMessage, SendFlags},
    };
    use std::mem::MaybeUninit;
    for case in [
        "absent",
        "two",
        "many",
        "wrong-byte",
        "wrong-inode",
        "extra-byte",
    ] {
        let f = Fixture::new();
        let owner = f.lock();
        fs::write(f.0.join("foreign"), []).unwrap();
        fs::set_permissions(f.0.join("foreign"), fs::Permissions::from_mode(0o600)).unwrap();
        let foreign = fs::File::open(f.0.join("foreign")).unwrap();
        let lender = process(400, "/owner.scope", f.uid());
        let observations = Peers {
            current: process(401, SUBSCRIPTION_CGROUP, f.uid()),
            peer: lender.clone(),
        };
        let (client, mut server) = UnixStream::pair().unwrap();
        let context = f.context();
        let owner_descriptor = owner.descriptor().unwrap();
        thread::scope(|scope| {
            let sender = scope.spawn(|| {
                let mut request = [0; 23];
                server
                    .read_exact(&mut request[.."--subscription-serving\n".len()])
                    .unwrap();
                assert_eq!(
                    &request[.."--subscription-serving\n".len()],
                    b"--subscription-serving\n"
                );
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
                let mut ancillary = SendAncillaryBuffer::new(&mut space);
                let rights = if case == "wrong-inode" {
                    vec![foreign.as_fd()]
                } else {
                    vec![
                        owner_descriptor.as_fd();
                        if case == "many" {
                            4
                        } else if case == "two" {
                            2
                        } else {
                            1
                        }
                    ]
                };
                if case != "absent" {
                    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
                }
                let payload = if case == "wrong-byte" {
                    &[2][..]
                } else if case == "extra-byte" {
                    &[1, 9][..]
                } else {
                    &[1][..]
                };
                let flags = SendFlags::empty();
                #[cfg(target_os = "linux")]
                let flags = flags | SendFlags::NOSIGNAL;
                assert_eq!(
                    net::sendmsg(&server, &[IoSlice::new(payload)], &mut ancillary, flags).unwrap(),
                    payload.len()
                );
            });
            assert!(
                matches!(
                    borrow(
                        client,
                        &f.0,
                        Role::SubscriptionServing,
                        &lender,
                        &observations,
                        &context
                    ),
                    Err(Error::Refused)
                ),
                "case {case}"
            );
            sender.join().unwrap();
        });
        drop(owner_descriptor);
        drop(owner);
        drop(f.lock()); // A leaked shared-description fd would leave this busy.
    }
}
#[test]
fn busy_start_retries_a_later_owner_handoff() {
    let f = Fixture::new();
    let owner = f.lock();
    let parent = process(500, "/owner.scope", f.uid());
    let child = process(501, PROXY_CGROUP, f.uid());
    let lender = Peers {
        current: parent.clone(),
        peer: child.clone(),
    };
    let borrower = Peers {
        current: child.clone(),
        peer: parent.clone(),
    };
    let attempts = AtomicUsize::new(0);
    let socket = f.socket("late.sock");
    let context = f.context();
    thread::scope(|scope| {
        let accepting = scope.spawn(|| {
            wait_until(|| attempts.load(Ordering::SeqCst) > 0);
            let offer = Handoff::new(
                UnixListener::bind(&socket).unwrap(),
                &owner,
                Role::ProxyStartAuthorize,
                child,
            )
            .unwrap();
            offer.accept(&lender, &context)
        });
        let lock = acquire_runtime_start(
            &f.0,
            f.uid(),
            Role::ProxyStartAuthorize,
            &borrower,
            &context,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                UnixStream::connect(&socket)
                    .map(|s| (s, parent.clone()))
                    .map_err(|_| Error::Refused)
            },
        )
        .unwrap();
        assert!(lock.is_borrowed());
        drop(lock);
        assert!(attempts.load(Ordering::SeqCst) >= 2);
        assert_eq!(accepting.join().unwrap(), Ok(()));
    });
    owner.verify().unwrap();
}
#[test]
fn ordinary_runtime_start_waits_for_actual_exclusion() {
    let f = Fixture::new();
    let owner = f.lock();
    let current = process(600, PROXY_CGROUP, f.uid());
    let observations = Peers {
        current: current.clone(),
        peer: current,
    };
    let context = f.context();
    thread::scope(|scope| {
        scope.spawn(move || {
            thread::sleep(Duration::from_millis(30));
            drop(owner);
        });
        let began = Instant::now();
        let lock = acquire_runtime_start(
            &f.0,
            f.uid(),
            Role::ProxyStartAuthorize,
            &observations,
            &context,
            || Err(Error::Refused),
        )
        .unwrap();
        assert!(!lock.is_borrowed());
        assert!(began.elapsed() >= Duration::from_millis(30));
    });
}
#[test]
fn every_process_binding_is_checked_before_a_handoff_grants_authority() {
    for field in ["pid", "parent", "start", "uid", "executable", "cgroup"] {
        let f = Fixture::new();
        let owner = f.lock();
        let expected = process(700, SUBSCRIPTION_CGROUP, f.uid());
        let mut actual = expected.clone();
        match field {
            "pid" => actual.pid += 1,
            "parent" => actual.parent_pid += 1,
            "start" => actual.start_ticks += 1,
            "uid" => actual.uid += 1,
            "executable" => actual.executable_sha256 = "b".repeat(64),
            _ => actual.cgroup.push_str("/other"),
        }
        let observations = Peers {
            current: process(701, "/owner.scope", f.uid()),
            peer: actual,
        };
        let socket = f.socket("peer.sock");
        let context = f.context();
        let offer = Handoff::new(
            UnixListener::bind(&socket).unwrap(),
            &owner,
            Role::SubscriptionServing,
            expected,
        )
        .unwrap();
        thread::scope(|scope| {
            let accepting = scope.spawn(|| offer.accept(&observations, &context));
            let _client = UnixStream::connect(&socket).unwrap();
            assert_eq!(
                accepting.join().unwrap(),
                Err(Error::Refused),
                "field {field}"
            );
        });
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_observation_binds_a_real_child_peer_and_parent_identity() {
    use std::process::{Command, Stdio};
    if let Ok(socket) = std::env::var("SBXR_HANDOFF_TEST_SOCKET") {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.write_all(&[1]).unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        return;
    }
    let f = Fixture::new();
    let socket = f.socket("child.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_linux_observation_binds_a_real_child_peer_and_parent_identity",
            "--nocapture",
        ])
        .env("SBXR_HANDOFF_TEST_SOCKET", &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct ChildGuard<'a>(&'a mut std::process::Child);
    impl Drop for ChildGuard<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let cleanup = ChildGuard(&mut child);
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("child socket: {error}"),
        }
    };
    let proof = LinuxPeers.peer(&stream).unwrap();
    assert_eq!(proof.pid, cleanup.0.id());
    assert_eq!(proof.parent_pid, std::process::id());
    assert_eq!(proof.uid, f.uid());
    assert_eq!(
        proof.executable_sha256,
        sbxr::records::sha256_hex(&fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    stream.write_all(&[1]).unwrap();
    assert!(cleanup.0.wait().unwrap().success());
}

fn proxy_record(checkpoint: Option<usize>) -> (OwnershipRecord, Vec<u8>) {
    use serde_json::json;
    let (http, configuration) = running_http();
    let mut record = OwnershipRecord::new_standard(
        http.release_identity(),
        "8.8.8.8",
        http.configuration_sha256(),
    )
    .unwrap();
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    let mut wire: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
    wire["schema"] = json!(2);
    wire["permitted_resources"][0] =
        json!("/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2");
    let digest = sbxr::records::sha256_hex(
        b"[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n",
    );
    wire["proxy_startup"] = json!({"drop_in_sha256": digest, "directory_created": true});
    let resources = wire["permitted_resources"].as_array_mut().unwrap();
    resources.push(json!(format!("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:{digest}")));
    resources.push(json!("/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal"));
    if let Some(index) = checkpoint {
        let checkpoints = [
            "rotation authorized",
            "target prepared",
            "startup integration published",
            "systemd reloaded",
            "startup route verified",
            "cutover gated",
            "source stopped",
            "source quiescent",
            "source revoked",
            "target published",
            "target started",
        ];
        let effects = [
            "prepare target",
            "publish startup integration",
            "reload systemd",
            "verify startup route",
            "establish cutover gate",
            "stop source",
            "prove source quiescence",
            "revoke source",
            "publish target",
            "start target",
            "verify target",
            "clean staging",
        ];
        let target = "d".repeat(64);
        wire["client_identity_rotation"] = json!({"operation_id":"1".repeat(32), "direction": if index < 8 { "cleanup" } else { "forward" }, "effects":effects, "completed_effects":&effects[..index], "source_configuration_sha256":record.configuration_sha256(), "target_configuration_sha256":target, "checkpoint":checkpoints[index]});
        let resources = wire["permitted_resources"].as_array_mut().unwrap();
        resources.extend([
            json!(format!("/var/lib/sbxr/client-identity-target.json root:root 0600 one-link sha256:{target}")),
            json!("/var/lib/sbxr/client-identity-target.json.sbxr-next root-owned Client Identity target publication"),
            json!(format!("/etc/sing-box/.config.json.sbxr-next root:sing-box 0640 one-link sha256:{target}")),
            json!("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf.sbxr-next root-owned Client Identity startup publication"),
        ]);
    }
    wire["resource_creating_releases"] =
        json!(vec![
            wire["release_identity"].clone();
            wire["permitted_resources"].as_array().unwrap().len()
        ]);
    (
        OwnershipRecord::decode(&serde_json::to_vec(&wire).unwrap()).unwrap(),
        configuration,
    )
}
struct ProxyFixture {
    fixture: Fixture,
    record: OwnershipRecord,
    configuration: Vec<u8>,
    borrowed: Mutex<Option<StartLock>>,
    owner: Option<StartLock>,
    consumed: AtomicBool,
}
impl ProxyFixture {
    fn new(checkpoint: Option<usize>) -> Self {
        let (record, configuration) = proxy_record(checkpoint);
        Self {
            fixture: Fixture::new(),
            record,
            configuration,
            borrowed: Mutex::new(None),
            owner: None,
            consumed: AtomicBool::new(false),
        }
    }
    fn install_borrowed(&mut self) {
        if self.owner.is_none() {
            self.owner = Some(self.fixture.lock());
        }
        let owner = self.owner.as_ref().unwrap();
        let parent = process(800, "/owner.scope", self.fixture.uid());
        let child = process(801, PROXY_CGROUP, self.fixture.uid());
        let lender = Peers {
            current: parent.clone(),
            peer: child.clone(),
        };
        let borrower = Peers {
            current: child.clone(),
            peer: parent.clone(),
        };
        let socket = self.fixture.socket("gate.sock");
        if socket.exists() {
            fs::remove_file(&socket).unwrap();
        }
        let offer = Handoff::new(
            UnixListener::bind(&socket).unwrap(),
            owner,
            Role::ProxyStartAuthorize,
            child,
        )
        .unwrap();
        let context = self.fixture.context();
        let received = thread::scope(|scope| {
            let accepting = scope.spawn(|| offer.accept(&lender, &context));
            let received = borrow(
                UnixStream::connect(&socket).unwrap(),
                &self.fixture.0,
                Role::ProxyStartAuthorize,
                &parent,
                &borrower,
                &context,
            )
            .unwrap();
            assert_eq!(accepting.join().unwrap(), Ok(()));
            received
        });
        *self.borrowed.lock().unwrap() = Some(received);
    }
}
impl ProxyStartHost for ProxyFixture {
    fn acquire_start(&self, _: &StartContext) -> Result<StartLock, Error> {
        if let Some(lock) = self.borrowed.lock().unwrap().take() {
            Ok(lock)
        } else {
            StartLock::existing(&self.fixture.0, self.fixture.uid())
        }
    }
    fn installed_identity(
        &self,
        _: &StartLock,
        _: &StartContext,
    ) -> Result<ReleaseIdentity, Error> {
        Ok(self.record.release_identity())
    }
    fn ownership(&self) -> Result<Vec<u8>, Error> {
        Ok(self.record.encode().unwrap())
    }
    fn verify_startup(&self, record: &OwnershipRecord, _: &StartContext) -> Result<(), Error> {
        let wire: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        assert!(wire["proxy_startup"]["drop_in_sha256"].is_string());
        Ok(())
    }
    fn configuration(&self) -> Result<Vec<u8>, Error> {
        Ok(self.configuration.clone())
    }
    fn mutation_in_progress(&self) -> Result<bool, Error> {
        Ok(self.owner.is_some())
    }
    fn consume_authorization(
        &self,
        expected: &str,
        _: &StartLock,
        _: &StartContext,
    ) -> Result<(), Error> {
        assert_eq!(expected, self.record.configuration_sha256());
        if self.consumed.swap(true, Ordering::SeqCst) {
            Err(Error::Refused)
        } else {
            Ok(())
        }
    }
}
#[test]
fn proxy_ordinary_start_works_only_before_the_identity_cutover_gate() {
    let host = ProxyFixture::new(None);
    authorize_proxy_start(&host, &host.fixture.context()).unwrap();
    assert!(!host.consumed.load(Ordering::SeqCst));
    for checkpoint in 0..=8 {
        let host = ProxyFixture::new(Some(checkpoint));
        let result = authorize_proxy_start(&host, &host.fixture.context());
        assert_eq!(result.is_ok(), checkpoint < 5, "checkpoint {checkpoint}");
        assert!(!host.consumed.load(Ordering::SeqCst));
        drop(host.fixture.lock());
    }
}
#[test]
fn gated_proxy_start_requires_borrowed_owner_and_consumes_exact_gate_once() {
    let mut host = ProxyFixture::new(Some(5));
    host.install_borrowed();
    authorize_proxy_start(&host, &host.fixture.context()).unwrap();
    assert!(host.consumed.load(Ordering::SeqCst));
    host.owner.as_ref().unwrap().verify().unwrap();
    host.install_borrowed();
    assert_eq!(
        authorize_proxy_start(&host, &host.fixture.context()),
        Err(Error::Refused)
    );
    host.owner.as_ref().unwrap().verify().unwrap();
}

#[test]
fn failed_start_closes_lender_promptly_without_cancelling_the_owner() {
    let f = Fixture::new();
    let owner = f.lock();
    let parent = process(900, "/owner.scope", f.uid());
    let child = process(901, SUBSCRIPTION_CGROUP, f.uid());
    let peers = Peers {
        current: parent,
        peer: child.clone(),
    };
    let socket = f.socket("fail.sock");
    let offer = Handoff::new(
        UnixListener::bind(&socket).unwrap(),
        &owner,
        Role::SubscriptionServing,
        child,
    )
    .unwrap();
    let context = f.context();
    let began = Instant::now();
    assert!(!with_runtime_start(offer, &peers, &context, |_| false));
    assert!(began.elapsed() < Duration::from_millis(300));
    assert!(!context.stop.is_cancelled());
    assert!(UnixStream::connect(&socket).is_err());
    owner.verify().unwrap();
}
#[test]
fn successful_start_requires_the_exact_one_use_handoff_to_complete() {
    let f = Fixture::new();
    let owner = f.lock();
    let parent = process(910, "/owner.scope", f.uid());
    let child = process(911, SUBSCRIPTION_CGROUP, f.uid());
    let lender = Peers {
        current: parent.clone(),
        peer: child.clone(),
    };
    let borrower = Peers {
        current: child.clone(),
        peer: parent.clone(),
    };
    let socket = f.socket("start.sock");
    let offer = Handoff::new(
        UnixListener::bind(&socket).unwrap(),
        &owner,
        Role::SubscriptionServing,
        child,
    )
    .unwrap();
    let context = f.context();
    assert!(with_runtime_start(offer, &lender, &context, |context| {
        let received = borrow(
            UnixStream::connect(&socket).unwrap(),
            &f.0,
            Role::SubscriptionServing,
            &parent,
            &borrower,
            context,
        )
        .unwrap();
        assert!(received.is_borrowed());
        drop(received);
        true
    }));
    assert!(!context.stop.is_cancelled());
    owner.verify().unwrap();
}

#[test]
fn duplicated_owner_descriptor_requires_existing_retained_exclusion() {
    let f = Fixture::new();
    let idle: std::os::fd::OwnedFd = fs::File::open(f.0.join("run/lock/sbxr.lock"))
        .unwrap()
        .into();
    assert!(
        StartLock::from_owner_duplicate(&f.0, f.uid(), idle).is_err(),
        "an idle descriptor must not mint Owner authority"
    );
    let owner = f.lock();
    let independent: std::os::fd::OwnedFd = fs::File::open(f.0.join("run/lock/sbxr.lock"))
        .unwrap()
        .into();
    assert!(
        StartLock::from_owner_duplicate(&f.0, f.uid(), independent).is_err(),
        "same inode does not prove same open file description"
    );
    let duplicate = owner.descriptor().unwrap();
    drop(StartLock::from_owner_duplicate(&f.0, f.uid(), duplicate).unwrap());
    assert!(matches!(
        StartLock::existing(&f.0, f.uid()),
        Err(Error::Busy)
    ));
    owner.verify().unwrap();
}

#[test]
fn lock_start_refuses_symlinks_hardlinks_unsafe_parents_and_wrong_owner() {
    use std::os::unix::fs::symlink;
    for kind in ["symlink", "hardlink", "parent", "owner"] {
        let f = Fixture::new();
        let path = f.0.join("run/lock/sbxr.lock");
        match kind {
            "symlink" => {
                fs::rename(&path, f.0.join("foreign")).unwrap();
                symlink("../../foreign", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, f.0.join("foreign")).unwrap(),
            "parent" => {
                fs::set_permissions(f.0.join("run"), fs::Permissions::from_mode(0o777)).unwrap()
            }
            _ => (),
        }
        let uid = if kind == "owner" {
            f.uid() + 1
        } else {
            f.uid()
        };
        assert!(
            matches!(StartLock::existing(&f.0, uid), Err(Error::Refused)),
            "kind {kind}"
        );
    }
}
