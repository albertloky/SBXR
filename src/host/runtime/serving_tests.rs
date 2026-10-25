use super::*;
use crate::{
    records::{HTTP_ENABLEMENT_CHECKPOINTS, SetupPhase},
    runtime_handoff::{
        PathAccess, SUBSCRIPTION_CGROUP, SandboxProcess, ServingHost, ServingSandbox,
    },
    server_configuration::ServerConfiguration,
    subscription_artifact::SubscriptionCredential,
    subscription_serving::{Code, Module},
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "sv-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn write(&self, p: &str, b: &[u8], mode: u32) {
        let p = self.0.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn setup(&self, archive: &AuthenticatedArchive) -> (OwnershipRecord, Vec<u8>) {
        let configuration =
            include_bytes!("../../../tests/testdata/server_configuration/standard.json").to_vec();
        let mut record = OwnershipRecord::new_standard(
            archive.record().release_identity(),
            "8.8.8.8",
            &sha256_hex(&configuration),
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
        record = record.commit_http_enablement().unwrap();
        self.write("usr/local/bin/sbxr", archive.executable(), 0o755);
        self.write(
            "var/lib/sbxr/installed.json",
            &archive.record().encode().unwrap(),
            0o600,
        );
        self.write(
            "var/lib/sbxr/proxy-ownership.json",
            &record.encode().unwrap(),
            0o600,
        );
        fs::set_permissions(
            self.0.join("var/lib/sbxr"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        self.write(
            "etc/group",
            format!(
                "root:x:0:\nsing-box:x:{}:\n",
                fs::metadata(&self.0).unwrap().gid()
            )
            .as_bytes(),
            0o644,
        );
        self.write("etc/sing-box/config.json", &configuration, 0o640);
        self.write(
            "etc/systemd/system/sbxr-subscription.service",
            runtime_handoff::SERVING_UNIT.as_bytes(),
            0o644,
        );
        fs::create_dir_all(self.0.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            "../sbxr-subscription.service",
            self.0
                .join("etc/systemd/system/multi-user.target.wants/sbxr-subscription.service"),
        )
        .unwrap();
        fs::create_dir_all(self.0.join("run/lock")).unwrap();
        drop(HostLock::provision(&self.0, self.uid()).unwrap());
        (record, configuration)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Clone)]
struct Environment {
    uid: u32,
    calls: Arc<AtomicUsize>,
    fail_watch: bool,
    sandbox_bad: bool,
    bound: Arc<Mutex<Option<SocketAddr>>>,
}
impl Environment {
    fn new(uid: u32) -> Self {
        Self {
            uid,
            calls: Arc::new(AtomicUsize::new(0)),
            fail_watch: false,
            sandbox_bad: false,
            bound: Arc::new(Mutex::new(None)),
        }
    }
}
impl ServingEnvironment for Environment {
    fn process(&self) -> Result<SandboxProcess, Error> {
        Ok(SandboxProcess {
            pid: 123,
            uid: self.uid,
            cgroup: SUBSCRIPTION_CGROUP.into(),
            executable_path: "/usr/local/bin/sbxr".into(),
        })
    }
    fn sandbox(&self) -> Result<ServingSandbox, Error> {
        let mut process = self.process()?;
        process.uid = 0; // explicit fixture mapping to the fixed root service
        Ok(ServingSandbox {
            effective_uid: 0,
            process,
            capabilities: if self.sandbox_bad {
                [1, 0, 0, 0]
            } else {
                [0; 4]
            },
            no_new_privileges: true,
            inaccessible: [PathAccess::PermissionDenied; 5],
            cgroup_procs: b"123\n".to_vec(),
        })
    }
    fn lender_uid(&self, _: &UnixStream) -> Result<u32, Error> {
        Ok(self.uid)
    }
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<TcpListener, Error> {
        let listener = TcpListener::bind((address, port)).map_err(refused)?;
        *self.bound.lock().unwrap() = Some(listener.local_addr().map_err(refused)?);
        Ok(listener)
    }
    fn public_ipv4(&self, context: &StartContext) -> Result<Ipv4Addr, Error> {
        context.check()?;
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_watch && n > 0 {
            Err(Error::Refused)
        } else {
            Ok(Ipv4Addr::new(8, 8, 8, 8))
        }
    }
}
fn context() -> StartContext {
    StartContext::new(Cancellation::new(), Instant::now() + Duration::from_secs(2))
}
fn host<'a>(
    root: &Root,
    a: &'a AuthenticatedArchive,
    e: Environment,
) -> ServingRuntimeHost<'a, Environment> {
    ServingRuntimeHost::injected(&root.0, a, e, root.0.join("start.sock"))
        .unwrap()
        .with_fixture_watch_interval(Duration::from_millis(15))
}
#[test]
fn concrete_serving_reads_protected_files_binds_loopback_and_joins_shutdown() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    let (record, config) = root.setup(&a);
    let e = Environment::new(root.uid());
    let calls = e.calls.clone();
    let bound = e.bound.clone();
    let host = host(&root, &a, e);
    let module = Module::new();
    let ctx = context();
    std::thread::scope(|scope| {
        let worker = scope
            .spawn(|| runtime_handoff::serve_subscription_loopback_fixture(&host, &module, &ctx));
        let end = Instant::now() + Duration::from_secs(1);
        let address = loop {
            if let Some(address) = *bound.lock().unwrap() {
                break Some(address);
            }
            if Instant::now() >= end {
                break None;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let response = (|| -> std::io::Result<Vec<u8>> {
            let mut socket = TcpStream::connect(address.ok_or(std::io::ErrorKind::TimedOut)?)?;
            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
            socket.set_write_timeout(Some(Duration::from_secs(1)))?;
            socket.write_all(
                format!("GET /s/{TOKEN} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
            )?;
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        ctx.stop.cancel();
        assert_eq!(worker.join().unwrap(), Code::Stopped);
        let response = response.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let expected = ServerConfiguration::decode_standard(&config)
            .unwrap()
            .connection_facts("127.0.0.1")
            .unwrap()
            .subscription_artifact()
            .unwrap();
        assert!(response.ends_with(expected.as_bytes()));
    });
    assert!(calls.load(Ordering::SeqCst) >= 1);
    HostLock::existing(&root.0, root.uid()).unwrap();
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        record.encode().unwrap()
    );
}
#[test]
fn periodic_public_ip_failure_stops_real_serving_as_failed() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.setup(&a);
    let mut e = Environment::new(root.uid());
    e.fail_watch = true;
    let calls = e.calls.clone();
    let host = host(&root, &a, e);
    let ctx = context();
    assert_eq!(
        runtime_handoff::serve_subscription_loopback_fixture(&host, &Module::new(), &ctx),
        Code::Failed
    );
    assert!(ctx.stop.is_cancelled());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    HostLock::existing(&root.0, root.uid()).unwrap();
}
#[test]
fn all_concrete_footprint_and_sandbox_refusals_preserve_authority() {
    for fault in 0..8 {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        let (record, _) = root.setup(&a);
        let mut e = Environment::new(root.uid());
        match fault {
            0 => root.write("var/lib/sbxr/foreign", b"preserve", 0o600),
            1 => root.write(
                "var/lib/sbxr/subscription-serving.json.sbxr-next",
                b"pending",
                0o600,
            ),
            2 => root.write(
                "etc/systemd/system/sbxr-subscription.service",
                b"foreign",
                0o644,
            ),
            3 => root.write(
                "etc/systemd/system/sbxr-subscription.service.d/foreign.conf",
                b"foreign",
                0o644,
            ),
            4 => root.write("var/lib/.sbxr-removal.json", b"pending", 0o600),
            5 => fs::hard_link(
                root.0.join("etc/sing-box/config.json"),
                root.0.join("foreign-config"),
            )
            .unwrap(),
            6 => e.sandbox_bad = true,
            _ => root.write("etc/group", b"root:x:0:\nsing-box:x:999999:\n", 0o644),
        }
        let host = host(&root, &a, e);
        assert_eq!(
            runtime_handoff::serve_subscription_loopback_fixture(&host, &Module::new(), &context()),
            Code::Refused,
            "fault {fault}"
        );
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            record.encode().unwrap()
        );
    }
}
#[test]
fn concrete_serving_refuses_native_route_and_non_loopback_fixture_bind() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.setup(&a);
    let host = host(&root, &a, Environment::new(root.uid()));
    assert!(host.bind_listener(Ipv4Addr::new(8, 8, 8, 8), 8443).is_err());
    assert!(
        ServingRuntimeHost::injected(
            Path::new("/"),
            &a,
            Environment::new(0),
            "/start.sock".into()
        )
        .is_err()
    );
    assert!(ServingRuntimeHost::native_unreleased(a.record()).is_err());
    assert!(NativeServingEnvironment.process().is_err());
}

struct ObservedPeers {
    owner: runtime_handoff::ProcessIdentity,
    child: runtime_handoff::ProcessIdentity,
}
impl runtime_handoff::PeerObservations for ObservedPeers {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, Error> {
        Ok(self.owner.clone())
    }
    fn peer(&self, _: &UnixStream) -> Result<runtime_handoff::ProcessIdentity, Error> {
        Ok(self.child.clone())
    }
}
type CommandEffect<'a> = dyn Fn(ServiceAction, &StartContext) -> Result<(), Error> + Sync + 'a;
struct Commands<'a> {
    effect: Box<CommandEffect<'a>>,
}
impl ServiceCommands for Commands<'_> {
    fn execute(&self, action: ServiceAction, context: &StartContext) -> Result<(), Error> {
        (self.effect)(action, context)
    }
}
fn peers(root: &Root, a: &AuthenticatedArchive, bad_image: bool) -> ObservedPeers {
    let hash = a.record().executable_sha256();
    let wrong = "f".repeat(64);
    ObservedPeers {
        owner: runtime_handoff::ProcessIdentity::new(100, 1, 1, root.uid(), hash, "/owner.scope")
            .unwrap(),
        child: runtime_handoff::ProcessIdentity::new(
            123,
            100,
            2,
            root.uid(),
            if bad_image { &wrong } else { hash },
            SUBSCRIPTION_CGROUP,
        )
        .unwrap(),
    }
}
#[test]
fn concrete_controller_starts_subscription_through_sandbox_safe_borrow_without_unlocking_owner() {
    for restart in [false, true] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        let (record, _) = root.setup(&a);
        let proof = a
            .bind_current(
                a.executable(),
                a.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let socket = root.0.join("start.sock");
        let receiver = host(&root, &a, Environment::new(root.uid()));
        let owner = Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
        let called = AtomicUsize::new(0);
        let commands = Commands {
            effect: Box::new(|action, ctx| {
                assert_eq!(
                    action,
                    if restart {
                        ServiceAction::RestartSubscription
                    } else {
                        ServiceAction::StartSubscription
                    }
                );
                called.fetch_add(1, Ordering::SeqCst);
                let lock = receiver.acquire_start(ctx)?;
                assert!(lock.is_borrowed());
                assert_eq!(
                    receiver.installed_identity(&lock, ctx)?,
                    record.release_identity()
                );
                owner.verify().unwrap();
                drop(lock);
                owner.verify().unwrap();
                Ok(())
            }),
        };
        let controller = ServiceController::injected(
            &root.0,
            &proof,
            owner.clone(),
            peers(&root, &a, false),
            commands,
            socket,
        )
        .unwrap();
        controller.start_subscription(restart, &context()).unwrap();
        assert_eq!(called.load(Ordering::SeqCst), 1);
        owner.verify().unwrap();
        assert!(matches!(
            HostLock::existing(&root.0, root.uid()),
            Err(HostError::Busy)
        ));
    }
}
#[test]
fn controller_rejects_foreign_material_before_effect_and_failed_child_image_keeps_owner() {
    for fault in ["override", "child-image", "pending"] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        let (record, _) = root.setup(&a);
        let proof = a
            .bind_current(
                a.executable(),
                a.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let receiver = host(&root, &a, Environment::new(root.uid()));
        if fault == "override" {
            root.write(
                "etc/systemd/system/sbxr-subscription.service.d/foreign.conf",
                b"preserve",
                0o644,
            );
        }
        if fault == "pending" {
            root.write(
                "var/lib/sbxr/proxy-ownership.json.sbxr-next",
                b"preserve",
                0o600,
            );
        }
        let owner = Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
        let called = AtomicUsize::new(0);
        let commands = Commands {
            effect: Box::new(|_, ctx| {
                called.fetch_add(1, Ordering::SeqCst);
                let _lock = receiver.acquire_start(ctx)?;
                Ok(())
            }),
        };
        let controller = ServiceController::injected(
            &root.0,
            &proof,
            owner.clone(),
            peers(&root, &a, fault == "child-image"),
            commands,
            root.0.join("start.sock"),
        )
        .unwrap();
        let ctx = StartContext::new(
            Cancellation::new(),
            Instant::now() + Duration::from_millis(80),
        );
        assert!(controller.start_subscription(false, &ctx).is_err());
        assert_eq!(
            called.load(Ordering::SeqCst),
            usize::from(fault == "child-image")
        );
        owner.verify().unwrap();
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            record.encode().unwrap()
        );
    }
}
#[test]
fn controller_fixed_stop_reload_and_native_refusal_do_not_claim_quiescence() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.setup(&a);
    let proof = a
        .bind_current(
            a.executable(),
            a.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let owner = Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
    let called = Mutex::new(Vec::new());
    let commands = Commands {
        effect: Box::new(|action, ctx| {
            ctx.check()?;
            called.lock().unwrap().push(action);
            Ok(())
        }),
    };
    let controller = ServiceController::injected(
        &root.0,
        &proof,
        owner.clone(),
        peers(&root, &a, false),
        commands,
        root.0.join("start.sock"),
    )
    .unwrap();
    controller.stop_subscription(&context()).unwrap();
    controller.reload(&context()).unwrap();
    assert_eq!(
        *called.lock().unwrap(),
        [ServiceAction::StopSubscription, ServiceAction::Reload]
    );
    assert_eq!(
        ServiceAction::StopSubscription.arguments(),
        ["stop", "sbxr-subscription.service"]
    );
    assert!(NativeServiceCommands::new(owner.clone()).is_err());
    assert!(ServiceController::native_unreleased(&proof, owner.clone()).is_err());
    owner.verify().unwrap();
}
#[test]
fn sandbox_receiver_refuses_changed_kernel_facts_without_creating_missing_lock() {
    let root = Root::new();
    let uid = root.uid();
    let observed = || {
        Ok(SandboxProcess {
            pid: 123,
            uid,
            cgroup: SUBSCRIPTION_CGROUP.into(),
            executable_path: "/usr/local/bin/sbxr".into(),
        })
    };
    assert!(
        runtime_handoff::acquire_serving_start(&root.0, uid, &context(), observed, || Err(
            Error::Refused
        ))
        .is_err()
    );
    assert!(!root.0.join("run/lock/sbxr.lock").exists());
    fs::create_dir_all(root.0.join("run/lock")).unwrap();
    drop(HostLock::provision(&root.0, uid).unwrap());
    for fault in ["path", "cgroup", "uid", "pid", "changed"] {
        let calls = AtomicUsize::new(0);
        let observe = || {
            let mut proof = observed().unwrap();
            match fault {
                "path" => proof.executable_path = "/tmp/other".into(),
                "cgroup" => proof.cgroup = "/foreign.scope".into(),
                "uid" => proof.uid += 1,
                "pid" => proof.pid = 0,
                _ => {
                    if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                        proof.pid += 1;
                    }
                }
            }
            Ok(proof)
        };
        assert!(
            runtime_handoff::acquire_serving_start(&root.0, uid, &context(), observe, || Err(
                Error::Refused
            ))
            .is_err(),
            "{fault}"
        );
        HostLock::existing(&root.0, uid).unwrap();
    }
}
