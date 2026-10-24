use super::*;
use crate::{
    host::process::CommandOutput,
    records::{SetupPhase, sha256_hex},
    runtime_handoff::{Handoff, ProcessIdentity},
};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const CONDITION: &str = "{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "proxy-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Self(path);
        fs::create_dir_all(root.0.join("run/lock")).unwrap();
        root
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn gid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().gid()
    }
    fn write(&self, path: &str, body: &[u8], mode: u32) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn install(
        &self,
        proof: &AuthenticatedInstalled,
        record: &OwnershipRecord,
        configuration: &[u8],
    ) {
        let a = crate::release_acquisition::fixture_archive();
        assert!(a.record() == proof.record());
        self.write("usr/local/bin/sbxr", a.executable(), 0o755);
        self.write(
            "var/lib/sbxr/installed.json",
            &proof.record().encode().unwrap(),
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
            format!("root:x:0:\nsing-box:x:{}:\n", self.gid()).as_bytes(),
            0o644,
        );
        self.write("etc/sing-box/config.json", configuration, 0o640);
        self.write(
            "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
            STARTUP,
            0o644,
        );
        drop(HostLock::provision(&self.0, self.uid()).unwrap());
    }
    fn socket(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn bind(&self, path: &Path) -> UnixListener {
        let cwd = std::env::current_dir().unwrap();
        UnixListener::bind(path.strip_prefix(cwd).unwrap()).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Clone)]
struct Peers {
    current: ProcessIdentity,
    peer: ProcessIdentity,
}
impl PeerObservations for Peers {
    fn current(&self) -> Result<ProcessIdentity, Error> {
        Ok(self.current.clone())
    }
    fn peer(&self, _: &std::os::unix::net::UnixStream) -> Result<ProcessIdentity, Error> {
        Ok(self.peer.clone())
    }
}
struct Runner {
    condition: Vec<u8>,
    stall: bool,
}
impl CommandRunner for Runner {
    fn query(&self, query: Query, stop: &CommandCancellation) -> Result<CommandOutput, HostError> {
        assert_eq!(query, Query::ProxyStartCondition);
        if self.stall {
            while !stop.cancelled() {
                std::thread::sleep(Duration::from_millis(1));
            }
            return Err(HostError::Cancelled);
        }
        CommandOutput::completed(0, self.condition.clone())
    }
}
fn context() -> StartContext {
    StartContext::new(Cancellation::new(), Instant::now() + Duration::from_secs(2))
}
fn identities(root: &Root, proof: &AuthenticatedInstalled) -> (ProcessIdentity, ProcessIdentity) {
    let hash = proof.record().executable_sha256();
    (
        ProcessIdentity::new(101, 100, 2, root.uid(), hash, runtime_handoff::PROXY_CGROUP).unwrap(),
        ProcessIdentity::new(100, 1, 1, root.uid(), hash, "/owner.scope").unwrap(),
    )
}
fn record(proof: &AuthenticatedInstalled, index: Option<usize>) -> (OwnershipRecord, Vec<u8>) {
    let source =
        include_bytes!("../../../tests/testdata/server_configuration/standard.json").to_vec();
    let mut target: serde_json::Value = serde_json::from_slice(&source).unwrap();
    target["inbounds"][0]["users"][0]["uuid"] = "22345678-1234-4234-8234-123456789abc".into();
    let target = serde_json::to_vec(&target).unwrap();
    crate::server_configuration::ServerConfiguration::decode_standard(&target).unwrap();
    let source_hash = sha256_hex(&source);
    let target_hash = sha256_hex(&target);
    let mut r =
        OwnershipRecord::new_standard(proof.record().release_identity(), "8.8.8.8", &source_hash)
            .unwrap();
    while r.phase() != SetupPhase::Running {
        r = r.next_setup_checkpoint().unwrap();
    }
    let mut wire: serde_json::Value = serde_json::from_slice(&r.encode().unwrap()).unwrap();
    wire["schema"] = 2.into();
    wire["permitted_resources"][0] =
        "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into();
    let startup = sha256_hex(STARTUP);
    wire["proxy_startup"] = serde_json::json!({"drop_in_sha256":startup,"directory_created":true});
    wire["permitted_resources"].as_array_mut().unwrap().extend([
  serde_json::json!(format!("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:{startup}")),serde_json::json!("/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal")]);
    if let Some(index) = index {
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
        wire["client_identity_rotation"] = serde_json::json!({"operation_id":"1".repeat(32),"direction":if index<8{"cleanup"}else{"forward"},"effects":effects,"completed_effects":&effects[..index],"source_configuration_sha256":source_hash,"target_configuration_sha256":target_hash,"checkpoint":checkpoints[index]});
        wire["permitted_resources"].as_array_mut().unwrap().extend([
   serde_json::json!(format!("/var/lib/sbxr/client-identity-target.json root:root 0600 one-link sha256:{target_hash}")),serde_json::json!("/var/lib/sbxr/client-identity-target.json.sbxr-next root-owned Client Identity target publication"),serde_json::json!(format!("/etc/sing-box/.config.json.sbxr-next root:sing-box 0640 one-link sha256:{target_hash}")),serde_json::json!("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf.sbxr-next root-owned Client Identity startup publication")]);
        if index >= 9 {
            wire["configuration_sha256"] = target_hash.clone().into();
            for item in wire["permitted_resources"].as_array_mut().unwrap() {
                if let Some(s) = item.as_str()
                    && s.starts_with("/etc/sing-box/config.json ")
                {
                    *item = s.replace(&source_hash, &target_hash).into();
                }
            }
        }
    }
    let count = wire["permitted_resources"].as_array().unwrap().len();
    wire["resource_creating_releases"] =
        serde_json::Value::Array(vec![wire["release_identity"].clone(); count]);
    (
        OwnershipRecord::decode(&serde_json::to_vec(&wire).unwrap()).unwrap(),
        if index.is_some_and(|i| i >= 9) {
            target
        } else {
            source
        },
    )
}
fn host<'a>(
    root: &Root,
    proof: &'a AuthenticatedInstalled,
    socket: PathBuf,
) -> ProxyRuntimeHost<'a, Peers, Runner> {
    let (child, parent) = identities(root, proof);
    ProxyRuntimeHost::injected(
        &root.0,
        proof,
        Peers {
            current: child,
            peer: parent,
        },
        Runner {
            condition: CONDITION.as_bytes().to_vec(),
            stall: false,
        },
        socket,
    )
    .unwrap()
}
fn borrowed_attempt(
    root: &Root,
    proof: &AuthenticatedInstalled,
    owner: &HostLock,
    name: &str,
    context: &StartContext,
) -> Result<(), Error> {
    let socket = root.socket(name);
    let (child, parent) = identities(root, proof);
    let duplicate = owner.runtime_start_lock().unwrap();
    let offer = Handoff::new(
        root.bind(&socket),
        duplicate.start_lock(),
        Role::ProxyStartAuthorize,
        child.clone(),
    )
    .unwrap();
    std::thread::scope(|scope| {
        let peers = Peers {
            current: parent,
            peer: child,
        };
        let lender = scope.spawn(move || offer.accept(&peers, context));
        let result = runtime_handoff::authorize_proxy_start(&host(root, proof, socket), context);
        assert_eq!(lender.join().unwrap(), Ok(()));
        result
    })
}
#[test]
fn concrete_ordinary_start_checks_real_installed_group_unit_condition_and_configuration() {
    let (proof, _) = crate::release_acquisition::fixture_authenticated();
    let root = Root::new();
    let (r, configuration) = record(&proof, None);
    root.install(&proof, &r, &configuration);
    let socket = root.socket("unused.sock");
    let runtime = host(&root, &proof, socket);
    assert!(runtime_handoff::authorize_proxy_start(&runtime, &context()).is_ok());
    for (path, body, mode) in [
        ("etc/group", b"sing-box:x:99999:\n".as_slice(), 0o644),
        (
            "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
            b"foreign".as_slice(),
            0o644,
        ),
        ("etc/sing-box/config.json", b"foreign".as_slice(), 0o640),
    ] {
        root.write(path, body, mode);
        assert!(runtime_handoff::authorize_proxy_start(&runtime, &context()).is_err());
        root.install(&proof, &r, &configuration);
    }
}
#[test]
fn borrowed_source_or_target_start_consumes_exact_gate_once_without_unlocking_owner() {
    for index in [5, 9] {
        let (proof, _) = crate::release_acquisition::fixture_authenticated();
        let root = Root::new();
        let (r, configuration) = record(&proof, Some(index));
        root.install(&proof, &r, &configuration);
        let body = format!("{}\n", r.configuration_sha256());
        root.write("run/sbxr-client-identity-start", body.as_bytes(), 0o600);
        // A gate alone never converts ordinary exclusion into Owner authority.
        assert!(
            runtime_handoff::authorize_proxy_start(
                &host(&root, &proof, root.socket("unused.sock")),
                &context()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(root.0.join("run/sbxr-client-identity-start")).unwrap(),
            body.as_bytes()
        );
        let owner = HostLock::existing(&root.0, root.uid()).unwrap();
        let before = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        assert_eq!(
            borrowed_attempt(&root, &proof, &owner, "one.sock", &context()),
            Ok(())
        );
        assert!(!root.0.join("run/sbxr-client-identity-start").exists());
        owner.verify().unwrap();
        assert!(matches!(
            HostLock::existing(&root.0, root.uid()),
            Err(HostError::Busy)
        ));
        assert!(borrowed_attempt(&root, &proof, &owner, "two.sock", &context()).is_err());
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            before
        );
    }
}
#[test]
fn revoked_source_wrong_or_foreign_gate_and_pending_authority_never_authorize() {
    for variant in [
        "revoked source",
        "wrong gate",
        "mode",
        "hardlink",
        "pending",
    ] {
        let (proof, _) = crate::release_acquisition::fixture_authenticated();
        let root = Root::new();
        let (r, configuration) = record(
            &proof,
            Some(if variant == "revoked source" { 8 } else { 5 }),
        );
        root.install(&proof, &r, &configuration);
        let hash = if variant == "wrong gate" {
            "a".repeat(64)
        } else {
            r.configuration_sha256().into()
        };
        let body = format!("{hash}\n");
        root.write(
            "run/sbxr-client-identity-start",
            body.as_bytes(),
            if variant == "mode" { 0o644 } else { 0o600 },
        );
        if variant == "hardlink" {
            fs::hard_link(
                root.0.join("run/sbxr-client-identity-start"),
                root.0.join("foreign"),
            )
            .unwrap();
        }
        if variant == "pending" {
            root.write("var/lib/sbxr/.proxy-ownership.json.next", b"unknown", 0o600);
        }
        let owner = HostLock::existing(&root.0, root.uid()).unwrap();
        assert!(
            borrowed_attempt(&root, &proof, &owner, "refuse.sock", &context()).is_err(),
            "{variant}"
        );
        assert_eq!(
            fs::read(root.0.join("run/sbxr-client-identity-start")).unwrap(),
            body.as_bytes()
        );
        owner.verify().unwrap();
    }
}
#[test]
fn native_factory_refuses_this_mac_and_readonly_query_cancels_without_gate_effects() {
    let (proof, _) = crate::release_acquisition::fixture_authenticated();
    #[cfg(not(target_os = "linux"))]
    assert!(matches!(
        ProxyRuntimeHost::native_unreleased(&proof),
        Err(HostError::UnsupportedHost)
    ));
    let root = Root::new();
    let (r, configuration) = record(&proof, None);
    root.install(&proof, &r, &configuration);
    let mut runtime = host(&root, &proof, root.socket("unused.sock"));
    runtime.runner.stall = true;
    let context = StartContext::new(
        Cancellation::new(),
        Instant::now() + Duration::from_millis(40),
    );
    let before = Instant::now();
    assert!(matches!(
        runtime_handoff::authorize_proxy_start(&runtime, &context),
        Err(Error::Deadline)
    ));
    assert!(before.elapsed() < Duration::from_secs(1));
}
#[test]
fn effective_exec_condition_matches_the_go_exact_command_contract() {
    assert!(exact_start_condition(CONDITION));
    assert!(exact_start_condition(
        &CONDITION.replace(" ; }", " ; start_time=ignored ; }")
    ));
    for bad in [
        CONDITION.replace("ignore_errors=no", "ignore_errors=yes"),
        CONDITION.replace("argv[]=", "argv[]=+"),
        CONDITION.replace("path=/usr/local/bin/sbxr", "path=/bin/true"),
        format!("{CONDITION} {CONDITION}"),
        CONDITION.replace("ignore_errors=no", "ignore_errors=no ; ignore_errors=no"),
    ] {
        assert!(!exact_start_condition(&bad), "{bad}");
    }
}

#[test]
fn owner_gate_publication_is_record_bound_and_checked_cleanup_never_adopts_foreign_bytes() {
    for index in [None, Some(5), Some(8), Some(9)] {
        let (proof, _) = crate::release_acquisition::fixture_authenticated();
        let root = Root::new();
        let (r, configuration) = record(&proof, index);
        root.install(&proof, &r, &configuration);
        let runtime = host(&root, &proof, root.socket("unused.sock"));
        let owner = std::sync::Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
        let before = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        let gate = runtime.prepare_cutover(&owner, &context());
        if matches!(index, Some(5 | 9)) {
            let gate = gate.unwrap();
            assert_eq!(
                fs::read(root.0.join("run/sbxr-client-identity-start")).unwrap(),
                format!("{}\n", r.configuration_sha256()).as_bytes()
            );
            gate.runtime_start_lock()
                .unwrap()
                .start_lock()
                .verify()
                .unwrap();
            assert_eq!(
                borrowed_attempt(&root, &proof, &owner, "gate.sock", &context()),
                Ok(())
            );
            gate.finish().unwrap();
            assert!(!root.0.join("run/sbxr-client-identity-start").exists());
            let gate = runtime.prepare_cutover(&owner, &context()).unwrap();
            drop(gate);
            assert!(!root.0.join("run/sbxr-client-identity-start").exists());
            let gate = runtime.prepare_cutover(&owner, &context()).unwrap();
            root.write("run/sbxr-client-identity-start", b"foreign", 0o600);
            assert!(gate.finish().is_err());
            assert_eq!(
                fs::read(root.0.join("run/sbxr-client-identity-start")).unwrap(),
                b"foreign"
            );
        } else {
            assert!(gate.is_err());
            assert!(!root.0.join("run/sbxr-client-identity-start").exists());
        }
        owner.verify().unwrap();
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            before
        );
    }
}

#[test]
fn owner_start_lends_to_the_observed_service_without_a_preassigned_pid() {
    let (proof, _) = crate::release_acquisition::fixture_authenticated();
    let root = Root::new();
    let (r, configuration) = record(&proof, Some(9));
    root.install(&proof, &r, &configuration);
    let socket = root.socket("service.sock");
    let runtime = host(&root, &proof, socket.clone());
    let owner = std::sync::Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
    let gate = runtime.prepare_cutover(&owner, &context()).unwrap();
    let (child, parent) = identities(&root, &proof);
    let lender = Peers {
        current: parent,
        peer: child,
    };
    assert!(
        gate.start_fixture(&socket, &proof, &lender, &context(), |ctx| {
            runtime_handoff::authorize_proxy_start(&runtime, ctx).is_ok()
        })
    );
    gate.finish().unwrap();
    owner.verify().unwrap();
    assert!(!root.0.join("run/sbxr-client-identity-start").exists());
}
#[test]
fn service_bound_lending_refuses_other_executable_cgroup_or_uid_and_joins_on_failed_start() {
    for fault in ["image", "cgroup", "uid"] {
        let (proof, _) = crate::release_acquisition::fixture_authenticated();
        let root = Root::new();
        let (r, configuration) = record(&proof, Some(5));
        root.install(&proof, &r, &configuration);
        let socket = root.socket("bad-service.sock");
        let runtime = host(&root, &proof, socket.clone());
        let owner = std::sync::Arc::new(HostLock::existing(&root.0, root.uid()).unwrap());
        let gate = runtime.prepare_cutover(&owner, &context()).unwrap();
        let (mut child, parent) = identities(&root, &proof);
        match fault {
            "image" => child.executable_sha256 = "f".repeat(64),
            "cgroup" => child.cgroup = "/foreign.scope".into(),
            _ => child.uid += 1,
        };
        let lender = Peers {
            current: parent,
            peer: child,
        };
        let ctx = StartContext::new(
            Cancellation::new(),
            Instant::now() + Duration::from_millis(70),
        );
        assert!(!gate.start_fixture(&socket, &proof, &lender, &ctx, |ctx| {
            runtime_handoff::authorize_proxy_start(&runtime, ctx).is_ok()
        }));
        assert_eq!(
            fs::read(root.0.join("run/sbxr-client-identity-start")).unwrap(),
            format!("{}\n", r.configuration_sha256()).as_bytes()
        );
        gate.finish().unwrap();
        owner.verify().unwrap();
    }
}
