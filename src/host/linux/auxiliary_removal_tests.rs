use super::*;
use crate::host::{identity as ci, subscription as http};
const JOURNAL: &str = "var/lib/sbxr/proxy-ownership.json";
const OWNER_BINARY: &[u8] = b"owner synthetic cloudflared";
fn artifact(configuration: &[u8]) -> Vec<u8> {
    ServerConfiguration::decode_supported(configuration)
        .unwrap()
        .connection_facts("8.8.8.8")
        .unwrap()
        .subscription_artifact()
        .unwrap()
        .as_bytes()
        .to_vec()
}
type ClientHost = StandardRemovalHost<
    super::super::super::system::SystemRunner<SystemFixtureTransport>,
    RemovalAuxiliary,
>;
type TunnelHost = StandardRemovalHost<
    super::super::super::system::SystemRunner<SystemFixtureTransport>,
    TunnelRemovalRuntime<RemovalAuxiliary, RemovalConnector>,
>;
fn client_host(root: &Root, forward: bool, shape: usize) -> (ClientHost, RemovalAuxiliary) {
    let (mut host, runtime) = http_removal_host(root, false);
    let base = read_ownership(&host.inner.fs).unwrap().unwrap();
    let source = fs::read(root.0.join(CONFIG)).unwrap();
    let target = String::from_utf8(source.clone())
        .unwrap()
        .replace(
            "12345678-1234-4234-8234-123456789abc",
            "87654321-4321-4321-8321-cba987654321",
        )
        .into_bytes();
    let target_artifact = artifact(&target);
    let template: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/testdata/removal/client-subscription.json"
    ))
    .unwrap();
    let r = &template["client_identity_rotation"];
    let mut text = serde_json::to_string(&template).unwrap();
    for (old, new) in [
        (
            r["source_configuration_sha256"].as_str().unwrap(),
            sha256_hex(&source),
        ),
        (
            r["target_configuration_sha256"].as_str().unwrap(),
            sha256_hex(&target),
        ),
        (
            r["subscription"]["source_artifact_sha256"]
                .as_str()
                .unwrap(),
            sha256_hex(&artifact(&source)),
        ),
        (
            r["subscription"]["target_artifact_sha256"]
                .as_str()
                .unwrap(),
            sha256_hex(&target_artifact),
        ),
    ] {
        text = text.replace(old, &new);
    }
    let template: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&base.encode().unwrap()).unwrap();
    value["proxy_startup"] = template["proxy_startup"].clone();
    value["client_identity_rotation"] = template["client_identity_rotation"].clone();
    value["client_identity_rotation"]["subscription"]["source"] = value["serving"].clone();
    value["client_identity_rotation"]["subscription"]["target"] = value["serving"].clone();
    if !forward {
        let cleanup: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../tests/testdata/removal/client-cleanup.json"
        ))
        .unwrap();
        for field in ["direction", "completed_effects", "checkpoint"] {
            value["client_identity_rotation"][field] =
                cleanup["client_identity_rotation"][field].clone();
        }
    } else {
        value["configuration_sha256"] = sha256_hex(&target).into();
        for resource in value["permitted_resources"].as_array_mut().unwrap() {
            if resource
                .as_str()
                .unwrap()
                .starts_with("/etc/sing-box/config.json sha256:")
            {
                *resource =
                    format!("/etc/sing-box/config.json sha256:{}", sha256_hex(&target)).into();
            }
        }
        root.write(CONFIG, &target, 0o640);
    }
    let resources = template["permitted_resources"].as_array().unwrap();
    for resource in &resources[resources.len() - 12..] {
        value["permitted_resources"]
            .as_array_mut()
            .unwrap()
            .push(resource.clone());
        let creator = value["release_identity"].clone();
        value["resource_creating_releases"]
            .as_array_mut()
            .unwrap()
            .push(creator);
    }
    let record = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    root.write(JOURNAL, &record.encode().unwrap(), 0o600);
    root.write(ci::TARGET, &target, 0o600);
    root.write(ci::CONFIG_STAGE, &target, 0o640);
    root.write(
        ci::STARTUP,
        crate::client_identity::STARTUP_DROP_IN.as_bytes(),
        0o644,
    );
    fs::set_permissions(
        root.0.join(ci::STARTUP_DIR),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let stage = format!("{}.sbxr-next", ci::ARTIFACT);
    if shape != 2 {
        root.write(ci::ARTIFACT, &target_artifact, 0o600);
    }
    if shape == 1 || shape == 2 {
        root.write(&stage, &target_artifact, 0o600);
    }
    if shape == 3 {
        fs::hard_link(root.0.join(ci::ARTIFACT), root.0.join(&stage)).unwrap();
    }
    root.write(
        http::CANDIDATE_STATE,
        &record.serving_authority().unwrap().state_bytes().unwrap(),
        0o600,
    );
    let upgrade = format!("{}.sbxr-next", http::UNIT);
    root.write(
        &upgrade,
        crate::runtime_handoff::SERVING_UNIT.as_bytes(),
        0o644,
    );
    if shape == 3 {
        fs::hard_link(
            root.0.join(&upgrade),
            root.0.join(format!("{upgrade}.sbxr-next")),
        )
        .unwrap();
    }
    let mut material = SetupMaterial::for_removal(Some(&record)).unwrap();
    material.key_sha256 = host.inner.material.key_sha256.clone();
    material.package_sha256 = host.inner.material.package_sha256.clone();
    host.inner.material = material;
    (host, runtime)
}
#[test]
fn client_subscription_removal_cleans_all_publication_shapes_and_keeps_forward_direction() {
    for forward in [false, true] {
        for shape in 0..4 {
            let root = Root::new();
            let (host, runtime) = client_host(&root, forward, shape);
            runtime.fail_stop.set(true);
            let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
            let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
            assert_eq!(
                removal.execute(prepared, Confirmation::Approved).outcome,
                Outcome::RemovalNeedsCompletion,
                "forward {forward}, shape {shape}"
            );
            let record = OwnershipRecord::decode(&fs::read(root.0.join(JOURNAL)).unwrap()).unwrap();
            assert_eq!(
                record.recovery_direction(),
                crate::records::RecoveryDirection::Removal
            );
            assert!(!root.0.join(ci::ARTIFACT).exists());
            assert!(!root.0.join(format!("{}.sbxr-next", ci::ARTIFACT)).exists());
            assert!(root.0.join(http::TOKEN).exists());
            runtime.fail_stop.set(false);
            let prepared = removal.review(Action::FinishRemoval).prepared.unwrap();
            assert_eq!(
                removal.execute(prepared, Confirmation::Approved).outcome,
                Outcome::RemovalComplete
            );
            assert!(!root.0.join("var/lib/sbxr").exists());
            assert!(!root.0.join(CONFIG).exists());
        }
    }
}
#[test]
fn client_subscription_removal_preserves_unproven_artifacts_and_links() {
    for attack in 0..6 {
        let root = Root::new();
        let (host, _) = client_host(&root, true, 0);
        match attack {
            0 => root.write(ci::ARTIFACT, b"foreign artifact", 0o600),
            1 => fs::set_permissions(root.0.join(ci::ARTIFACT), fs::Permissions::from_mode(0o644))
                .unwrap(),
            2 => {
                fs::rename(root.0.join(ci::ARTIFACT), root.0.join("outside")).unwrap();
                symlink(root.0.join("outside"), root.0.join(ci::ARTIFACT)).unwrap();
            }
            3 => fs::hard_link(root.0.join(ci::ARTIFACT), root.0.join("outside")).unwrap(),
            4 => root.write(
                &format!("{}.sbxr-next.sbxr-next", http::UNIT),
                b"foreign startup",
                0o644,
            ),
            5 => root.write(http::CANDIDATE_STATE, b"foreign state", 0o600),
            _ => unreachable!(),
        }
        let before = fs::read(root.0.join(ci::ARTIFACT)).unwrap();
        let journal = fs::read(root.0.join(JOURNAL)).unwrap();
        let removal = crate::proxyinstallation::RemovalInstallation::new(host);
        assert!(
            removal.review(Action::CompleteRemoval).prepared.is_none(),
            "attack {attack}"
        );
        assert_eq!(fs::read(root.0.join(ci::ARTIFACT)).unwrap(), before);
        assert_eq!(fs::read(root.0.join(JOURNAL)).unwrap(), journal);
    }
}
#[derive(Clone)]
struct RemovalConnector {
    root: PathBuf,
    active: Arc<std::sync::atomic::AtomicBool>,
    loaded: Arc<std::sync::atomic::AtomicBool>,
    fault: Arc<AtomicUsize>,
    foreign_image: Arc<std::sync::atomic::AtomicBool>,
    commands: Arc<std::sync::Mutex<Vec<crate::host::tunnel_native::ConnectorAction>>>,
}
impl crate::host::tunnel_native::ConnectorIo for RemovalConnector {
    fn query(
        &self,
        q: crate::host::tunnel_native::ConnectorQuery,
        _: &Cancellation,
        _: std::time::Duration,
    ) -> Result<CommandOutput, HostError> {
        use crate::host::tunnel_native::ConnectorQuery as Q;
        let body=match q {
            Q::Version=>panic!("removal must not execute Owner cloudflared"),
            Q::Listener(_)=>panic!("removal must not probe a public connection"),
            Q::Properties if !self.loaded.load(Ordering::SeqCst)=>"LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n".into(),
            Q::Properties=>{let active=self.active.load(Ordering::SeqCst);format!("LoadState=loaded\nActiveState={}\nMainPID={}\nControlPID=0\nControlGroup={}\nFragmentPath=/etc/systemd/system/sbxr-tunnel.service\nDropInPaths=\nExecCondition=\nExecStartPre=\nExecStartPost=\nExecReload=\nExecStop=\nExecStopPost=\nKillMode=control-group\nDynamicUser=yes\nLoadCredential=tunnel-token:/etc/cloudflared/sbxr.token\nExecStart={{ path=/usr/bin/cloudflared ; argv[]=/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file /run/credentials/sbxr-tunnel.service/tunnel-token ; ignore_errors=no }}\n",if active{"active"}else{"inactive"},if active{"300"}else{"0"},if active{"/system.slice/sbxr-tunnel.service"}else{""})}
        };
        CommandOutput::completed(0, body.into_bytes())
    }
    fn command(
        &self,
        a: crate::host::tunnel_native::ConnectorAction,
        owner: &Arc<crate::host::locks::HostLock>,
        _: &Cancellation,
    ) -> Result<(), HostError> {
        use crate::host::tunnel_native::ConnectorAction as A;
        owner.verify()?;
        assert!(matches!(
            crate::host::locks::HostLock::existing(
                &self.root,
                fs::metadata(&self.root).unwrap().uid()
            ),
            Err(HostError::Busy)
        ));
        self.commands.lock().unwrap().push(a);
        let fault = self.fault.load(Ordering::SeqCst);
        if a == A::Stop && fault == 1 {
            self.fault.store(0, Ordering::SeqCst);
            return Err(HostError::Injected);
        }
        match a {
            A::Start => panic!("removal must never restart a connector"),
            A::Stop => self.active.store(false, Ordering::SeqCst),
            A::Reload => {
                if fault == 3 {
                    self.fault.store(0, Ordering::SeqCst);
                    return Err(HostError::Injected);
                }
                self.loaded.store(
                    self.root
                        .join("etc/systemd/system/sbxr-tunnel.service")
                        .exists(),
                    Ordering::SeqCst,
                );
            }
        }
        if a == A::Stop && fault == 2 {
            self.fault.store(0, Ordering::SeqCst);
            return Err(HostError::Injected);
        }
        Ok(())
    }
    fn process(&self, pid: u32) -> Result<crate::runtime_handoff::ProcessIdentity, HostError> {
        crate::runtime_handoff::ProcessIdentity::new(
            pid,
            1,
            2,
            2000,
            &if self.foreign_image.load(Ordering::SeqCst) {
                "f".repeat(64)
            } else {
                sha256_hex(OWNER_BINARY)
            },
            "/system.slice/sbxr-tunnel.service",
        )
        .map_err(|_| HostError::Foreign)
    }
    fn quiescent(&self, _: &Cancellation) -> Result<bool, HostError> {
        Ok(!self.active.load(Ordering::SeqCst))
    }
}
fn tunnel_host(
    root: &Root,
    missing_owner: bool,
) -> (TunnelHost, RemovalConnector, RemovalAuxiliary) {
    let (host, http) = client_host(root, true, 3);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.0.join(JOURNAL)).unwrap()).unwrap();
    let authority = crate::records::TunnelAuthority::new(
        "11111111-2222-4333-8444-555555555555",
        &sha256_hex(b"Owner token"),
        &sha256_hex(OWNER_BINARY),
    )
    .unwrap();
    value["tunnel"] = serde_json::json!({"tunnel_id":authority.tunnel_id(),"token_sha256":sha256_hex(b"Owner token"),"binary_sha256":authority.binary_sha256()});
    let offset = value["permitted_resources"]
        .as_array()
        .unwrap()
        .iter()
        .position(|r| {
            r.as_str()
                .unwrap()
                .starts_with("/etc/systemd/system/sbxr-subscription.service ")
        })
        .unwrap();
    let resources: Vec<_> = authority
        .resources()
        .into_iter()
        .map(serde_json::Value::String)
        .collect();
    let creators = vec![value["release_identity"].clone(); resources.len()];
    value["permitted_resources"]
        .as_array_mut()
        .unwrap()
        .splice(offset..offset, resources);
    value["resource_creating_releases"]
        .as_array_mut()
        .unwrap()
        .splice(offset..offset, creators);
    let record = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    root.write(JOURNAL, &record.encode().unwrap(), 0o600);
    root.write(
        "etc/systemd/system/sbxr-tunnel.service",
        crate::server_configuration::tunnel_unit().as_bytes(),
        0o644,
    );
    symlink(
        "../sbxr-tunnel.service",
        root.0
            .join("etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"),
    )
    .unwrap();
    if !missing_owner {
        root.write("etc/cloudflared/sbxr.token", b"Owner token", 0o600);
        root.write("usr/bin/cloudflared", OWNER_BINARY, 0o755);
    }
    root.write(
        "etc/cloudflared/config.yml",
        b"foreign Owner configuration",
        0o600,
    );
    root.write(
        "etc/systemd/system/cloudflared.service",
        b"unrelated Owner service",
        0o644,
    );
    fs::create_dir_all(root.0.join("etc/systemd/system/graphical.target.wants")).unwrap();
    symlink(
        "../sbxr-tunnel.service",
        root.0
            .join("etc/systemd/system/graphical.target.wants/sbxr-tunnel.service"),
    )
    .unwrap();
    let io = RemovalConnector {
        root: root.0.clone(),
        active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        loaded: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        fault: Arc::new(AtomicUsize::new(0)),
        foreign_image: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        commands: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let connector = crate::host::tunnel_native::Connector::injected(&root.0, io.clone()).unwrap();
    (host.with_tunnel(connector), io, http)
}
#[test]
fn dedicated_tunnel_removal_retries_each_interruption_preserving_owner_resources() {
    for missing in [false, true] {
        for fault in 0..=3 {
            let root = Root::new();
            let (host, io, http) = tunnel_host(&root, missing);
            io.fault.store(fault, Ordering::SeqCst);
            let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
            let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
            let result = removal.execute(prepared, Confirmation::Approved);
            if fault != 0 {
                assert_eq!(
                    result.outcome,
                    Outcome::RemovalNeedsCompletion,
                    "fault {fault}"
                );
                assert_eq!(
                    OwnershipRecord::decode(&fs::read(root.0.join(JOURNAL)).unwrap())
                        .unwrap()
                        .recovery_direction(),
                    crate::records::RecoveryDirection::Removal
                );
                let inner = {
                    let host = removal.into_host();
                    host.inner
                };
                let connector =
                    crate::host::tunnel_native::Connector::injected(&root.0, io.clone()).unwrap();
                let host = StandardRemovalHost::new(inner)
                    .unwrap()
                    .with_auxiliary(http)
                    .with_tunnel(connector);
                let mut reopened = crate::proxyinstallation::RemovalInstallation::new(host);
                let prepared = reopened.review(Action::FinishRemoval).prepared.unwrap();
                assert_eq!(
                    reopened.execute(prepared, Confirmation::Approved).outcome,
                    Outcome::RemovalComplete,
                    "fault {fault}"
                );
            } else {
                assert_eq!(result.outcome, Outcome::RemovalComplete);
            }
            assert_eq!(
                fs::read(root.0.join("etc/cloudflared/config.yml")).unwrap(),
                b"foreign Owner configuration"
            );
            assert_eq!(
                fs::read(root.0.join("etc/systemd/system/cloudflared.service")).unwrap(),
                b"unrelated Owner service"
            );
            assert_eq!(
                fs::read_link(
                    root.0
                        .join("etc/systemd/system/graphical.target.wants/sbxr-tunnel.service")
                )
                .unwrap(),
                Path::new("../sbxr-tunnel.service")
            );
            if !missing {
                assert_eq!(
                    fs::read(root.0.join("etc/cloudflared/sbxr.token")).unwrap(),
                    b"Owner token"
                );
                assert_eq!(
                    fs::read(root.0.join("usr/bin/cloudflared")).unwrap(),
                    OWNER_BINARY
                );
            }
        }
    }
}
#[test]
fn dedicated_tunnel_removal_preserves_foreign_units_links_processes_and_unowned_names() {
    for attack in 0..6 {
        let root = Root::new();
        let (host, io, _) = tunnel_host(&root, false);
        let unit = "etc/systemd/system/sbxr-tunnel.service";
        match attack {
            0 => root.write(unit, b"foreign connector", 0o644),
            1 => {
                fs::rename(root.0.join(unit), root.0.join("outside")).unwrap();
                symlink(root.0.join("outside"), root.0.join(unit)).unwrap();
            }
            2 => fs::hard_link(root.0.join(unit), root.0.join("outside")).unwrap(),
            3 => root.write(
                "etc/systemd/system/sbxr-tunnel.service.d/foreign.conf",
                b"foreign dropin",
                0o644,
            ),
            4 => io.foreign_image.store(true, Ordering::SeqCst),
            5 => {
                fs::remove_file(
                    root.0
                        .join("etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"),
                )
                .unwrap();
                symlink(
                    "../cloudflared.service",
                    root.0
                        .join("etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::read(root.0.join(unit)).unwrap();
        let journal = fs::read(root.0.join(JOURNAL)).unwrap();
        let removal = crate::proxyinstallation::RemovalInstallation::new(host);
        assert!(
            removal.review(Action::CompleteRemoval).prepared.is_none(),
            "attack {attack}"
        );
        assert_eq!(fs::read(root.0.join(unit)).unwrap(), before);
        assert_eq!(fs::read(root.0.join(JOURNAL)).unwrap(), journal);
        assert!(io.commands.lock().unwrap().is_empty());
    }
}
#[test]
fn dedicated_tunnel_interrupted_reload_never_grants_ordinary_start_or_erases_foreign_stage() {
    let root = Root::new();
    let (host, io, _) = tunnel_host(&root, true);
    io.fault.store(3, Ordering::SeqCst);
    let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
    let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalNeedsCompletion
    );
    let connector = crate::host::tunnel_native::Connector::injected(&root.0, io.clone()).unwrap();
    assert!(connector.inspect(true, &Cancellation::new()).is_err());
    root.write(
        "etc/systemd/system/sbxr-tunnel.service.sbxr-next",
        b"foreign staged connector",
        0o644,
    );
    assert!(removal.review(Action::FinishRemoval).prepared.is_none());
    assert_eq!(
        fs::read(
            root.0
                .join("etc/systemd/system/sbxr-tunnel.service.sbxr-next")
        )
        .unwrap(),
        b"foreign staged connector"
    );
    assert!(root.0.join(ci::ARTIFACT).exists());
}
#[test]
fn client_subscription_removal_reopens_after_every_completed_file_cleanup_boundary() {
    for point in 0..=2 {
        let root = Root::new();
        let (mut host, runtime) = client_host(&root, true, 3);
        host.interrupt_auxiliary_removal(point);
        let before = fs::read(root.0.join(CONFIG)).unwrap();
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalNeedsCompletion
        );
        assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), before);
        assert!(runtime.active.get()); // Artifact cleanup does not restart/reconfigure serving.
        let inner = {
            let host = removal.into_host();
            host.inner
        };
        let host = StandardRemovalHost::new(inner)
            .unwrap()
            .with_auxiliary(runtime);
        let mut reopened = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = reopened.review(Action::FinishRemoval).prepared.unwrap();
        assert_eq!(
            reopened.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete,
            "boundary {point}"
        );
        assert!(!root.0.join("var/lib/sbxr").exists());
    }
}
#[test]
fn auxiliary_removal_never_adopts_an_artifact_without_rotation_authority() {
    for orphan in [
        ci::ARTIFACT.to_owned(),
        format!("{}.sbxr-next", ci::ARTIFACT),
        format!("{}.sbxr-next.sbxr-next", http::UNIT),
    ] {
        let root = Root::new();
        let (host, _) = http_removal_host(&root, false);
        let bytes = if orphan.contains("client-artifact") {
            artifact(&fs::read(root.0.join(CONFIG)).unwrap())
        } else {
            crate::runtime_handoff::SERVING_UNIT.as_bytes().to_vec()
        };
        root.write(
            &orphan,
            &bytes,
            if orphan.contains("client-artifact") {
                0o600
            } else {
                0o644
            },
        );
        let before = fs::read(root.0.join(JOURNAL)).unwrap();
        let removal = crate::proxyinstallation::RemovalInstallation::new(host);
        assert!(removal.review(Action::CompleteRemoval).prepared.is_none());
        assert_eq!(fs::read(root.0.join(orphan)).unwrap(), bytes);
        assert_eq!(fs::read(root.0.join(JOURNAL)).unwrap(), before);
    }
}

#[test]
fn dedicated_connector_removal_plans_only_exact_stop_and_reload() {
    use crate::host::tunnel_native::ConnectorAction;
    assert_eq!(
        ConnectorAction::Stop.arguments(),
        &["stop", "sbxr-tunnel.service"]
    );
    assert_eq!(ConnectorAction::Reload.arguments(), &["daemon-reload"]);
}
#[test]
fn dedicated_tunnel_without_subscription_needs_no_http_runtime_or_owner_material() {
    let root = Root::new();
    let (host, _) = running_removal_host(&root);
    let original = read_ownership(&host.inner.fs).unwrap().unwrap();
    let authority = crate::records::TunnelAuthority::new(
        "11111111-2222-4333-8444-555555555555",
        &sha256_hex(b"missing Owner token"),
        &sha256_hex(OWNER_BINARY),
    )
    .unwrap();
    let mut record = OwnershipRecord::new_tunnel_setup(
        original.release_identity(),
        original.public_ipv4(),
        original.configuration_sha256(),
        authority,
    )
    .unwrap();
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    root.write(JOURNAL, &record.encode().unwrap(), 0o600);
    root.write(
        "etc/systemd/system/sbxr-tunnel.service",
        crate::server_configuration::tunnel_unit().as_bytes(),
        0o644,
    );
    symlink(
        "../sbxr-tunnel.service",
        root.0
            .join("etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"),
    )
    .unwrap();
    let io = RemovalConnector {
        root: root.0.clone(),
        active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        loaded: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        fault: Arc::new(AtomicUsize::new(0)),
        foreign_image: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        commands: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let connector = crate::host::tunnel_native::Connector::injected(&root.0, io).unwrap();
    let mut removal =
        crate::proxyinstallation::RemovalInstallation::new(host.with_tunnel(connector));
    let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalComplete
    );
    assert!(!root.0.join("var/lib/sbxr").exists());
    assert!(!root.0.join("etc/cloudflared").exists());
}
