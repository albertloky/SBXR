//! Socket-free protected HTTP authority tests. Runtime health is injected;
//! service execution and HTTP/network qualification are deliberately absent.
use super::*;
use crate::host::subscription::{FIREWALL, HttpEffect};
#[test]
fn two_node_http_review_requires_matching_protected_configuration_and_authority() {
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
    let standard = fs::read(root.0.join("etc/sing-box/config.json")).unwrap();
    let config = crate::server_configuration::ServerConfiguration::decode_standard(&standard)
        .unwrap()
        .with_vmess_websocket("offline.example.com")
        .unwrap();
    let authority = crate::records::TunnelAuthority::new(
        "12345678-1234-1234-1234-123456789abc",
        &"1".repeat(64),
        &"2".repeat(64),
    )
    .unwrap();
    let mut record = OwnershipRecord::new_tunnel_setup(
        proof.record().release_identity(),
        "8.8.8.8",
        &config.sha256_hex(),
        authority,
    )
    .unwrap();
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    root.write("etc/sing-box/config.json", config.as_bytes(), 0o640);
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &record.encode().unwrap(),
        0o600,
    );
    let m = module(&root, &proof, archive);
    assert!(
        m.review(Action::EnableSubscription).prepared.is_some(),
        "proved two-node configuration must remain supported"
    );
    root.write("etc/sing-box/config.json", &standard, 0o640);
    assert!(
        m.review(Action::EnableSubscription).prepared.is_none(),
        "changed configuration is not adopted"
    );
    assert_eq!(
        fs::read(root.0.join("etc/sing-box/config.json")).unwrap(),
        standard
    );
    assert!(!root.0.join(FIREWALL).exists());
    // Ownership of a connector does not authorize a mismatched single-node shape.
    let authority = record.tunnel_authority().unwrap();
    let mut inconsistent = OwnershipRecord::new_tunnel_setup(
        proof.record().release_identity(),
        "8.8.8.8",
        &sha256_hex(&standard),
        authority,
    )
    .unwrap();
    while inconsistent.phase() != SetupPhase::Running {
        inconsistent = inconsistent.next_setup_checkpoint().unwrap();
    }
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &inconsistent.encode().unwrap(),
        0o600,
    );
    assert!(m.review(Action::EnableSubscription).prepared.is_none());
}

#[derive(Clone)]
struct FileRuntime {
    root: PathBuf,
    active: bool,
    rule: bool,
}
impl HttpRuntime for FileRuntime {
    fn facts(&self) -> Result<RuntimeFacts, HostError> {
        let rule = if self.rule {
            "-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n"
        } else {
            ""
        };
        Ok(RuntimeFacts {
            public_ipv4: "8.8.8.8".into(),
            proxy_running: true,
            firewall_rules: format!("*filter\n:INPUT ACCEPT [0:0]\n{rule}COMMIT\n"),
            serving_running: self.active,
            quiescent: !self.active,
        })
    }
    fn effect(
        &mut self,
        e: SystemEffect,
        _: &OwnershipRecord,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        c.check().map_err(|_| HostError::Cancelled)?;
        owner.verify()?;
        if owner.root() != self.root {
            return Err(HostError::Foreign);
        }
        match e {
            SystemEffect::Reload => {}
            SystemEffect::EnableFirewall => self.rule = true,
            SystemEffect::DisableFirewall => self.rule = false,
            SystemEffect::ActivateServing => self.active = true,
            SystemEffect::StopServing | SystemEffect::DisableServing => self.active = false,
        }
        Ok(())
    }
    fn probe(
        &self,
        r: &OwnershipRecord,
        a: &crate::records::ServingAuthority,
        token: &SubscriptionCredential,
        c: &StartContext,
    ) -> Result<(), HostError> {
        c.check().map_err(|_| HostError::Cancelled)?;
        let bytes =
            fs::read(self.root.join("etc/sing-box/config.json")).map_err(|_| HostError::Io)?;
        if !self.active
            || a.credential_sha256() != sha256_hex(token.as_str().as_bytes())
            || sha256_hex(&bytes) != r.configuration_sha256()
        {
            return Err(HostError::Foreign);
        }
        let body = crate::server_configuration::ServerConfiguration::decode_supported(&bytes)
            .map_err(|_| HostError::Foreign)?
            .connection_facts(r.public_ipv4())
            .map_err(|_| HostError::Foreign)?
            .subscription_artifact()
            .map_err(|_| HostError::Foreign)?;
        let lines = std::str::from_utf8(body.as_bytes())
            .map_err(|_| HostError::Foreign)?
            .lines()
            .collect::<Vec<_>>();
        if lines.len() != 2
            || !lines[0].starts_with("vless://")
            || !lines[1].starts_with("vmess://")
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
fn two_node(root: &Root, archive: &AuthenticatedArchive) -> OwnershipRecord {
    root.setup(archive);
    let bytes = fs::read(root.0.join("etc/sing-box/config.json")).unwrap();
    let config = crate::server_configuration::ServerConfiguration::decode_standard(&bytes)
        .unwrap()
        .with_vmess_websocket("offline.example.com")
        .unwrap();
    let authority = crate::records::TunnelAuthority::new(
        "12345678-1234-1234-1234-123456789abc",
        &"1".repeat(64),
        &"2".repeat(64),
    )
    .unwrap();
    let mut r = OwnershipRecord::new_tunnel_setup(
        archive.record().release_identity(),
        "8.8.8.8",
        &config.sha256_hex(),
        authority,
    )
    .unwrap();
    while r.phase() != SetupPhase::Running {
        r = r.next_setup_checkpoint().unwrap();
    }
    root.write("etc/sing-box/config.json", config.as_bytes(), 0o640);
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &r.encode().unwrap(),
        0o600,
    );
    r
}
fn read_record(root: &Root) -> OwnershipRecord {
    OwnershipRecord::decode(&fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap())
        .unwrap()
}
fn file_module<'a>(
    root: &Root,
    proof: &'a AuthenticatedInstalled,
    runtime: FileRuntime,
    seed: u8,
) -> HttpInstallation<ProtectedHttpHost<'a, FileRuntime>> {
    HttpInstallation::with_entropy(
        ProtectedHttpHost::injected(&root.0, proof, runtime).unwrap(),
        proof.record().release_identity(),
        Box::new(EntropyCounter(seed)),
    )
    .unwrap()
}
fn unchanged_profile(root: &Root, initial: &OwnershipRecord) {
    let r = read_record(root);
    assert_eq!(r.tunnel_authority(), initial.tunnel_authority());
    assert_eq!(r.configuration_sha256(), initial.configuration_sha256());
    assert_eq!(
        sha256_hex(&fs::read(root.0.join("etc/sing-box/config.json")).unwrap()),
        initial.configuration_sha256()
    );
    assert!(r.http_operation().unwrap().is_none());
}
#[test]
fn two_node_http_enable_rotate_repair_preserve_independent_tunnel_authority() {
    let root = Root::new();
    let archive = crate::release_acquisition::fixture_archive();
    let initial = two_node(&root, &archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let runtime = FileRuntime {
        root: root.0.clone(),
        active: false,
        rule: false,
    };
    let mut m = file_module(&root, &proof, runtime, 0);
    assert_eq!(
        execute(&mut m, Action::EnableSubscription).outcome,
        Outcome::SubscriptionEnabled
    );
    let first = fs::read(root.0.join(TOKEN)).unwrap();
    unchanged_profile(&root, &initial);
    assert_eq!(
        execute(&mut m, Action::RotateSubscriptionLink).outcome,
        Outcome::SubscriptionLinkRotated
    );
    let rotated = fs::read(root.0.join(TOKEN)).unwrap();
    assert_ne!(first, rotated);
    unchanged_profile(&root, &initial);
    m.host_mut().backend_mut().active = false;
    assert_eq!(
        execute(&mut m, Action::RepairSubscription).outcome,
        Outcome::SubscriptionRepaired
    );
    assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), rotated);
    unchanged_profile(&root, &initial);
}
#[test]
fn two_node_http_interrupted_enablement_reopens_for_cleanup_only() {
    for &checkpoint in crate::records::HTTP_ENABLEMENT_CHECKPOINTS.iter().skip(1) {
        for after in [false, true] {
            let root = Root::new();
            let archive = crate::release_acquisition::fixture_archive();
            let initial = two_node(&root, &archive);
            let proof = archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap();
            let mut m = file_module(
                &root,
                &proof,
                FileRuntime {
                    root: root.0.clone(),
                    active: false,
                    rule: false,
                },
                0,
            );
            let effect = HttpEffect::Enable(checkpoint);
            m.host_mut().inject_fault(Some(if after {
                HttpFault::After(effect)
            } else {
                HttpFault::Before(effect)
            }));
            assert_eq!(
                execute(&mut m, Action::EnableSubscription).outcome,
                Outcome::SubscriptionChangeIncomplete
            );
            assert!(m.take_subscription_link().is_none());
            let runtime = m.into_host().into_backend();
            let mut reopened = file_module(&root, &proof, runtime, 120);
            assert_eq!(
                execute(&mut reopened, Action::FinishSubscriptionChange).outcome,
                Outcome::SubscriptionChangeCleanedUp
            );
            assert!(!root.0.join(TOKEN).exists());
            unchanged_profile(&root, &initial);
        }
    }
}
#[test]
fn two_node_http_rotation_and_repair_recover_without_revoked_source_resurrection() {
    for (repair, effect) in [
        (false, HttpEffect::PrepareRotation),
        (false, HttpEffect::StopSource),
        (false, HttpEffect::PublishTarget),
        (false, HttpEffect::Activate),
        (false, HttpEffect::Verify),
        (true, HttpEffect::Activate),
        (true, HttpEffect::Verify),
        (true, HttpEffect::FinishRepairState),
    ] {
        for after in [false, true] {
            let root = Root::new();
            let archive = crate::release_acquisition::fixture_archive();
            let initial = two_node(&root, &archive);
            let proof = archive
                .bind_current(
                    archive.executable(),
                    archive.executable(),
                    &crate::artifact_trust::SelectionBudget::new(),
                )
                .unwrap();
            let mut m = file_module(
                &root,
                &proof,
                FileRuntime {
                    root: root.0.clone(),
                    active: false,
                    rule: false,
                },
                0,
            );
            execute(&mut m, Action::EnableSubscription);
            let source = fs::read(root.0.join(TOKEN)).unwrap();
            if repair {
                m.host_mut().backend_mut().active = false;
            }
            m.host_mut().inject_fault(Some(if after {
                HttpFault::After(effect)
            } else {
                HttpFault::Before(effect)
            }));
            let action = if repair {
                Action::RepairSubscription
            } else {
                Action::RotateSubscriptionLink
            };
            assert_eq!(
                execute(&mut m, action).outcome,
                Outcome::SubscriptionChangeIncomplete
            );
            let forward = matches!(
                read_record(&root).http_operation().unwrap(),
                Some(crate::records::HttpOperation::Rotation {
                    direction: crate::records::ChangeDirection::Forward,
                    ..
                })
            );
            let runtime = m.into_host().into_backend();
            let mut reopened = file_module(&root, &proof, runtime, 120);
            let result = execute(&mut reopened, Action::FinishSubscriptionChange);
            assert!(!matches!(
                result.outcome,
                Outcome::Refused | Outcome::SubscriptionChangeIncomplete
            ));
            if forward {
                assert_ne!(fs::read(root.0.join(TOKEN)).unwrap(), source);
            } else {
                assert_eq!(fs::read(root.0.join(TOKEN)).unwrap(), source);
            }
            unchanged_profile(&root, &initial);
        }
    }
}

#[test]
fn two_node_http_stale_configuration_and_unsafe_file_never_grant_effects() {
    let root = Root::new();
    let archive = crate::release_acquisition::fixture_archive();
    two_node(&root, &archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = file_module(
        &root,
        &proof,
        FileRuntime {
            root: root.0.clone(),
            active: false,
            rule: false,
        },
        0,
    );
    let old = m.review(Action::EnableSubscription).prepared.unwrap();
    let path = root.0.join("etc/sing-box/config.json");
    let original = fs::read(&path).unwrap();
    let changed_bytes = std::str::from_utf8(&original)
        .unwrap()
        .replace("offline.example.com", "changed.example.com");
    let changed = crate::server_configuration::ServerConfiguration::decode_supported(
        changed_bytes.as_bytes(),
    )
    .unwrap();
    root.write("etc/sing-box/config.json", changed.as_bytes(), 0o640);
    assert_eq!(
        m.execute(old, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert_eq!(fs::read(&path).unwrap(), changed.as_bytes());
    assert!(!root.0.join(FIREWALL).exists());
    root.write("etc/sing-box/config.json", &original, 0o644);
    assert!(m.review(Action::EnableSubscription).prepared.is_none());
    root.write("etc/sing-box/config.json", &original, 0o640);
    fs::hard_link(&path, root.0.join("foreign-alias")).unwrap();
    assert!(m.review(Action::EnableSubscription).prepared.is_none());
    assert_eq!(fs::read(root.0.join("foreign-alias")).unwrap(), original);
}
#[test]
fn failed_tunnel_journey_does_not_acquire_or_leak_another_journeys_writer() {
    struct Sources<'a> {
        root: &'a Root,
        proof: &'a AuthenticatedInstalled,
    }
    impl<'a> OwnerSources<'a> for Sources<'a> {
        fn journeys(&self) -> Result<Vec<Journey>, HostError> {
            Ok(vec![Journey::Tunnel, Journey::Http])
        }
        fn open(&self, j: Journey) -> Result<Box<dyn Interface + 'a>, HostError> {
            if j != Journey::Http {
                return Err(HostError::LiveUnavailable);
            }
            Ok(Box::new(file_module(
                self.root,
                self.proof,
                FileRuntime {
                    root: self.root.0.clone(),
                    active: false,
                    rule: false,
                },
                0,
            )))
        }
        fn mode(&self) -> ExecutionMode {
            ExecutionMode::InjectedHost
        }
    }
    let root = Root::new();
    let archive = crate::release_acquisition::fixture_archive();
    two_node(&root, &archive);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut owner = OwnerInstallation::new(Sources {
        root: &root,
        proof: &proof,
    });
    let action = owner.review(Action::EnableSubscription).prepared.unwrap();
    let directory = root.0.join("var/lib/sbxr");
    assert!(matches!(
        crate::durable::OwnershipStore::open(&directory, root.uid()),
        Err(crate::durable::StoreError {
            kind: crate::durable::StoreErrorKind::Busy,
            ..
        })
    ));
    owner.review(Action::Status);
    drop(crate::durable::OwnershipStore::open(&directory, root.uid()).unwrap());
    assert_eq!(
        owner.execute(action, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert!(!root.0.join(TOKEN).exists());
}
