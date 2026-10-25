use super::*;
use crate::host::subscription as http;
#[derive(Clone)]
struct LegacyRuntime {
    root: PathBuf,
    active: std::rc::Rc<std::cell::Cell<bool>>,
    firewall: std::rc::Rc<std::cell::Cell<bool>>,
    stale: std::rc::Rc<std::cell::Cell<bool>>,
    live: std::rc::Rc<std::cell::Cell<bool>>,
}
impl AuxiliaryRuntime for LegacyRuntime {
    fn observe(&self, record: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError> {
        let v: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        let legacy = v["subscription_resources"]["http"] != true;
        let mut rules = "*filter\n:INPUT ACCEPT [0:0]\n".to_owned();
        if self.firewall.get() {
            for port in if legacy { vec![80, 8443] } else { vec![8443] } {
                rules.push_str(&format!("-A INPUT -d {}/32 -p tcp -m tcp --dport {port} -m comment --comment sbxr-subscription -j ACCEPT\n",record.public_ipv4()));
            }
        }
        rules.push_str("COMMIT\n");
        Ok(AuxiliaryFacts {
            fingerprint: "synthetic historical runtime".into(),
            serving_running: self.active.get(),
            quiescent: !self.active.get(),
            firewall_rules: rules,
        })
    }
    fn disable(
        &mut self,
        firewall: bool,
        _: &OwnershipRecord,
        owner: &Arc<crate::host::locks::HostLock>,
    ) -> Result<(), HostError> {
        owner.verify()?;
        if firewall {
            self.firewall.set(false);
        } else {
            self.active.set(false);
        }
        Ok(())
    }
    fn historical(
        &self,
        _: &OwnershipRecord,
        unfinished: &[crate::host::historical::UnfinishedRenewal],
    ) -> Result<HistoricalRuntimeFacts, HostError> {
        Ok(HistoricalRuntimeFacts {
            fingerprint: format!("{:?}:{}", unfinished, self.stale.get()),
            renewal_quiet: !self.live.get(),
            official_route: !self.stale.get()
                && !self
                    .root
                    .join("etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf")
                    .exists(),
        })
    }
}
fn parts(g: u32) -> [Vec<u8>; 4] {
    [
        format!("owned cert {g}\n").into_bytes(),
        format!("owned chain {g}\n").into_bytes(),
        format!("owned fullchain {g}\n").into_bytes(),
        format!("owned private key {g}\n").into_bytes(),
    ]
}
fn rewrite_certificates(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(o) => {
            if let Some(g) = o
                .get("certificate_generation")
                .and_then(|v| v.as_u64())
                .filter(|g| *g > 0)
            {
                o.insert(
                    "certificate_sha256".into(),
                    serde_json::json!(parts(g as u32).map(|p| sha256_hex(&p))),
                );
            }
            for child in o.values_mut() {
                rewrite_certificates(child);
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                rewrite_certificates(child);
            }
        }
        _ => {}
    }
}
type LegacyHost = StandardRemovalHost<
    super::super::super::system::SystemRunner<SystemFixtureTransport>,
    LegacyRuntime,
>;
fn fixture(root: &Root, retired: bool) -> (LegacyHost, LegacyRuntime) {
    let (mut inner, original) = {
        let (base, _) = running_removal_host(root);
        let original = read_ownership(&base.inner.fs).unwrap().unwrap();
        (base.inner, original)
    };
    let bytes = if retired {
        include_bytes!("../../records/testdata/authority/http-retired-https.json").as_slice()
    } else {
        include_bytes!("../../records/testdata/authority/https-activation-b.json").as_slice()
    };
    let mut v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    v["release_identity"]=serde_json::to_value(serde_json::from_slice::<serde_json::Value>(&original.encode().unwrap()).unwrap()["release_identity"].clone()).unwrap();
    v["configuration_sha256"] = original.configuration_sha256().into();
    rewrite_certificates(&mut v);
    let evidence=serde_json::to_vec(&serde_json::json!({"schema":1,"recorder_id":"33333333333333333333333333333333","established_at":"2026-01-01T00:00:00Z","attempts":[]})).unwrap();
    let configuration=b"archive_dir = /etc/letsencrypt/archive/sbxr-subscription\ncert = /etc/letsencrypt/live/sbxr-subscription/cert.pem\n";
    if retired {
        v["https_retirement"]["configuration_sha256"] = sha256_hex(configuration).into();
        v["https_retirement"]["evidence_sha256"] = sha256_hex(&evidence).into();
    }
    let mut record = crate::records::historical_fixture(v);
    if !retired {
        let unit = crate::host::historical::firewall_unit(&record).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        v["subscription_resources"]["firewall_sha256"] = sha256_hex(&unit).into();
        record = crate::records::historical_fixture(v);
    }
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &record.encode().unwrap(),
        0o600,
    );
    for d in [
        "etc/letsencrypt/archive/sbxr-subscription",
        "etc/letsencrypt/live/sbxr-subscription",
        "var/lib/letsencrypt",
        "var/log/letsencrypt",
    ] {
        fs::create_dir_all(root.0.join(d)).unwrap();
        fs::set_permissions(
            root.0.join(d),
            fs::Permissions::from_mode(if d.contains("sbxr-subscription") {
                0o700
            } else {
                0o755
            }),
        )
        .unwrap();
    }
    for g in 1..=if retired { 1 } else { 2 } {
        for (i, name) in ["cert", "chain", "fullchain", "privkey"].iter().enumerate() {
            root.write(
                &format!("etc/letsencrypt/archive/sbxr-subscription/{name}{g}.pem"),
                &parts(g)[i],
                if i == 3 { 0o600 } else { 0o644 },
            );
        }
    }
    for name in ["cert", "chain", "fullchain", "privkey"] {
        symlink(
            format!(
                "../../archive/sbxr-subscription/{name}{}.pem",
                if retired { 1 } else { 2 }
            ),
            root.0
                .join(format!("etc/letsencrypt/live/sbxr-subscription/{name}.pem")),
        )
        .unwrap();
    }
    let managed = [
        (
            "recorder.conf",
            "etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf",
            b"[Service]\nExecStart=\nExecStart=/usr/local/bin/sbxr --certbot-recorder\n".as_slice(),
            0o644,
        ),
        (
            "deploy-hook",
            "etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription",
            b"#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-deploy-hook\n".as_slice(),
            0o700,
        ),
        (
            "post-hook",
            "etc/letsencrypt/renewal-hooks/post/sbxr-subscription",
            b"#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-post-hook\n".as_slice(),
            0o700,
        ),
    ];
    fs::create_dir_all(
        root.0
            .join("etc/systemd/system/snap.certbot.renew.service.d"),
    )
    .unwrap();
    fs::set_permissions(
        root.0
            .join("etc/systemd/system/snap.certbot.renew.service.d"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    if retired {
        root.write(
            "var/lib/sbxr/subscription-https-retired/renewal.conf",
            configuration,
            0o600,
        );
        fs::set_permissions(
            root.0.join("var/lib/sbxr/subscription-https-retired"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    } else {
        root.write(
            "etc/letsencrypt/renewal/sbxr-subscription.conf",
            configuration,
            0o600,
        );
    }
    for (backup, path, body, mode) in managed {
        root.write(
            &if retired {
                format!("var/lib/sbxr/subscription-https-retired/{backup}")
            } else {
                path.into()
            },
            body,
            mode,
        );
    }
    for (path, body) in [
        (
            "var/lib/sbxr/renewal-admission.lock",
            b"sbxr renewal admission v1\n".as_slice(),
        ),
        (
            "var/lib/sbxr/renewal-writer.lock",
            b"sbxr renewal writer v1\n".as_slice(),
        ),
        ("var/lib/sbxr/renewal-attempts.json", evidence.as_slice()),
    ] {
        root.write(path, body, 0o600);
    }
    let credential =
        crate::subscription_artifact::SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    root.write(
        http::TOKEN,
        format!("{}\n", credential.as_str()).as_bytes(),
        0o600,
    );
    root.write(
        http::STATE,
        &record.serving_authority().unwrap().state_bytes().unwrap(),
        0o600,
    );
    root.write(
        http::UNIT,
        crate::runtime_handoff::SERVING_UNIT.as_bytes(),
        0o644,
    );
    root.write(
        http::FIREWALL,
        &crate::host::historical::firewall_unit(&record).unwrap(),
        0o644,
    );
    symlink("../sbxr-subscription.service", root.0.join(http::LINK)).unwrap();
    symlink(
        "../sbxr-subscription-firewall.service",
        root.0.join(http::FIREWALL_LINK),
    )
    .unwrap();
    fs::create_dir_all(root.0.join(http::STAGING)).unwrap();
    fs::set_permissions(
        root.0.join(http::STAGING),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    root.write(
        "etc/letsencrypt/accounts/foreign/account.json",
        b"foreign account",
        0o600,
    );
    root.write(
        "etc/letsencrypt/live/other-owner/keep",
        b"foreign lineage",
        0o600,
    );
    let runtime = LegacyRuntime {
        root: root.0.clone(),
        active: std::rc::Rc::new(std::cell::Cell::new(true)),
        firewall: std::rc::Rc::new(std::cell::Cell::new(true)),
        stale: std::rc::Rc::new(std::cell::Cell::new(false)),
        live: std::rc::Rc::new(std::cell::Cell::new(false)),
    };
    let mut material = SetupMaterial::for_removal(Some(&record)).unwrap();
    material.key_sha256 = inner.material.key_sha256.clone();
    material.package_sha256 = inner.material.package_sha256.clone();
    inner.material = material;
    // Dropping the original store before reopening avoids overlapping writers.
    let host = StandardRemovalHost::new(inner)
        .unwrap()
        .with_auxiliary(runtime.clone());
    (host, runtime)
}
#[test]
fn historical_active_and_retired_cleanup_preserve_shared_resources() {
    for retired in [false, true] {
        let root = Root::new();
        let (host, _) = fixture(&root, retired);
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete,
            "retired {retired}"
        );
        assert!(!root.0.join("var/lib/sbxr").exists());
        assert_eq!(
            fs::read(root.0.join("etc/letsencrypt/accounts/foreign/account.json")).unwrap(),
            b"foreign account"
        );
        assert_eq!(
            fs::read(root.0.join("etc/letsencrypt/live/other-owner/keep")).unwrap(),
            b"foreign lineage"
        );
    }
}
#[test]
fn historical_renewal_reload_failure_keeps_forward_removal_and_reopens() {
    let root = Root::new();
    let (host, runtime) = fixture(&root, false);
    runtime.stale.set(true);
    let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
    let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalNeedsCompletion
    );
    assert!(root.0.join("var/lib/sbxr/renewal-attempts.json").exists());
    runtime.stale.set(false);
    let inner = {
        let h = removal.into_host();
        h.inner
    };
    let host = StandardRemovalHost::new(inner)
        .unwrap()
        .with_auxiliary(runtime);
    let mut reopened = crate::proxyinstallation::RemovalInstallation::new(host);
    let p = reopened.review(Action::FinishRemoval).prepared.unwrap();
    assert_eq!(
        reopened.execute(p, Confirmation::Approved).outcome,
        Outcome::RemovalComplete
    );
}

#[test]
fn historical_removal_resumes_after_each_owned_cleanup_boundary() {
    for (retired, points) in [
        (
            false,
            (120..123)
                .chain(130..133)
                .chain(170..184)
                .chain(200..202)
                .collect::<Vec<_>>(),
        ),
        (true, (140..159).collect::<Vec<_>>()),
    ] {
        for point in points {
            let root = Root::new();
            let (mut host, runtime) = fixture(&root, retired);
            host.interrupt_finalization(point);
            let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
            let review = removal.review(Action::CompleteRemoval);
            assert!(
                review.prepared.is_some(),
                "review retired={retired} point={point}"
            );
            let result = removal.execute(review.prepared.unwrap(), Confirmation::Approved);
            assert_eq!(
                result.outcome,
                Outcome::RemovalNeedsCompletion,
                "retired={retired} point={point}"
            );
            let inner = {
                let host = removal.into_host();
                host.inner
            };
            let host = StandardRemovalHost::new(inner)
                .unwrap()
                .with_auxiliary(runtime);
            let mut reopened = crate::proxyinstallation::RemovalInstallation::new(host);
            let review = reopened.review(Action::FinishRemoval);
            assert!(
                review.prepared.is_some(),
                "reopen retired={retired} point={point}"
            );
            assert_eq!(
                reopened
                    .execute(review.prepared.unwrap(), Confirmation::Approved)
                    .outcome,
                Outcome::RemovalComplete,
                "retired={retired} point={point}"
            );
            assert_eq!(
                fs::read(root.0.join("etc/letsencrypt/accounts/foreign/account.json")).unwrap(),
                b"foreign account"
            );
        }
    }
}
#[test]
fn historical_foreign_resources_and_active_renewal_are_preserved() {
    for retired in [false, true] {
        for bad in 0..7 {
            let root = Root::new();
            let (host, runtime) = fixture(&root, retired);
            let path = match bad {
                0 => "etc/letsencrypt/archive/sbxr-subscription/cert1.pem",
                1 => "etc/letsencrypt/archive/sbxr-subscription/cert99.pem",
                2 => "etc/letsencrypt/live/sbxr-subscription/foreign.pem",
                3 => "var/lib/sbxr/renewal-attempts.json",
                4 => "var/lib/sbxr/renewal-admission.lock",
                _ => "etc/letsencrypt/accounts/foreign/account.json",
            };
            if bad < 5 {
                root.write(
                    path,
                    b"foreign preserve",
                    if bad < 2 { 0o644 } else { 0o600 },
                );
            }
            if bad == 5 {
                runtime.live.set(true);
            }
            if bad == 6 {
                let p = root
                    .0
                    .join("etc/letsencrypt/live/sbxr-subscription/privkey.pem");
                fs::remove_file(&p).unwrap();
                symlink("../../accounts/foreign/account.json", p).unwrap();
            }
            let canonical = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
            let removal = crate::proxyinstallation::RemovalInstallation::new(host);
            assert!(
                removal.review(Action::CompleteRemoval).prepared.is_none(),
                "retired={retired} bad={bad}"
            );
            assert_eq!(
                fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
                canonical
            );
            if bad < 5 {
                assert_eq!(fs::read(root.0.join(path)).unwrap(), b"foreign preserve");
            }
        }
    }
}
