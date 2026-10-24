use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "hist-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let r = Self(path);
        for path in [
            "run/lock",
            "var/lib/sbxr",
            "etc/letsencrypt",
            "var/lib/letsencrypt",
            "var/log/letsencrypt",
        ] {
            fs::create_dir_all(r.0.join(path)).unwrap();
            fs::set_permissions(
                r.0.join(path),
                fs::Permissions::from_mode(if path == "var/lib/sbxr" { 0o700 } else { 0o755 }),
            )
            .unwrap();
        }
        r
    }
    fn write(&self, path: &str, body: &[u8], mode: u32) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn certificate(&self, generation: u32) -> ServingAuthority {
        let cert = include_bytes!("../testdata/admission/server.pem").to_vec();
        let chain = include_bytes!("../testdata/admission/ca.pem").to_vec();
        let key = include_bytes!("../testdata/admission/server-key.pem").to_vec();
        let parts = [cert.clone(), chain.clone(), [cert, chain].concat(), key];
        for (i, name) in NAMES.iter().enumerate() {
            self.write(
                &format!("{ARCHIVE}/{name}{generation}.pem"),
                &parts[i],
                if i == 3 { 0o600 } else { 0o644 },
            );
        }
        for dir in [ARCHIVE, LIVE] {
            fs::create_dir_all(self.0.join(dir)).unwrap();
            fs::set_permissions(self.0.join(dir), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in NAMES {
            let path = self.0.join(format!("{LIVE}/{name}.pem"));
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            symlink(
                format!("../../archive/sbxr-subscription/{name}{generation}.pem"),
                path,
            )
            .unwrap();
        }
        ServingAuthority::https_digest(
            &"1".repeat(32),
            &"2".repeat(64),
            generation,
            parts.map(|p| sha256_hex(&p)),
        )
        .unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn trust() -> CertificateTrust {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(include_bytes!(
        "../testdata/admission/ca.pem"
    ))) {
        roots.add(cert.unwrap()).unwrap();
    }
    CertificateTrust::fixture(
        roots,
        rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            1_800_000_000,
        )),
    )
}
#[test]
fn historical_certificate_selection_checks_trust_ip_key_links_and_preserves_bytes() {
    let root = Root::new();
    let source = root.certificate(1);
    let host = HistoricalHttps::injected(&root.0).unwrap();
    let selected = host
        .select_published(&source, "127.0.0.1", &trust())
        .unwrap();
    assert_eq!(selected.authority(), &source);
    assert!(!format!("{selected:?}").contains("PRIVATE"));
    assert!(host.select_published(&source, "8.8.8.8", &trust()).is_err());
    assert!(
        host.select_published(&source, "127.0.0.1", &CertificateTrust::public_roots())
            .is_err()
    );
    let next = root.certificate(2);
    assert_eq!(
        host.select_published(&source, "127.0.0.1", &trust())
            .unwrap()
            .authority(),
        &next
    );
    fs::remove_file(root.0.join(format!("{LIVE}/chain.pem"))).unwrap();
    symlink(
        "../../archive/sbxr-subscription/chain1.pem",
        root.0.join(format!("{LIVE}/chain.pem")),
    )
    .unwrap();
    assert!(
        host.select_published(&source, "127.0.0.1", &trust())
            .is_err()
    );
}
#[test]
fn historical_state_decoder_is_exact_and_rejects_duplicate_unknown_and_wrong_generation() {
    let root = Root::new();
    let authority = root.certificate(1);
    let bytes = authority.state_bytes().unwrap();
    assert_eq!(ServingAuthority::decode_state(&bytes).unwrap(), authority);
    for body in [
        bytes[..bytes.len() - 1].to_vec(),
        String::from_utf8(bytes.clone())
            .unwrap()
            .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1)
            .into_bytes(),
        String::from_utf8(bytes)
            .unwrap()
            .replacen("\"schema\":1", "\"schema\":1,\"foreign\":true", 1)
            .into_bytes(),
    ] {
        assert!(ServingAuthority::decode_state(&body).is_err());
    }
}
#[test]
fn renewal_receipts_reject_unknown_duplicate_and_cross_recorder_without_mutation() {
    let root = Root::new();
    let host = HistoricalHttps::injected(&root.0).unwrap();
    let authority = serde_json::json!({"recorder_id":"33333333333333333333333333333333"});
    let body=b"{\"schema\":1,\"recorder_id\":\"33333333333333333333333333333333\",\"established_at\":\"2026-01-01T00:00:00Z\",\"attempts\":[]}";
    assert!(host.validate_evidence(body, &authority).unwrap().is_empty());
    for text in [
        String::from_utf8(body.to_vec())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
        String::from_utf8(body.to_vec())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":1,\"unknown\":true"),
        String::from_utf8(body.to_vec()).unwrap().replace(
            "33333333333333333333333333333333",
            "44444444444444444444444444444444",
        ),
    ] {
        assert!(host.validate_evidence(text.as_bytes(), &authority).is_err());
    }
    assert_eq!(super::renewal::stamp("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(
        super::renewal::stamp("1970-01-01T01:00:00+01:00").unwrap(),
        0
    );
    assert!(super::renewal::stamp("2026-02-29T00:00:00Z").is_err());
}

fn activation(
    root: &Root,
    source: &ServingAuthority,
    target: &ServingAuthority,
) -> OwnershipRecord {
    let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../records/testdata/authority/https-activation-b.json"
    ))
    .unwrap();
    let state = |a: &ServingAuthority| {
        serde_json::from_slice::<serde_json::Value>(&a.state_bytes().unwrap()).unwrap()["serving"]
            .clone()
    };
    value["serving"] = state(target);
    value["certificate_activation"]["source"] = state(source);
    value["certificate_activation"]["target"] = state(target);
    let record = crate::records::historical_fixture(value);
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &record.encode().unwrap(),
        0o600,
    );
    root.write(
        "var/lib/sbxr/subscription-serving.json",
        &source.state_bytes().unwrap(),
        0o600,
    );
    root.write("var/lib/sbxr/subscription-staging/.placeholder", b"", 0o600);
    fs::remove_file(
        root.0
            .join("var/lib/sbxr/subscription-staging/.placeholder"),
    )
    .unwrap();
    fs::set_permissions(
        root.0.join("var/lib/sbxr/subscription-staging"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    record
}
#[test]
fn historical_certificate_state_publication_retries_stage_and_rename_without_changing_record() {
    for fault in [1, 2] {
        let root = Root::new();
        let source = root.certificate(1);
        let target = root.certificate(2);
        let record = activation(&root, &source, &target);
        let mut host = HistoricalHttps::injected(&root.0).unwrap();
        let selected = host
            .select_published(&source, "127.0.0.1", &trust())
            .unwrap()
            .publication_fixture(record.public_ipv4());
        let owner = Arc::new(HostLock::acquire(&root.0, host.fs.uid).unwrap());
        host.publication_fault = Some(fault);
        assert!(matches!(
            host.publish_serving_state(&owner, &record, &selected),
            Err(HostError::Injected)
        ));
        let before = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        drop(host);
        let mut host = HistoricalHttps::injected(&root.0).unwrap();
        host.publish_serving_state(&owner, &record, &selected)
            .unwrap();
        assert_eq!(host.inspect_serving_state(&target).unwrap(), target);
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::read_dir(root.0.join("var/lib/sbxr/subscription-staging"))
                .unwrap()
                .count(),
            0
        );
    }
}
#[test]
fn historical_state_publication_preserves_stale_record_foreign_stage_and_changed_certificates() {
    for bad in 0..6 {
        let root = Root::new();
        let source = root.certificate(1);
        let target = root.certificate(2);
        let record = activation(&root, &source, &target);
        let mut host = HistoricalHttps::injected(&root.0).unwrap();
        let selected = host
            .select_published(&source, "127.0.0.1", &trust())
            .unwrap()
            .publication_fixture(record.public_ipv4());
        let owner = Arc::new(HostLock::acquire(&root.0, host.fs.uid).unwrap());
        match bad {
            0 => root.write(
                "var/lib/sbxr/subscription-staging/serving.json",
                b"foreign stage",
                0o600,
            ),
            1 => root.write(
                "etc/letsencrypt/archive/sbxr-subscription/cert2.pem",
                b"changed certificate",
                0o644,
            ),
            2 => root.write(
                "var/lib/sbxr/proxy-ownership.json",
                b"changed record",
                0o600,
            ),
            3 => {
                root.certificate(3);
            }
            5 => root.write(
                "var/lib/sbxr/subscription-staging/foreign",
                b"preserve unrelated stage",
                0o600,
            ),
            _ => {
                let state = ServingAuthority::https_digest(
                    target.link_id(),
                    &"f".repeat(64),
                    1,
                    source.certificate_sha256().clone(),
                )
                .unwrap();
                root.write(
                    "var/lib/sbxr/subscription-serving.json",
                    &state.state_bytes().unwrap(),
                    0o600,
                );
            }
        }
        let before = fs::read(root.0.join("var/lib/sbxr/subscription-serving.json")).unwrap();
        assert!(
            host.publish_serving_state(&owner, &record, &selected)
                .is_err(),
            "bad {bad}"
        );
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/subscription-serving.json")).unwrap(),
            before
        );
    }
}
#[test]
fn historical_cleanup_hooks_refuse_hidden_recorder_routes_but_preserve_unrelated_hooks() {
    let root = Root::new();
    let host = HistoricalHttps::injected(&root.0).unwrap();
    root.write(
        "etc/letsencrypt/renewal-hooks/pre/other",
        b"#!/bin/sh\nexit 0\n",
        0o755,
    );
    root.write(
        "etc/letsencrypt/renewal/other.conf",
        b"no-directory-hooks = false\n",
        0o644,
    );
    host.renewal_hooks_safe().unwrap();
    for (path, bytes) in [
        (
            "etc/letsencrypt/renewal-hooks/pre/other",
            b"#!/bin/sh\n/usr/local/bin/sbxr --certbot-recorder\n".as_slice(),
        ),
        (
            "etc/letsencrypt/renewal/other.conf",
            b"no_directory_hooks = true\n".as_slice(),
        ),
        (
            "etc/letsencrypt/renewal/other.conf",
            b"deploy-hook = /usr/local/bin/sbxr --certbot-deploy-hook\n".as_slice(),
        ),
    ] {
        let before = fs::read(root.0.join(path)).unwrap();
        let mode = fs::metadata(root.0.join(path)).unwrap().permissions();
        root.write(path, bytes, mode.mode());
        assert!(host.renewal_hooks_safe().is_err());
        assert_eq!(fs::read(root.0.join(path)).unwrap(), bytes);
        root.write(path, &before, mode.mode());
    }
}
#[test]
fn historical_posix_child() {
    let Some(path) = std::env::var_os("SBXR_HISTORICAL_LOCK_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    assert!(path.starts_with(std::env::var_os("TMPDIR").unwrap()));
    let host = HistoricalHttps::injected(&path).unwrap();
    if std::env::var("SBXR_HISTORICAL_UMASK").as_deref() == Ok("1") {
        // Only this disposable helper process changes its mask. The test runner
        // and host environment keep their existing settings.
        let prior = rustix::process::umask(Mode::from_raw_mode(0o777));
        let result = host.fs.historical_exclusion(false, true);
        rustix::process::umask(prior);
        let locks = result.unwrap();
        locks.verify().unwrap();
        drop(locks);
        return;
    }
    let file = rustix::fs::open(
        path.join("etc/letsencrypt/.certbot.lock"),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap();
    let busy = rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .is_err();
    assert_eq!(busy, std::env::var("SBXR_EXPECT_BUSY").unwrap() == "1");
    drop(host);
}
#[test]
fn historical_exclusion_holds_real_cross_process_locks_and_cleans_only_created_inodes() {
    let root = Root::new();
    let fs = ProtectedFs::open(&root.0).unwrap();
    // Existing package/CA-owned lock files are retained byte-for-byte.
    root.write("var/lib/letsencrypt/.certbot.lock", b"existing lock", 0o600);
    let locks = fs.historical_exclusion(false, true).unwrap();
    let child = |busy| {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host::historical::tests::historical_posix_child"])
            .env("SBXR_HISTORICAL_LOCK_FIXTURE", &root.0)
            .env("SBXR_EXPECT_BUSY", busy)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    };
    child("1");
    locks.verify().unwrap();
    // A replaced inode is refused and the new foreign inode must survive Drop.
    let p = root.0.join("var/log/letsencrypt/.certbot.lock");
    fs::remove_file(&p).unwrap();
    root.write(
        "var/log/letsencrypt/.certbot.lock",
        b"foreign replacement",
        0o600,
    );
    assert!(locks.verify().is_err());
    // Keep an originally created path for a post-release process check.
    let retained = root.0.join("etc/letsencrypt/.certbot.lock");
    fs::write(&retained, b"retained CA data").unwrap();
    drop(locks);
    child("0");
    assert_eq!(fs::read(&p).unwrap(), b"foreign replacement");
    assert_eq!(
        fs::read(root.0.join("var/lib/letsencrypt/.certbot.lock")).unwrap(),
        b"existing lock"
    );
    assert_eq!(fs::read(&retained).unwrap(), b"retained CA data");
    let locks = fs.historical_exclusion(false, true).unwrap();
    std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(locks.verify().is_err());
    drop(locks);
    assert!(root.0.join("etc/letsencrypt/.certbot.lock").exists());
}

#[test]
fn historical_selection_refuses_expired_or_not_yet_valid_and_mismatched_keys() {
    let root = Root::new();
    let source = root.certificate(1);
    let host = HistoricalHttps::injected(&root.0).unwrap();
    for now in [0, 5_000_000_000] {
        let mut t = trust();
        t = super::certificates::CertificateTrust::fixture_for_test_time(t, now);
        assert!(host.select_published(&source, "127.0.0.1", &t).is_err());
    }
    root.write(
        "etc/letsencrypt/archive/sbxr-subscription/privkey1.pem",
        include_bytes!("../../release_https/testdata/server-key.pem"),
        0o600,
    );
    assert!(
        host.select_published(&source, "127.0.0.1", &trust())
            .is_err()
    );
    // Exact stored historical bytes remain readable for cleanup without time validation.
    root.certificate(1);
    root.write(
        "var/lib/sbxr/subscription-serving.json",
        &source.state_bytes().unwrap(),
        0o600,
    );
    assert_eq!(host.inspect_serving_state(&source).unwrap(), source);
}
#[test]
fn historical_exclusion_error_releases_created_locks_and_preserves_foreign_lock() {
    let root = Root::new();
    root.write(
        "var/lib/letsencrypt/.certbot.lock",
        b"foreign writable",
        0o666,
    );
    let fs = ProtectedFs::open(&root.0).unwrap();
    assert!(fs.historical_exclusion(false, true).is_err());
    assert!(!root.0.join("etc/letsencrypt/.certbot.lock").exists());
    assert_eq!(
        fs::read(root.0.join("var/lib/letsencrypt/.certbot.lock")).unwrap(),
        b"foreign writable"
    );
}

#[test]
fn historical_created_lock_normalization_survives_restrictive_child_umask() {
    let root = Root::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "host::historical::tests::historical_posix_child"])
        .env("SBXR_HISTORICAL_LOCK_FIXTURE", &root.0)
        .env("SBXR_HISTORICAL_UMASK", "1")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!root.0.join("etc/letsencrypt/.certbot.lock").exists());
}

#[test]
fn historical_created_lock_parent_replacement_refuses_and_preserves_both_namespaces() {
    for reuse_inode in [false, true] {
        let root = Root::new();
        let protected = ProtectedFs::open(&root.0).unwrap();
        let locks = protected.historical_exclusion(false, true).unwrap();
        std::fs::rename(
            root.0.join("etc/letsencrypt"),
            root.0.join("etc/letsencrypt-prior"),
        )
        .unwrap();
        let replacement = root.0.join("etc/letsencrypt/.certbot.lock");
        if reuse_inode {
            std::fs::create_dir(root.0.join("etc/letsencrypt")).unwrap();
            std::fs::rename(
                root.0.join("etc/letsencrypt-prior/.certbot.lock"),
                &replacement,
            )
            .unwrap();
        } else {
            root.write(
                "etc/letsencrypt/.certbot.lock",
                b"foreign new namespace",
                0o600,
            );
        }
        assert!(locks.verify().is_err());
        drop(locks);
        // Even moving the original one-link inode into a new parent cannot
        // transfer retained coordination authority into that namespace.
        assert_eq!(
            std::fs::read(replacement).unwrap(),
            if reuse_inode {
                b"".as_slice()
            } else {
                b"foreign new namespace".as_slice()
            }
        );
        assert_eq!(
            root.0.join("etc/letsencrypt-prior/.certbot.lock").exists(),
            !reuse_inode
        );
    }
}

#[test]
fn historical_empty_directory_group_must_match_the_recorded_owner_before_cleanup() {
    let root = Root::new();
    for path in [ARCHIVE, LIVE] {
        std::fs::create_dir_all(root.0.join(path)).unwrap();
        std::fs::set_permissions(root.0.join(path), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let mut host = HistoricalHttps::injected(&root.0).unwrap();
    let record = OwnershipRecord::decode(include_bytes!(
        "../../records/testdata/authority/https-activation-b.json"
    ))
    .unwrap();
    assert!(host.plan(&record).is_ok());
    // Change only the fixture's expected group; no operating-system identity,
    // membership or inode ownership is changed by this regression.
    host.fs.gid = host.fs.gid.wrapping_add(1);
    let plan_refused = host.plan(&record).is_err();
    let effect_refused = host
        .fs
        .remove_historical_directory(LIVE, Mode::from_raw_mode(0o700))
        .is_err();
    assert!(plan_refused && effect_refused);
    assert!(root.0.join(LIVE).exists());
}
