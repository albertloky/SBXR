use super::*;
use crate::{
    records::{OwnershipRecord, sha256_hex},
    removal::{checkpoint, checkpoint_limit, commit_removal, next_checkpoint},
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "restore-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for p in ["run/lock", "var/lib", "usr/local/bin"] {
            fs::create_dir_all(root.join(p)).unwrap();
            fs::set_permissions(root.join(p), fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self(root)
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn write(&self, path: &str, body: &[u8], mode: u32) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn state(&self) {
        let p = self.0.join(STATE);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn journal(&self, archive: &AuthenticatedArchive, finalizer: bool) -> Vec<u8> {
        let mut record = commit_removal(None, &archive.record().release_identity()).unwrap();
        if finalizer {
            while checkpoint(&record).unwrap() < checkpoint_limit(&record).unwrap() {
                record = next_checkpoint(&record).unwrap();
            }
        }
        let body = record.encode().unwrap();
        if !finalizer {
            self.state();
        }
        self.write(if finalizer { FINAL } else { CURRENT }, &body, 0o600);
        body
    }
    fn stage(&self, path: &str, archive: &AuthenticatedArchive) -> String {
        format!(
            "{path}.sbxr-restore-{}",
            archive.record().executable_sha256()
        )
    }
    fn assert_pair(&self, a: &AuthenticatedArchive) {
        assert_eq!(
            fs::read(self.0.join(INSTALLED)).unwrap(),
            a.record().encode().unwrap()
        );
        assert_eq!(fs::read(self.0.join(EXECUTABLE)).unwrap(), a.executable());
        assert_eq!(
            fs::metadata(self.0.join(INSTALLED)).unwrap().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(self.0.join(EXECUTABLE)).unwrap().mode() & 0o7777,
            0o755
        );
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn archive() -> AuthenticatedArchive {
    crate::release_acquisition::fixture_archive()
}

#[test]
fn finalizer_only_recovery_recreates_exact_pair_and_retains_both_locks() {
    let a = archive();
    let root = Root::new();
    let authority = root.journal(&a, true);
    let mut host = RestorationHost::injected(&root.0).unwrap();
    assert_eq!(host.release(), &a.record().release_identity());
    let restored = host.restore(&a, &SelectionBudget::new()).unwrap();
    assert_eq!(
        restored.code(),
        "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED"
    );
    assert!(restored.executable_restored && restored.installed_record_restored);
    assert!(restored.record() == a.record());
    root.assert_pair(&a);
    assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
    assert!(!root.0.join("etc/sing-box").exists());
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    assert!(OwnershipStore::open(&root.0.join(STATE), root.uid()).is_err());
    drop(host);
    let mut fresh = RestorationHost::injected(&root.0).unwrap();
    let result = fresh.restore(&a, &SelectionBudget::new()).unwrap();
    assert!(!result.executable_restored && !result.installed_record_restored);
    assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
}
#[test]
fn record_is_published_before_executable_and_every_interruption_reopens_forward() {
    for point in 0..=4 {
        let a = archive();
        let root = Root::new();
        let authority = root.journal(&a, true);
        let mut host = RestorationHost::injected(&root.0).unwrap();
        host.fault = Some(point);
        assert!(matches!(
            host.restore(&a, &SelectionBudget::new()),
            Err(HostError::Injected)
        ));
        assert_eq!(root.0.join(INSTALLED).exists(), point >= 2);
        assert_eq!(root.0.join(EXECUTABLE).exists(), point >= 4);
        assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
        drop(host);
        let mut fresh = RestorationHost::injected(&root.0).unwrap();
        fresh.restore(&a, &SelectionBudget::new()).unwrap();
        root.assert_pair(&a);
        assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
    }
}
#[test]
fn matching_empty_partial_and_complete_private_prefixes_resume_and_disappear() {
    for member in [INSTALLED, EXECUTABLE] {
        for size in [0, 1, 64, usize::MAX] {
            let a = archive();
            let root = Root::new();
            root.journal(&a, true);
            root.state();
            let record = a.record().encode().unwrap();
            let body = if member == INSTALLED {
                record.as_slice()
            } else {
                a.executable()
            };
            let count = size.min(body.len());
            let stage = root.stage(member, &a);
            root.write(&stage, &body[..count], 0o600);
            let mut host = RestorationHost::injected(&root.0).unwrap();
            host.restore(&a, &SelectionBudget::new()).unwrap();
            root.assert_pair(&a);
            assert!(!root.0.join(stage).exists());
        }
    }
}
#[test]
fn foreign_prefix_metadata_links_and_wrong_staging_identity_are_preserved() {
    for variant in [
        "bytes",
        "mode",
        "partial executable",
        "symlink",
        "hardlink",
        "wrong identity",
    ] {
        let a = archive();
        let root = Root::new();
        let authority = root.journal(&a, true);
        root.state();
        let stage = if variant == "wrong identity" {
            format!("{INSTALLED}.sbxr-restore-{}", "f".repeat(64))
        } else {
            root.stage(EXECUTABLE, &a)
        };
        let body = if variant == "bytes" {
            b"foreign".as_slice()
        } else {
            &a.executable()[..16]
        };
        if variant == "symlink" {
            root.write("foreign", body, 0o600);
            symlink(root.0.join("foreign"), root.0.join(&stage)).unwrap();
        } else {
            root.write(
                &stage,
                body,
                if variant == "mode" {
                    0o644
                } else if variant == "partial executable" {
                    0o755
                } else {
                    0o600
                },
            );
        }
        if variant == "hardlink" {
            fs::hard_link(root.0.join(&stage), root.0.join("foreign")).unwrap();
        }
        let before = fs::read(root.0.join(&stage)).unwrap();
        let mut host = RestorationHost::injected(&root.0).unwrap();
        assert!(
            host.restore(&a, &SelectionBudget::new()).is_err(),
            "{variant}"
        );
        assert_eq!(fs::read(root.0.join(stage)).unwrap(), before);
        assert!(!root.0.join(INSTALLED).exists());
        assert!(!root.0.join(EXECUTABLE).exists());
        assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
    }
}
#[test]
fn existing_members_must_be_canonical_exact_pair_and_are_never_replaced() {
    for variant in [
        "executable only",
        "foreign record",
        "record whitespace",
        "foreign executable",
        "record mode",
        "record symlink",
        "record hardlink",
    ] {
        let a = archive();
        let root = Root::new();
        root.journal(&a, true);
        root.state();
        let body = if variant == "foreign record" {
            b"foreign".to_vec()
        } else if variant == "record whitespace" {
            serde_json::to_vec_pretty(
                &serde_json::from_slice::<serde_json::Value>(&a.record().encode().unwrap())
                    .unwrap(),
            )
            .unwrap()
        } else {
            a.record().encode().unwrap()
        };
        if variant != "executable only" {
            root.write(
                INSTALLED,
                &body,
                if variant == "record mode" {
                    0o644
                } else {
                    0o600
                },
            );
        }
        if variant == "record symlink" {
            fs::rename(root.0.join(INSTALLED), root.0.join("foreign")).unwrap();
            symlink(root.0.join("foreign"), root.0.join(INSTALLED)).unwrap();
        }
        if variant == "record hardlink" {
            fs::hard_link(root.0.join(INSTALLED), root.0.join("foreign")).unwrap();
        }
        let executable = if variant == "foreign executable" {
            b"foreign".as_slice()
        } else {
            a.executable()
        };
        root.write(EXECUTABLE, executable, 0o755);
        let mut host = RestorationHost::injected(&root.0).unwrap();
        assert!(
            host.restore(&a, &SelectionBudget::new()).is_err(),
            "{variant}"
        );
        assert_eq!(fs::read(root.0.join(EXECUTABLE)).unwrap(), executable);
        if variant != "executable only" {
            assert_eq!(fs::read(root.0.join(INSTALLED)).unwrap(), body);
        }
    }
}
#[test]
fn exact_existing_pair_cleans_only_authenticated_prefix_staging() {
    let a = archive();
    let root = Root::new();
    root.journal(&a, true);
    root.state();
    root.write(INSTALLED, &a.record().encode().unwrap(), 0o600);
    root.write(EXECUTABLE, a.executable(), 0o755);
    for (path, body) in [
        (INSTALLED, a.record().encode().unwrap()),
        (EXECUTABLE, a.executable().to_vec()),
    ] {
        root.write(&root.stage(path, &a), &body[..16], 0o600);
    }
    let mut host = RestorationHost::injected(&root.0).unwrap();
    let result = host.restore(&a, &SelectionBudget::new()).unwrap();
    assert!(!result.installed_record_restored && !result.executable_restored);
    for path in [INSTALLED, EXECUTABLE] {
        assert!(!root.0.join(root.stage(path, &a)).exists());
    }
}
#[test]
fn conflicting_staged_changed_or_uncommitted_authority_cannot_restore() {
    for variant in [
        "both",
        "staged",
        "changed",
        "uncommitted",
        "early finalizer",
    ] {
        let a = archive();
        let root = Root::new();
        let authority = root.journal(&a, true);
        if variant == "both" {
            root.state();
            root.write(CURRENT, &authority, 0o600);
        }
        if variant == "staged" {
            root.state();
            root.write(
                &format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
                &authority,
                0o600,
            );
        }
        if variant == "uncommitted" {
            root.write(
                FINAL,
                include_bytes!("../records/testdata/standard-schema1-go.json"),
                0o600,
            );
        }
        if variant == "early finalizer" {
            let record = commit_removal(None, &a.record().release_identity()).unwrap();
            root.write(FINAL, &record.encode().unwrap(), 0o600);
        }
        if variant == "changed" {
            let mut host = RestorationHost::injected(&root.0).unwrap();
            root.write(FINAL, b"changed authority", 0o600);
            assert!(host.restore(&a, &SelectionBudget::new()).is_err());
        } else {
            assert!(RestorationHost::injected(&root.0).is_err(), "{variant}");
        }
        assert!(!root.0.join(INSTALLED).exists());
        assert!(!root.0.join(EXECUTABLE).exists());
    }
}
#[test]
fn mismatched_release_cancelled_work_unknown_children_and_unsafe_parents_refuse() {
    for variant in ["release", "cancel", "child", "parent"] {
        let a = archive();
        let root = Root::new();
        root.journal(&a, true);
        if variant == "release" {
            let r = commit_removal(
                None,
                &ReleaseIdentity::new("v3.1.117", &"a".repeat(40), &"b".repeat(64)).unwrap(),
            )
            .unwrap();
            let mut value: serde_json::Value =
                serde_json::from_slice(&r.encode().unwrap()).unwrap();
            value["removal_checkpoint"] = 3.into();
            let r = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
            root.write(FINAL, &r.encode().unwrap(), 0o600);
        }
        if variant == "child" {
            root.state();
            root.write("var/lib/sbxr/foreign", b"keep", 0o600);
        }
        let mut host = RestorationHost::injected(&root.0).unwrap();
        let budget = SelectionBudget::new();
        if variant == "cancel" {
            budget.cancel();
        }
        if variant == "parent" {
            fs::set_permissions(
                root.0.join("usr/local/bin"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        }
        assert!(host.restore(&a, &budget).is_err(), "{variant}");
        assert!(!root.0.join(INSTALLED).exists());
        assert!(!root.0.join(EXECUTABLE).exists());
        if variant == "child" {
            assert_eq!(
                fs::read(root.0.join("var/lib/sbxr/foreign")).unwrap(),
                b"keep"
            );
        }
    }
    assert!(matches!(
        RestorationHost::injected(Path::new("/")),
        Err(HostError::LiveUnavailable)
    ));
}
#[test]
fn current_removal_authority_is_retained_without_checkpoint_or_secret_rewrites() {
    let a = archive();
    let root = Root::new();
    let original = root.journal(&a, false);
    let mut host = RestorationHost::injected(&root.0).unwrap();
    host.restore(&a, &SelectionBudget::new()).unwrap();
    root.assert_pair(&a);
    assert_eq!(fs::read(root.0.join(CURRENT)).unwrap(), original);
    assert_eq!(sha256_hex(a.executable()), a.record().executable_sha256());
}

#[test]
fn preserved_go_journal_shapes_restore_only_the_test_bound_finisher_and_keep_direction() {
    let archive = crate::release_acquisition::fixture_archive_with_capabilities();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/removal");
    let mut count = 0;
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let original = fs::read(entry.path()).unwrap();
        let record = OwnershipRecord::decode(&original).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&record.encode().unwrap()).unwrap();
        let id = archive.record().release_identity();
        let key = if record.schema() == 1 {
            "release_identity"
        } else {
            "finishing_release_identity"
        };
        value[key] = serde_json::json!({"Repository":id.repository(),"Tag":id.tag(),"Commit":id.commit(),"IndexSHA256":id.index_sha256()});
        let bound = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let root = Root::new();
        root.state();
        let body = bound.encode().unwrap();
        root.write(CURRENT, &body, 0o600);
        let mut host = RestorationHost::injected(&root.0).unwrap();
        host.restore(&archive, &SelectionBudget::new()).unwrap();
        root.assert_pair(&archive);
        assert_eq!(fs::read(root.0.join(CURRENT)).unwrap(), body);
        assert_eq!(fs::read(entry.path()).unwrap(), original);
        count += 1;
    }
    assert_eq!(count, 10);
}
#[test]
fn a_finisher_missing_the_recorded_runtime_capability_refuses_before_publication() {
    let a = archive();
    let root = Root::new();
    root.state();
    let original = include_bytes!("../records/testdata/authority/http-retired-https.json");
    let source = OwnershipRecord::decode(original).unwrap();
    let record = commit_removal(Some(&source), &a.record().release_identity()).unwrap();
    root.write(CURRENT, &record.encode().unwrap(), 0o600);
    let mut host = RestorationHost::injected(&root.0).unwrap();
    assert!(host.restore(&a, &SelectionBudget::new()).is_err());
    assert!(!root.0.join(INSTALLED).exists());
    assert!(!root.0.join(EXECUTABLE).exists());
}

#[test]
fn exact_finisher_holds_authenticated_inode_and_both_locks_without_executing() {
    use std::io::Read;
    let a = archive();
    let root = Root::new();
    let authority = root.journal(&a, true);
    let mut host = RestorationHost::injected(&root.0).unwrap();
    let pair = host.restore(&a, &SelectionBudget::new()).unwrap();
    let finisher = host
        .prepare_finisher(pair, &SelectionBudget::new())
        .unwrap();
    assert!(finisher.record() == a.record());
    let mut bytes = Vec::new();
    finisher
        .descriptor
        .try_clone()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, a.executable());
    finisher.recheck().unwrap();
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    assert!(OwnershipStore::open(&root.0.join(STATE), root.uid()).is_err());
    assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
    drop(finisher);
    HostLock::existing(&root.0, root.uid()).unwrap();
    OwnershipStore::open(&root.0.join(STATE), root.uid()).unwrap();
}
#[test]
fn exact_finisher_refuses_path_replacement_and_changed_forward_authority() {
    for change_authority in [false, true] {
        let a = archive();
        let root = Root::new();
        root.journal(&a, true);
        let mut host = RestorationHost::injected(&root.0).unwrap();
        let pair = host.restore(&a, &SelectionBudget::new()).unwrap();
        let finisher = host
            .prepare_finisher(pair, &SelectionBudget::new())
            .unwrap();
        if change_authority {
            root.write(FINAL, b"foreign authority", 0o600);
        } else {
            let renamed = root.0.join("usr/local/bin/old-executable");
            fs::rename(root.0.join(EXECUTABLE), renamed).unwrap();
            root.write(EXECUTABLE, a.executable(), 0o755);
        }
        assert!(finisher.recheck().is_err());
        assert!(root.0.join(EXECUTABLE).exists());
    }
}
#[test]
fn unreleased_finisher_exec_refuses_injected_root_and_preserves_restoration() {
    let a = archive();
    let root = Root::new();
    let authority = root.journal(&a, true);
    let mut host = RestorationHost::injected(&root.0).unwrap();
    let pair = host.restore(&a, &SelectionBudget::new()).unwrap();
    let finisher = host
        .prepare_finisher(pair, &SelectionBudget::new())
        .unwrap();
    assert!(finisher.exec_native_unreleased().is_err());
    root.assert_pair(&a);
    assert_eq!(fs::read(root.0.join(FINAL)).unwrap(), authority);
    if !cfg!(target_os = "linux") {
        assert!(matches!(
            RestorationHost::native_unreleased(),
            Err(HostError::UnsupportedHost)
        ));
    }
}
