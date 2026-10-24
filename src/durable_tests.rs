use super::*;
use crate::records::{OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    path: PathBuf,
    uid: u32,
}
impl Fixture {
    fn new() -> Self {
        let path =
            PathBuf::from(std::env::var_os("TMPDIR").expect("workspace-local TMPDIR required"))
                .join(format!(
                    "durable-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&path).unwrap().uid();
        Self { path, uid }
    }
    fn open(&self) -> OwnershipStore {
        OwnershipStore::open(&self.path, self.uid).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "fixture cleanup failed: {error}"
            );
        }
    }
}
fn standard() -> OwnershipRecord {
    OwnershipRecord::new_standard(
        ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap(),
        "8.8.8.8",
        &"c".repeat(64),
    )
    .unwrap()
}
fn precommit() -> OwnershipRecord {
    let mut record = standard();
    while record.phase() != SetupPhase::ServiceUnmasked {
        record = record.next_setup_checkpoint().unwrap();
    }
    record
}
fn write_owned(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn publication_is_persistent_exact_and_exclusive() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let record = standard();
    assert_eq!(store.load().unwrap().recovery(), Recovery::Absent);
    store.publish(None, &record).unwrap();
    let first = store.load().unwrap();
    assert_eq!(first.recovery(), Recovery::Cleanup);
    assert_eq!(
        first.current.as_ref().unwrap().bytes(),
        record.encode().unwrap()
    );
    let metadata = fs::metadata(fixture.path.join(OWNERSHIP_FILE)).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), fixture.uid);
    assert!(matches!(
        OwnershipStore::open(&fixture.path, fixture.uid),
        Err(StoreError {
            kind: StoreErrorKind::Busy,
            ..
        })
    ));
    let target = record.next_setup_checkpoint().unwrap();
    store
        .publish(Some(first.current.as_ref().unwrap().bytes()), &target)
        .unwrap();
    assert!(
        store
            .publish(Some(first.current.as_ref().unwrap().bytes()), &target)
            .is_err()
    );
    drop(store);
    let store = fixture.open();
    assert_eq!(store.load().unwrap().current.unwrap().record, target);
    assert!(!fixture.path.join(STAGED_FILE).exists());
}

#[test]
fn staged_initial_publication_requires_the_exact_expected_target() {
    for point in [
        FaultPoint::AfterStageWrite,
        FaultPoint::AfterStageSync,
        FaultPoint::BeforeRename,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let record = standard();
        store.fault = Some(point);
        let error = store.publish(None, &record).unwrap_err();
        assert_eq!(error.publication, Publication::Unchanged);
        drop(store);
        let mut store = fixture.open();
        assert_eq!(store.load().unwrap().recovery(), Recovery::Refused);
        assert!(
            store
                .publish(None, &record.next_setup_checkpoint().unwrap())
                .is_err()
        );
        store.publish(None, &record).unwrap();
        assert_eq!(store.load().unwrap().recovery(), Recovery::Cleanup);
    }
}

#[test]
fn interruption_at_activation_never_guesses_or_reverses_direction() {
    for point in [
        FaultPoint::AfterStageWrite,
        FaultPoint::AfterStageSync,
        FaultPoint::BeforeRename,
        FaultPoint::AfterRename,
        FaultPoint::BeforeDirectorySync,
        FaultPoint::AfterDirectorySync,
    ] {
        let fixture = Fixture::new();
        let source = precommit();
        let target = source.next_setup_checkpoint().unwrap();
        write_owned(
            &fixture.path.join(OWNERSHIP_FILE),
            &source.encode().unwrap(),
        );
        let mut store = fixture.open();
        store.fault = Some(point);
        let error = store
            .publish(Some(&source.encode().unwrap()), &target)
            .unwrap_err();
        drop(store);
        let mut store = fixture.open();
        let snapshot = store.load().unwrap();
        match point {
            FaultPoint::AfterStageWrite | FaultPoint::AfterStageSync | FaultPoint::BeforeRename => {
                assert_eq!(error.publication, Publication::Unchanged);
                assert_eq!(
                    snapshot
                        .current
                        .as_ref()
                        .unwrap()
                        .record
                        .recovery_direction(),
                    RecoveryDirection::Cleanup
                );
                assert_eq!(snapshot.recovery(), Recovery::Refused);
                // Only an explicit exact retry can publish the reviewed target.
                store
                    .publish(Some(&source.encode().unwrap()), &target)
                    .unwrap();
            }
            _ => {
                assert_eq!(error.publication, Publication::Uncertain);
                assert_eq!(snapshot.recovery(), Recovery::FinishSetup);
                store
                    .synchronize(snapshot.current.as_ref().unwrap().bytes())
                    .unwrap();
                assert!(
                    store
                        .publish(Some(snapshot.current.as_ref().unwrap().bytes()), &source)
                        .is_err()
                );
            }
        }
        assert_eq!(store.load().unwrap().recovery(), Recovery::FinishSetup);
    }
}

#[test]
fn staged_precommit_checkpoint_can_be_replayed_without_inventing_authority() {
    let fixture = Fixture::new();
    let source = standard();
    let target = source.next_setup_checkpoint().unwrap();
    write_owned(
        &fixture.path.join(OWNERSHIP_FILE),
        &source.encode().unwrap(),
    );
    write_owned(&fixture.path.join(STAGED_FILE), &target.encode().unwrap());
    let mut store = fixture.open();
    assert_eq!(store.load().unwrap().recovery(), Recovery::Cleanup);
    store
        .publish(Some(&source.encode().unwrap()), &target)
        .unwrap();
    assert_eq!(store.load().unwrap().current.unwrap().record, target);
}

#[test]
fn incompatible_staging_and_foreign_entries_are_preserved() {
    let fixture = Fixture::new();
    let source = standard();
    let target = source.next_setup_checkpoint().unwrap();
    write_owned(
        &fixture.path.join(OWNERSHIP_FILE),
        &source.encode().unwrap(),
    );
    write_owned(&fixture.path.join(STAGED_FILE), &source.encode().unwrap());
    fs::write(fixture.path.join("foreign"), b"keep me").unwrap();
    let mut store = fixture.open();
    assert!(
        store
            .publish(Some(&source.encode().unwrap()), &target)
            .is_err()
    );
    assert_eq!(
        fs::read(fixture.path.join(STAGED_FILE)).unwrap(),
        source.encode().unwrap()
    );
    assert_eq!(fs::read(fixture.path.join("foreign")).unwrap(), b"keep me");
}

#[test]
fn links_permissions_unknown_records_and_unsafe_parents_refuse_without_writes() {
    for case in 0..5 {
        let fixture = Fixture::new();
        let path = fixture.path.join(OWNERSHIP_FILE);
        let record = standard().encode().unwrap();
        match case {
            0 => {
                write_owned(&path, &record);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            1 => {
                write_owned(&path, &record);
                fs::hard_link(&path, fixture.path.join("shared")).unwrap();
            }
            2 => {
                write_owned(&fixture.path.join("foreign"), &record);
                symlink("foreign", &path).unwrap();
            }
            3 => {
                write_owned(&path, b"{\"schema\":1,\"credential\":\"do-not-leak\"}");
            }
            _ => {
                fs::create_dir(&path).unwrap();
            }
        }
        let store = fixture.open();
        assert!(store.load().is_err(), "unsafe case {case} accepted");
    }
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(OwnershipStore::open(&fixture.path, fixture.uid).is_err());
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(OwnershipStore::open(&fixture.path, fixture.uid + 1).is_err());
    symlink(&fixture.path, fixture.path.join("alias")).unwrap();
    assert!(OwnershipStore::open(&fixture.path.join("alias"), fixture.uid).is_err());
}

#[test]
fn store_never_rewrites_noncanonical_reads_or_accepts_skipped_checkpoints() {
    let fixture = Fixture::new();
    let record = standard();
    let mut bytes = b" ".to_vec();
    bytes.extend(record.encode().unwrap());
    write_owned(&fixture.path.join(OWNERSHIP_FILE), &bytes);
    let mut store = fixture.open();
    let snapshot = store.load().unwrap();
    assert_eq!(snapshot.current.unwrap().bytes(), bytes);
    assert_eq!(fs::read(fixture.path.join(OWNERSHIP_FILE)).unwrap(), bytes);
    assert!(
        store
            .publish(Some(&bytes), &record.next_setup_checkpoint().unwrap())
            .is_err()
    );
    let fixture2 = Fixture::new();
    let mut store2 = fixture2.open();
    store2.publish(None, &record).unwrap();
    let skipped = record
        .next_setup_checkpoint()
        .unwrap()
        .next_setup_checkpoint()
        .unwrap();
    assert!(
        store2
            .publish(Some(&record.encode().unwrap()), &skipped)
            .is_err()
    );
}

#[test]
fn empty_or_partial_staging_is_retained_and_never_overwritten() {
    for point in [
        FaultPoint::AfterStageCreate,
        FaultPoint::AfterPartialStageWrite,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.fault = Some(point);
        assert_eq!(
            store.publish(None, &standard()).unwrap_err().publication,
            Publication::Unchanged
        );
        drop(store);
        let mut store = fixture.open();
        let staged = fs::read(fixture.path.join(STAGED_FILE)).unwrap();
        assert!(store.load().is_err());
        assert!(store.publish(None, &standard()).is_err());
        assert_eq!(fs::read(fixture.path.join(STAGED_FILE)).unwrap(), staged);
        assert!(!fixture.path.join(OWNERSHIP_FILE).exists());
    }
}

#[test]
fn changed_directory_identity_and_writable_ancestors_are_refused() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let moved_container = Fixture::new();
    let moved = moved_container.path.join("moved");
    fs::rename(&fixture.path, &moved).unwrap();
    fs::create_dir(&fixture.path).unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(store.publish(None, &standard()).is_err());
    assert!(!moved.join(OWNERSHIP_FILE).exists());
    fs::remove_dir(&fixture.path).unwrap();
    fs::rename(moved, &fixture.path).unwrap();
    drop(store);
    let nested = fixture.path.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(OwnershipStore::open(&nested, fixture.uid).is_err());
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn cleanup_authority_removal_requires_all_checkpoints_and_preserves_conflicts() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut record = standard();
    store.publish(None, &record).unwrap();
    assert!(
        store
            .remove_completed_cleanup(&record.encode().unwrap())
            .is_err()
    );
    while record.cleanup_checkpoint() < 8 {
        let next = record.next_cleanup_checkpoint().unwrap();
        store
            .publish(Some(&record.encode().unwrap()), &next)
            .unwrap();
        record = next;
    }
    let foreign = standard().encode().unwrap();
    write_owned(&fixture.path.join(STAGED_FILE), &foreign);
    assert!(
        store
            .remove_completed_cleanup(&record.encode().unwrap())
            .is_err()
    );
    assert_eq!(fs::read(fixture.path.join(STAGED_FILE)).unwrap(), foreign);
    fs::remove_file(fixture.path.join(STAGED_FILE)).unwrap();
    fs::write(fixture.path.join("foreign"), b"keep me").unwrap();
    store
        .remove_completed_cleanup(&record.encode().unwrap())
        .unwrap();
    assert_eq!(store.load().unwrap().recovery(), Recovery::Absent);
    assert_eq!(fs::read(fixture.path.join("foreign")).unwrap(), b"keep me");
}

fn authority(name: &str) -> OwnershipRecord {
    OwnershipRecord::decode(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/records/testdata/authority")
                .join(format!("{name}.json")),
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn schema2_recovery_reports_pending_direction_instead_of_running() {
    for (name, expected) in [
        ("http-enable-x", Recovery::SubscriptionCleanup),
        ("http-rotate-b", Recovery::SubscriptionCleanup),
        ("http-rotate-c", Recovery::SubscriptionForward),
        ("http-repair-a", Recovery::SubscriptionCleanup),
        ("http-repair-b", Recovery::SubscriptionForward),
        ("client-rotation-h", Recovery::ClientIdentityCleanup),
        ("client-rotation-i", Recovery::ClientIdentityForward),
        ("https-activation-a", Recovery::Historical),
        ("http-migration-pending", Recovery::Historical),
        ("profile-removal-c", Recovery::Removal),
    ] {
        let fixture = Fixture::new();
        let bytes = authority(name).encode().unwrap();
        write_owned(&fixture.path.join(OWNERSHIP_FILE), &bytes);
        let snapshot = fixture.open().load().unwrap();
        assert_eq!(snapshot.recovery(), expected, "{name}");
        assert_eq!(snapshot.current.unwrap().bytes(), bytes);
    }
}
#[test]
fn schema2_commit_publication_failures_never_reverse_or_promote_staging() {
    for (source, target, complete) in [
        ("http-rotate-b", "http-rotate-c", true),
        ("http-repair-a", "http-repair-b", false),
        ("http-enable-x", "http-active", false),
    ] {
        for point in [
            FaultPoint::AfterStageWrite,
            FaultPoint::AfterStageSync,
            FaultPoint::BeforeRename,
            FaultPoint::AfterRename,
            FaultPoint::BeforeDirectorySync,
            FaultPoint::AfterDirectorySync,
        ] {
            let fixture = Fixture::new();
            let source = authority(source);
            let target = authority(target);
            write_owned(
                &fixture.path.join(OWNERSHIP_FILE),
                &source.encode().unwrap(),
            );
            let mut store = fixture.open();
            store.fault = Some(point);
            let error = store
                .publish(Some(&source.encode().unwrap()), &target)
                .unwrap_err();
            drop(store);
            let mut store = fixture.open();
            let snapshot = store.load().unwrap();
            if error.publication == Publication::Unchanged {
                assert_eq!(snapshot.recovery(), Recovery::Refused);
                assert_eq!(snapshot.current.unwrap().record, source);
                store
                    .publish(Some(&source.encode().unwrap()), &target)
                    .unwrap();
            } else {
                assert_eq!(snapshot.current.as_ref().unwrap().record, target);
                assert_eq!(
                    snapshot.recovery(),
                    if target.pending_change().is_none() {
                        Recovery::Running
                    } else {
                        Recovery::SubscriptionForward
                    }
                );
                store.synchronize(&target.encode().unwrap()).unwrap();
            }
            assert!(
                store
                    .publish(Some(&target.encode().unwrap()), &source)
                    .is_err()
            );
            if complete {
                let done = target.complete_http_link_rotation().unwrap();
                store
                    .publish(Some(&target.encode().unwrap()), &done)
                    .unwrap();
                assert_eq!(store.load().unwrap().recovery(), Recovery::Running);
                assert_ne!(done.serving_authority(), source.serving_authority());
            }
        }
    }
}
#[test]
fn http_enablement_publication_reopens_every_checkpoint_without_secret_bytes() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut current = standard();
    store.publish(None, &current).unwrap();
    while current.phase() != SetupPhase::Running {
        let next = current.next_setup_checkpoint().unwrap();
        store
            .publish(Some(&current.encode().unwrap()), &next)
            .unwrap();
        current = next;
    }
    let credential =
        crate::subscription_artifact::SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    let next = current
        .begin_http_enablement(
            &"1".repeat(32),
            &credential,
            &"3".repeat(32),
            &"d".repeat(64),
        )
        .unwrap();
    store
        .publish(Some(&current.encode().unwrap()), &next)
        .unwrap();
    current = next;
    for index in 0..crate::records::HTTP_ENABLEMENT_CHECKPOINTS.len() {
        drop(store);
        store = fixture.open();
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.recovery(), Recovery::SubscriptionCleanup);
        assert_eq!(snapshot.current.unwrap().record, current);
        assert!(
            !String::from_utf8(current.encode().unwrap())
                .unwrap()
                .contains(credential.as_str())
        );
        if index + 1 < crate::records::HTTP_ENABLEMENT_CHECKPOINTS.len() {
            let next = current.advance_http_enablement().unwrap();
            store
                .publish(Some(&current.encode().unwrap()), &next)
                .unwrap();
            current = next;
        }
    }
    let done = current.commit_http_enablement().unwrap();
    store
        .publish(Some(&current.encode().unwrap()), &done)
        .unwrap();
    drop(store);
    assert_eq!(fixture.open().load().unwrap().recovery(), Recovery::Running);
}

#[test]
fn pending_stages_do_not_admit_operations_or_report_completion_early() {
    let source = authority("http-active");
    let prepared = authority("http-rotate-a");
    let fixture = Fixture::new();
    write_owned(
        &fixture.path.join(OWNERSHIP_FILE),
        &source.encode().unwrap(),
    );
    write_owned(&fixture.path.join(STAGED_FILE), &prepared.encode().unwrap());
    let mut store = fixture.open();
    assert_eq!(store.load().unwrap().recovery(), Recovery::Refused);
    store
        .publish(Some(&source.encode().unwrap()), &prepared)
        .unwrap();
    assert_eq!(
        store.load().unwrap().recovery(),
        Recovery::SubscriptionCleanup
    );
    drop(store);
    for source in [
        authority("http-rotate-a"),
        authority("http-rotate-c"),
        authority("http-repair-c"),
        authority("http-enable-x"),
    ] {
        let target = match source.pending_change().unwrap() {
            crate::records::PendingChange::LinkRotation {
                direction: crate::records::ChangeDirection::Cleanup,
                ..
            } => source.cleanup_http_link_rotation().unwrap(),
            crate::records::PendingChange::LinkRotation { .. } => {
                source.complete_http_link_rotation().unwrap()
            }
            crate::records::PendingChange::Enablement { .. } => {
                source.cleanup_http_enablement().unwrap()
            }
            _ => source.complete_http_runtime_repair().unwrap(),
        };
        let fixture = Fixture::new();
        write_owned(
            &fixture.path.join(OWNERSHIP_FILE),
            &source.encode().unwrap(),
        );
        write_owned(&fixture.path.join(STAGED_FILE), &target.encode().unwrap());
        let mut store = fixture.open();
        let expected = if source.pending_change().unwrap().direction()
            == Some(crate::records::ChangeDirection::Forward)
        {
            Recovery::SubscriptionForward
        } else {
            Recovery::SubscriptionCleanup
        };
        assert_eq!(store.load().unwrap().recovery(), expected);
        store
            .publish(Some(&source.encode().unwrap()), &target)
            .unwrap();
        assert_eq!(store.load().unwrap().recovery(), Recovery::Running);
    }
}

#[test]
fn dropping_store_releases_exclusion_with_a_retained_descriptor() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let inherited = rustix::io::fcntl_dupfd_cloexec(&store.directory, 3).unwrap();
    assert!(matches!(
        OwnershipStore::open(&fixture.path, fixture.uid),
        Err(StoreError {
            kind: StoreErrorKind::Busy,
            ..
        })
    ));
    drop(store);
    let next = fixture.open();
    drop(inherited);
    assert!(matches!(
        OwnershipStore::open(&fixture.path, fixture.uid),
        Err(StoreError {
            kind: StoreErrorKind::Busy,
            ..
        })
    ));
    drop(next);
}
