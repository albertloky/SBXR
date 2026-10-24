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
