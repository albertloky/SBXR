#![forbid(unsafe_code)]
use sbxr::removal::*;
use sbxr::{domain, host, records};

#[test]
fn commitment_preserves_creator_and_binds_exact_finisher() {
    let source = records::OwnershipRecord::decode(include_bytes!(
        "../src/records/testdata/authority/schema1-running.json"
    ))
    .unwrap();
    let finisher =
        records::ReleaseIdentity::new("v3.1.119", &"d".repeat(40), &"e".repeat(64)).unwrap();
    let committed = commit_removal(Some(&source), &finisher).unwrap();
    assert_eq!(committed.phase(), records::SetupPhase::RemovalCommitted);
    assert_eq!(
        committed.recovery_direction(),
        records::RecoveryDirection::Removal
    );
    assert_eq!(committed.release_identity(), source.release_identity());
    assert_eq!(finishing_release(&committed).unwrap(), finisher);
    assert!(
        committed
            .creating_releases()
            .iter()
            .all(|r| r == &source.release_identity())
    );
    assert_eq!(checkpoint_limit(&committed).unwrap(), 11);
}

#[test]
fn software_only_commitment_has_three_forward_checkpoints() {
    let release =
        records::ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap();
    let mut record = commit_removal(None, &release).unwrap();
    assert_eq!(checkpoint_limit(&record).unwrap(), 3);
    for expected in 1..=3 {
        record = next_checkpoint(&record).unwrap();
        assert_eq!(checkpoint(&record).unwrap(), expected);
    }
    assert!(next_checkpoint(&record).is_err());
}

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR").expect("validation must provide an isolated TMPDIR");
        let root = PathBuf::from(base).join(format!(
            "removal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("clean only this test's disposable root");
    }
}
fn release() -> records::ReleaseIdentity {
    records::ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap()
}
fn running() -> records::OwnershipRecord {
    records::OwnershipRecord::decode(include_bytes!(
        "../src/records/testdata/authority/schema1-running.json"
    ))
    .unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
const PROXY: [RemovalEffect; 8] = [
    RemovalEffect::StopDisableProxy,
    RemovalEffect::PackageArtifact,
    RemovalEffect::PackageHold,
    RemovalEffect::Package,
    RemovalEffect::ConfigurationState,
    RemovalEffect::PackageIdentity,
    RemovalEffect::AptSource,
    RemovalEffect::AptKey,
];
struct FakeHost {
    native_presentation: bool,
    root: TempRoot,
    executing: records::ReleaseIdentity,
    changed: bool,
    locked: bool,
    package_locks: bool,
    fail_before: Option<RemovalEffect>,
    fail_after: Option<RemovalEffect>,
    fail_publish_stage: Option<u32>,
    fail_publish_after: Option<u32>,
    fail_sync: Option<u32>,
    fail_finalizer: Option<u8>,
    race: Option<RemovalEffect>,
    cancelled: bool,
    unavailable: bool,
    effects: Vec<RemovalEffect>,
    changed_on_lock: bool,
    cancel_on_lock: bool,
    cancel_after: Option<RemovalEffect>,
    ineffective: Option<RemovalEffect>,
    accepted: bool,
    inspected_effects: std::cell::RefCell<Vec<RemovalEffect>>,
}
impl FakeHost {
    fn new(record: Option<&records::OwnershipRecord>) -> Self {
        let executing = record
            .and_then(|r| finishing_release(r).ok())
            .unwrap_or_else(release);
        let host = Self {
            native_presentation: false,
            root: TempRoot::new(),
            executing,
            changed: false,
            locked: false,
            package_locks: false,
            fail_before: None,
            fail_after: None,
            fail_publish_stage: None,
            fail_publish_after: None,
            fail_sync: None,
            fail_finalizer: None,
            race: None,
            cancelled: false,
            unavailable: false,
            effects: vec![],
            changed_on_lock: false,
            cancel_on_lock: false,
            cancel_after: None,
            ineffective: None,
            accepted: true,
            inspected_effects: Default::default(),
        };
        if let Some(record) = record {
            write(&host.root.0.join("current"), &record.encode().unwrap());
            let cp = checkpoint(record).unwrap_or(0);
            for (index, effect) in PROXY.into_iter().enumerate() {
                if cp <= index as u32 {
                    host.put(effect);
                }
            }
        }
        let cp = record.and_then(|r| checkpoint(r).ok()).unwrap_or(0);
        if cp < 10 {
            host.put(RemovalEffect::Executable);
        }
        if cp < 11 {
            host.put(RemovalEffect::InstalledRecord);
        }
        write(
            &host.root.0.join("foreign-owner-data"),
            b"preserve unrelated data\n",
        );
        host
    }
    fn path(&self, effect: RemovalEffect) -> PathBuf {
        self.root.0.join(format!("effect-{effect:?}"))
    }
    fn put(&self, effect: RemovalEffect) {
        write(&self.path(effect), format!("owned {effect:?}\n").as_bytes());
    }
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, host::HostError> {
        match fs::symlink_metadata(self.root.0.join(name)) {
            Ok(meta) => {
                if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
                    return Err(host::HostError::Foreign);
                }
                fs::read(self.root.0.join(name))
                    .map(Some)
                    .map_err(|_| host::HostError::Io)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(host::HostError::Io),
        }
    }
    fn committed(&self) -> records::OwnershipRecord {
        let bytes = self
            .read("current")
            .unwrap()
            .or_else(|| self.read("finalizer").unwrap())
            .unwrap();
        records::OwnershipRecord::decode(&bytes).unwrap()
    }
    fn complete(&mut self) -> RemovalOutcome {
        let mut removal = Removal::new(std::mem::replace(self, Self::new(None)));
        let prepared = removal.review(RemovalAction::Complete).unwrap();
        let result = removal.execute(prepared, domain::Confirmation::Approved);
        *self = removal.into_host();
        result
    }
    fn finish(&mut self) -> RemovalOutcome {
        let mut removal = Removal::new(std::mem::replace(self, Self::new(None)));
        let prepared = removal.review(RemovalAction::Finish).unwrap();
        let result = removal.execute(prepared, domain::Confirmation::Approved);
        *self = removal.into_host();
        result
    }
    fn preserved(&self) {
        assert_eq!(
            fs::read(self.root.0.join("foreign-owner-data")).unwrap(),
            b"preserve unrelated data\n"
        );
    }
}
impl RemovalHost for FakeHost {
    fn is_native_system(&self) -> bool {
        self.native_presentation
    }
    fn effects_available(&self) -> bool {
        !self.unavailable
    }
    fn executing_release(&self) -> Result<records::ReleaseIdentity, host::HostError> {
        Ok(self.executing.clone())
    }
    fn read_authority(&self) -> Result<AuthoritySnapshot, host::HostError> {
        Ok(AuthoritySnapshot {
            current: self.read("current")?,
            staged: self.read("stage")?,
            finalizer: self.read("finalizer")?,
        })
    }
    fn inspect_removal(
        &self,
        _: Option<&records::OwnershipRecord>,
        _: &records::ReleaseIdentity,
    ) -> Result<RemovalFacts, host::HostError> {
        Ok(RemovalFacts {
            fingerprint: [u8::from(self.changed); 32],
            accepted: self.accepted,
        })
    }
    fn inspect_lifecycle(
        &self,
        release: &records::ReleaseIdentity,
    ) -> Result<LifecycleFacts, host::HostError> {
        let executable = self.inspect_effect(RemovalEffect::Executable, &running())?;
        let installed = self.inspect_effect(RemovalEffect::InstalledRecord, &running())?;
        Ok(LifecycleFacts {
            release: release.clone(),
            valid: true,
            executable_present: executable == EffectState::ExactOwned,
            installed_record_present: installed == EffectState::ExactOwned,
            state_directory_empty: !self.root.0.join("unknown-state-residue").exists(),
        })
    }
    fn begin_change(
        &mut self,
        _: Option<&records::OwnershipRecord>,
    ) -> Result<(), host::HostError> {
        assert!(!self.locked);
        self.locked = true;
        self.package_locks = true;
        if self.changed_on_lock {
            self.changed = true;
        }
        if self.cancel_on_lock {
            self.cancelled = true;
        }
        Ok(())
    }
    fn release_package_locks(&mut self) {
        assert!(self.locked);
        self.package_locks = false;
    }
    fn end_change(&mut self) {
        self.locked = false;
        self.package_locks = false;
    }
    fn publish(
        &mut self,
        expected: Option<&[u8]>,
        record: &records::OwnershipRecord,
    ) -> Result<(), host::HostError> {
        assert!(self.locked);
        if self.read("current")?.as_deref() != expected || self.read("finalizer")?.is_some() {
            return Err(host::HostError::Foreign);
        }
        let target = record.encode().unwrap();
        if self.read("stage")?.is_some_and(|bytes| bytes != target) {
            return Err(host::HostError::Foreign);
        }
        write(&self.root.0.join("stage"), &target);
        fs::File::open(self.root.0.join("stage"))
            .unwrap()
            .sync_all()
            .unwrap();
        if self.fail_publish_stage == checkpoint(record).ok() {
            return Err(host::HostError::Injected);
        }
        fs::rename(self.root.0.join("stage"), self.root.0.join("current")).unwrap();
        fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        if self.fail_publish_after == checkpoint(record).ok() {
            return Err(host::HostError::Injected);
        }
        Ok(())
    }
    fn synchronize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), host::HostError> {
        assert!(self.locked);
        let record = records::OwnershipRecord::decode(expected).unwrap();
        if self.fail_sync == checkpoint(&record).ok() {
            return Err(host::HostError::Injected);
        }
        let name = if location == AuthorityLocation::Current {
            "current"
        } else {
            "finalizer"
        };
        if self.read(name)?.as_deref() != Some(expected) {
            return Err(host::HostError::Foreign);
        }
        fs::File::open(self.root.0.join(name))
            .unwrap()
            .sync_all()
            .unwrap();
        fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        Ok(())
    }
    fn inspect_effect(
        &self,
        effect: RemovalEffect,
        _: &records::OwnershipRecord,
    ) -> Result<EffectState, host::HostError> {
        self.inspected_effects.borrow_mut().push(effect);
        let path = self.path(effect);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EffectState::Absent);
            }
            _ => return Err(host::HostError::Io),
        };
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != fs::metadata(&self.root.0).unwrap().uid()
            || meta.mode() & 0o7777 != 0o600
            || fs::read(path).unwrap() != format!("owned {effect:?}\n").as_bytes()
        {
            return Err(host::HostError::Foreign);
        }
        Ok(EffectState::ExactOwned)
    }
    fn apply(
        &mut self,
        effect: RemovalEffect,
        authority: &records::OwnershipRecord,
    ) -> Result<(), host::HostError> {
        assert!(self.locked && !self.package_locks);
        assert_eq!(
            authority.recovery_direction(),
            records::RecoveryDirection::Removal
        );
        if self.fail_before == Some(effect) {
            return Err(host::HostError::Injected);
        }
        if self.race == Some(effect) {
            write(&self.path(effect), b"foreign replacement\n");
        }
        if self.inspect_effect(effect, authority)? != EffectState::ExactOwned {
            return Err(host::HostError::Foreign);
        }
        if self.ineffective == Some(effect) {
            return Ok(());
        }
        fs::remove_file(self.path(effect)).unwrap();
        self.effects.push(effect);
        if self.cancel_after == Some(effect) {
            self.cancelled = true;
        }
        if self.fail_after == Some(effect) {
            return Err(host::HostError::Injected);
        }
        Ok(())
    }
    fn proxy_absent(&self, authority: &records::OwnershipRecord) -> Result<bool, host::HostError> {
        for effect in PROXY.into_iter().chain([
            RemovalEffect::DedicatedTunnel,
            RemovalEffect::ClientIdentitySubscription,
            RemovalEffect::ClientIdentityTarget,
            RemovalEffect::PreparedSubscription,
            RemovalEffect::SubscriptionRotation,
            RemovalEffect::SubscriptionRepair,
            RemovalEffect::ServingRuntime,
            RemovalEffect::RenewalIntegration,
            RemovalEffect::SubscriptionResources,
            RemovalEffect::RetiredHttps,
            RemovalEffect::ProxyStartup,
        ]) {
            if self.inspect_effect(effect, authority)? != EffectState::Absent {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn finalize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), FinalizationError> {
        assert!(self.locked && !self.package_locks);
        let record = records::OwnershipRecord::decode(expected).unwrap();
        assert_eq!(
            checkpoint(&record).unwrap(),
            checkpoint_limit(&record).unwrap()
        );
        if location == AuthorityLocation::Current {
            if let Some(stage) = self.read("stage").unwrap() {
                if stage != expected {
                    return Err(FinalizationError::Interrupted);
                }
                fs::remove_file(self.root.0.join("stage")).unwrap();
            }
            if self.read("current").unwrap().as_deref() != Some(expected)
                || self.read("finalizer").unwrap().is_some()
            {
                return Err(FinalizationError::Interrupted);
            }
            fs::rename(self.root.0.join("current"), self.root.0.join("finalizer")).unwrap();
            fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        }
        if self.fail_finalizer == Some(1) {
            return Err(FinalizationError::Interrupted);
        }
        if self.read("finalizer").unwrap().as_deref() != Some(expected) {
            return Err(FinalizationError::Interrupted);
        }
        fs::remove_file(self.root.0.join("finalizer")).unwrap();
        if self.fail_finalizer == Some(2) {
            return Err(FinalizationError::SynchronizationUnknown);
        }
        fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        Ok(())
    }
    fn cancelled(&self) -> bool {
        self.cancelled
    }
}

#[test]
fn complete_removal_deletes_only_exact_owned_resources_and_finalizes_last() {
    for record in [None, Some(running())] {
        let mut host = FakeHost::new(record.as_ref());
        assert_eq!(host.complete(), RemovalOutcome::Completed);
        assert_eq!(host.read_authority().unwrap(), AuthoritySnapshot::default());
        assert!(!host.path(RemovalEffect::Executable).exists());
        assert!(!host.path(RemovalEffect::InstalledRecord).exists());
        assert_eq!(host.effects.last(), Some(&RemovalEffect::InstalledRecord));
        assert!(!host.locked);
        host.preserved();
    }
}

#[test]
fn every_durable_checkpoint_recovers_forward_after_reopening() {
    for boundary in 0..=11 {
        let mut host = FakeHost::new(Some(&running()));
        host.fail_sync = Some(boundary);
        assert!(
            matches!(host.complete(), RemovalOutcome::NeedsCompletion(_)),
            "boundary {boundary}"
        );
        assert_eq!(checkpoint(&host.committed()).unwrap(), boundary);
        let committed = host.committed();
        assert_eq!(finishing_release(&committed).unwrap(), release());
        assert!(commit_removal(Some(&committed), &release()).is_err());
        host.fail_sync = None;
        assert_eq!(
            host.finish(),
            RemovalOutcome::Completed,
            "boundary {boundary}"
        );
        assert!(
            host.effects
                .iter()
                .all(|effect| effect.host_operation().is_some()
                    || matches!(
                        effect,
                        RemovalEffect::PackageHold
                            | RemovalEffect::Executable
                            | RemovalEffect::InstalledRecord
                    ))
        );
        host.preserved();
    }
}

#[test]
fn each_effect_can_fail_before_or_after_without_losing_authority_or_foreign_data() {
    for effect in PROXY
        .into_iter()
        .chain([RemovalEffect::Executable, RemovalEffect::InstalledRecord])
    {
        for after in [false, true] {
            let mut host = FakeHost::new(Some(&running()));
            if after {
                host.fail_after = Some(effect);
            } else {
                host.fail_before = Some(effect);
            }
            assert!(
                matches!(host.complete(), RemovalOutcome::NeedsCompletion(_)),
                "{effect:?}, after={after}"
            );
            assert_eq!(host.path(effect).exists(), !after);
            assert_eq!(
                host.committed().recovery_direction(),
                records::RecoveryDirection::Removal
            );
            host.fail_after = None;
            host.fail_before = None;
            assert_eq!(host.finish(), RemovalOutcome::Completed);
            host.preserved();
        }
    }
}

#[test]
fn staged_next_checkpoint_is_retried_but_never_grants_commitment() {
    let mut host = FakeHost::new(Some(&running()));
    host.fail_publish_stage = Some(1);
    assert!(matches!(
        host.complete(),
        RemovalOutcome::NeedsCompletion(_)
    ));
    assert_eq!(checkpoint(&host.committed()).unwrap(), 0);
    assert!(host.read("stage").unwrap().is_some());
    host.fail_publish_stage = None;
    assert_eq!(host.finish(), RemovalOutcome::Completed);
    let host = FakeHost::new(Some(&running()));
    write(
        &host.root.0.join("stage"),
        &commit_removal(Some(&running()), &release())
            .unwrap()
            .encode()
            .unwrap(),
    );
    let mut removal = Removal::new(host);
    assert!(removal.review(RemovalAction::Complete).is_err());
    assert!(removal.host().effects.is_empty());
}

#[test]
fn late_successful_publication_errors_are_reinspected_and_synchronized() {
    for boundary in 0..=11 {
        let mut host = FakeHost::new(Some(&running()));
        host.fail_publish_after = Some(boundary);
        assert_eq!(
            host.complete(),
            RemovalOutcome::Completed,
            "boundary {boundary}"
        );
        host.preserved();
    }
}

#[test]
fn stale_foreign_or_declined_prepared_action_changes_nothing() {
    let mut removal = Removal::new(FakeHost::new(Some(&running())));
    let first = removal.review(RemovalAction::Complete).unwrap();
    let second = removal.review(RemovalAction::Complete).unwrap();
    assert_eq!(
        removal.execute(first, domain::Confirmation::Approved),
        RemovalOutcome::Refused(RemovalError::PreparedAction)
    );
    assert_eq!(
        removal.execute(second, domain::Confirmation::Declined),
        RemovalOutcome::Declined
    );
    let prepared = removal.review(RemovalAction::Complete).unwrap();
    assert_eq!(
        removal.execute(prepared, domain::Confirmation::Declined),
        RemovalOutcome::Declined
    );
    let prepared = removal.review(RemovalAction::Complete).unwrap();
    let mut other = Removal::new(FakeHost::new(Some(&running())));
    assert_eq!(
        other.execute(prepared, domain::Confirmation::Approved),
        RemovalOutcome::Refused(RemovalError::PreparedAction)
    );
    assert!(removal.host().effects.is_empty());
    let mut host = removal.into_host();
    host.changed_on_lock = true;
    assert_eq!(
        host.complete(),
        RemovalOutcome::Refused(RemovalError::Safety)
    );
    assert!(host.effects.is_empty());
    assert_eq!(host.committed().phase(), records::SetupPhase::Running);
    assert!(!host.locked);
}

#[test]
fn foreign_bytes_symlinks_hardlinks_modes_and_preapply_replacements_are_preserved() {
    for kind in 0..5 {
        let mut host = FakeHost::new(Some(&running()));
        let path = host.path(RemovalEffect::AptKey);
        match kind {
            0 => write(&path, b"foreign signing key\n"),
            1 => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("foreign-owner-data", &path).unwrap();
            }
            2 => fs::hard_link(&path, host.root.0.join("foreign-hardlink")).unwrap(),
            3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => host.race = Some(RemovalEffect::AptKey),
        }
        assert!(
            matches!(host.complete(), RemovalOutcome::NeedsCompletion(_)),
            "kind {kind}"
        );
        assert!(fs::symlink_metadata(&path).is_ok());
        assert!(!host.effects.contains(&RemovalEffect::AptKey));
        assert!(host.path(RemovalEffect::Executable).exists());
        assert_eq!(checkpoint(&host.committed()).unwrap(), 7);
        host.preserved();
    }
}

#[test]
fn unknown_state_residue_blocks_executable_deletion_without_recursive_cleanup() {
    let mut host = FakeHost::new(Some(&running()));
    write(
        &host.root.0.join("unknown-state-residue"),
        b"unknown owned-by-somebody-else\n",
    );
    assert_eq!(
        host.complete(),
        RemovalOutcome::NeedsCompletion("SBXR state directory inspection")
    );
    assert!(host.path(RemovalEffect::Executable).exists());
    assert!(host.root.0.join("unknown-state-residue").exists());
    host.preserved();
}

#[test]
fn interrupted_finalizer_keeps_exact_release_and_restored_members_are_removed_again() {
    let mut host = FakeHost::new(Some(&running()));
    host.fail_finalizer = Some(1);
    assert!(matches!(
        host.complete(),
        RemovalOutcome::NeedsCompletion(_)
    ));
    let snapshot = host.read_authority().unwrap();
    assert!(snapshot.current.is_none() && snapshot.finalizer.is_some());
    let facts = host.inspect_lifecycle(&release()).unwrap();
    let plan = exact_restoration(&snapshot, facts).unwrap().unwrap();
    assert_eq!(plan.release, release());
    assert!(plan.restore_executable && plan.restore_installed_record);
    host.put(RemovalEffect::Executable);
    host.put(RemovalEffect::InstalledRecord);
    host.fail_finalizer = None;
    assert_eq!(host.finish(), RemovalOutcome::Completed);
    assert_eq!(
        host.effects
            .iter()
            .filter(|e| **e == RemovalEffect::Executable)
            .count(),
        2
    );
    host.preserved();
}

#[test]
fn final_unlink_sync_uncertainty_never_claims_completion_or_available_recovery() {
    let mut host = FakeHost::new(Some(&running()));
    host.fail_finalizer = Some(2);
    assert_eq!(host.complete(), RemovalOutcome::FinalSynchronizationUnknown);
    assert_eq!(host.read_authority().unwrap(), AuthoritySnapshot::default());
    assert!(
        exact_restoration(
            &host.read_authority().unwrap(),
            host.inspect_lifecycle(&release()).unwrap()
        )
        .is_err()
    );
    host.preserved();
}

#[test]
fn contradictory_finalizers_and_wrong_finisher_refuse_without_effects() {
    let committed = commit_removal(Some(&running()), &release()).unwrap();
    for finalizer_checkpoint in [0, 11] {
        let host = FakeHost::new(Some(&running()));
        let mut record = committed.clone();
        for _ in 0..finalizer_checkpoint {
            record = next_checkpoint(&record).unwrap();
        }
        write(&host.root.0.join("finalizer"), &record.encode().unwrap());
        if finalizer_checkpoint == 0 {
            fs::remove_file(host.root.0.join("current")).unwrap();
        }
        let mut removal = Removal::new(host);
        assert!(removal.review(RemovalAction::Finish).is_err());
        assert!(removal.host().effects.is_empty());
    }
    let mut host = FakeHost::new(Some(&committed));
    host.executing =
        records::ReleaseIdentity::new("v3.1.119", &"d".repeat(40), &"e".repeat(64)).unwrap();
    let mut removal = Removal::new(host);
    assert_eq!(
        removal.review(RemovalAction::Finish).err(),
        Some(RemovalError::ExactRelease)
    );
    assert!(removal.host().effects.is_empty());
}

#[test]
fn cancellation_and_unavailable_effects_refuse_before_commitment() {
    for unavailable in [false, true] {
        let mut host = FakeHost::new(Some(&running()));
        host.unavailable = unavailable;
        if !unavailable {
            host.cancelled = true;
        }
        let mut removal = Removal::new(host);
        if unavailable {
            assert!(removal.review(RemovalAction::Complete).is_err());
        } else {
            let prepared = removal.review(RemovalAction::Complete).unwrap();
            assert!(matches!(
                removal.execute(prepared, domain::Confirmation::Approved),
                RemovalOutcome::Refused(_)
            ));
        }
        assert!(removal.host().effects.is_empty());
    }
}

#[test]
fn exact_machine_codes_and_host_mutation_invalidation_are_retained() {
    assert_eq!(
        RemovalOutcome::Completed.code(),
        "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
    );
    assert_eq!(
        RemovalOutcome::NeedsCompletion("fixed check").code(),
        "PROXY-INSTALLATION-REMOVAL-COMPLETION-REQUIRED"
    );
    let mut removal = Removal::new(FakeHost::new(Some(&running())));
    let prepared = removal.review(RemovalAction::Complete).unwrap();
    removal.host_mut().changed = true;
    assert_eq!(
        removal.execute(prepared, domain::Confirmation::Approved),
        RemovalOutcome::Refused(RemovalError::PreparedAction)
    );
}

fn journal_cases() -> Vec<(&'static str, Vec<RemovalEffect>)> {
    use RemovalEffect::*;
    vec![
        (
            "activation-accepted.json",
            vec![ServingRuntime, RenewalIntegration, SubscriptionResources],
        ),
        (
            "activation-recorded.json",
            vec![ServingRuntime, RenewalIntegration, SubscriptionResources],
        ),
        (
            "client-cleanup.json",
            vec![ClientIdentityTarget, ProxyStartup],
        ),
        (
            "client-forward.json",
            vec![ClientIdentityTarget, ProxyStartup],
        ),
        (
            "client-subscription.json",
            vec![
                ClientIdentitySubscription,
                SubscriptionRepair,
                ClientIdentityTarget,
                SubscriptionResources,
                ProxyStartup,
            ],
        ),
        (
            "compromised.json",
            vec![ServingRuntime, SubscriptionResources],
        ),
        ("enablement-early.json", vec![PreparedSubscription]),
        ("enablement-prepared.json", vec![PreparedSubscription]),
        (
            "rotation-cleanup.json",
            vec![SubscriptionRotation, ServingRuntime, SubscriptionResources],
        ),
        (
            "rotation-forward.json",
            vec![SubscriptionRotation, ServingRuntime, SubscriptionResources],
        ),
    ]
}

#[test]
fn all_preserved_go_interrupted_journals_finish_without_starting_any_generation() {
    for (name, expected) in journal_cases() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/testdata/removal")
                .join(name),
        )
        .unwrap();
        let record = records::OwnershipRecord::decode(&bytes).unwrap();
        assert_eq!(record.encode().unwrap(), bytes, "original Go bytes: {name}");
        let finisher = finishing_release(&record).unwrap();
        let mut host = FakeHost::new(Some(&record));
        for effect in &expected {
            host.put(*effect);
        }
        assert_eq!(host.finish(), RemovalOutcome::Completed, "{name}");
        let mut observed = host.effects.clone();
        assert_eq!(observed.pop(), Some(RemovalEffect::InstalledRecord));
        assert_eq!(observed, expected, "{name}");
        assert_eq!(finisher.tag(), "v3.0.0");
        host.preserved();
    }
}

#[test]
fn every_auxiliary_effect_retries_after_interruption_without_restoring_access() {
    for (name, effects) in journal_cases() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/testdata/removal")
                .join(name),
        )
        .unwrap();
        let record = records::OwnershipRecord::decode(&bytes).unwrap();
        for effect in &effects {
            for after in [false, true] {
                let mut host = FakeHost::new(Some(&record));
                for effect in &effects {
                    host.put(*effect);
                }
                if after {
                    host.fail_after = Some(*effect);
                } else {
                    host.fail_before = Some(*effect);
                }
                assert!(
                    matches!(host.finish(), RemovalOutcome::NeedsCompletion(_)),
                    "{name} {effect:?}"
                );
                assert!(host.read_authority().unwrap().current.is_some());
                host.fail_after = None;
                host.fail_before = None;
                assert_eq!(
                    host.finish(),
                    RemovalOutcome::Completed,
                    "{name} {effect:?}"
                );
                host.preserved();
            }
        }
    }
}

#[test]
fn tunnel_prerequisites_and_foreign_firewall_rules_survive_owned_cleanup() {
    let record = records::OwnershipRecord::decode(include_bytes!(
        "../src/records/testdata/authority/http-tunnel.json"
    ))
    .unwrap();
    let mut host = FakeHost::new(Some(&record));
    for effect in [
        RemovalEffect::DedicatedTunnel,
        RemovalEffect::ServingRuntime,
        RemovalEffect::SubscriptionResources,
    ] {
        host.put(effect);
    }
    for name in [
        "owner-cloudflared",
        "owner-token",
        "owner-tunnel",
        "foreign-firewall-8443",
        "shared-acme-account",
    ] {
        write(
            &host.root.0.join(name),
            b"external prerequisite preserved\n",
        );
    }
    assert_eq!(host.complete(), RemovalOutcome::Completed);
    assert_eq!(host.effects.first(), Some(&RemovalEffect::DedicatedTunnel));
    for name in [
        "owner-cloudflared",
        "owner-token",
        "owner-tunnel",
        "foreign-firewall-8443",
        "shared-acme-account",
    ] {
        assert_eq!(
            fs::read(host.root.0.join(name)).unwrap(),
            b"external prerequisite preserved\n"
        );
    }
    host.preserved();
}

#[test]
fn old_committed_schema_one_keeps_its_release_binding_without_conversion() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&running().encode().unwrap()).unwrap();
    value["phase"] = "Removal committed".into();
    value["unfinished_direction"] = "removal required".into();
    value["removal_checkpoint"] = 0.into();
    let record = records::OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(record.schema(), 1);
    assert_eq!(
        finishing_release(&record).unwrap(),
        record.release_identity()
    );
    assert!(commit_removal(Some(&record), &release()).is_err());
    let mut host = FakeHost::new(Some(&record));
    host.fail_sync = Some(3);
    assert!(matches!(host.finish(), RemovalOutcome::NeedsCompletion(_)));
    assert_eq!(host.committed().schema(), 1);
    assert_eq!(
        host.committed().release_identity(),
        record.release_identity()
    );
    host.fail_sync = None;
    assert_eq!(host.finish(), RemovalOutcome::Completed);
}

#[test]
fn restoration_refuses_conflicting_identity_and_never_selects_latest() {
    let record = commit_removal(Some(&running()), &release()).unwrap();
    let host = FakeHost::new(Some(&record));
    let snapshot = host.read_authority().unwrap();
    let mut facts = host.inspect_lifecycle(&release()).unwrap();
    facts.release =
        records::ReleaseIdentity::new("v3.1.999", &"d".repeat(40), &"e".repeat(64)).unwrap();
    facts.executable_present = false;
    assert_eq!(
        exact_restoration(&snapshot, facts).unwrap_err(),
        RemovalError::ExactRelease
    );
    let mut facts = host.inspect_lifecycle(&release()).unwrap();
    facts.valid = false;
    assert_eq!(
        exact_restoration(&snapshot, facts).unwrap_err(),
        RemovalError::ExactRelease
    );
}

#[test]
fn denied_admission_cancellation_during_lock_and_changed_record_do_not_commit() {
    let mut host = FakeHost::new(Some(&running()));
    host.accepted = false;
    let mut removal = Removal::new(host);
    assert_eq!(
        removal.review(RemovalAction::Complete).err(),
        Some(RemovalError::Safety)
    );
    assert!(removal.host().effects.is_empty());
    let mut host = removal.into_host();
    host.accepted = true;
    host.cancel_on_lock = true;
    assert_eq!(
        host.complete(),
        RemovalOutcome::Refused(RemovalError::Host(host::HostError::Cancelled))
    );
    assert_eq!(host.committed().phase(), records::SetupPhase::Running);
    let mut removal = Removal::new(FakeHost::new(Some(&running())));
    let prepared = removal.review(RemovalAction::Complete).unwrap();
    write(
        &removal.host().root.0.join("current"),
        &commit_removal(Some(&running()), &release())
            .unwrap()
            .encode()
            .unwrap(),
    );
    assert_eq!(
        removal.execute(prepared, domain::Confirmation::Approved),
        RemovalOutcome::Refused(RemovalError::PreparedAction)
    );
    assert!(removal.host().effects.is_empty());
}

#[test]
fn committed_cancellation_keeps_the_checkpoint_and_never_rolls_back() {
    let mut host = FakeHost::new(Some(&running()));
    host.cancel_after = Some(RemovalEffect::ConfigurationState);
    assert_eq!(
        host.complete(),
        RemovalOutcome::NeedsCompletion("Managed termination")
    );
    assert_eq!(checkpoint(&host.committed()).unwrap(), 5);
    assert!(!host.path(RemovalEffect::ConfigurationState).exists());
    host.cancelled = false;
    host.cancel_after = None;
    assert_eq!(host.finish(), RemovalOutcome::Completed);
}

#[test]
fn effect_success_without_proved_absence_cannot_advance_the_journal() {
    let mut host = FakeHost::new(Some(&running()));
    host.ineffective = Some(RemovalEffect::Package);
    assert!(matches!(
        host.complete(),
        RemovalOutcome::NeedsCompletion(_)
    ));
    assert_eq!(checkpoint(&host.committed()).unwrap(), 3);
    assert!(host.path(RemovalEffect::Package).exists());
    assert!(host.path(RemovalEffect::Executable).exists());
}

#[test]
fn matching_final_stage_is_cleaned_but_ambiguous_stage_is_never_adopted() {
    let mut record = commit_removal(None, &release()).unwrap();
    for _ in 0..3 {
        record = next_checkpoint(&record).unwrap();
    }
    let mut host = FakeHost::new(Some(&record));
    for effect in PROXY {
        if host.path(effect).exists() {
            fs::remove_file(host.path(effect)).unwrap();
        }
    }
    for effect in [RemovalEffect::Executable, RemovalEffect::InstalledRecord] {
        if host.path(effect).exists() {
            fs::remove_file(host.path(effect)).unwrap();
        }
    }
    write(&host.root.0.join("stage"), &record.encode().unwrap());
    assert_eq!(host.finish(), RemovalOutcome::Completed);
    let host = FakeHost::new(Some(&record));
    write(&host.root.0.join("stage"), b"foreign stage bytes\n");
    let mut removal = Removal::new(host);
    assert!(removal.review(RemovalAction::Finish).is_err());
    assert_eq!(
        fs::read(removal.host().root.0.join("stage")).unwrap(),
        b"foreign stage bytes\n"
    );
}

#[test]
fn all_source_target_and_creator_inventory_survives_new_commitment() {
    for (name, _) in journal_cases() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/testdata/removal")
                .join(name),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["phase"] = "Running".into();
        value["unfinished_direction"] = "none".into();
        value["removal_checkpoint"] = 0.into();
        value
            .as_object_mut()
            .unwrap()
            .remove("finishing_release_identity");
        let source =
            records::OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        let finisher =
            records::ReleaseIdentity::new("v3.1.119", &"d".repeat(40), &"e".repeat(64)).unwrap();
        let committed = commit_removal(Some(&source), &finisher).unwrap();
        let mut target: serde_json::Value =
            serde_json::from_slice(&committed.encode().unwrap()).unwrap();
        target["phase"] = "Running".into();
        target["unfinished_direction"] = "none".into();
        target
            .as_object_mut()
            .unwrap()
            .remove("finishing_release_identity");
        assert_eq!(target, value, "complete inventory: {name}");
        assert_eq!(finishing_release(&committed).unwrap(), finisher);
    }
}

#[test]
fn foreign_optional_resource_is_preserved_and_blocks_finalization() {
    for (name, effects) in journal_cases() {
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/testdata/removal")
                .join(name),
        )
        .unwrap();
        let record = records::OwnershipRecord::decode(&bytes).unwrap();
        let effect = effects[0];
        let mut host = FakeHost::new(Some(&record));
        write(&host.path(effect), b"foreign changed resource\n");
        assert!(matches!(host.finish(), RemovalOutcome::NeedsCompletion(_)));
        assert_eq!(
            fs::read(host.path(effect)).unwrap(),
            b"foreign changed resource\n"
        );
        assert!(host.read_authority().unwrap().current.is_some());
        assert!(host.effects.is_empty());
        host.preserved();
    }
}

#[test]
fn every_software_only_checkpoint_recovers_without_proxy_operations() {
    for boundary in 0..=3 {
        let mut host = FakeHost::new(None);
        host.fail_sync = Some(boundary);
        assert!(matches!(
            host.complete(),
            RemovalOutcome::NeedsCompletion(_)
        ));
        assert_eq!(checkpoint(&host.committed()).unwrap(), boundary);
        assert_eq!(checkpoint_limit(&host.committed()).unwrap(), 3);
        host.fail_sync = None;
        assert_eq!(host.finish(), RemovalOutcome::Completed);
        assert!(host.effects.iter().all(|effect| matches!(
            effect,
            RemovalEffect::Executable | RemovalEffect::InstalledRecord
        )));
    }
}

#[test]
fn repairs_retirement_and_schema_one_tunnel_remove_exact_pending_inventory() {
    use RemovalEffect::*;
    let cases: &[(&str, &[RemovalEffect])] = &[
        (
            "http-repair-a.json",
            &[ServingRuntime, SubscriptionResources],
        ),
        (
            "http-repair-target.json",
            &[SubscriptionRepair, SubscriptionResources],
        ),
        (
            "https-certificate-repair-target.json",
            &[
                SubscriptionRepair,
                RenewalIntegration,
                SubscriptionResources,
            ],
        ),
        (
            "http-retired-https.json",
            &[ServingRuntime, SubscriptionResources, RetiredHttps],
        ),
        ("schema1-tunnel.json", &[DedicatedTunnel]),
    ];
    for (name, expected) in cases {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/records/testdata/authority")
            .join(name);
        let source = records::OwnershipRecord::decode(&fs::read(path).unwrap()).unwrap();
        let mut host = FakeHost::new(Some(&source));
        for effect in *expected {
            host.put(*effect);
        }
        assert_eq!(host.complete(), RemovalOutcome::Completed, "{name}");
        assert_eq!(&host.effects[..expected.len()], *expected, "{name}");
        host.preserved();
    }
}

#[test]
fn historical_transport_migration_is_read_only_and_cannot_invent_a_removal_conversion() {
    let record = records::OwnershipRecord::decode(include_bytes!(
        "../src/records/testdata/authority/http-migration-pending.json"
    ))
    .unwrap();
    assert_eq!(
        commit_removal(Some(&record), &release()).err(),
        Some(RemovalError::Authority)
    );
    let mut removal = Removal::new(FakeHost::new(Some(&record)));
    assert_eq!(
        removal.review(RemovalAction::Complete).err(),
        Some(RemovalError::Authority)
    );
    assert!(removal.host().effects.is_empty());
    assert_eq!(removal.host().committed(), record);
}

#[test]
fn removal_bridge_describes_native_and_injected_hosts_without_changing_outcomes() {
    use sbxr::proxyinstallation::RemovalInstallation;
    for native in [false, true] {
        let mut host = FakeHost::new(Some(&running()));
        host.native_presentation = native;
        let mut installation = RemovalInstallation::new(host);
        let review = installation.review(domain::Action::CompleteRemoval);
        assert_eq!(review.status, domain::Status::Running);
        assert!(review.prepared.is_some());
        assert!(review.refusal.is_none());
        let details = review.details.join(" ");
        assert!(!details.contains("unavailable"), "{details}");
        if native {
            assert!(details.contains("Native"), "{details}");
            assert!(!details.to_lowercase().contains("injected"));
        } else {
            assert!(details.contains("Injected"), "{details}");
        }
        let result = installation.execute(review.prepared.unwrap(), domain::Confirmation::Approved);
        assert_eq!(result.outcome, domain::Outcome::RemovalComplete);
        assert_eq!(result.status, domain::Status::NotInstalled);
        assert_eq!(result.proxy_traffic, domain::Availability::CannotBeVerified);
        assert_eq!(
            result.outcome.code(),
            "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
        );
        assert_eq!(
            result.message.contains("injected root"),
            !native,
            "{}",
            result.message
        );
        installation.into_host().preserved();

        let mut host = FakeHost::new(Some(&running()));
        host.native_presentation = native;
        let mut installation = RemovalInstallation::new(host);
        let review = installation.review(domain::Action::CompleteRemoval);
        let result = installation.execute(review.prepared.unwrap(), domain::Confirmation::Declined);
        assert_eq!(result.outcome, domain::Outcome::Cancelled);
        assert_eq!(result.status, domain::Status::Running);
        let host = installation.into_host();
        assert!(host.effects.is_empty());
        host.preserved();
    }
}
