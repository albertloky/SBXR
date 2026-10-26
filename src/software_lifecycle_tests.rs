use super::*;
use crate::{
    artifact_trust::{AcquisitionRequest, AcquisitionResponse},
    host::locks::HostLock,
    records::{InstalledRecord, sha256_hex},
    release_identity::{self, Architecture},
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
        let p = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "lc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        let r = Self(p);
        for p in [
            "usr/local/bin",
            "var/lib",
            "var/lib/sbxr",
            "run",
            "run/lock",
        ] {
            fs::create_dir_all(r.0.join(p)).unwrap();
            fs::set_permissions(
                r.0.join(p),
                fs::Permissions::from_mode(if p == "var/lib/sbxr" { 0o700 } else { 0o755 }),
            )
            .unwrap();
        }
        r
    }
    fn write(&self, path: &str, bytes: &[u8], mode: u32) {
        let p = self.0.join(path);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn pair(&self, a: &AuthenticatedArchive) {
        self.write("usr/local/bin/sbxr", a.executable(), 0o755);
        self.write(
            "var/lib/sbxr/installed.json",
            &a.record().encode().unwrap(),
            0o600,
        );
    }
    fn journal(&self, a: &AuthenticatedArchive, finalizer: bool) -> Vec<u8> {
        let mut r = commit_removal(None, &a.record().release_identity()).unwrap();
        if finalizer {
            while checkpoint(&r).unwrap() < checkpoint_limit(&r).unwrap() {
                r = next_checkpoint(&r).unwrap();
            }
        }
        let b = r.encode().unwrap();
        self.write(
            if finalizer {
                "var/lib/.sbxr-removal.json"
            } else {
                "var/lib/sbxr/proxy-ownership.json"
            },
            &b,
            0o600,
        );
        b
    }
    fn module(&self) -> Installed<Unavailable> {
        Installed::new(
            LifecycleHost::injected(&self.0).unwrap(),
            Unavailable { calls: 0 },
        )
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Unavailable {
    calls: usize,
}
impl AcquisitionTransport for Unavailable {
    fn get(
        &mut self,
        _: &AcquisitionRequest,
        _: &SelectionBudget,
    ) -> std::result::Result<AcquisitionResponse, TrustError> {
        self.calls += 1;
        Err(TrustError::Unavailable)
    }
}
#[test]
fn local_ready_and_check_are_independent_from_proxy_configuration_and_do_not_create_locks() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.pair(&a);
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        b"malformed proxy state, not lifecycle authority",
        0o600,
    );
    let mut m = root.module();
    assert_eq!(m.status().code, Code::StatusReady);
    assert_eq!(m.check().code, Code::CheckReleaseUnavailable);
    assert_eq!(m.transport.calls, 1);
    assert_eq!(m.update().code, Code::UpdateReleaseRefused);
    assert_eq!(m.transport.calls, 1);
    assert_eq!(
        m.recover(Confirmation::Approved).code,
        Code::RecoverNotRequired
    );
    assert!(!root.0.join("run/lock/sbxr.lock").exists());
}
#[test]
fn sticky_coordination_parent_allows_read_only_ready_probe_without_creating_or_changing_lock() {
    for existing in [false, true] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        root.pair(&a);
        let parent = root.0.join("run/lock");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
        let path = parent.join("sbxr.lock");
        let body = b"retained coordination bytes";
        if existing {
            root.write("run/lock/sbxr.lock", body, 0o600);
        }
        let before = fs::symlink_metadata(&path).ok();
        let mut m = root.module();
        assert_eq!(m.status().code, Code::StatusReady);
        assert_eq!(m.check().code, Code::CheckReleaseUnavailable);
        assert_eq!(
            m.recover(Confirmation::Approved).code,
            Code::RecoverNotRequired
        );
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o1777);
        if let Some(before) = before {
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (after.dev(), after.ino(), after.mode()),
                (before.dev(), before.ino(), before.mode())
            );
            assert_eq!(fs::read(&path).unwrap(), body);
            HostLock::existing(&root.0, fs::metadata(&root.0).unwrap().uid()).unwrap();
        } else {
            assert!(!path.exists());
        }
    }
}
#[test]
fn active_mutation_probe_never_releases_the_real_owner_or_lent_lock() {
    for mode in [0o755, 0o1777] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        root.pair(&a);
        fs::set_permissions(root.0.join("run/lock"), fs::Permissions::from_mode(mode)).unwrap();
        let uid = fs::metadata(&root.0).unwrap().uid();
        let owner = HostLock::provision(&root.0, uid).unwrap();
        let lent = owner.runtime_start_lock().unwrap();
        let path = root.0.join("run/lock/sbxr.lock");
        let before = fs::metadata(&path).unwrap();
        let mut m = root.module();
        assert_eq!(m.status().code, Code::StatusUpdateInProgress);
        assert_eq!(m.check().code, Code::CheckNotReady);
        assert_eq!(
            m.recover(Confirmation::Approved).code,
            Code::RecoverConcurrentMutation
        );
        assert_eq!(m.transport.calls, 0);
        // Verify contention before either guard can reacquire its flock.
        assert!(matches!(
            HostLock::existing(&root.0, uid),
            Err(crate::host::HostError::Busy)
        ));
        drop(lent);
        assert!(matches!(
            HostLock::existing(&root.0, uid),
            Err(crate::host::HostError::Busy)
        ));
        owner.verify().unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_eq!(fs::read(&path).unwrap(), b"");
        drop(owner);
        assert_eq!(m.status().code, Code::StatusReady);
        assert_eq!(
            fs::metadata(root.0.join("run/lock")).unwrap().mode() & 0o7777,
            mode
        );
    }
}
fn assert_coordination_refused(root: &Root) {
    let mut m = root.module();
    assert_eq!(m.status().code, Code::StatusRecoveryRequired);
    assert_eq!(m.check().code, Code::CheckNotReady);
    assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
    assert_eq!(m.transport.calls, 0);
}
#[test]
fn writable_nonsticky_or_symlinked_coordination_parents_are_preserved_and_refused() {
    for bad in 0..4 {
        let root = Root::new();
        root.pair(&crate::release_acquisition::fixture_archive());
        root.write("run/lock/sbxr.lock", b"keep coordination bytes", 0o600);
        match bad {
            0 => fs::set_permissions(root.0.join("run/lock"), fs::Permissions::from_mode(0o777))
                .unwrap(),
            1 => {
                fs::set_permissions(root.0.join("run"), fs::Permissions::from_mode(0o1777)).unwrap()
            }
            2 => {
                fs::rename(root.0.join("run/lock"), root.0.join("run/kept")).unwrap();
                symlink("kept", root.0.join("run/lock")).unwrap();
            }
            _ => {
                fs::rename(root.0.join("run"), root.0.join("kept")).unwrap();
                symlink("kept", root.0.join("run")).unwrap();
            }
        }
        let path = root.0.join("run/lock/sbxr.lock");
        let before = fs::metadata(&path).unwrap();
        assert_coordination_refused(&root);
        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_eq!(fs::read(path).unwrap(), b"keep coordination bytes");
        if bad >= 2 {
            assert!(
                root.0
                    .join(if bad == 2 { "run/lock" } else { "run" })
                    .is_symlink()
            );
        }
    }
}
#[test]
fn foreign_coordination_files_under_sticky_parent_are_preserved_and_refused() {
    for bad in 0..5 {
        let root = Root::new();
        root.pair(&crate::release_acquisition::fixture_archive());
        fs::set_permissions(root.0.join("run/lock"), fs::Permissions::from_mode(0o1777)).unwrap();
        let path = root.0.join("run/lock/sbxr.lock");
        root.write("run/lock/sbxr.lock", b"keep foreign bytes", 0o600);
        match bad {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => fs::hard_link(&path, root.0.join("kept-lock")).unwrap(),
            2 => {
                fs::rename(&path, root.0.join("kept-lock")).unwrap();
                symlink("../../kept-lock", &path).unwrap();
            }
            3 => root.write("run/lock/sbxr.lock", &[b'x'; 4097], 0o600),
            _ => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let before = fs::symlink_metadata(&path).unwrap();
        let body = (!before.is_dir()).then(|| fs::read(&path).unwrap());
        assert_coordination_refused(&root);
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode(), after.nlink()),
            (before.dev(), before.ino(), before.mode(), before.nlink())
        );
        if let Some(body) = body {
            assert_eq!(fs::read(&path).unwrap(), body);
        }
    }
}
#[test]
fn malformed_or_foreign_pair_is_preserved_and_cannot_start_network_or_recovery() {
    for bad in 0..5 {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        root.pair(&a);
        match bad {
            0 => root.write("var/lib/sbxr/installed.json", b"unknown record", 0o600),
            1 => root.write("usr/local/bin/sbxr", b"foreign executable", 0o755),
            2 => fs::set_permissions(
                root.0.join("var/lib/sbxr/installed.json"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            3 => {
                fs::remove_file(root.0.join("var/lib/sbxr/installed.json")).unwrap();
                symlink("/etc/hosts", root.0.join("var/lib/sbxr/installed.json")).unwrap();
            }
            _ => {
                fs::hard_link(
                    root.0.join("usr/local/bin/sbxr"),
                    root.0.join("usr/local/bin/keep"),
                )
                .unwrap();
            }
        }
        let mut m = root.module();
        assert_eq!(m.status().state, State::RecoveryRequired);
        assert_eq!(m.check().code, Code::CheckNotReady);
        assert!(m.review_recover().recovery_direction.is_none());
        assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
        assert_eq!(m.transport.calls, 0);
        assert!(root.0.join("usr/local/bin/sbxr").exists());
    }
}
#[test]
fn historical_transaction_evidence_is_preserved_without_update_or_migration() {
    for name in [
        "var/lib/sbxr/update.json",
        "var/lib/sbxr/.update.json.next",
        "usr/local/bin/.sbxr-update-prior",
        "var/lib/sbxr/.installed.json.candidate",
    ] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        root.pair(&a);
        let body = b"retained transaction evidence; never reinterpret as new authority";
        root.write(name, body, 0o600);
        let mut m = root.module();
        assert_eq!(m.status().state, State::RecoveryRequired);
        assert!(m.review_recover().recovery_direction.is_none());
        assert_eq!(m.update().code, Code::UpdateNotReady);
        assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
        assert_eq!(m.transport.calls, 0);
        assert_eq!(fs::read(root.0.join(name)).unwrap(), body);
    }
}
#[test]
fn exact_same_release_check_differs_from_clean_install_refusal_and_stale_local_facts() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.pair(&a);
    let m = root.module();
    let before = m.host.inspect().unwrap();
    assert_eq!(
        m.finish_check(&before, Ok(crate::release_acquisition::fixture_archive()))
            .code,
        Code::CheckAlreadyCurrent
    );
    root.write("usr/local/bin/sbxr", b"changed while fetching", 0o755);
    assert_eq!(
        m.finish_check(&before, Ok(crate::release_acquisition::fixture_archive()))
            .code,
        Code::CheckConcurrentChange
    );
    let old = release_identity::read_executable_identity(a.executable()).unwrap();
    let prior = release_identity::stamp_executable(
        old.payload(),
        "v3.1.117",
        old.commit(),
        191,
        Architecture::Amd64,
    )
    .unwrap();
    let r = InstalledRecord::new(
        crate::records::ReleaseIdentity::new("v3.1.117", old.commit(), &"a".repeat(64)).unwrap(),
        191,
        "amd64",
        &sha256_hex(&prior),
    )
    .unwrap();
    root.write("usr/local/bin/sbxr", &prior, 0o755);
    root.write("var/lib/sbxr/installed.json", &r.encode().unwrap(), 0o600);
    let before = m.host.inspect().unwrap();
    let result = m.finish_check(&before, Ok(crate::release_acquisition::fixture_archive()));
    assert_eq!(result.code, Code::CheckReleaseRefused);
    assert_eq!(result.message, CLEAN_INSTALL_CORRECTION);
    assert!(result.latest.is_none());
}
#[test]
fn removal_recovery_review_is_read_only_declined_stale_or_unproved_never_fetches() {
    for bad in 0..4 {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        let body = root.journal(&a, false);
        let mut m = root.module();
        assert!(m.review_recover().recovery_direction.is_some());
        assert!(!root.0.join("run/lock/sbxr.lock").exists());
        match bad {
            0 => {
                assert_eq!(m.recover(Confirmation::Declined).code, Code::RecoverRefused);
            }
            1 => {
                m.status();
                assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
            }
            2 => {
                root.write(
                    "var/lib/sbxr/.proxy-ownership.json.next",
                    b"foreign stage",
                    0o600,
                );
                assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
            }
            _ => {
                root.write("var/lib/sbxr/installed.json", b"foreign pair", 0o600);
                assert_eq!(m.recover(Confirmation::Approved).code, Code::RecoverRefused);
            }
        }
        assert_eq!(m.transport.calls, 0);
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            body
        );
        assert!(!root.0.join("usr/local/bin/sbxr").exists());
    }
}
#[test]
fn reviewed_committed_removal_restores_only_exact_pair_and_lends_one_use_finisher() {
    for finalizer in [false, true] {
        let root = Root::new();
        let a = crate::release_acquisition::fixture_archive();
        let journal = root.journal(&a, finalizer);
        let mut m = root.module();
        assert!(m.review_recover().recovery_direction.is_some());
        let before = m.prepared.take().unwrap();
        let result = m.finish_recovery(before, &a, &SelectionBudget::new());
        assert_eq!(result.code, Code::RemovalRestored);
        assert_eq!(result.state, State::RecoveryRequired);
        assert_eq!(
            fs::read(root.0.join("usr/local/bin/sbxr")).unwrap(),
            a.executable()
        );
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/installed.json")).unwrap(),
            a.record().encode().unwrap()
        );
        assert_eq!(
            fs::read(root.0.join(if finalizer {
                "var/lib/.sbxr-removal.json"
            } else {
                "var/lib/sbxr/proxy-ownership.json"
            }))
            .unwrap(),
            journal
        );
        let finisher = m.take_finisher().unwrap();
        assert!(m.take_finisher().is_none());
        assert!(HostLock::existing(&root.0, fs::metadata(&root.0).unwrap().uid()).is_err());
        drop(finisher);
        HostLock::existing(&root.0, fs::metadata(&root.0).unwrap().uid()).unwrap();
    }
}
#[test]
fn restoration_refuses_changed_review_and_wrong_authenticated_release() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.journal(&a, false);
    let mut m = root.module();
    m.review_recover();
    let expected = m.prepared.take().unwrap();
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        b"changed journal",
        0o600,
    );
    assert_eq!(
        m.finish_recovery(expected, &a, &SelectionBudget::new())
            .code,
        Code::RecoverRefused
    );
    assert!(!root.0.join("usr/local/bin/sbxr").exists());
}
#[test]
fn exact_finisher_never_substitutes_latest_or_another_authenticated_release() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    let other =
        crate::records::ReleaseIdentity::new("v9.8.7", &"a".repeat(40), &"b".repeat(64)).unwrap();
    let journal = commit_removal(None, &other).unwrap().encode().unwrap();
    root.write("var/lib/sbxr/proxy-ownership.json", &journal, 0o600);
    let mut m = root.module();
    assert!(m.review_recover().recovery_direction.is_some());
    let p = m.prepared.take().unwrap();
    assert_eq!(
        m.finish_recovery(p, &a, &SelectionBudget::new()).code,
        Code::RecoverRefused
    );
    assert!(!root.0.join("usr/local/bin/sbxr").exists());
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        journal
    );
}

#[test]
fn composed_terminal_shows_check_recover_but_never_update_and_blocks_proxy_when_not_ready() {
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.pair(&a);
    let mut m = root.module();
    let mut proxy = crate::proxyinstallation::Installation::simulation();
    let mut output = Vec::new();
    crate::terminal::run_with_lifecycle(
        &mut std::io::Cursor::new(b"3\n4\n0\n"),
        &mut output,
        &mut proxy,
        &mut m,
    )
    .unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("Check SBXR") && text.contains("Recover SBXR"));
    assert!(!text.contains("Update SBXR"));
    assert!(text.contains(Code::CheckReleaseUnavailable.as_str()));
    assert!(text.contains("No recovery is available"));
    assert_eq!(m.transport.calls, 1);
    fs::remove_file(root.0.join("usr/local/bin/sbxr")).unwrap();
    fs::remove_file(root.0.join("var/lib/sbxr/installed.json")).unwrap();
    let body = root.journal(&a, false);
    for approval in ["", "n"] {
        let mut m = root.module();
        let mut proxy = crate::proxyinstallation::Installation::simulation();
        let mut output = Vec::new();
        crate::terminal::run_with_lifecycle(
            &mut std::io::Cursor::new(format!("3\n{approval}\n0\n")),
            &mut output,
            &mut proxy,
            &mut m,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Recover SBXR? [y/N]"));
        assert!(!text.contains(". Start setup"));
        assert!(text.contains("No changes were made"));
        assert_eq!(m.transport.calls, 0);
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            body
        );
        assert!(!root.0.join("run/lock/sbxr.lock").exists());
    }
}
#[test]
fn terminal_output_failure_before_check_cannot_start_acquisition() {
    struct Fails;
    impl std::io::Write for Fails {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.windows(b"Progress:".len()).any(|p| p == b"Progress:") {
                return Err(std::io::Error::other("fixture output failure"));
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    root.pair(&a);
    let mut m = root.module();
    let mut proxy = crate::proxyinstallation::Installation::simulation();
    assert!(
        crate::terminal::run_with_lifecycle(
            &mut std::io::Cursor::new(b"3\n"),
            &mut Fails,
            &mut proxy,
            &mut m
        )
        .is_err()
    );
    assert_eq!(m.transport.calls, 0);
}
#[test]
fn composed_recovery_returns_to_exact_finisher_without_reporting_removal_complete() {
    // The UI accepts the already opaque archive at its acquisition boundary.
    // Production recover always obtains it through the real signature verifier.
    struct VerifiedFixture {
        inner: Installed<Unavailable>,
        archive: AuthenticatedArchive,
    }
    impl Interface for VerifiedFixture {
        fn status(&mut self) -> Result {
            self.inner.status()
        }
        fn check(&mut self) -> Result {
            self.inner.check()
        }
        fn update(&mut self) -> Result {
            self.inner.update()
        }
        fn review_recover(&mut self) -> Result {
            self.inner.review_recover()
        }
        fn recover(&mut self, c: Confirmation) -> Result {
            if c != Confirmation::Approved {
                return self.inner.recover(c);
            }
            let p = self.inner.prepared.take().unwrap();
            self.inner
                .finish_recovery(p, &self.archive, &SelectionBudget::new())
        }
        fn take_finisher(&mut self) -> Option<RestoredFinisher> {
            self.inner.take_finisher()
        }
    }
    let root = Root::new();
    let a = crate::release_acquisition::fixture_archive();
    let journal = root.journal(&a, false);
    let mut m = VerifiedFixture {
        inner: root.module(),
        archive: a,
    };
    let mut proxy = crate::proxyinstallation::Installation::simulation();
    let mut output = Vec::new();
    crate::terminal::run_with_lifecycle(
        &mut std::io::Cursor::new(b"3\ny\n"),
        &mut output,
        &mut proxy,
        &mut m,
    )
    .unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains(Code::RemovalRestored.as_str()));
    assert!(text.contains("Removal remains incomplete"));
    assert!(!text.contains("Code: PROXY-INSTALLATION-REMOVAL-COMPLETE"));
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        journal
    );
    drop(m.take_finisher().unwrap());
    assert!(m.take_finisher().is_none());
}

#[test]
fn owner_cancellation_prevents_latest_acquisition_and_exact_finisher_restoration() {
    let root = Root::new();
    let archive = crate::release_acquisition::fixture_archive();
    root.pair(&archive);
    let session = crate::subscription_serving::Cancellation::new();
    let mut module = root.module().with_cancellation(session.clone());
    session.cancel();
    assert_eq!(module.check().code, Code::CheckReleaseRefused);
    assert_eq!(module.transport.calls, 0);
    let journal = root.journal(&archive, false);
    fs::remove_file(root.0.join("usr/local/bin/sbxr")).unwrap();
    assert!(module.review_recover().recovery_direction.is_some());
    assert_eq!(
        module.recover(Confirmation::Approved).code,
        Code::RecoverFailed
    );
    assert_eq!(module.transport.calls, 0);
    assert!(module.take_finisher().is_none());
    module.review_recover();
    let mut module = module.with_cancellation(crate::subscription_serving::Cancellation::new());
    assert_eq!(
        module.recover(Confirmation::Approved).code,
        Code::RecoverRefused
    );
    assert_eq!(module.transport.calls, 0);
    assert!(!root.0.join("usr/local/bin/sbxr").exists());
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        journal
    );
}
