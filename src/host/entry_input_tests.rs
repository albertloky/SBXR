use super::*;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
const CA: &[u8] = include_bytes!("../release_https/testdata/ca.pem");
const BUNDLE: &[u8] = include_bytes!(
    "../../internal/softwarelifecycle/adapter/github/testdata/github-attestation.bundle"
);
pub(in crate::host) struct Fixture {
    path: PathBuf,
    time: u64,
}
impl Fixture {
    fn absent() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "entry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            path,
            time: now().unwrap(),
        }
    }
    pub(in crate::host) fn new() -> Self {
        let f = Self::absent();
        f.write(
            "qualification-manifest.json",
            &crate::release_acquisition::fixture_candidate_manifest(),
            0o600,
        );
        f.write("qualification.bundle", BUNDLE, 0o600);
        f.write("ca.crt", CA, 0o644);
        f.write("staging-owned", b"1234-1\n", 0o644);
        f.write("transport-owned", b"", 0o600);
        f.write("deadline", format!("{}\n", f.time + 3600).as_bytes(), 0o600);
        f.write(
            "runtime-deadline",
            format!("{}\n", f.time + 3540).as_bytes(),
            0o600,
        );
        f
    }
    fn root(&self) -> ProtectedFs {
        ProtectedFs::open(&self.path).unwrap()
    }
    fn stage(&self) -> PathBuf {
        self.path.join(DIRECTORY)
    }
    pub(in crate::host) fn write(&self, name: &str, bytes: &[u8], mode: u32) {
        let p = self.stage().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    pub(in crate::host) fn candidate(&self) -> Arc<ProtectedCandidateInput> {
        match select(&self.root(), self.time).unwrap() {
            EntryInput::Candidate(i) => i,
            EntryInput::Stable => panic!("explicit protected input must select candidate"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
#[test]
fn zero_argument_source_selection_defaults_to_stable_only_when_handoff_is_absent() {
    let f = Fixture::absent();
    assert!(matches!(
        select(&f.root(), f.time).unwrap(),
        EntryInput::Stable
    ));
    let f = Fixture::new();
    let input = f.candidate();
    assert_eq!(input.identity.tag(), "v9.0.0");
    assert_eq!(input.sequence, 200);
    assert_eq!(input.ca_sha256(), sha256_hex(CA));
    assert_eq!(
        input.manifest_sha256,
        sha256_hex(&crate::release_acquisition::fixture_candidate_manifest())
    );
    input.verify(f.time).unwrap();
    // This is source selection, never a positive signed-candidate proof.
    assert!(
        input.authenticate(&SelectionBudget::new()).is_err(),
        "genuine bundle must reject different raw bytes"
    );
}
#[test]
fn any_missing_required_input_refuses_instead_of_silently_selecting_stable() {
    for (name, _) in FILES {
        let f = Fixture::new();
        std::fs::remove_file(f.stage().join(name)).unwrap();
        assert!(select(&f.root(), f.time).is_err(), "{name}");
    }
    let f = Fixture::absent();
    std::fs::create_dir_all(f.stage()).unwrap();
    assert!(select(&f.root(), f.time).is_err());
}
#[test]
fn stale_invalid_deadlines_run_markers_and_unapproved_or_foreign_manifests_refuse() {
    for (name, bytes) in [
        ("deadline", b"0\n".to_vec()),
        ("runtime-deadline", b"1\n".to_vec()),
        ("runtime-deadline", b"01\n".to_vec()),
        ("staging-owned", b"9999-1\n".to_vec()),
        ("transport-owned", b"claimed\n".to_vec()),
        ("qualification.bundle", b"not JSON".to_vec()),
        ("ca.crt", b"not a certificate".to_vec()),
    ] {
        let f = Fixture::new();
        f.write(name, &bytes, 0o600);
        assert!(select(&f.root(), f.time).is_err(), "{name}");
    }
    let f = Fixture::new();
    f.write(
        "deadline",
        format!("{}\n", f.time + 21601).as_bytes(),
        0o600,
    );
    f.write(
        "runtime-deadline",
        format!("{}\n", f.time + 21541).as_bytes(),
        0o600,
    );
    assert!(select(&f.root(), f.time).is_err());
    let f = Fixture::new();
    assert!(select(&f.root(), f.time + 3540).is_err());
    let input = f.candidate();
    assert!(input.verify(f.time + 3540).is_err());
    let mut input = f.candidate();
    Arc::get_mut(&mut input).unwrap().until = Instant::now();
    assert!(
        input.verify(f.time).is_err(),
        "wall clock cannot extend the original monotonic expiry"
    );
    for (field, value) in [
        ("mode", serde_json::json!("normal")),
        ("source_state", serde_json::json!("v3-recurring")),
        ("repository", serde_json::json!("foreign/repo")),
    ] {
        let f = Fixture::new();
        let mut v: serde_json::Value =
            serde_json::from_slice(&crate::release_acquisition::fixture_candidate_manifest())
                .unwrap();
        v[field] = value;
        f.write(
            "qualification-manifest.json",
            &serde_json::to_vec(&v).unwrap(),
            0o600,
        );
        assert!(select(&f.root(), f.time).is_err(), "{field}");
    }
    let f = Fixture::new();
    let mut v: serde_json::Value =
        serde_json::from_slice(&crate::release_acquisition::fixture_candidate_manifest()).unwrap();
    v["approval"]["state"] = "unapproved".into();
    f.write(
        "qualification-manifest.json",
        &serde_json::to_vec(&v).unwrap(),
        0o600,
    );
    assert!(select(&f.root(), f.time).is_err());
}
#[test]
fn retained_input_checks_inodes_bytes_ownership_links_and_safe_parents() {
    let f = Fixture::new();
    let input = f.candidate();
    let replacement = f.stage().join("replacement");
    std::fs::write(&replacement, CA).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::rename(replacement, f.stage().join("ca.crt")).unwrap();
    assert!(input.verify(f.time).is_err());
    for (name, _) in FILES {
        let f = Fixture::new();
        let source = f.stage().join(name);
        let original = f.path.join("saved");
        std::fs::rename(&source, &original).unwrap();
        symlink(&original, &source).unwrap();
        assert!(select(&f.root(), f.time).is_err(), "symlink {name}");
        std::fs::remove_file(&source).unwrap();
        std::fs::hard_link(&original, &source).unwrap();
        assert!(select(&f.root(), f.time).is_err(), "hardlink {name}");
    }
    let f = Fixture::new();
    std::fs::set_permissions(
        f.stage().join("staging-owned"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(select(&f.root(), f.time).is_err());
    let f = Fixture::new();
    std::fs::set_permissions(f.stage(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(select(&f.root(), f.time).is_err());
    let f = Fixture::new();
    let old = f.path.join("original");
    std::fs::rename(f.stage(), &old).unwrap();
    symlink(&old, f.stage()).unwrap();
    assert!(select(&f.root(), f.time).is_err());
}
#[test]
fn duplicate_json_and_changed_input_never_issue_candidate_or_stable_authority() {
    let f = Fixture::new();
    let input = f.candidate();
    f.write("staging-owned", b"1234-2\n", 0o600);
    assert!(input.verify(f.time).is_err());
    let f = Fixture::new();
    let mut bytes = b"{\"repository\":\"albertloky/SBXR\",".to_vec();
    bytes.extend_from_slice(&crate::release_acquisition::fixture_candidate_manifest()[1..]);
    f.write("qualification-manifest.json", &bytes, 0o600);
    assert!(select(&f.root(), f.time).is_err());
}

#[test]
fn reviewed_identity_sequence_raw_manifest_and_cancellation_are_independent_checks() {
    let f = Fixture::new();
    let input = f.candidate();
    let record = |identity, sequence| {
        InstalledRecord::new(identity, sequence, "amd64", &"c".repeat(64)).unwrap()
    };
    let original = record(input.identity.clone(), input.sequence);
    input.verify_record(&original, f.time).unwrap();
    for other in [
        record(
            ReleaseIdentity::new("v9.0.1", &"a".repeat(40), &"b".repeat(64)).unwrap(),
            input.sequence,
        ),
        record(
            ReleaseIdentity::new("v9.0.0", &"d".repeat(40), &"b".repeat(64)).unwrap(),
            input.sequence,
        ),
        record(
            ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"d".repeat(64)).unwrap(),
            input.sequence,
        ),
        record(input.identity.clone(), input.sequence + 1),
    ] {
        assert!(input.verify_record(&other, f.time).is_err());
    }
    input
        .verify_manifest(&input.manifest_sha256, f.time)
        .unwrap();
    assert!(input.verify_manifest(&"d".repeat(64), f.time).is_err());
    let budget = SelectionBudget::new();
    budget.cancel();
    assert_eq!(input.authenticate(&budget), Err(HostError::Cancelled));
}
