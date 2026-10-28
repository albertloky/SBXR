use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
// Inert ELF bytes reuse the retained identity contract. This is an untrusted
// structural fixture, never a candidate signature or positive native authority.
fn executable() -> Vec<u8> {
    let commit = "a".repeat(40);
    let payload = elf(
        Architecture::Amd64,
        &[
            (
                release_identity::RUST_ARTIFACT_SECTION,
                release_identity::rust_artifact_metadata(&commit, Architecture::Amd64).unwrap(),
            ),
            (".comment", release_identity::RUST_COMPILER_COMMENT.to_vec()),
        ],
    );
    release_identity::stamp_executable(&payload, "v9.0.0", &commit, 200, Architecture::Amd64)
        .unwrap()
}
fn elf(architecture: Architecture, language_sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut sections = vec![
        ("", Vec::new(), 0_u32, 0_u64),
        (".text", vec![0xc3], 1, 6),
        (".rodata", b"fixture".to_vec(), 1, 2),
    ];
    sections.extend(
        language_sections
            .iter()
            .map(|(name, data)| (*name, data.clone(), 1, 0)),
    );
    let mut names = vec![0];
    let mut offsets = vec![0];
    for (name, _, _, _) in sections.iter().skip(1) {
        offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let name_offset = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");
    sections.push((".shstrtab", names, 3, 0));
    offsets.push(name_offset);
    let mut bytes = vec![0_u8; 64 + 56];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(
        &(match architecture {
            Architecture::Amd64 => 62_u16,
            Architecture::Arm64 => 183,
        })
        .to_le_bytes(),
    );
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400080_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&((sections.len() - 1) as u16).to_le_bytes());
    let mut locations = vec![];
    for (_, data, _, _) in &sections {
        bytes.resize((bytes.len() + 15) & !15, 0);
        locations.push(bytes.len());
        bytes.extend_from_slice(data);
    }
    let data_size = bytes.len();
    let table_offset = bytes.len();
    bytes[40..48].copy_from_slice(&(table_offset as u64).to_le_bytes());
    for (i, (_, data, kind, flags)) in sections.iter().enumerate() {
        let mut sh = [0_u8; 64];
        sh[..4].copy_from_slice(&offsets[i].to_le_bytes());
        sh[4..8].copy_from_slice(&kind.to_le_bytes());
        sh[8..16].copy_from_slice(&flags.to_le_bytes());
        sh[16..24].copy_from_slice(&(0x400000 + locations[i] as u64).to_le_bytes());
        sh[24..32].copy_from_slice(&(locations[i] as u64).to_le_bytes());
        sh[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
        sh[48..56].copy_from_slice(&1_u64.to_le_bytes());
        if i == 0 {
            sh.fill(0);
        }
        bytes.extend_from_slice(&sh);
    }
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(data_size as u64).to_le_bytes());
    bytes[104..112].copy_from_slice(&(data_size as u64).to_le_bytes());
    bytes[112..120].copy_from_slice(&1_u64.to_le_bytes());
    bytes
}
pub(in crate::host) struct Fixture(pub(in crate::host) PathBuf);
impl Fixture {
    pub(in crate::host) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "admit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = Self(p);
        let b = executable();
        let r = InstalledRecord::new(
            crate::records::ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"b".repeat(64))
                .unwrap(),
            200,
            "amd64",
            &crate::records::sha256_hex(&b),
        )
        .unwrap();
        f.write(EXECUTABLE, &b, 0o755);
        f.write("var/lib/sbxr/installed.json", &r.encode().unwrap(), 0o600);
        std::fs::set_permissions(
            f.0.join("var/lib/sbxr"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        f
    }
    pub(in crate::host) fn write(&self, path: &str, b: &[u8], m: u32) {
        let p = self.0.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    pub(in crate::host) fn capture(&self) -> Result<Snapshot, HostError> {
        Snapshot::capture(
            ProtectedFs::open(&self.0)?,
            File::open(self.0.join(EXECUTABLE)).map_err(refused)?,
            release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64).unwrap(),
            Cancellation::new(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn structural_snapshot_is_fresh_same_inode_and_not_authenticated_authority() {
    let f = Fixture::new();
    let snapshot = f.capture().unwrap();
    snapshot.verify().unwrap();
    let (proof, _) = release_acquisition::fixture_authenticated();
    assert_eq!(proof.role(), DeliveryRole::Stable);
    assert!(
        NativeAdmission::bind(
            snapshot,
            Box::new(proof),
            DeliveryRole::Stable,
            &SelectionBudget::new()
        )
        .is_err()
    );
}
#[test]
fn copied_inode_stale_namespace_wrong_bytes_loaded_identity_or_cancel_cannot_bind() {
    let f = Fixture::new();
    let s = f.capture().unwrap();
    let copy = f.0.join("copy");
    std::fs::copy(f.0.join(EXECUTABLE), &copy).unwrap();
    assert!(
        Snapshot::capture(
            ProtectedFs::open(&f.0).unwrap(),
            File::open(&copy).unwrap(),
            s.loaded.clone(),
            Cancellation::new()
        )
        .is_err()
    );
    std::fs::rename(&copy, f.0.join(EXECUTABLE)).unwrap();
    assert!(s.verify().is_err());
    let f = Fixture::new();
    let s = f.capture().unwrap();
    f.write(EXECUTABLE, b"different", 0o755);
    assert!(s.verify().is_err());
    let f = Fixture::new();
    let mut s = f.capture().unwrap();
    s.loaded =
        release_identity::rust_artifact_metadata(&"c".repeat(40), Architecture::Amd64).unwrap();
    assert!(s.verify().is_err());
    let f = Fixture::new();
    let s = f.capture().unwrap();
    s.stop.cancel();
    assert_eq!(s.verify(), Err(HostError::Cancelled));
}
#[test]
fn native_constructor_refuses_development_before_transport_or_activation() {
    struct Never;
    impl AcquisitionTransport for Never {
        fn get(
            &mut self,
            _: &crate::artifact_trust::AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<crate::artifact_trust::AcquisitionResponse, TrustError> {
            panic!("network must not run")
        }
    }
    assert!(
        NativeAdmission::stable(&mut Never, &SelectionBudget::new(), Cancellation::new()).is_err()
    );
    assert!(super::super::require_live_adapter().is_err());
    let mut input = File::open("/dev/null").unwrap();
    let (mut reader, mut output) = std::io::pipe().unwrap();
    assert!(crate::host::owner::run_public_unreleased(&mut input, &mut output).is_err());
    drop(output);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap();
    assert!(bytes.is_empty());
}
#[test]
fn a_prepared_journey_cannot_execute_or_disclose_after_process_evidence_changes() {
    use crate::{
        domain::{Action, Confirmation, Outcome},
        proxyinstallation::{Installation, Interface},
    };
    let f = Fixture::new();
    let snapshot = f.capture().unwrap();
    let mut journey = BoundJourney::new(&snapshot, Box::new(Installation::simulation()));
    let prepared = journey.review(Action::StartSetup).prepared.unwrap();
    f.write(EXECUTABLE, b"changed", 0o755);
    assert!(journey.review(Action::StartSetup).prepared.is_none());
    assert_eq!(
        journey.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    let mut output = Vec::new();
    assert!(journey.write_details(&mut output).is_err());
    assert!(output.is_empty());
}
#[test]
fn identical_record_bytes_under_a_replaced_inode_expire_the_snapshot() {
    let f = Fixture::new();
    let snapshot = f.capture().unwrap();
    let record = f.0.join("var/lib/sbxr/installed.json");
    let bytes = std::fs::read(&record).unwrap();
    let next = f.0.join("replacement");
    std::fs::write(&next, bytes).unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(next, record).unwrap();
    assert!(snapshot.verify().is_err());
}

#[test]
fn delivery_source_cannot_promote_stable_to_candidate_and_cancel_is_preserved() {
    let (proof, _) = release_acquisition::fixture_authenticated();
    require_delivery(&proof, DeliveryRole::Stable).unwrap();
    assert!(require_delivery(&proof, DeliveryRole::Candidate).is_err());
    let budget = SelectionBudget::new();
    budget.cancel();
    struct Never;
    impl AcquisitionTransport for Never {
        fn get(
            &mut self,
            _: &crate::artifact_trust::AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<crate::artifact_trust::AcquisitionResponse, TrustError> {
            panic!("cancelled admission must not acquire")
        }
    }
    assert!(matches!(
        NativeAdmission::stable(&mut Never, &budget, Cancellation::new()),
        Err(HostError::Cancelled)
    ));
    assert!(matches!(
        NativeAdmission::candidate("untrusted pin", &budget, Cancellation::new()),
        Err(HostError::Cancelled)
    ));
}

#[test]
fn candidate_entry_input_remains_part_of_each_selected_journey_guard() {
    let f = Fixture::new();
    let stage = super::super::entry_input::tests::Fixture::new();
    let (identity, sequence) = crate::release_acquisition::inspect_candidate_handoff(
        &crate::release_acquisition::fixture_candidate_manifest(),
    )
    .unwrap();
    let record = InstalledRecord::new(
        identity,
        sequence,
        "amd64",
        &crate::records::sha256_hex(&executable()),
    )
    .unwrap();
    f.write(
        "var/lib/sbxr/installed.json",
        &record.encode().unwrap(),
        0o600,
    );
    let mut snapshot = f.capture().unwrap();
    // Structural freshness only: this does not construct NativeAdmission or
    // fabricate the missing matching signed candidate positive evidence.
    snapshot.candidate_input = Some(stage.candidate());
    snapshot.verify().unwrap();
    use crate::{
        domain::*,
        proxyinstallation::{Installation, Interface},
    };
    let mut journey = BoundJourney::new(&snapshot, Box::new(Installation::simulation()));
    let prepared = journey.review(Action::StartSetup).prepared.unwrap();
    stage.write("staging-owned", b"1234-2\n", 0o600);
    assert!(snapshot.verify().is_err());
    assert!(journey.review(Action::StartSetup).prepared.is_none());
    assert_eq!(
        journey.execute(prepared, Confirmation::Approved).outcome,
        Outcome::Refused
    );
}

#[test]
fn snapshot_timings_keep_fresh_record_refusal_and_never_emit_authority() {
    let fixture = Fixture::new();
    let snapshot = fixture.capture().unwrap();
    for changed in [false, true] {
        if changed {
            fixture.write(
                "var/lib/sbxr/installed.json",
                b"SECRET-SENTINEL /private/path",
                0o600,
            );
        }
        let (result, bytes) = super::super::timing::capture(|| snapshot.verify());
        assert_eq!(result.is_err(), changed);
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in [
            "SECRET-SENTINEL",
            "/private/path",
            fixture.0.to_str().unwrap(),
            "v9.0.0",
            &"a".repeat(40),
        ] {
            assert!(!text.contains(forbidden));
        }
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| {
                serde_json::from_str(line.strip_prefix("SBXR_NATIVE_PHASE ").unwrap()).unwrap()
            })
            .collect();
        assert_eq!(rows[0]["phase"], "snapshot");
        assert_eq!(rows[0]["event"], "begin");
        assert_eq!(rows.last().unwrap()["event"], "end");
        assert_eq!(rows[0]["id"], rows.last().unwrap()["id"]);
    }
}

#[test]
fn snapshot_revalidation_reads_the_named_image_once_without_repeating_pair_work() {
    use std::{sync::Arc, time::Instant};
    let f = Fixture::new();
    let payload = elf(
        Architecture::Amd64,
        &[
            (
                release_identity::RUST_ARTIFACT_SECTION,
                release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64)
                    .unwrap(),
            ),
            (".comment", release_identity::RUST_COMPILER_COMMENT.to_vec()),
            (".padding", vec![0; 8 * 1024 * 1024]),
        ],
    );
    let image = release_identity::stamp_executable(
        &payload,
        "v9.0.0",
        &"a".repeat(40),
        200,
        Architecture::Amd64,
    )
    .unwrap();
    let record = InstalledRecord::new(
        crate::records::ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"b".repeat(64)).unwrap(),
        200,
        "amd64",
        &crate::records::sha256_hex(&image),
    )
    .unwrap();
    f.write(EXECUTABLE, &image, 0o755);
    f.write(
        "var/lib/sbxr/installed.json",
        &record.encode().unwrap(),
        0o600,
    );
    let capture_start = Instant::now();
    let snapshot = f.capture().unwrap();
    let capture_elapsed = capture_start.elapsed();
    let named_reads = Arc::new(AtomicUsize::new(0));
    let count = named_reads.clone();
    *snapshot.fs.raw_observer.lock().unwrap() = Some(Box::new(move |path| {
        if path == EXECUTABLE {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }));
    let start = Instant::now();
    let ((), trace) = super::super::timing::capture(|| {
        for _ in 0..4 {
            snapshot.verify().unwrap();
        }
    });
    println!(
        "inert image bytes={} capture_us={} four_verify_us={} named_reads={}",
        image.len(),
        capture_elapsed.as_micros(),
        start.elapsed().as_micros(),
        named_reads.load(Ordering::Relaxed)
    );
    assert_eq!(
        named_reads.load(Ordering::Relaxed),
        4,
        "one fresh full named-image read per guard"
    );
    let trace = String::from_utf8(trace).unwrap();
    assert_eq!(
        trace
            .lines()
            .filter(|l| l.contains("\"phase\":\"snapshot\"") && l.contains("\"event\":\"begin\""))
            .count(),
        4
    );
    assert!(
        !trace.contains("installed-pair"),
        "captured tuple must not be re-proved"
    );
}

#[test]
fn capture_rejects_record_bytes_changed_after_the_initial_pair_read() {
    let f = Fixture::new();
    // Both records independently match image A; only the release-index identity
    // differs. The exact record returned by the first read must bind held bytes.
    let other = InstalledRecord::new(
        crate::records::ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"c".repeat(64)).unwrap(),
        200,
        "amd64",
        &crate::records::sha256_hex(&executable()),
    )
    .unwrap();
    release_identity::verify_installed_pair(&other, &executable()).unwrap();
    let fs = ProtectedFs::open(&f.0).unwrap();
    let record_path = f.0.join("var/lib/sbxr/installed.json");
    let mut changed = false;
    *fs.raw_observer.lock().unwrap() = Some(Box::new(move |path| {
        if path == EXECUTABLE && !changed {
            changed = true;
            std::fs::write(&record_path, other.encode().unwrap()).unwrap();
        }
    }));
    assert!(
        Snapshot::capture(
            fs,
            File::open(f.0.join(EXECUTABLE)).unwrap(),
            release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64).unwrap(),
            Cancellation::new()
        )
        .is_err()
    );
}

#[test]
fn capture_rejects_a_valid_image_that_does_not_match_the_captured_record() {
    let f = Fixture::new();
    let image_a = executable();
    let payload = release_identity::read_executable_identity(&image_a).unwrap();
    let image_b = release_identity::stamp_executable(
        payload.payload(),
        "v9.0.0",
        &"a".repeat(40),
        201,
        Architecture::Amd64,
    )
    .unwrap();
    release_identity::inspect_linux_artifact(&image_b, Architecture::Amd64).unwrap();
    let record_b = InstalledRecord::new(
        crate::records::ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"b".repeat(64)).unwrap(),
        201,
        "amd64",
        &crate::records::sha256_hex(&image_b),
    )
    .unwrap();
    release_identity::verify_installed_pair(&record_b, &image_b).unwrap();
    let fs = ProtectedFs::open(&f.0).unwrap();
    let image_path = f.0.join(EXECUTABLE);
    let mut records = 0;
    *fs.raw_observer.lock().unwrap() = Some(Box::new(move |path| {
        if path == "var/lib/sbxr/installed.json" {
            records += 1;
            if records == 2 {
                std::fs::write(&image_path, &image_b).unwrap();
            }
        }
    }));
    assert!(
        Snapshot::capture(
            fs,
            File::open(f.0.join(EXECUTABLE)).unwrap(),
            release_identity::rust_artifact_metadata(&"a".repeat(40), Architecture::Amd64).unwrap(),
            Cancellation::new()
        )
        .is_err()
    );
}

#[test]
fn every_guard_keeps_fresh_metadata_namespace_record_and_transaction_refusals() {
    for case in [
        "image-mode",
        "record-mode",
        "image-link",
        "record-link",
        "parent-mode",
        "record-identity",
        "uid",
        "gid",
        "prior-image",
        "candidate-image",
        "prior-record",
        "candidate-record",
        "update",
        "next-update",
    ] {
        let f = Fixture::new();
        let mut snapshot = f.capture().unwrap();
        let record_path = "var/lib/sbxr/installed.json";
        match case {
            "image-mode" => std::fs::set_permissions(
                f.0.join(EXECUTABLE),
                std::fs::Permissions::from_mode(0o754),
            )
            .unwrap(),
            "record-mode" => std::fs::set_permissions(
                f.0.join(record_path),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            "image-link" => std::fs::hard_link(f.0.join(EXECUTABLE), f.0.join("link")).unwrap(),
            "record-link" => std::fs::hard_link(f.0.join(record_path), f.0.join("link")).unwrap(),
            "parent-mode" => std::fs::set_permissions(
                f.0.join("usr/local/bin"),
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap(),
            "record-identity" => {
                let other = InstalledRecord::new(
                    crate::records::ReleaseIdentity::new(
                        "v9.0.0",
                        &"a".repeat(40),
                        &"c".repeat(64),
                    )
                    .unwrap(),
                    200,
                    "amd64",
                    &crate::records::sha256_hex(&executable()),
                )
                .unwrap();
                f.write(record_path, &other.encode().unwrap(), 0o600);
            }
            // Exercise expected-owner comparisons without changing OS ownership.
            "uid" => snapshot.fs.uid += 1,
            "gid" => snapshot.fs.gid += 1,
            other => f.write(
                match other {
                    "prior-image" => "usr/local/bin/.sbxr-update-prior",
                    "candidate-image" => "usr/local/bin/.sbxr-update-candidate",
                    "prior-record" => "var/lib/sbxr/.installed.json.prior",
                    "candidate-record" => "var/lib/sbxr/.installed.json.candidate",
                    "update" => "var/lib/sbxr/update.json",
                    "next-update" => "var/lib/sbxr/.update.json.next",
                    _ => unreachable!(),
                },
                b"pending transaction",
                0o600,
            ),
        }
        assert!(snapshot.verify().is_err(), "guard accepted {case}");
    }
}

#[test]
fn cancellation_during_a_fresh_read_still_refuses_the_guard() {
    let f = Fixture::new();
    let snapshot = f.capture().unwrap();
    let stop = snapshot.stop.clone();
    *snapshot.fs.raw_observer.lock().unwrap() = Some(Box::new(move |path| {
        if path == "var/lib/sbxr/installed.json" {
            stop.cancel();
        }
    }));
    assert_eq!(snapshot.verify(), Err(HostError::Cancelled));
}

#[test]
fn stale_process_proof_blocks_streaming_execution_without_output_or_effects() {
    use crate::{
        domain::{Action, Confirmation, Outcome},
        proxyinstallation::{Installation, Interface},
    };
    let f = Fixture::new();
    let snapshot = f.capture().unwrap();
    let mut journey = BoundJourney::new(&snapshot, Box::new(Installation::simulation()));
    let prepared = journey.review(Action::StartSetup).prepared.unwrap();
    f.write("var/lib/sbxr/update.json", b"transaction appeared", 0o600);
    let mut output = Vec::new();
    assert_eq!(
        journey
            .execute_output(prepared, Confirmation::Approved, &mut output)
            .unwrap()
            .outcome,
        Outcome::Refused
    );
    assert!(output.is_empty());
    assert!(journey.review(Action::StartSetup).prepared.is_none());
    assert!(journey.write_details(&mut output).is_err());
    assert!(output.is_empty());
}
