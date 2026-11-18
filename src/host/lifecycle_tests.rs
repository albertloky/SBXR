use super::*;
use std::fs;

#[test]
fn lifecycle_fingerprint_preserves_exact_file_evidence_and_missing_image_authority() {
    for (arch, bytes) in [
        (
            Architecture::Amd64,
            include_bytes!("../../tests/testdata/release_identity/go-amd64-valid.bin").as_slice(),
        ),
        (
            Architecture::Arm64,
            include_bytes!("../../tests/testdata/release_identity/go-arm64-valid.bin").as_slice(),
        ),
    ] {
        let root = super::super::admission::tests::Fixture::new();
        let identity = release_identity::read_executable_identity(bytes).unwrap();
        let record = InstalledRecord::new(
            ReleaseIdentity::new(identity.tag(), identity.commit(), &"a".repeat(64)).unwrap(),
            identity.sequence(),
            arch.as_str(),
            &sha256_hex(bytes),
        )
        .unwrap();
        root.write("usr/local/bin/sbxr", bytes, 0o755);
        root.write(
            "var/lib/sbxr/installed.json",
            &record.encode().unwrap(),
            0o600,
        );
        let host = LifecycleHost::injected(&root.0).unwrap();
        assert_eq!(
            host.require_owner_installed(&record).is_ok(),
            arch == Architecture::Amd64
        );
        let original = host.inspect().unwrap();
        assert!(original.installed.as_ref() == Some(&record));
        for missing in [false, true] {
            if missing {
                fs::rename(root.0.join("usr/local/bin/sbxr"), root.0.join("old-image")).unwrap();
                let authority =
                    crate::removal::commit_removal(None, &record.release_identity()).unwrap();
                root.write(
                    "var/lib/sbxr/proxy-ownership.json",
                    &authority.encode().unwrap(),
                    0o600,
                );
            }
            let snapshot = host.inspect().unwrap();
            let protected = ProtectedFs::open(&root.0).unwrap();
            let record_file = protected
                .raw(
                    "var/lib/sbxr/installed.json",
                    Mode::from_raw_mode(0o600),
                    4096,
                )
                .unwrap();
            let executable = protected
                .raw(
                    "usr/local/bin/sbxr",
                    Mode::from_raw_mode(0o755),
                    release_identity::MAX_EXECUTABLE_BYTES,
                )
                .unwrap();
            // Preserve the original independently hashed fingerprint format.
            let mut image = format!(
                "{:?}:{:?}",
                record_file
                    .as_ref()
                    .map(|(b, p)| (sha256_hex(b), format!("{p:?}"))),
                executable
                    .as_ref()
                    .map(|(b, p)| (sha256_hex(b), format!("{p:?}")))
            );
            if missing {
                image.push_str(&format!("{:?}", snapshot.authority));
            }
            assert_eq!(snapshot.fingerprint, sha256_hex(image.as_bytes()));
            assert_eq!(snapshot.installed.is_none(), missing);
            if missing {
                assert_ne!(snapshot.fingerprint, original.fingerprint);
                assert_eq!(snapshot.restoration, Some(record.release_identity()));
            }
        }
        root.write("usr/local/bin/sbxr", bytes, 0o755);
        let replacement = host.inspect().unwrap();
        assert_ne!(replacement.fingerprint, original.fingerprint);
        let mut changed = bytes.to_vec();
        changed[100] ^= 1;
        root.write("usr/local/bin/sbxr", &changed, 0o755);
        assert!(host.inspect().is_err());
    }
}

#[test]
fn owner_eligibility_rechecks_the_installed_pair_once_per_observation() {
    use std::{io::Write, os::unix::fs::MetadataExt, time::Instant};

    let (root, record, bytes) = super::super::admission::tests::padded_fixture();
    let host = LifecycleHost::injected(&root.0).unwrap();
    let before = release_identity::payload_hashes_for_test();
    let start = Instant::now();
    // Initial route enumeration and four guarded opens, followed by the
    // terminal's independent lifecycle status. Only measure the pair boundary.
    for _ in 0..5 {
        host.require_owner_installed(&record).unwrap();
    }
    assert!(host.inspect().unwrap().installed.as_ref() == Some(&record));
    let passes = release_identity::payload_hashes_for_test() - before;
    println!(
        "installed eligibility: bytes={bytes} pair_checks={passes} elapsed_us={}",
        start.elapsed().as_micros()
    );
    assert_eq!(passes, 6);

    let transaction = root.0.join(TRANSACTIONS[4]);
    root.write(TRANSACTIONS[4], b"pending", 0o600);
    assert!(host.require_owner_installed(&record).is_err());
    fs::remove_file(transaction).unwrap();

    root.write("run/lock/sbxr.lock", b"", 0o600);
    let uid = fs::metadata(&root.0).unwrap().uid();
    let guard = crate::host::locks::HostLock::existing(&root.0, uid).unwrap();
    assert!(host.require_owner_installed(&record).is_err());
    drop(guard);
    host.require_owner_installed(&record).unwrap();

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(root.0.join(EXECUTABLE))
        .unwrap();
    file.write_all(b"changed").unwrap();
    assert!(host.require_owner_installed(&record).is_err());
}

#[test]
fn owner_eligibility_refuses_changes_between_inspection_and_final_pair_read() {
    for changed_path in [INSTALLED, EXECUTABLE] {
        let root = super::super::admission::tests::Fixture::new();
        let host = LifecycleHost::injected(&root.0).unwrap();
        let record = host.inspect().unwrap().installed.unwrap();
        let changed = root.0.join(changed_path);
        let mut changed_once = false;
        *host.fs.raw_observer.lock().unwrap() = Some(Box::new(move |path| {
            if path == EXECUTABLE && !changed_once {
                changed_once = true;
                fs::write(&changed, b"replaced during inspection").unwrap();
            }
        }));
        let (result, trace) =
            super::super::timing::capture(|| host.require_owner_installed(&record));
        assert!(result.is_err());
        let trace = String::from_utf8(trace).unwrap();
        for event in ["begin", "end"] {
            assert!(trace.contains(&format!(r#""phase":"installed-pair","event":"{event}""#)));
        }
    }
}
