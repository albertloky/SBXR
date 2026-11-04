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
