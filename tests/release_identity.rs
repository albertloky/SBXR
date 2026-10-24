//! Offline release wire/ELF checks. Fixtures are synthetic, never release qualification.
use sbxr::records::{self, InstalledRecord, sha256_hex};
use sbxr::release_identity::*;

const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TAG: &str = "v3.2.1";

fn assets() -> Vec<AssetProof> {
    INDEXED_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::new(name, 1, &"a".repeat(64)).unwrap())
        .collect()
}
fn index(support: Option<ReleaseSupport>) -> ReleaseIndex {
    ReleaseIndex::build(TAG, COMMIT, 193, assets(), support).unwrap()
}
fn proofs(index: &ReleaseIndex) -> Vec<AssetProof> {
    let mut proofs = index.assets().to_vec();
    proofs.push(AssetProof::for_bytes("release-index.json", index.bytes()).unwrap());
    proofs
}
fn trailer(payload: &[u8], document: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(document);
    bytes.extend_from_slice(&Sha256::digest(document));
    bytes.extend_from_slice(&(document.len() as u64).to_le_bytes());
    bytes.extend_from_slice(IDENTITY_MAGIC);
    bytes
}
fn document(payload: &[u8]) -> Vec<u8> {
    format!("{{\"schema\":1,\"repository\":\"albertloky/SBXR\",\"tag\":\"{TAG}\",\"commit\":\"{COMMIT}\",\"sequence\":193,\"architecture\":\"amd64\",\"payload_sha256\":\"{}\"}}", sha256_hex(payload)).into_bytes()
}

#[test]
fn stamp_and_index_match_preserved_go_bytes() {
    let payload = b"synthetic offline executable\n";
    let expected = include_bytes!("testdata/release_identity/go-stamped.bin");
    assert_eq!(
        stamp_executable(payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap(),
        expected
    );
    let parsed = read_executable_identity(expected).unwrap();
    assert_eq!(parsed.payload(), payload);
    assert_eq!(parsed.tag(), TAG);
    assert_eq!(parsed.commit(), COMMIT);
    assert_eq!(parsed.repository(), REPOSITORY);
    assert_eq!(parsed.sequence(), 193);
    assert_eq!(parsed.architecture(), Architecture::Amd64);
    assert_eq!(parsed.payload_sha256(), sha256_hex(payload));
    assert_eq!(
        index(None).bytes(),
        include_bytes!("testdata/release_identity/go-index-v1.json")
    );
    let support = ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![]).unwrap();
    assert_eq!(
        index(Some(support)).bytes(),
        include_bytes!("testdata/release_identity/go-index-v2.json")
    );
}

#[test]
fn trailer_binds_raw_document_payload_and_exact_length() {
    let payload = b"synthetic";
    let stamped = stamp_executable(payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap();
    for position in [
        0,
        payload.len(),
        stamped.len() - IDENTITY_MAGIC.len() - 9,
        stamped.len() - 1,
    ] {
        let mut changed = stamped.clone();
        changed[position] ^= 1;
        assert!(
            read_executable_identity(&changed).is_err(),
            "mutation {position}"
        );
    }
    for count in 0..stamped.len() {
        assert!(read_executable_identity(&stamped[..count]).is_err());
    }
    let mut trailing = stamped.clone();
    trailing.push(0);
    assert!(read_executable_identity(&trailing).is_err());
    assert!(stamp_executable(&stamped, TAG, COMMIT, 193, Architecture::Amd64).is_err());
    assert!(read_executable_identity(&trailer(&stamped, &document(&stamped))).is_err());
    let spaced = format!(" \n{}\n", String::from_utf8(document(payload)).unwrap());
    assert!(read_executable_identity(&trailer(payload, spaced.as_bytes())).is_ok());
}

#[test]
fn trailer_refuses_unknown_duplicate_missing_positional_and_conflicting_identity() {
    let payload = b"fixture";
    let original = String::from_utf8(document(payload)).unwrap();
    let cases = [
        original.replace("\"schema\":1", "\"schema\":1,\"secret\":\"private\""),
        original.replace("\"schema\":1", "\"schema\":1,\"sche\\u006da\":1"),
        original.replace("\"schema\":1,", ""),
        original.replace("\"sequence\":193", "\"sequence\":0"),
        original.replace("\"architecture\":\"amd64\"", "\"architecture\":\"x86_64\""),
        original.replace(TAG, "v03.2.1"), original.replace(TAG, "v3.2.1-rc.1"),
        original.replace(COMMIT, &COMMIT.to_uppercase()),
        original.replace(REPOSITORY, "other/SBXR"),
        original.replace(&sha256_hex(payload), &"0".repeat(64)),
        format!("{original} {{}}"), "null".into(), "[]".into(),
        "[1,\"albertloky/SBXR\",\"v3.2.1\",\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",193,\"amd64\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]".into(),
    ];
    for case in cases {
        assert!(
            read_executable_identity(&trailer(payload, case.as_bytes())).is_err(),
            "{case}"
        );
    }
    for (tag, commit, seq) in [
        ("v3.02.1", COMMIT, 193),
        (TAG, "bad", 193),
        (TAG, COMMIT, 0),
    ] {
        assert!(stamp_executable(payload, tag, commit, seq, Architecture::Arm64).is_err());
    }
    assert!(stamp_executable(b"", TAG, COMMIT, 193, Architecture::Amd64).is_err());
    let error = read_executable_identity(b"private secret").err().unwrap();
    assert!(!format!("{error:?} {error}").contains("private"));
}

#[test]
fn installed_pair_binds_every_release_field_and_full_executable_digest() {
    let bytes = stamp_executable(b"fixture", TAG, COMMIT, 193, Architecture::Amd64).unwrap();
    let release = index(None).identity();
    let record_identity =
        records::ReleaseIdentity::new(release.tag(), release.commit(), release.index_sha256())
            .unwrap();
    let record = InstalledRecord::new(record_identity, 193, "amd64", &sha256_hex(&bytes)).unwrap();
    assert!(verify_installed_pair(&record, &bytes).is_ok());
    for (tag, commit, sequence, arch, digest) in [
        ("v3.2.2", COMMIT, 193, "amd64", sha256_hex(&bytes)),
        (
            TAG,
            "cccccccccccccccccccccccccccccccccccccccc",
            193,
            "amd64",
            sha256_hex(&bytes),
        ),
        (TAG, COMMIT, 194, "amd64", sha256_hex(&bytes)),
        (TAG, COMMIT, 193, "arm64", sha256_hex(&bytes)),
        (TAG, COMMIT, 193, "amd64", "0".repeat(64)),
    ] {
        let id = records::ReleaseIdentity::new(tag, commit, release.index_sha256()).unwrap();
        let changed = InstalledRecord::new(id, sequence, arch, &digest).unwrap();
        assert!(verify_installed_pair(&changed, &bytes).is_err());
    }
    // Syntax/digest pairing cannot establish an attestation or link the index digest to these bytes.
    assert!(inspect_linux_artifact(&bytes, Architecture::Amd64).is_err());
}

#[test]
fn index_verifies_all_four_exact_proofs_without_reserializing_input() {
    let release = index(None);
    assert!(
        verify_release_index(REPOSITORY, TAG, COMMIT, release.bytes(), &proofs(&release)).is_ok()
    );
    let mut reordered = proofs(&release);
    reordered.reverse();
    assert!(
        release
            .verify_asset_proofs(&release.identity(), &reordered)
            .is_ok()
    );
    assert_eq!(release.sequence(), 193);
    assert!(release.support().is_none());
    assert_eq!(release.canonical_bytes().unwrap(), release.bytes());
    assert_eq!(release.assets()[0].name(), "install.sh");
    assert_eq!(release.assets()[0].size(), 1);
    assert_eq!(release.assets()[0].sha256(), "a".repeat(64));
    let mut spaced = release.bytes().to_vec();
    spaced.push(b'\n');
    let parsed = ReleaseIndex::decode(&spaced).unwrap();
    assert_ne!(parsed.identity(), release.identity());
    assert!(
        parsed
            .verify_asset_proofs(&parsed.identity(), &proofs(&parsed))
            .is_ok()
    );
    assert!(
        parsed
            .verify_asset_proofs(&release.identity(), &proofs(&parsed))
            .is_err()
    );
    for n in 0..4 {
        let mut bad = proofs(&release);
        bad.remove(n);
        assert!(
            release
                .verify_asset_proofs(&release.identity(), &bad)
                .is_err()
        );
    }
    let mut duplicate = proofs(&release);
    duplicate[3] = duplicate[0].clone();
    assert!(
        release
            .verify_asset_proofs(&release.identity(), &duplicate)
            .is_err()
    );
    let mut wrong = proofs(&release);
    wrong[0] = AssetProof::new("install.sh", 2, &"a".repeat(64)).unwrap();
    assert!(
        release
            .verify_asset_proofs(&release.identity(), &wrong)
            .is_err()
    );
    let mut wrong = proofs(&release);
    wrong[3] = AssetProof::new(
        "release-index.json",
        release.bytes().len() as u64,
        &"0".repeat(64),
    )
    .unwrap();
    assert!(
        release
            .verify_asset_proofs(&release.identity(), &wrong)
            .is_err()
    );
    for (repository, tag, commit) in [
        ("other/SBXR", TAG, COMMIT),
        (REPOSITORY, "v3.2.2", COMMIT),
        (REPOSITORY, TAG, "cccccccccccccccccccccccccccccccccccccccc"),
    ] {
        assert!(
            verify_release_index(repository, tag, commit, release.bytes(), &proofs(&release))
                .is_err()
        );
    }
}

#[test]
fn index_rejects_ambiguous_fields_bad_assets_bounds_and_schema() {
    let original = String::from_utf8(index(None).bytes().to_vec()).unwrap();
    for case in [
        original.replace("\"schema\":1", "\"schema\":1,\"Schema\":1"),
        original.replace("\"schema\":1", "\"schema\":1,\"sche\\u006da\":1"),
        original.replace("\"schema\":1", "\"schema\":2"),
        original.replace("\"schema\":1", "\"schema\":3"),
        original.replace("\"schema\":1,", ""),
        original.replace("\"sequence\":193", "\"sequence\":0"),
        original.replace("\"sequence\":193", "\"sequence\":18446744073709551616"),
        original.replace("\"sequence\":193", "\"sequence\":193.0"),
        original.replace("\"size\":1", "\"size\":0"),
        original.replace("\"size\":1", "\"size\":1,\"si\\u007ae\":1"),
        original.replace("\"size\":1", "\"size\":-1"),
        original.replace("\"name\":\"install.sh\"", "\"name\":\"release-index.json\""),
        original.replace("sbxr-linux-arm64.tar.gz", "sbxr-linux-amd64.tar.gz"),
        original.replace(TAG, "v3.2.01"),
        original.replace("\"assets\":[", "\"support\":null,\"assets\":["),
        format!("{original}{{}}"),
        "[]".into(),
        "null".into(),
    ] {
        assert!(ReleaseIndex::decode(case.as_bytes()).is_err(), "{case}");
    }
    let mut swapped = assets();
    swapped.swap(0, 1);
    assert!(ReleaseIndex::build(TAG, COMMIT, 193, swapped, None).is_err());
    for (name, size) in [
        ("install.sh", MAX_INDEX_BYTES as u64 + 1),
        ("release-index.json", MAX_INDEX_BYTES as u64 + 1),
        ("sbxr-linux-amd64.tar.gz", MAX_EXECUTABLE_BYTES as u64 + 1),
        ("unknown", 1),
    ] {
        assert!(AssetProof::new(name, size, &"a".repeat(64)).is_err());
    }
    assert!(AssetProof::new("install.sh", 1, &"A".repeat(64)).is_err());
    assert!(ReleaseIndex::decode(&vec![b' '; MAX_INDEX_BYTES + 1]).is_err());
}

#[test]
fn support_retains_historical_scopes_and_exact_uppercase_source_identity() {
    let source = ReleaseIdentity::new("v3.2.0", COMMIT, &"c".repeat(64)).unwrap();
    for scope in [
        SupportScope::FirstCleanInstall,
        SupportScope::CleanInstallRepair,
        SupportScope::CleanInstallOnly,
    ] {
        assert!(ReleaseSupport::new(scope, vec![source.clone()]).is_err());
        let release = index(Some(ReleaseSupport::new(scope, vec![]).unwrap()));
        let support = release.support().unwrap();
        assert_eq!(support.scope(), scope);
        assert!(support.sources().is_empty());
        assert_eq!(support.contract(), SUBSCRIPTION_UPDATE_CONTRACT);
        assert!(ReleaseIndex::decode(release.bytes()).is_ok());
    }
    assert!(ReleaseSupport::new(SupportScope::RecurringUpgrade, vec![]).is_err());
    assert!(
        ReleaseSupport::new(
            SupportScope::RecurringUpgrade,
            vec![source.clone(), source.clone()]
        )
        .is_err()
    );
    let release = index(Some(
        ReleaseSupport::new(SupportScope::RecurringUpgrade, vec![source.clone()]).unwrap(),
    ));
    assert_eq!(release.support().unwrap().sources(), vec![source]);
    let original = String::from_utf8(release.bytes().to_vec()).unwrap();
    assert!(original.contains("\"Repository\":\"albertloky/SBXR\""));
    for case in [
        original.replace("\"Repository\"", "\"repository\""),
        original.replace("\"sources\":[{", "\"sources\":[{\"unknown\":0,"),
        original.replace(
            "\"sources\":[{",
            "\"sources\":[{\"Repository\":\"albertloky/SBXR\",",
        ),
        original.replace(SUBSCRIPTION_UPDATE_CONTRACT, "unknown"),
        original.replace("\"schema\":2", "\"schema\":1"),
    ] {
        assert!(ReleaseIndex::decode(case.as_bytes()).is_err());
    }
    let clean = String::from_utf8(
        index(Some(
            ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![]).unwrap(),
        ))
        .bytes()
        .to_vec(),
    )
    .unwrap();
    for case in [
        clean.replace("\"sources\":[]", "\"sources\":null"),
        clean.replace("\"sources\":[],", ""),
        clean.replace("\"scope\":", "\"unknown\":0,\"scope\":"),
        clean.replace(
            "\"support\":{",
            "\"support\":{\"scope\":\"subscription-clean-install-only\",",
        ),
    ] {
        assert!(ReleaseIndex::decode(case.as_bytes()).is_err());
    }
}

// Tiny ELF64 files with a real header/table layout and inert text. They are never executed.
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
fn rust_sections(architecture: Architecture) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            RUST_ARTIFACT_SECTION,
            rust_artifact_metadata(COMMIT, architecture).unwrap(),
        ),
        (
            ".comment",
            b"\0rustc version 1.90.0 (1159e78c4 2025-09-14)\0".to_vec(),
        ),
    ]
}
fn varstring(bytes: &[u8], out: &mut Vec<u8>) {
    let mut n = bytes.len();
    while n >= 128 {
        out.push((n as u8) | 128);
        n >>= 7;
    }
    out.push(n as u8);
    out.extend_from_slice(bytes);
}
fn go_sections(architecture: Architecture, extra: &str) -> Vec<(&'static str, Vec<u8>)> {
    let mut info = b"\xff Go buildinf:\x08\x02".to_vec();
    info.resize(32, 0);
    varstring(b"go1.26.6", &mut info);
    let mut module = vec![
        0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18,
        0xe6,
    ];
    module.extend_from_slice(format!("path\tgithub.com/albertloky/SBXR/cmd/sbxr\nmod\tgithub.com/albertloky/SBXR\t(devel)\t\nbuild\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=0\nbuild\tGOARCH={}\nbuild\tGOOS=linux\n{extra}", architecture.as_str()).as_bytes());
    module.extend_from_slice(&[
        0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8,
        0xf2,
    ]);
    varstring(&module, &mut info);
    vec![(".gopclntab", vec![1]), (".go.buildinfo", info)]
}

#[test]
fn rust_artifact_requires_explicit_pinned_metadata_static_elf_and_identity_commit() {
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        let payload = elf(architecture, &rust_sections(architecture));
        let executable = stamp_executable(&payload, TAG, COMMIT, 193, architecture).unwrap();
        assert_eq!(
            inspect_linux_artifact(&executable, architecture)
                .unwrap()
                .kind(),
            ArtifactKind::Rust
        );
        assert!(
            inspect_linux_artifact(
                &executable,
                if architecture == Architecture::Amd64 {
                    Architecture::Arm64
                } else {
                    Architecture::Amd64
                }
            )
            .is_err()
        );
        let wrong_commit =
            stamp_executable(&payload, TAG, &"c".repeat(40), 193, architecture).unwrap();
        assert!(inspect_linux_artifact(&wrong_commit, architecture).is_err());
    }
    let mut sections = rust_sections(Architecture::Amd64);
    sections.pop();
    assert!(
        inspect_linux_artifact(&elf(Architecture::Amd64, &sections), Architecture::Amd64).is_err()
    );
    let payload = elf(Architecture::Amd64, &rust_sections(Architecture::Amd64));
    assert!(
        inspect_linux_artifact(&payload, Architecture::Amd64).is_err(),
        "inspection requires digest-bound trailer"
    );
    for replacement in [
        "rustc 1.91.0",
        "aarch64-unknown-linux-musl",
        "unknown",
        "debug",
    ] {
        let mut sections = rust_sections(Architecture::Amd64);
        let source = String::from_utf8(sections[0].1.clone()).unwrap();
        sections[0].1 = source
            .replace(
                if replacement.starts_with("rustc") {
                    "rustc 1.90.0"
                } else if replacement.contains("musl") {
                    "x86_64-unknown-linux-musl"
                } else if replacement == "debug" {
                    "release"
                } else {
                    "sbxr-rust-artifact-v1"
                },
                replacement,
            )
            .into_bytes();
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
}

#[test]
fn historical_go_proof_remains_required_and_conflicting_languages_refuse() {
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        let payload = elf(architecture, &go_sections(architecture, ""));
        let executable = stamp_executable(&payload, TAG, COMMIT, 193, architecture).unwrap();
        assert_eq!(
            inspect_linux_artifact(&executable, architecture)
                .unwrap()
                .kind(),
            ArtifactKind::HistoricalGo
        );
    }
    for extra in [
        "build\tGOOS=linux\n",
        "build\t\"GOOS\"=linux\n",
        "build\t\"GO\\x4fS\"=linux\n",
        "build\tunknown=x\nbuild\tunknown=y\n",
        "=>\tdep\tv1.0.0\tsum\n=>\tdep\tv1.0.0\tsum\n",
    ] {
        let payload = elf(
            Architecture::Amd64,
            &go_sections(Architecture::Amd64, extra),
        );
        assert!(
            inspect_linux_artifact(
                &stamp_executable(&payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap(),
                Architecture::Amd64
            )
            .is_err()
        );
    }
    let mut both = go_sections(Architecture::Amd64, "");
    both.extend(rust_sections(Architecture::Amd64));
    assert!(
        inspect_linux_artifact(
            &stamp_executable(
                &elf(Architecture::Amd64, &both),
                TAG,
                COMMIT,
                193,
                Architecture::Amd64
            )
            .unwrap(),
            Architecture::Amd64
        )
        .is_err()
    );
    for transform in [0, 1, 2, 3, 4] {
        let mut sections = go_sections(Architecture::Amd64, "");
        match transform {
            0 => {
                sections.remove(0);
            }
            1 => {
                sections[1].1[34] = b'X';
            }
            2 => {
                let copy = sections[1].clone();
                sections.push(copy);
            }
            3 => {
                let pos = sections[1]
                    .1
                    .windows(13)
                    .position(|b| b == b"CGO_ENABLED=0")
                    .unwrap();
                sections[1].1[pos + 12] = b'1';
            }
            _ => {
                let pos = sections[1]
                    .1
                    .windows(10)
                    .position(|b| b == b"GOOS=linux")
                    .unwrap();
                sections[1].1[pos + 5] = b'x';
            }
        }
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
}

#[test]
fn malformed_dynamic_nonexecuting_or_untyped_elf_is_never_admitted() {
    for mutation in 0..10 {
        let mut payload = elf(Architecture::Amd64, &rust_sections(Architecture::Amd64));
        match mutation {
            0 => payload[4] = 1,
            1 => payload[5] = 2,
            2 => payload[16] = 1,
            3 => payload[18] = 3,
            4 => payload[64] = 3,
            5 => payload[64] = 2,
            6 => payload[68] = 4,
            7 => payload[24..32].fill(0),
            8 => payload[40..48].fill(255),
            _ => payload.truncate(100),
        }
        let executable = stamp_executable(&payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap();
        assert!(
            inspect_linux_artifact(&executable, Architecture::Amd64).is_err(),
            "mutation {mutation}"
        );
    }
    for sections in [
        vec![],
        vec![(".comment", b"rustc version 1.90.0\0".to_vec())],
        vec![(".dynamic", vec![])],
        vec![(".dynsym", vec![])],
    ] {
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
}

#[test]
fn release_tags_and_sequences_keep_go_bounds_including_major_zero() {
    for tag in ["v0.0.0", "v0.1.0", "v99999999999999999999999.1.0"] {
        let index = ReleaseIndex::build(tag, COMMIT, u64::MAX, assets(), None).unwrap();
        assert_eq!(index.identity().tag(), tag);
        assert_eq!(index.sequence(), u64::MAX);
        let stamped =
            stamp_executable(b"synthetic", tag, COMMIT, u64::MAX, Architecture::Arm64).unwrap();
        assert_eq!(read_executable_identity(&stamped).unwrap().tag(), tag);
        let source = ReleaseIdentity::new(tag, COMMIT, &"c".repeat(64)).unwrap();
        let support = ReleaseSupport::new(SupportScope::RecurringUpgrade, vec![source]).unwrap();
        assert!(ReleaseIndex::build(TAG, COMMIT, 1, assets(), Some(support)).is_ok());
    }
    for tag in [
        "v00.1.0",
        "v1.00.0",
        "v1.1.00",
        "v1.0",
        "v1.0.0+metadata",
        "v1.0.0-rc.1",
    ] {
        assert!(ReleaseIndex::build(tag, COMMIT, 1, assets(), None).is_err());
    }
    assert!(
        serde_json::from_str::<AssetProof>(r#"{"name":"install.sh","size":0,"sha256":"x"}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<ReleaseSupport>(r#"{"scope":"recurring-subscription-upgrade","sources":[],"contract":"sbxr-subscription-update-v1"}"#).is_err());
}

#[test]
fn rust_build_statement_rejects_unknown_duplicate_positional_and_conflicting_fields() {
    let original =
        String::from_utf8(rust_artifact_metadata(COMMIT, Architecture::Amd64).unwrap()).unwrap();
    for statement in [
        original.replace("{", "{\"unknown\":1,"),
        original.replace("{", "{\"package\":\"sbxr\","),
        original.replace("{", "{\"pack\\u0061ge\":\"sbxr\","),
        original.replace(&format!(",\"commit\":\"{COMMIT}\""), ""),
        "null".into(),
        "[]".into(),
        format!("{original}{{}}"),
    ] {
        let mut sections = rust_sections(Architecture::Amd64);
        sections[0].1 = statement.into_bytes();
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
    for comment in [
        b"rustc version 1.90.0 (wrong compiler commit)\0".as_slice(),
        b"rustc version 1.90.0\0",
        b"rustc version 1.90.0 (1159e78c4 2025-09-14)\0rustc version 1.91.0\0",
    ] {
        let mut sections = rust_sections(Architecture::Amd64);
        sections[1].1 = comment.to_vec();
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
}

#[test]
fn original_go_verifier_fixture_results_match_rust_and_bind_index_sequence() {
    for (architecture, valid, wrong_toolchain, duplicate) in [
        (
            Architecture::Amd64,
            include_bytes!("testdata/release_identity/go-amd64-valid.bin").as_slice(),
            include_bytes!("testdata/release_identity/go-amd64-wrong-toolchain.bin").as_slice(),
            include_bytes!("testdata/release_identity/go-amd64-duplicate-setting.bin").as_slice(),
        ),
        (
            Architecture::Arm64,
            include_bytes!("testdata/release_identity/go-arm64-valid.bin").as_slice(),
            include_bytes!("testdata/release_identity/go-arm64-wrong-toolchain.bin").as_slice(),
            include_bytes!("testdata/release_identity/go-arm64-duplicate-setting.bin").as_slice(),
        ),
    ] {
        let inspected = inspect_release_executable(&index(None), valid, architecture).unwrap();
        assert_eq!(inspected.kind(), ArtifactKind::HistoricalGo);
        assert_eq!(inspected.architecture(), architecture);
        for bytes in [wrong_toolchain, duplicate] {
            assert!(
                read_executable_identity(bytes).is_ok(),
                "fixture trailer still binds exact bytes"
            );
            assert!(inspect_linux_artifact(bytes, architecture).is_err());
        }
        for (tag, commit, sequence) in [
            ("v3.2.2", COMMIT, 193),
            (TAG, "cccccccccccccccccccccccccccccccccccccccc", 193),
            (TAG, COMMIT, 194),
        ] {
            let conflicting = ReleaseIndex::build(tag, commit, sequence, assets(), None).unwrap();
            assert!(inspect_release_executable(&conflicting, valid, architecture).is_err());
        }
    }
}

#[test]
fn malformed_lengths_and_positional_nested_objects_are_refused() {
    let mut executable =
        stamp_executable(b"fixture", TAG, COMMIT, 193, Architecture::Amd64).unwrap();
    let offset = executable.len() - IDENTITY_MAGIC.len() - 8;
    for length in [0_u64, 4097, u64::MAX] {
        executable[offset..offset + 8].copy_from_slice(&length.to_le_bytes());
        assert!(read_executable_identity(&executable).is_err());
    }
    let original = String::from_utf8(index(None).bytes().to_vec()).unwrap();
    let positional = original.replace(
        &format!(
            "{{\"name\":\"install.sh\",\"size\":1,\"sha256\":\"{}\"}}",
            "a".repeat(64)
        ),
        &format!("[\"install.sh\",1,\"{}\"]", "a".repeat(64)),
    );
    assert!(ReleaseIndex::decode(positional.as_bytes()).is_err());
    let error = read_executable_identity(b"private secret").err().unwrap();
    assert_eq!(error, ReleaseError);
}

#[test]
fn dynamic_dependencies_refuse_but_static_pie_has_no_language_waiver() {
    for (tag, accepted) in [
        (0_u64, true),
        (30, true),
        (1, false),
        (0x7fff_fffd, false),
        (0x7fff_ffff, false),
        (0x6fff_fefb, false),
        (0x6fff_fefc, false),
    ] {
        let mut dynamic = tag.to_le_bytes().to_vec();
        dynamic.extend_from_slice(&0_u64.to_le_bytes());
        if tag != 0 {
            dynamic.extend_from_slice(&[0; 16]);
        }
        let mut sections = rust_sections(Architecture::Amd64);
        sections.push((".dynamic", dynamic));
        let mut payload = elf(Architecture::Amd64, &sections);
        let table = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
        payload[table + 5 * 64 + 4..table + 5 * 64 + 8].copy_from_slice(&6_u32.to_le_bytes());
        payload[16..18].copy_from_slice(&3_u16.to_le_bytes());
        let executable = stamp_executable(&payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap();
        assert_eq!(
            inspect_linux_artifact(&executable, Architecture::Amd64).is_ok(),
            accepted,
            "dynamic tag {tag}"
        );
    }
    let mut payload = elf(Architecture::Amd64, &rust_sections(Architecture::Amd64));
    let table = u64::from_le_bytes(payload[40..48].try_into().unwrap()) as usize;
    payload[table + 64 + 24..table + 64 + 32].copy_from_slice(&160_u64.to_le_bytes());
    let executable = stamp_executable(&payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap();
    assert!(
        inspect_linux_artifact(&executable, Architecture::Amd64).is_err(),
        "section file bytes must match its executable load mapping"
    );
}

#[test]
fn original_go_verifier_and_rust_refuse_orphan_module_replacements() {
    for (architecture, executable) in [
        (
            Architecture::Amd64,
            include_bytes!("testdata/release_identity/go-amd64-orphan-replacement.bin").as_slice(),
        ),
        (
            Architecture::Arm64,
            include_bytes!("testdata/release_identity/go-arm64-orphan-replacement.bin").as_slice(),
        ),
    ] {
        assert!(read_executable_identity(executable).is_ok());
        assert!(inspect_linux_artifact(executable, architecture).is_err());
    }
}

#[test]
fn retained_rust_statement_requires_exact_canonical_bytes_not_just_equal_json() {
    for transform in [0, 1] {
        let mut sections = rust_sections(Architecture::Amd64);
        let bytes = &mut sections[0].1;
        if transform == 0 {
            bytes.insert(0, b' ');
        } else {
            let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            *bytes = serde_json::to_vec_pretty(&value).unwrap();
        }
        let executable = stamp_executable(
            &elf(Architecture::Amd64, &sections),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64,
        )
        .unwrap();
        assert!(inspect_linux_artifact(&executable, Architecture::Amd64).is_err());
    }
}
