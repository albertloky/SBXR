use sbxr::records::sha256_hex;
use sbxr::release_identity::{
    Architecture, RUST_ARTIFACT_SECTION, RUST_COMPILER_COMMENT, rust_artifact_metadata,
};
use sbxr_rust_package::{
    build_index, package_executable, read_input, unpack_archive, verify_package, write_exclusive,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TAG: &str = "v9.8.7";

// Inert ELF64 fixture: a real layout, never an executable build or live proof.
fn fixture(architecture: Architecture) -> Vec<u8> {
    let mut sections = vec![
        ("", vec![], 0_u32, 0_u64),
        (".text", vec![0xc3], 1, 6),
        (".rodata", b"fixture".to_vec(), 1, 2),
        (
            RUST_ARTIFACT_SECTION,
            rust_artifact_metadata(COMMIT, architecture).unwrap(),
            1,
            0,
        ),
        (".comment", [RUST_COMPILER_COMMENT, &[0]].concat(), 1, 0),
    ];
    let mut names = vec![0];
    let mut name_offsets = vec![0_u32];
    for (name, _, _, _) in sections.iter().skip(1) {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    name_offsets.push(names.len() as u32);
    names.extend_from_slice(b".shstrtab\0");
    sections.push((".shstrtab", names, 3, 0));
    let mut bytes = vec![0_u8; 128];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    let machine: u16 = if architecture == Architecture::Amd64 {
        62
    } else {
        183
    };
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400080_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    for (offset, value) in [
        (52, 64_u16),
        (54, 56),
        (56, 1),
        (58, 64),
        (60, sections.len() as u16),
        (62, (sections.len() - 1) as u16),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    let mut offsets = vec![];
    for (_, data, _, _) in &sections {
        offsets.push(bytes.len());
        bytes.extend_from_slice(data);
    }
    let end = bytes.len();
    bytes[40..48].copy_from_slice(&(end as u64).to_le_bytes());
    for (i, (_, data, kind, flags)) in sections.iter().enumerate() {
        let mut header = [0_u8; 64];
        if i != 0 {
            header[..4].copy_from_slice(&name_offsets[i].to_le_bytes());
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[8..16].copy_from_slice(&flags.to_le_bytes());
            header[16..24].copy_from_slice(&(0x400000_u64 + offsets[i] as u64).to_le_bytes());
            header[24..32].copy_from_slice(&(offsets[i] as u64).to_le_bytes());
            header[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            header[48..56].copy_from_slice(&1_u64.to_le_bytes());
        }
        bytes.extend_from_slice(&header);
    }
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(end as u64).to_le_bytes());
    bytes[104..112].copy_from_slice(&(end as u64).to_le_bytes());
    bytes[112..120].copy_from_slice(&1_u64.to_le_bytes());
    bytes
}

#[test]
fn both_archives_are_deterministic_single_member_packages() {
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        let payload = fixture(architecture);
        let archive = package_executable(&payload, TAG, COMMIT, 193, architecture).unwrap();
        assert_eq!(
            archive,
            package_executable(&payload, TAG, COMMIT, 193, architecture).unwrap()
        );
        // Independent Python stdlib decoder checks the public tar/gzip boundary.
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-c",
                r#"
import gzip, io, sys, tarfile
b = sys.stdin.buffer.read()
assert b[:3] == b'\x1f\x8b\x08' and b[3:8] == b'\0'*5
with tarfile.open(fileobj=io.BytesIO(b), mode='r:gz') as t:
    assert t.getnames() == ['sbxr']
    h = t.getmembers()[0]
    assert h.isfile() and h.mode == 0o755 and h.uid == h.gid == h.mtime == 0
    assert not h.uname and not h.gname and not h.linkname
    assert t.extractfile(h).read().endswith(b'SBXR-IDENTITY-V1')
"#,
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&archive).unwrap();
        assert!(child.wait().unwrap().success());
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rust-package-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sbxr-rust-package"))
        .args(arguments)
        .output()
        .unwrap()
}
fn populate(directory: &Path) {
    let mut installer = format!(
        "#!/bin/sh\n# SYNTHETIC BINDING FIXTURE ONLY; NEVER RUN\nexit 97\nREPOSITORY='albertloky/SBXR'\nTAG='{TAG}'\nCOMMIT='{COMMIT}'\nSEQUENCE='193'\n"
    );
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        let archive =
            package_executable(&fixture(architecture), TAG, COMMIT, 193, architecture).unwrap();
        installer.push_str(&format!(
            "{}_EXECUTABLE_SHA256='{}'\n",
            architecture.as_str().to_uppercase(),
            sha256_hex(&unpack_archive(&archive).unwrap())
        ));
        fs::write(
            directory.join(format!("sbxr-linux-{}.tar.gz", architecture.as_str())),
            archive,
        )
        .unwrap();
    }
    fs::write(directory.join("install.sh"), installer).unwrap();
}
fn index(directory: &Path) {
    let index = build_index(directory, TAG, COMMIT, 193).unwrap();
    fs::write(directory.join("release-index.json"), index).unwrap();
}

#[test]
fn cli_round_trip_preserves_exact_four_assets_and_canonical_go_index() {
    let scratch = Directory::new();
    let assets = scratch.0.join("assets");
    fs::create_dir(&assets).unwrap();
    let mut installer = format!(
        "#!/bin/sh\n# SYNTHETIC; NEVER RUN\nexit 97\nREPOSITORY='albertloky/SBXR'\nTAG='{TAG}'\nCOMMIT='{COMMIT}'\nSEQUENCE='193'\n"
    );
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        let input = scratch.0.join("input");
        fs::write(&input, fixture(architecture)).unwrap();
        let output = assets.join(format!("sbxr-linux-{}.tar.gz", architecture.as_str()));
        let args = [
            "package",
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--sequence",
            "193",
            "--architecture",
            architecture.as_str(),
            "--executable",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ];
        let result = cli(&args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let message: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(message["outcome"], "packaged-local");
        installer.push_str(&format!(
            "{}_EXECUTABLE_SHA256='{}'\n",
            architecture.as_str().to_uppercase(),
            message["executable_sha256"].as_str().unwrap()
        ));
        assert!(!cli(&args).status.success(), "must never overwrite");
    }
    fs::write(assets.join("install.sh"), installer).unwrap();
    let output = assets.join("release-index.json");
    let result = cli(&[
        "index",
        "-tag",
        TAG,
        "-commit",
        COMMIT,
        "-sequence",
        "193",
        "-directory",
        assets.to_str().unwrap(),
        "-output",
        output.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected = Command::new("/usr/bin/python3").args(["-c", r#"
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
assets = []
for name in ['install.sh', 'sbxr-linux-amd64.tar.gz', 'sbxr-linux-arm64.tar.gz']:
    b = (p / name).read_bytes()
    assets.append(dict(name=name, size=len(b), sha256=hashlib.sha256(b).hexdigest()))
expected = dict(schema=2, repository='albertloky/SBXR', tag='v9.8.7',
                commit='a'*40, sequence=193, assets=assets,
                support=dict(scope='subscription-clean-install-only', sources=[],
                             contract='sbxr-subscription-update-v1'))
assert (p / 'release-index.json').read_bytes() == json.dumps(expected, separators=(',', ':')).encode()
assert sorted(x.name for x in p.iterdir()) == sorted([x['name'] for x in assets] + ['release-index.json'])
"#, assets.to_str().unwrap()]).status().unwrap();
    assert!(expected.success());
    for architecture in ["amd64", "arm64"] {
        let result = cli(&[
            "verify-package",
            "--directory",
            assets.to_str().unwrap(),
            "--architecture",
            architecture,
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let message: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(message["outcome"], "consistent-local");
        assert_eq!(message["sequence"], 193);
    }
}

#[test]
fn package_refuses_wrong_architecture_dynamic_elf_identity_and_compiler() {
    let payload = fixture(Architecture::Amd64);
    assert!(package_executable(&payload, TAG, COMMIT, 193, Architecture::Arm64).is_err());
    assert!(package_executable(&payload, TAG, COMMIT, 0, Architecture::Amd64).is_err());
    assert!(package_executable(&payload, "v01.2.3", COMMIT, 193, Architecture::Amd64).is_err());
    assert!(package_executable(&payload, TAG, &"b".repeat(40), 193, Architecture::Amd64).is_err());
    let mut dynamic = payload.clone();
    dynamic[64..68].copy_from_slice(&3_u32.to_le_bytes());
    assert!(package_executable(&dynamic, TAG, COMMIT, 193, Architecture::Amd64).is_err());
    let mut wrong_compiler = payload.clone();
    let position = wrong_compiler
        .windows(RUST_COMPILER_COMMENT.len())
        .position(|part| part == RUST_COMPILER_COMMENT)
        .unwrap();
    wrong_compiler[position + 14] = b'9';
    assert!(package_executable(&wrong_compiler, TAG, COMMIT, 193, Architecture::Amd64).is_err());
    let archive = package_executable(&payload, TAG, COMMIT, 193, Architecture::Amd64).unwrap();
    assert!(
        package_executable(
            &unpack_archive(&archive).unwrap(),
            TAG,
            COMMIT,
            193,
            Architecture::Amd64
        )
        .is_err()
    );
}

#[test]
fn archive_decoder_refuses_extra_members_links_traversal_metadata_and_corruption() {
    let archive = package_executable(
        &fixture(Architecture::Amd64),
        TAG,
        COMMIT,
        193,
        Architecture::Amd64,
    )
    .unwrap();
    for case in [
        "extra",
        "link",
        "path",
        "mode",
        "uid",
        "mtime",
        "padding",
        "truncated",
    ] {
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-c",
                r#"
import gzip, sys
b = sys.stdin.buffer.read()
raw = bytearray(gzip.decompress(b))
case = sys.argv[1]
if case == 'padding': raw = raw[:-1] + b'X'
elif case == 'truncated': raw = raw[:700]
elif case == 'extra': raw = raw[:-1024] + raw[:512] + bytes(1024)
else:
    if case == 'path': raw[:100] = b'../sbxr'.ljust(100, b'\0')
    if case == 'mode': raw[100:108] = b'0000700\0'
    if case == 'uid': raw[108:116] = b'0000001\0'
    if case == 'mtime': raw[136:148] = b'00000000001\0'
    if case == 'link':
        raw[156] = ord('2')
        raw[157:257] = b'/tmp/foreign'.ljust(100, b'\0')
    raw[148:156] = b' '*8
    raw[148:156] = ('%06o' % sum(raw[:512])).encode() + b'\0 '
sys.stdout.buffer.write(gzip.compress(raw, mtime=0))
"#,
                case,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&archive).unwrap();
        let changed = child.wait_with_output().unwrap();
        assert!(changed.status.success());
        assert!(unpack_archive(&changed.stdout).is_err(), "{case}");
    }
    let mut corrupt = archive;
    let mut timestamped = corrupt.clone();
    timestamped[4] = 1;
    assert!(
        unpack_archive(&timestamped).is_err(),
        "non-deterministic gzip metadata"
    );
    let offset = corrupt.len() - 8;
    corrupt[offset] ^= 1;
    assert!(unpack_archive(&corrupt).is_err());
    assert!(unpack_archive(b"not gzip").is_err());
}

#[test]
fn package_and_index_refuse_extra_missing_swapped_and_changed_assets() {
    let scratch = Directory::new();
    populate(&scratch.0);
    fs::write(scratch.0.join("extra"), b"unexpected").unwrap();
    assert!(build_index(&scratch.0, TAG, COMMIT, 193).is_err());
    fs::remove_file(scratch.0.join("extra")).unwrap();
    let arm = scratch.0.join("sbxr-linux-arm64.tar.gz");
    let saved_arm = fs::read(&arm).unwrap();
    fs::remove_file(&arm).unwrap();
    assert!(build_index(&scratch.0, TAG, COMMIT, 193).is_err());
    fs::copy(scratch.0.join("sbxr-linux-amd64.tar.gz"), &arm).unwrap();
    assert!(build_index(&scratch.0, TAG, COMMIT, 193).is_err());
    fs::write(&arm, saved_arm).unwrap();
    assert!(build_index(&scratch.0, TAG, COMMIT, 194).is_err());
    index(&scratch.0);
    assert!(verify_package(&scratch.0, Architecture::Amd64).is_ok());
    let installer_path = scratch.0.join("install.sh");
    let installer = fs::read(&installer_path).unwrap();
    fs::write(
        &installer_path,
        [installer.as_slice(), b"# changed\n"].concat(),
    )
    .unwrap();
    assert!(verify_package(&scratch.0, Architecture::Amd64).is_err());
    fs::write(&installer_path, &installer).unwrap();
    fs::remove_file(scratch.0.join("release-index.json")).unwrap();
    let changed = String::from_utf8(installer)
        .unwrap()
        .replace("TAG='v9.8.7'", "TAG='v9.8.8'");
    fs::write(&installer_path, changed).unwrap();
    assert!(build_index(&scratch.0, TAG, COMMIT, 193).is_err());
}

#[test]
fn files_refuse_symlinks_fifo_oversize_and_overwrite_without_touching_targets() {
    use std::os::unix::fs::symlink;
    let scratch = Directory::new();
    let target = scratch.0.join("target");
    fs::write(&target, b"foreign").unwrap();
    let link = scratch.0.join("link");
    symlink(&target, &link).unwrap();
    assert!(read_input(&link, 100).is_err());
    assert!(write_exclusive(&link, b"overwrite").is_err());
    assert!(write_exclusive(&target, b"overwrite").is_err());
    assert!(read_input(&target, 2).is_err());
    assert!(read_input(&scratch.0, 100).is_err());
    let fifo = scratch.0.join("fifo");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(read_input(&fifo, 100).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"foreign");
}

#[test]
fn directory_checks_refuse_symlink_assets_and_symlink_root() {
    use std::os::unix::fs::symlink;
    let scratch = Directory::new();
    let assets = scratch.0.join("assets");
    fs::create_dir(&assets).unwrap();
    populate(&assets);
    let path = assets.join("install.sh");
    let target = scratch.0.join("foreign");
    fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert!(build_index(&assets, TAG, COMMIT, 193).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&target, &path).unwrap();
    let root_link = scratch.0.join("linked-assets");
    symlink(&assets, &root_link).unwrap();
    assert!(build_index(&root_link, TAG, COMMIT, 193).is_err());
}

#[test]
fn metadata_cli_and_argument_refusals_are_local_and_secret_safe() {
    let scratch = Directory::new();
    let output = scratch.0.join("metadata.json");
    let result = cli(&[
        "metadata",
        "--commit",
        COMMIT,
        "--architecture",
        "arm64",
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(result.status.success());
    assert_eq!(
        fs::read(output).unwrap(),
        rust_artifact_metadata(COMMIT, Architecture::Arm64).unwrap()
    );
    for arguments in [
        vec!["bootstrap"],
        vec![
            "metadata",
            "--commit",
            "PRIVATE-SENTINEL",
            "--architecture",
            "arm64",
            "--output",
            "unused",
        ],
        vec!["metadata", "--commit", COMMIT, "--commit", COMMIT],
        vec![
            "verify-package",
            "--directory",
            "PRIVATE-SENTINEL",
            "--architecture",
            "arm64",
            "--unknown",
            "x",
        ],
    ] {
        let result = cli(&arguments);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("PRIVATE-SENTINEL"));
        assert!(result.stdout.is_empty());
    }
}
