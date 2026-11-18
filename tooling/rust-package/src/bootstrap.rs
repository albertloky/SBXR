//! Self-contained installer ported byte-for-byte from the preserved Go template.
//! No Go process participates in generation or installation. Full asset digests
//! remain the bootstrap authority; structural inspection is performed before
//! these digests can be bound by index/qualification/provenance.
use crate::{PackageError, Result};
use sbxr::{
    records::sha256_hex,
    release_identity::{REPOSITORY, ReleaseIdentity},
    server_configuration::tunnel_unit,
};
const TEMPLATE: &str = include_str!("../templates/install.sh.tmpl");
/// Root is deliberately fixed. There is no fixture-root or bypass CLI argument.
pub fn bootstrap(
    tag: &str,
    commit: &str,
    sequence: u64,
    amd64: &str,
    arm64: &str,
) -> Result<Vec<u8>> {
    render(
        TEMPLATE,
        tunnel_unit().as_bytes(),
        tag,
        commit,
        sequence,
        amd64,
        arm64,
    )
}

// Replay reads these immutable inputs as data. The renderer stays on the
// reviewed dispatch revision; no candidate program or installer runs here.
pub(super) fn replay(
    tag: &str,
    commit: &str,
    sequence: u64,
    amd64: &str,
    arm64: &str,
) -> Result<Vec<u8>> {
    // The caller has matched commit to the validated release-index identity.
    if git_object("-t", commit)? != b"commit\n" {
        return Err(PackageError("candidate-source"));
    }
    let template = source_blob(commit, "tooling/rust-package/templates/install.sh.tmpl")?;
    let unit = source_blob(commit, "src/records/tunnel-authority.service")?;
    render(
        std::str::from_utf8(&template).map_err(|_| PackageError("candidate-source"))?,
        &unit,
        tag,
        commit,
        sequence,
        amd64,
        arm64,
    )
}

fn git_object(operation: &str, object: &str) -> Result<Vec<u8>> {
    let result = std::process::Command::new("git")
        .args(["--no-replace-objects", "cat-file", operation, object])
        .env("GIT_NO_LAZY_FETCH", "1")
        .output()
        .map_err(|_| PackageError("candidate-source"))?;
    if !result.status.success() {
        return Err(PackageError("candidate-source"));
    }
    Ok(result.stdout)
}

fn source_blob(commit: &str, path: &str) -> Result<Vec<u8>> {
    let object = format!("{commit}:{path}");
    let size = git_object("-s", &object)?;
    let size = std::str::from_utf8(&size)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|size| (1..=sbxr::release_identity::MAX_INDEX_BYTES).contains(size))
        .ok_or(PackageError("candidate-source"))?;
    let bytes = git_object("blob", &object)?;
    if bytes.len() != size {
        return Err(PackageError("candidate-source"));
    }
    Ok(bytes)
}

fn render(
    template: &str,
    unit: &[u8],
    tag: &str,
    commit: &str,
    sequence: u64,
    amd64: &str,
    arm64: &str,
) -> Result<Vec<u8>> {
    ReleaseIdentity::new(tag, commit, amd64).map_err(|_| PackageError("bootstrap-identity"))?;
    ReleaseIdentity::new(tag, commit, arm64).map_err(|_| PackageError("bootstrap-identity"))?;
    if sequence == 0 {
        return Err(PackageError("sequence"));
    }
    let sequence = sequence.to_string();
    let tunnel = sha256_hex(unit);
    let mut body = template.to_owned();
    for (name, value) in [
        ("Repository", REPOSITORY),
        ("Tag", tag),
        ("Commit", commit),
        ("Version", &tag[1..]),
        ("Sequence", &sequence),
        ("Root", ""),
        ("AMD64ExecutableSHA256", amd64),
        ("ARM64ExecutableSHA256", arm64),
        ("TunnelUnitSHA256", &tunnel),
    ] {
        let token = format!("{{{{.{name}}}}}");
        if !body.contains(&token) {
            return Err(PackageError("bootstrap-template"));
        }
        body = body.replace(&token, value);
    }
    if body.contains("{{.") {
        return Err(PackageError("bootstrap-template"));
    }
    Ok(body.into_bytes())
}
