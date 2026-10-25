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
    ReleaseIdentity::new(tag, commit, amd64).map_err(|_| PackageError("bootstrap-identity"))?;
    ReleaseIdentity::new(tag, commit, arm64).map_err(|_| PackageError("bootstrap-identity"))?;
    if sequence == 0 {
        return Err(PackageError("sequence"));
    }
    let sequence = sequence.to_string();
    let tunnel = sha256_hex(tunnel_unit().as_bytes());
    let mut body = TEMPLATE.to_owned();
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
