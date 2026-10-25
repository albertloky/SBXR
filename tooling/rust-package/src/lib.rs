//! Offline packaging: supplied bytes are never executed or authenticated.
mod archive;
mod bootstrap;
pub use bootstrap::bootstrap;
mod files;
pub use archive::{package_executable, unpack_archive};
pub use files::{read_input, write_exclusive, write_script_exclusive};
use sbxr::records::sha256_hex;
use sbxr::release_identity::{
    Architecture, ArtifactKind, AssetProof, INDEXED_ASSET_NAMES, RELEASE_ASSET_NAMES, ReleaseIndex,
    ReleaseSupport, SupportScope, inspect_release_executable,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageError(pub &'static str);
impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rust-package/{} refused", self.0)
    }
}
impl std::error::Error for PackageError {}
pub type Result<T> = std::result::Result<T, PackageError>;

/// Current schema-2 clean-install-only index, with explicit empty sources.
pub fn build_index(directory: &Path, tag: &str, commit: &str, sequence: u64) -> Result<Vec<u8>> {
    let bodies = files::asset_files(directory, &INDEXED_ASSET_NAMES)?;
    let proofs = INDEXED_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::for_bytes(name, &bodies[*name]))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| PackageError("asset-proof"))?;
    let support = ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![])
        .map_err(|_| PackageError("support"))?;
    let index = ReleaseIndex::build(tag, commit, sequence, proofs, Some(support))
        .map_err(|_| PackageError("index"))?;
    for architecture in [Architecture::Amd64, Architecture::Arm64] {
        check_architecture(&bodies, &index, architecture, false)?;
    }
    Ok(index.bytes().to_vec())
}
fn check_architecture(
    bodies: &BTreeMap<String, Vec<u8>>,
    index: &ReleaseIndex,
    architecture: Architecture,
    historical: bool,
) -> Result<()> {
    let executable =
        unpack_archive(&bodies[&format!("sbxr-linux-{}.tar.gz", architecture.as_str())])?;
    let inspected = inspect_release_executable(index, &executable, architecture)
        .map_err(|_| PackageError("executable"))?;
    if !historical && inspected.kind() != ArtifactKind::Rust {
        return Err(PackageError("rust-executable"));
    }
    let mut hashes = Vec::new();
    for arch in [Architecture::Amd64, Architecture::Arm64] {
        let executable = unpack_archive(&bodies[&format!("sbxr-linux-{}.tar.gz", arch.as_str())])?;
        if inspect_release_executable(index, &executable, arch)
            .map_err(|_| PackageError("executable"))?
            .kind()
            != inspected.kind()
        {
            return Err(PackageError("rust-executable"));
        }
        hashes.push(sha256_hex(&executable));
    }
    if inspected.kind() == ArtifactKind::HistoricalGo {
        // Historical Go proof stays strict in inspect_release_executable. Its
        // original bootstrap may predate this template; retain its exact pin
        // contract, never use this route for mixed or Rust artifacts.
        let script =
            std::str::from_utf8(&bodies["install.sh"]).map_err(|_| PackageError("bootstrap"))?;
        for line in [
            format!("REPOSITORY='{}'", sbxr::release_identity::REPOSITORY),
            format!("TAG='{}'", index.identity().tag()),
            format!("COMMIT='{}'", index.identity().commit()),
            format!("SEQUENCE='{}'", index.sequence()),
            format!("AMD64_EXECUTABLE_SHA256='{}'", hashes[0]),
            format!("ARM64_EXECUTABLE_SHA256='{}'", hashes[1]),
        ] {
            if script.lines().filter(|s| *s == line).count() != 1 {
                return Err(PackageError("bootstrap-binding"));
            }
        }
        return Ok(());
    }
    let expected = bootstrap(
        index.identity().tag(),
        index.identity().commit(),
        index.sequence(),
        &hashes[0],
        &hashes[1],
    )?;
    if bodies["install.sh"] != expected {
        return Err(PackageError("bootstrap-binding"));
    }
    Ok(())
}
/// Structural agreement only; caller still needs authenticated asset proofs.
pub fn verify_package(directory: &Path, architecture: Architecture) -> Result<ReleaseIndex> {
    let bodies = files::asset_files(directory, &RELEASE_ASSET_NAMES)?;
    let index =
        ReleaseIndex::decode(&bodies["release-index.json"]).map_err(|_| PackageError("index"))?;
    let proofs = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::for_bytes(name, &bodies[*name]))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| PackageError("asset-proof"))?;
    index
        .verify_asset_proofs(&index.identity(), &proofs)
        .map_err(|_| PackageError("asset-proof"))?;
    check_architecture(&bodies, &index, architecture, true)?;
    Ok(index)
}
