//! Exact-tag native release acquisition, authentication and installed-byte binding.
//! No network transport, extraction, update/migration or production authorization.
mod acceptance;
use crate::{
    artifact_trust::{
        self as trust, AcquisitionRequest, AcquisitionTransport, ExpectedRelease, SelectionBudget,
        TrustError, VerifiedNativeReleaseClaims,
    },
    records::InstalledRecord,
    release_identity::{
        self as identity, Architecture, AssetProof, MAX_EXECUTABLE_BYTES, MAX_INDEX_BYTES,
        RELEASE_ASSET_NAMES, REPOSITORY, ReleaseIdentity, ReleaseIndex, SupportScope,
    },
};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};
type Result<T> = std::result::Result<T, TrustError>;
#[derive(Deserialize)]
struct WireAsset {
    name: String,
    size: u64,
    digest: String,
    state: String,
    url: String,
}
#[derive(Deserialize)]
struct WireRelease {
    tag_name: String,
    target_commitish: String,
    body: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    assets: Vec<WireAsset>,
    #[serde(default)]
    sbxr_qualification: Option<serde_json::Value>,
}
struct Asset {
    id: u64,
    proof: AssetProof,
}
struct Metadata {
    identity: ReleaseIdentity,
    sequence: u64,
    assets: BTreeMap<String, Asset>,
}
impl Metadata {
    fn decode(bytes: &[u8], record: &InstalledRecord) -> Result<Self> {
        let value = trust::json_object(bytes, MAX_INDEX_BYTES)?;
        let wire: WireRelease = serde_json::from_value(value).map_err(|_| TrustError::Refused)?;
        let selected = record.release_identity();
        if wire.draft
            || wire.prerelease
            || !wire.immutable
            || wire.sbxr_qualification.is_some()
            || wire.tag_name != selected.tag()
            || wire.target_commitish != selected.commit()
            || wire.assets.len() != 4
        {
            return Err(TrustError::Refused);
        }
        let mut assets = BTreeMap::new();
        for asset in wire.assets {
            if !RELEASE_ASSET_NAMES.contains(&asset.name.as_str()) || asset.state != "uploaded" {
                return Err(TrustError::Refused);
            }
            let maximum = if matches!(asset.name.as_str(), "install.sh" | "release-index.json") {
                MAX_INDEX_BYTES
            } else {
                MAX_EXECUTABLE_BYTES
            };
            if asset.size == 0 || asset.size > maximum as u64 {
                return Err(TrustError::Refused);
            }
            let hash = asset
                .digest
                .strip_prefix("sha256:")
                .ok_or(TrustError::Refused)?;
            let proof =
                AssetProof::new(&asset.name, asset.size, hash).map_err(|_| TrustError::Refused)?;
            let prefix = format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/");
            let id = asset.url.strip_prefix(&prefix).ok_or(TrustError::Refused)?;
            let number = id.parse::<u64>().map_err(|_| TrustError::Refused)?;
            if number == 0
                || number.to_string() != id
                || assets
                    .insert(asset.name, Asset { id: number, proof })
                    .is_some()
            {
                return Err(TrustError::Refused);
            }
        }
        let hash = assets
            .get("release-index.json")
            .ok_or(TrustError::Refused)?
            .proof
            .sha256();
        let identity = ReleaseIdentity::new(&wire.tag_name, &wire.target_commitish, hash)
            .map_err(|_| TrustError::Refused)?;
        if hash != selected.index_sha256() {
            return Err(TrustError::Refused);
        }
        let proofs: Vec<_> = assets.values().map(|a| a.proof.clone()).collect();
        let sequence = acceptance::check(&wire.body, &identity, &proofs)?;
        if sequence != record.sequence() {
            return Err(TrustError::Refused);
        }
        Ok(Self {
            identity,
            sequence,
            assets,
        })
    }
    fn expected(&self) -> Result<ExpectedRelease> {
        ExpectedRelease::new(
            self.identity.clone(),
            self.assets.values().map(|a| a.proof.clone()).collect(),
        )
    }
}
/// Only the actual acquisition/authentication path constructs this result.
/// It proves supplied current/installed bytes, not the identity of an OS process.
pub struct AuthenticatedInstalled {
    record: InstalledRecord,
    index: ReleaseIndex,
}
impl fmt::Debug for AuthenticatedInstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticated installed bytes")
    }
}
impl AuthenticatedInstalled {
    pub fn record(&self) -> &InstalledRecord {
        &self.record
    }
    pub fn index(&self) -> &ReleaseIndex {
        &self.index
    }
    /// Native protected readers must supply freshly observed current and installed bytes.
    pub fn acquire(
        transport: &mut impl AcquisitionTransport,
        record: InstalledRecord,
        installed: &[u8],
        current: &[u8],
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        if installed != current {
            return Err(TrustError::Refused);
        }
        let architecture = match record.architecture() {
            "amd64" => Architecture::Amd64,
            "arm64" => Architecture::Arm64,
            _ => return Err(TrustError::Refused),
        };
        identity::verify_installed_pair(&record, installed).map_err(|_| TrustError::Refused)?;
        identity::inspect_linux_artifact(current, architecture).map_err(|_| TrustError::Refused)?;
        let request = AcquisitionRequest::release_metadata(record.release_identity().tag())?;
        let response = transport.get(&request, budget)?;
        let bytes = trust::read_complete_json_response(response, request.max_bytes(), budget)?;
        let metadata = Metadata::decode(&bytes, &record)?;
        let claims = trust::verify_native_release(transport, &metadata.expected()?, budget)?;
        complete(
            transport,
            record,
            installed,
            &metadata,
            &claims,
            architecture,
            budget,
        )
    }
}
fn complete(
    transport: &mut impl AcquisitionTransport,
    record: InstalledRecord,
    installed: &[u8],
    metadata: &Metadata,
    claims: &VerifiedNativeReleaseClaims,
    architecture: Architecture,
    budget: &SelectionBudget,
) -> Result<AuthenticatedInstalled> {
    budget.check()?;
    if claims.identity() != &metadata.identity {
        return Err(TrustError::Refused);
    }
    let asset = metadata
        .assets
        .get("release-index.json")
        .ok_or(TrustError::Refused)?;
    let proof = claims
        .asset("release-index.json")
        .ok_or(TrustError::Refused)?;
    let bytes = trust::acquire_digest_checked_asset(transport, asset.id, proof, budget)?;
    let proofs: Vec<_> = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| claims.asset(name).cloned().ok_or(TrustError::Refused))
        .collect::<Result<_>>()?;
    let index = identity::verify_release_index(
        REPOSITORY,
        metadata.identity.tag(),
        metadata.identity.commit(),
        &bytes,
        &proofs,
    )
    .map_err(|_| TrustError::Refused)?;
    if index.sequence() != metadata.sequence
        || index
            .support()
            .is_none_or(|s| s.scope() != SupportScope::CleanInstallOnly || !s.sources().is_empty())
    {
        return Err(TrustError::Refused);
    }
    let name = match architecture {
        Architecture::Amd64 => "sbxr-linux-amd64.tar.gz",
        Architecture::Arm64 => "sbxr-linux-arm64.tar.gz",
    };
    let asset = metadata.assets.get(name).ok_or(TrustError::Refused)?;
    let bytes = trust::acquire_digest_checked_asset(
        transport,
        asset.id,
        claims.asset(name).ok_or(TrustError::Refused)?,
        budget,
    )?;
    let executable = crate::release_archive::unpack(&bytes, budget)?;
    if executable != installed {
        return Err(TrustError::Refused);
    }
    identity::inspect_release_executable(&index, &executable, architecture)
        .map_err(|_| TrustError::Refused)?;
    budget.check()?;
    Ok(AuthenticatedInstalled { record, index })
}
#[cfg(test)]
#[path = "release_acquisition_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn fixture_authenticated() -> (AuthenticatedInstalled, Vec<u8>) {
    tests::verified_fixture()
}
