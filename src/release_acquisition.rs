//! Exact-tag native release acquisition, authentication and installed-byte binding.
//! No network transport, extraction, update/migration or production authorization.
mod acceptance;
mod candidate;
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
pub use candidate::{AuthenticatedCandidateArchive, AuthenticatedCandidateInstalled};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};
type Result<T> = std::result::Result<T, TrustError>;
/// Delivery role is never a qualification/activation flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryRole {
    Stable,
    Candidate,
}
pub(crate) mod installed_seal {
    pub trait Sealed {}
}
/// Sealed authenticated bytes, with the original delivery role retained.
/// Native entry additionally requires host::admission::NativeAdmission, not
/// this byte proof alone. A bound native proof rechecks its protected snapshot.
/// ```compile_fail
/// struct Forged;
/// impl sbxr::release_acquisition::InstalledEvidence for Forged {
/// fn record(&self)->&sbxr::records::InstalledRecord { panic!() }
/// fn index(&self)->&sbxr::release_identity::ReleaseIndex { panic!() }
/// fn role(&self)->sbxr::release_acquisition::DeliveryRole { sbxr::release_acquisition::DeliveryRole::Stable }
/// fn verify_binding(&self)->Result<(),sbxr::artifact_trust::TrustError> { Ok(()) }
/// }
/// ```
pub trait InstalledEvidence: installed_seal::Sealed + Send + Sync {
    fn record(&self) -> &InstalledRecord;
    fn index(&self) -> &ReleaseIndex;
    fn role(&self) -> DeliveryRole;
    fn verify_binding(&self) -> std::result::Result<(), TrustError>;
}
impl<T: InstalledEvidence + ?Sized> installed_seal::Sealed for std::sync::Arc<T> {}
impl<T: InstalledEvidence + ?Sized> InstalledEvidence for std::sync::Arc<T> {
    fn record(&self) -> &InstalledRecord {
        (**self).record()
    }
    fn index(&self) -> &ReleaseIndex {
        (**self).index()
    }
    fn role(&self) -> DeliveryRole {
        (**self).role()
    }
    fn verify_binding(&self) -> std::result::Result<(), TrustError> {
        (**self).verify_binding()
    }
}
impl installed_seal::Sealed for AuthenticatedInstalled {}
impl InstalledEvidence for AuthenticatedInstalled {
    fn record(&self) -> &InstalledRecord {
        self.record()
    }
    fn index(&self) -> &ReleaseIndex {
        self.index()
    }
    fn role(&self) -> DeliveryRole {
        DeliveryRole::Stable
    }
    fn verify_binding(&self) -> std::result::Result<(), TrustError> {
        Ok(())
    }
}
impl installed_seal::Sealed for AuthenticatedCandidateInstalled {}
impl InstalledEvidence for AuthenticatedCandidateInstalled {
    fn record(&self) -> &InstalledRecord {
        self.record()
    }
    fn index(&self) -> &ReleaseIndex {
        self.index()
    }
    fn role(&self) -> DeliveryRole {
        DeliveryRole::Candidate
    }
    fn verify_binding(&self) -> std::result::Result<(), TrustError> {
        Ok(())
    }
}

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
        let selected = record.release_identity();
        let selected =
            ReleaseIdentity::new(selected.tag(), selected.commit(), selected.index_sha256())
                .map_err(|_| TrustError::Refused)?;
        let result = Self::decode_exact(bytes, &selected)?;
        if result.sequence != record.sequence() {
            return Err(TrustError::Refused);
        }
        Ok(result)
    }
    fn decode_exact(bytes: &[u8], selected: &ReleaseIdentity) -> Result<Self> {
        let value = trust::json_object(bytes, MAX_INDEX_BYTES)?;
        let wire: WireRelease = serde_json::from_value(value).map_err(|_| TrustError::Refused)?;
        if wire.sbxr_qualification.is_some() {
            return Err(TrustError::Refused);
        }
        let assets = Self::assets(&wire, selected)?;
        let identity = selected.clone();
        let proofs: Vec<_> = assets.values().map(|a| a.proof.clone()).collect();
        let sequence = acceptance::check(&wire.body, &identity, &proofs)?;
        Ok(Self {
            identity,
            sequence,
            assets,
        })
    }
    fn assets(wire: &WireRelease, selected: &ReleaseIdentity) -> Result<BTreeMap<String, Asset>> {
        if wire.draft
            || wire.prerelease
            || !wire.immutable
            || wire.tag_name != selected.tag()
            || wire.target_commitish != selected.commit()
            || wire.assets.len() != 4
        {
            return Err(TrustError::Refused);
        }
        let mut assets = BTreeMap::new();
        for asset in &wire.assets {
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
                    .insert(asset.name.clone(), Asset { id: number, proof })
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
        if hash != selected.index_sha256() {
            return Err(TrustError::Refused);
        }
        Ok(assets)
    }
    fn expected(&self) -> Result<ExpectedRelease> {
        ExpectedRelease::new(
            self.identity.clone(),
            self.assets.values().map(|a| a.proof.clone()).collect(),
        )
    }
}
/// Exact authenticated release bytes. This proves no installed file or process,
/// grants no restoration permission and cannot be constructed from structural
/// checks. Filesystem recovery separately requires committed removal authority.
pub struct AuthenticatedArchive {
    record: InstalledRecord,
    index: ReleaseIndex,
    executable: Vec<u8>,
}
impl fmt::Debug for AuthenticatedArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticated exact release archive")
    }
}
impl AuthenticatedArchive {
    pub fn record(&self) -> &InstalledRecord {
        &self.record
    }
    pub fn index(&self) -> &ReleaseIndex {
        &self.index
    }
    pub fn executable(&self) -> &[u8] {
        &self.executable
    }
    pub fn acquire(
        transport: &mut impl AcquisitionTransport,
        selected: &crate::records::ReleaseIdentity,
        architecture: Architecture,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        let expected =
            ReleaseIdentity::new(selected.tag(), selected.commit(), selected.index_sha256())
                .map_err(|_| TrustError::Refused)?;
        let request = AcquisitionRequest::release_metadata(selected.tag())?;
        let response = transport.get(&request, budget)?;
        let bytes = trust::read_complete_json_response(response, request.max_bytes(), budget)?;
        let metadata = Metadata::decode_exact(&bytes, &expected)?;
        let claims = trust::verify_native_release(transport, &metadata.expected()?, budget)?;
        acquire_archive(transport, &metadata, &claims, architecture, budget)
    }
    /// Check the canonical qualified Latest using the same immutable metadata,
    /// signatures, index, installer and executable validation as exact recovery.
    /// This acquires bytes only; it never offers or performs an update.
    pub fn acquire_latest(
        transport: &mut impl AcquisitionTransport,
        architecture: Architecture,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        Self::acquire_public_request(
            transport,
            AcquisitionRequest::latest_metadata(),
            None,
            architecture,
            budget,
        )
    }
    /// Repository verification only: an immutable public exact tag still needs
    /// native signatures, Acceptance Record, index and executable verification.
    pub fn acquire_public_tag(
        transport: &mut impl AcquisitionTransport,
        tag: &str,
        architecture: Architecture,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        let request = AcquisitionRequest::release_metadata(tag)?;
        Self::acquire_public_request(transport, request, Some(tag), architecture, budget)
    }
    fn acquire_public_request(
        transport: &mut impl AcquisitionTransport,
        request: AcquisitionRequest,
        tag: Option<&str>,
        architecture: Architecture,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        let response = transport.get(&request, budget)?;
        let bytes = trust::read_complete_json_response(response, request.max_bytes(), budget)?;
        let value = trust::json_object(&bytes, MAX_INDEX_BYTES)?;
        let wire: WireRelease = serde_json::from_value(value).map_err(|_| TrustError::Refused)?;
        if tag.is_some_and(|tag| tag != wire.tag_name) {
            return Err(TrustError::Refused);
        }
        let digest = wire
            .assets
            .iter()
            .find(|a| a.name == "release-index.json")
            .and_then(|a| a.digest.strip_prefix("sha256:"))
            .ok_or(TrustError::Refused)?;
        let selected = ReleaseIdentity::new(&wire.tag_name, &wire.target_commitish, digest)
            .map_err(|_| TrustError::Refused)?;
        let metadata = Metadata::decode_exact(&bytes, &selected)?;
        let claims = trust::verify_native_release(transport, &metadata.expected()?, budget)?;
        acquire_archive(transport, &metadata, &claims, architecture, budget)
    }
    /// Native callers must freshly read protected installed/current executable
    /// bytes. The archive alone makes no assertion about their physical source.
    pub fn bind_current(
        &self,
        installed: &[u8],
        current: &[u8],
        budget: &SelectionBudget,
    ) -> Result<AuthenticatedInstalled> {
        budget.check()?;
        if installed != self.executable || current != self.executable {
            return Err(TrustError::Refused);
        }
        let installed = AuthenticatedInstalled {
            record: self.record.clone(),
            index: self.index.clone(),
        };
        budget.check()?;
        Ok(installed)
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
    let archive = acquire_archive(transport, metadata, claims, architecture, budget)?;
    if archive.record != record {
        return Err(TrustError::Refused);
    }
    archive.bind_current(installed, installed, budget)
}
fn acquire_archive(
    transport: &mut impl AcquisitionTransport,
    metadata: &Metadata,
    claims: &VerifiedNativeReleaseClaims,
    architecture: Architecture,
    budget: &SelectionBudget,
) -> Result<AuthenticatedArchive> {
    acquire_with_proof(
        transport,
        metadata,
        ArchiveProof::Stable(claims),
        architecture,
        budget,
    )
}
enum ArchiveProof<'a> {
    Stable(&'a VerifiedNativeReleaseClaims),
    Candidate(&'a candidate::VerifiedManifest),
}
impl ArchiveProof<'_> {
    fn identity(&self) -> &ReleaseIdentity {
        match self {
            Self::Stable(p) => p.identity(),
            Self::Candidate(p) => &p.metadata.identity,
        }
    }
    fn asset(&self, name: &str) -> Option<&AssetProof> {
        match self {
            Self::Stable(p) => p.asset(name),
            Self::Candidate(p) => p.metadata.assets.get(name).map(|p| &p.proof),
        }
    }
    fn check_index(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Stable(_) => Ok(()),
            Self::Candidate(p) if bytes == p.index => Ok(()),
            _ => Err(TrustError::Refused),
        }
    }
}
fn acquire_with_proof(
    transport: &mut impl AcquisitionTransport,
    metadata: &Metadata,
    authority: ArchiveProof<'_>,
    architecture: Architecture,
    budget: &SelectionBudget,
) -> Result<AuthenticatedArchive> {
    budget.check()?;
    if authority.identity() != &metadata.identity {
        return Err(TrustError::Refused);
    }
    let asset = metadata
        .assets
        .get("release-index.json")
        .ok_or(TrustError::Refused)?;
    let proof = authority
        .asset("release-index.json")
        .ok_or(TrustError::Refused)?;
    let bytes = trust::acquire_digest_checked_asset(transport, asset.id, proof, budget)?;
    let proofs: Vec<_> = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| authority.asset(name).cloned().ok_or(TrustError::Refused))
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
    authority.check_index(&bytes)?;
    let name = match architecture {
        Architecture::Amd64 => "sbxr-linux-amd64.tar.gz",
        Architecture::Arm64 => "sbxr-linux-arm64.tar.gz",
    };
    let asset = metadata.assets.get(name).ok_or(TrustError::Refused)?;
    let bytes = trust::acquire_digest_checked_asset(
        transport,
        asset.id,
        authority.asset(name).ok_or(TrustError::Refused)?,
        budget,
    )?;
    let executable = crate::release_archive::unpack(&bytes, budget)?;
    identity::inspect_release_executable(&index, &executable, architecture)
        .map_err(|_| TrustError::Refused)?;
    budget.check()?;
    let id = index.identity();
    let release = crate::records::ReleaseIdentity::new(id.tag(), id.commit(), id.index_sha256())
        .map_err(|_| TrustError::Refused)?;
    let arch = match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    };
    let record = InstalledRecord::new(
        release,
        index.sequence(),
        arch,
        &crate::records::sha256_hex(&executable),
    )
    .map_err(|_| TrustError::Refused)?;
    budget.check()?;
    Ok(AuthenticatedArchive {
        record,
        index,
        executable,
    })
}
#[cfg(test)]
#[path = "release_acquisition_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn fixture_authenticated() -> (AuthenticatedInstalled, Vec<u8>) {
    tests::verified_fixture()
}

#[cfg(test)]
pub(crate) fn fixture_archive() -> AuthenticatedArchive {
    let (installed, executable) = tests::verified_fixture();
    AuthenticatedArchive {
        record: installed.record,
        index: installed.index,
        executable,
    }
}

#[cfg(test)]
pub(crate) fn fixture_archive_with_capabilities() -> AuthenticatedArchive {
    let (installed, executable) = tests::verified_fixture_with_markers(
        b"SBXR-DEDICATED-TUNNEL-V1 SBXR-SUBSCRIPTION-HTTP-V1 SBXR-SUBSCRIPTION-HTTPS-RETIREMENT-V1",
    );
    AuthenticatedArchive {
        record: installed.record,
        index: installed.index,
        executable,
    }
}
pub(crate) fn inspect_candidate_handoff(
    bytes: &[u8],
) -> Result<(crate::records::ReleaseIdentity, u64)> {
    candidate::handoff_identity(bytes)
}
#[cfg(test)]
pub(crate) fn fixture_candidate_manifest() -> Vec<u8> {
    candidate::semantic_fixture()
}
