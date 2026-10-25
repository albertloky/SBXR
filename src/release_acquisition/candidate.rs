//! Signed candidate delivery. This is never Qualified Stable Release authority.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;

/// An exact archive authorized by the candidate workflow, not a stable record.
pub struct AuthenticatedCandidateArchive {
    archive: AuthenticatedArchive,
    manifest_sha256: String,
}
/// Candidate installation binding remains a different type from stable proof.
/// ```compile_fail
/// use sbxr::release_acquisition::{AuthenticatedInstalled, AuthenticatedCandidateInstalled};
/// fn promote(candidate: AuthenticatedCandidateInstalled) -> AuthenticatedInstalled { candidate }
/// ```
pub struct AuthenticatedCandidateInstalled {
    installed: AuthenticatedInstalled,
    manifest_sha256: String,
}
impl fmt::Debug for AuthenticatedCandidateArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticated candidate archive")
    }
}
impl fmt::Debug for AuthenticatedCandidateInstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticated candidate installed bytes")
    }
}
impl AuthenticatedCandidateArchive {
    /// Only the retained gateway's fixed Latest route supplies candidate wire.
    /// The reviewed full identity is rechecked, never selected from server input.
    /// Transport/TLS admission and production activation are separate boundaries.
    pub fn acquire(
        transport: &mut impl AcquisitionTransport,
        selected: &crate::records::ReleaseIdentity,
        architecture: Architecture,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        let selected =
            ReleaseIdentity::new(selected.tag(), selected.commit(), selected.index_sha256())
                .map_err(|_| TrustError::Refused)?;
        let request = AcquisitionRequest::latest_metadata();
        let response = transport.get(&request, budget)?;
        let bytes = trust::read_complete_json_response(response, request.max_bytes(), budget)?;
        let proof = VerifiedManifest::verify(&bytes, &selected, budget)?;
        let archive = acquire_with_proof(
            transport,
            &proof.metadata,
            ArchiveProof::Candidate(&proof),
            architecture,
            budget,
        )?;
        if identity::inspect_linux_artifact(archive.executable(), architecture)
            .map_err(|_| TrustError::Refused)?
            .kind()
            != identity::ArtifactKind::Rust
        {
            return Err(TrustError::Refused);
        }
        budget.check()?;
        Ok(Self {
            archive,
            manifest_sha256: proof.statement.policy().digest().into(),
        })
    }
    pub fn record(&self) -> &InstalledRecord {
        self.archive.record()
    }
    pub fn index(&self) -> &ReleaseIndex {
        self.archive.index()
    }
    pub fn executable(&self) -> &[u8] {
        self.archive.executable()
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn bind_current(
        &self,
        installed: &[u8],
        current: &[u8],
        budget: &SelectionBudget,
    ) -> Result<AuthenticatedCandidateInstalled> {
        Ok(AuthenticatedCandidateInstalled {
            installed: self.archive.bind_current(installed, current, budget)?,
            manifest_sha256: self.manifest_sha256.clone(),
        })
    }
}
impl AuthenticatedCandidateInstalled {
    pub fn record(&self) -> &InstalledRecord {
        self.installed.record()
    }
    pub fn index(&self) -> &ReleaseIndex {
        self.installed.index()
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}

// This concrete proof can only be built after real cryptographic verification.
// There is no alternate verifier argument or test-only signature constructor.
pub(super) struct VerifiedManifest {
    pub(super) metadata: Metadata,
    pub(super) index: Vec<u8>,
    statement: trust::VerifiedStatement,
}
impl VerifiedManifest {
    fn verify(bytes: &[u8], selected: &ReleaseIdentity, budget: &SelectionBudget) -> Result<Self> {
        budget.check()?;
        let value = trust::json_object(bytes, MAX_INDEX_BYTES)?;
        let wire: WireRelease = serde_json::from_value(value).map_err(|_| TrustError::Refused)?;
        let wrapper: WireProof =
            serde_json::from_value(wire.sbxr_qualification.clone().ok_or(TrustError::Refused)?)
                .map_err(|_| TrustError::Refused)?;
        let manifest = decode_base64(&wrapper.manifest, MAX_INDEX_BYTES)?;
        let bundle = decode_base64(&wrapper.bundle, trust::MAX_BUNDLE_BYTES)?;
        // The exact raw manifest, dedicated subject name, pinned root, issuer,
        // workflow URI, Rekor and observer-time policies all remain mandatory.
        let statement = trust::verify_candidate_manifest(&bundle, &manifest, budget)?;
        let inspected = inspect(&manifest, &wire, selected)?;
        budget.check()?;
        Ok(Self {
            metadata: inspected.metadata,
            index: inspected.index,
            statement,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    manifest: String,
    bundle: String,
}
fn decode_base64(text: &str, max: usize) -> Result<Vec<u8>> {
    if text.is_empty() || text.len() > max.div_ceil(3) * 4 {
        return Err(TrustError::Refused);
    }
    let bytes = STANDARD.decode(text).map_err(|_| TrustError::Refused)?;
    if bytes.is_empty() || bytes.len() > max || STANDARD.encode(&bytes) != text {
        return Err(TrustError::Refused);
    }
    Ok(bytes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    repository: String,
    mode: String,
    source_state: String,
    workflow: Workflow,
    approval: Approval,
    releases: Vec<Release>,
    native_evidence: Vec<Evidence>,
    acceptance_vps_checklist_sha256: String,
    candidate_failure_state_sha256: String,
    pinned_actions: Vec<String>,
    rescue: Option<Value>,
    v3_attempt: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    path: String,
    r#ref: String,
    commit: String,
    run_id: String,
    run_url: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    state: String,
    environments: Vec<Environment>,
    decision_chain: Vec<Decision>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    stage: String,
    outcome: String,
    facts_sha256: String,
    decision_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    tag: String,
    commit: String,
    sequence: u64,
    release_id: u64,
    #[serde(deserialize_with = "decode_identity")]
    release_identity: ReleaseIdentity,
    assets: Vec<AssetProof>,
}
fn decode_identity<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<ReleaseIdentity, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        repository: String,
        tag: String,
        commit: String,
        release_index_sha256: String,
    }
    let wire = Wire::deserialize(decoder)?;
    if wire.repository != REPOSITORY {
        return Err(serde::de::Error::custom("candidate repository refused"));
    }
    ReleaseIdentity::new(&wire.tag, &wire.commit, &wire.release_index_sha256)
        .map_err(serde::de::Error::custom)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: String,
    sha256: String,
}
struct Inspected {
    metadata: Metadata,
    index: Vec<u8>,
}
fn digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn positive(text: &str) -> bool {
    text.parse::<u64>()
        .is_ok_and(|n| n > 0 && n.to_string() == text)
}
fn release_valid(r: &Release) -> bool {
    r.sequence > 0
        && r.release_id > 0
        && r.tag == r.release_identity.tag()
        && r.commit == r.release_identity.commit()
        && r.assets.len() == 4
        && RELEASE_ASSET_NAMES
            .iter()
            .all(|name| r.assets.iter().filter(|a| a.name() == *name).count() == 1)
        && r.assets
            .iter()
            .find(|a| a.name() == "release-index.json")
            .is_some_and(|a| a.sha256() == r.release_identity.index_sha256())
}
// Structural inspection is intentionally not an authentication result. Only
// VerifiedManifest::verify can turn it into a candidate acquisition proof.
fn inspect(bytes: &[u8], wire: &WireRelease, selected: &ReleaseIdentity) -> Result<Inspected> {
    let value = trust::json_object(bytes, MAX_INDEX_BYTES)?;
    let m: Manifest = serde_json::from_value(value).map_err(|_| TrustError::Refused)?;
    if m.schema != "sbxr-qualification-manifest-v3"
        || m.repository != REPOSITORY
        || m.mode != "v3"
        || m.source_state != "v3-subscription-clean"
        || m.rescue.is_some()
        || m.releases.len() != 1
        || m.workflow.path != ".github/workflows/candidate.yml"
        || m.workflow.r#ref
            != format!("{REPOSITORY}/.github/workflows/candidate.yml@refs/heads/main")
        || m.workflow.commit != selected.commit()
        || !positive(&m.workflow.run_id)
        || m.workflow.run_url
            != format!(
                "https://github.com/{REPOSITORY}/actions/runs/{}",
                m.workflow.run_id
            )
        || m.approval.state != "approved"
        || m.approval.environments.len() != 1
        || m.approval.environments[0].name != "acceptance-vps"
        || !digest(&m.acceptance_vps_checklist_sha256)
        || !digest(&m.candidate_failure_state_sha256)
    {
        return Err(TrustError::Refused);
    }
    let stages = [
        ("candidate-preflight", "accepted"),
        ("candidate-draft-construction", "actions-required"),
        ("candidate-draft-verification", "accepted"),
    ];
    if m.approval.decision_chain.len() != stages.len()
        || !m
            .approval
            .decision_chain
            .iter()
            .zip(stages)
            .all(|(d, (stage, outcome))| {
                d.stage == stage
                    && d.outcome == outcome
                    && digest(&d.facts_sha256)
                    && digest(&d.decision_sha256)
            })
    {
        return Err(TrustError::Refused);
    }
    let release = &m.releases[0];
    if !release_valid(release)
        || &release.release_identity != selected
        || release.commit != m.workflow.commit
    {
        return Err(TrustError::Refused);
    }
    let expected_paths = [
        format!(
            "native/native-{}-amd64/evidence/native-amd64.json",
            release.tag
        ),
        format!(
            "native/native-{}-arm64/evidence/native-arm64.json",
            release.tag
        ),
    ];
    if m.native_evidence.len() != 2
        || !m
            .native_evidence
            .iter()
            .zip(expected_paths)
            .all(|(e, path)| e.path == path && digest(&e.sha256))
        || m.pinned_actions.is_empty()
        || m.pinned_actions.iter().any(|p| {
            !p.split_once('@').is_some_and(|(name, sha)| {
                name.starts_with("actions/")
                    && sha.len() == 40
                    && sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    {
        return Err(TrustError::Refused);
    }
    let assets = Metadata::assets(wire, selected)?;
    if release
        .assets
        .iter()
        .any(|a| assets.get(a.name()).is_none_or(|bound| bound.proof != *a))
    {
        return Err(TrustError::Refused);
    }
    let index = attempt_index(&m.v3_attempt, &m.workflow, release)?;
    Ok(Inspected {
        metadata: Metadata {
            identity: selected.clone(),
            sequence: release.sequence,
            assets,
        },
        index,
    })
}
fn attempt_index(attempt: &Value, workflow: &Workflow, release: &Release) -> Result<Vec<u8>> {
    let map = attempt.as_object().ok_or(TrustError::Refused)?;
    const FIELDS: &[&str] = &[
        "after_snap_refresh",
        "attempt_id",
        "attended_finish_by",
        "automated_only_scenarios",
        "baseline",
        "candidate_index",
        "evidence_policy",
        "karing_latest_checked_at",
        "karing_limit_seconds",
        "karing_response_limit_seconds",
        "late_confirmation_review",
        "live89_correction_review",
        "mac_runner_id",
        "macos_version",
        "outside_runner_id",
        "owner_exception",
        "packages",
        "proxy_package",
        "proxy_profile",
        "required_scenarios",
        "run_attempt",
        "runner",
        "scenario_limit_seconds",
        "schema",
        "sources",
        "started_at",
        "support",
        "validation_limit_seconds",
        "vps_id",
        "vps_identity_sha256",
    ];
    if map.keys().any(|k| !FIELDS.contains(&k.as_str()))
        || attempt["schema"] != "sbxr-v3-qualification-attempt-v3"
        || attempt["evidence_policy"] != "mvp-http-live-v1"
        || attempt["sources"] != serde_json::json!([])
        || attempt["support"]
            != serde_json::json!({"scope":"subscription-clean-install-only","contract":"sbxr-subscription-update-v1","sources":[]})
        || attempt["required_scenarios"]
            != serde_json::json!([
                "mvp-install",
                "mvp-subscription",
                "mvp-credentials",
                "mvp-serving",
                "mvp-removal"
            ])
    {
        return Err(TrustError::Refused);
    }
    for field in ["late_confirmation_review", "live89_correction_review"] {
        if attempt.get(field).is_some_and(|v| !v.is_null()) {
            return Err(TrustError::Refused);
        }
    }
    if attempt.get("owner_exception").is_some_and(|v| v != "")
        || attempt
            .get("automated_only_scenarios")
            .is_some_and(|v| !v.is_null() && v != &serde_json::json!([]))
        || attempt
            .get("proxy_profile")
            .is_some_and(|v| v != "" && v != "vless-vmess")
    {
        return Err(TrustError::Refused);
    }
    if attempt["proxy_profile"] == "vless-vmess"
        && attempt
            .get("automated_only_scenarios")
            .is_some_and(|v| !v.is_null())
    {
        return Err(TrustError::Refused);
    }
    let run = attempt["run_attempt"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(TrustError::Refused)?;
    if attempt["attempt_id"] != format!("run-{}-attempt-{run}", workflow.run_id) {
        return Err(TrustError::Refused);
    }
    let baseline: Release = serde_json::from_value(
        attempt
            .get("baseline")
            .cloned()
            .ok_or(TrustError::Refused)?,
    )
    .map_err(|_| TrustError::Refused)?;
    if !release_valid(&baseline)
        || baseline.sequence >= release.sequence
        || baseline.tag == release.tag
        || baseline.release_id == release.release_id
    {
        return Err(TrustError::Refused);
    }
    let index = attempt["candidate_index"]
        .as_str()
        .ok_or(TrustError::Refused)?
        .as_bytes();
    if index.is_empty()
        || index.len() > MAX_INDEX_BYTES
        || crate::records::sha256_hex(index) != release.release_identity.index_sha256()
    {
        return Err(TrustError::Refused);
    }
    let index = identity::verify_release_index(
        REPOSITORY,
        &release.tag,
        &release.commit,
        index,
        &release.assets,
    )
    .map_err(|_| TrustError::Refused)?;
    if index.sequence() != release.sequence
        || index
            .support()
            .is_none_or(|s| s.scope() != SupportScope::CleanInstallOnly || !s.sources().is_empty())
    {
        return Err(TrustError::Refused);
    }
    Ok(index.bytes().to_vec())
}

#[cfg(test)]
#[path = "candidate_tests.rs"]
mod tests;
