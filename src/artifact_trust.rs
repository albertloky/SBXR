//! Bounded, offline release trust-policy components and injectable acquisition.
//!
//! `inspect_*` results are UNAUTHENTICATED. `verify_*` uses the maintained
//! sigstore-verify backend against exact preserved roots and signer policies.
//! Only private constructors issue authenticated statements and release claims;
//! structural inspection, tool exit codes and caller-supplied flags cannot.
use crate::records::sha256_hex;
use crate::release_identity::{AssetProof, RELEASE_ASSET_NAMES, REPOSITORY, ReleaseIdentity};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sigstore_verify::{
    IdentityMatcher, VerificationPolicy as SigstorePolicy, Verifier,
    trust_root::TrustedRoot,
    types::{Bundle, Sha256Hash, SignatureContent},
};
use std::{
    collections::BTreeMap,
    fmt,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const MAX_BUNDLE_BYTES: usize = 8 << 20;
pub const MAX_NATIVE_PROOFS: usize = 99;
const MAX_JSON_NODES: usize = 100_000;
pub const SELECTION_TIMEOUT: Duration = Duration::from_secs(30);
pub const NATIVE_SIGNER: &str = "https://dotcom.releases.github.com";
pub const CANDIDATE_SIGNER: &str =
    "https://github.com/albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main";
pub const CANDIDATE_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    Refused,
    Unavailable,
    Interrupted,
}
impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused => "Release evidence refused",
            Self::Unavailable => "Release acquisition unavailable",
            Self::Interrupted => "Release verification interrupted",
        })
    }
}
impl std::error::Error for TrustError {}
type Result<T> = std::result::Result<T, TrustError>;

/// One deadline for the entire selection, including I/O and every proof.
/// Transports must enforce this deadline while blocked. Checks around reads and
/// synchronous crypto prevent late acceptance; they cannot interrupt those calls.
pub struct SelectionBudget {
    deadline: Instant,
    cancelled: AtomicBool,
    parent: Option<crate::subscription_serving::Cancellation>,
}
impl Default for SelectionBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl SelectionBudget {
    pub fn new() -> Self {
        Self::until(Instant::now() + SELECTION_TIMEOUT)
    }
    pub fn until(deadline: Instant) -> Self {
        Self {
            deadline: deadline.min(Instant::now() + SELECTION_TIMEOUT),
            cancelled: AtomicBool::new(false),
            parent: None,
        }
    }
    /// Couple acquisition and verification to the enclosing Owner session.
    pub fn with_cancellation(mut self, stop: crate::subscription_serving::Cancellation) -> Self {
        self.parent = Some(stop);
        self
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(crate::subscription_serving::Cancellation::is_cancelled)
            || Instant::now() >= self.deadline
        {
            Err(TrustError::Interrupted)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedRoot {
    NativeRelease,
    CandidateWorkflow,
}
impl PinnedRoot {
    pub fn fingerprint(self) -> &'static str {
        match self {
            Self::NativeRelease => {
                "26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485"
            }
            Self::CandidateWorkflow => {
                "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1"
            }
        }
    }
    /// Exact preserved Go roots, checked before use; no ambient root download.
    pub fn bytes(self) -> Result<&'static [u8]> {
        let bytes: &[u8] = match self {
            Self::NativeRelease => {
                include_bytes!("../internal/softwarelifecycle/adapter/github/trusted_root.json")
            }
            Self::CandidateWorkflow => include_bytes!(
                "../internal/softwarelifecycle/adapter/github/qualification_trusted_root.json"
            ),
        };
        if sha256_hex(bytes) != self.fingerprint() {
            return Err(TrustError::Refused);
        }
        json_object(bytes, MAX_BUNDLE_BYTES)?;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPolicy {
    root: PinnedRoot,
    digest: String,
}
impl VerificationPolicy {
    pub fn native_release(commit: &str) -> Result<Self> {
        if !lower_hex(commit, 40) {
            return Err(TrustError::Refused);
        }
        Ok(Self {
            root: PinnedRoot::NativeRelease,
            digest: commit.into(),
        })
    }
    pub fn candidate_manifest(sha256: &str) -> Result<Self> {
        if !lower_hex(sha256, 64) {
            return Err(TrustError::Refused);
        }
        Ok(Self {
            root: PinnedRoot::CandidateWorkflow,
            digest: sha256.into(),
        })
    }
    pub fn root(&self) -> PinnedRoot {
        self.root
    }
    pub fn signer(&self) -> &'static str {
        match self.root {
            PinnedRoot::NativeRelease => NATIVE_SIGNER,
            PinnedRoot::CandidateWorkflow => CANDIDATE_SIGNER,
        }
    }
    /// Native release identity retains Go's any-issuer policy under its pinned
    /// GitHub roots; the Actions workflow requires this exact OIDC issuer.
    pub fn issuer(&self) -> Option<&'static str> {
        (self.root == PinnedRoot::CandidateWorkflow).then_some(CANDIDATE_ISSUER)
    }
    pub fn digest_algorithm(&self) -> &'static str {
        match self.root {
            PinnedRoot::NativeRelease => "sha1",
            PinnedRoot::CandidateWorkflow => "sha256",
        }
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn signed_timestamp_threshold(&self) -> usize {
        usize::from(self.root == PinnedRoot::NativeRelease)
    }
    pub fn transparency_log_threshold(&self) -> usize {
        usize::from(self.root == PinnedRoot::CandidateWorkflow)
    }
    pub fn observer_timestamp_threshold(&self) -> usize {
        self.transparency_log_threshold()
    }
}

/// Exact DSSE payload authenticated under this policy and these bundle bytes.
/// Signature verification alone does not establish release qualification.
pub struct VerifiedStatement {
    payload: Vec<u8>,
    policy: VerificationPolicy,
    bundle_sha256: String,
}
impl fmt::Debug for VerifiedStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedStatement")
            .field("policy", &self.policy)
            .field("bundle_sha256", &self.bundle_sha256)
            .finish_non_exhaustive()
    }
}
impl VerifiedStatement {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }
    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }
}

/// Authenticates the entire DSSE payload, including its exact subject digest.
/// Native GitHub release proofs have TSA evidence instead of a public log/SCT.
/// Candidate proofs require the exact Actions identity/issuer and verified log.
pub fn verify_bundle(
    body: &[u8],
    policy: &VerificationPolicy,
    budget: &SelectionBudget,
) -> Result<VerifiedStatement> {
    budget.check()?;
    let document = json_object(body, MAX_BUNDLE_BYTES)?;
    bundle_fields(&document)?;
    let root = TrustedRoot::from_json(
        std::str::from_utf8(policy.root.bytes()?).map_err(|_| TrustError::Refused)?,
    )
    .map_err(|_| TrustError::Refused)?;
    let bundle = Bundle::from_json(std::str::from_utf8(body).map_err(|_| TrustError::Refused)?)
        .map_err(|_| TrustError::Refused)?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(TrustError::Refused);
    };
    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(TrustError::Refused);
    }
    let statement = json_object(envelope.payload.as_bytes(), MAX_BUNDLE_BYTES)?;
    if statement.get("_type").and_then(Value::as_str) != Some("https://in-toto.io/Statement/v1") {
        return Err(TrustError::Refused);
    }
    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or(TrustError::Refused)?;
    if !subjects.iter().any(|subject| {
        subject
            .get("digest")
            .and_then(|v| v.get(policy.digest_algorithm()))
            .and_then(Value::as_str)
            == Some(policy.digest())
    }) {
        return Err(TrustError::Refused);
    }
    // The backend has no SHA-1 artifact API. Its DSSE verification authenticates
    // the whole payload: bind a signed SHA-256 asset here, and the exact signed
    // SHA-1 commit above. No digest is calculated or substituted for that commit.
    let binding = match policy.root {
        PinnedRoot::NativeRelease => {
            if bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps
                .is_empty()
            {
                return Err(TrustError::Refused);
            }
            subjects
                .iter()
                .find_map(|subject| subject.get("digest")?.get("sha256")?.as_str())
                .ok_or(TrustError::Refused)?
        }
        PinnedRoot::CandidateWorkflow => {
            if bundle.verification_material.tlog_entries.is_empty() {
                return Err(TrustError::Refused);
            }
            policy.digest()
        }
    };
    if !lower_hex(binding, 64) {
        return Err(TrustError::Refused);
    }
    // Go requests certificate-chain/time/identity checks, without an SCT gate.
    let mut signer_policy = SigstorePolicy::any_identity()
        .require_identity(IdentityMatcher::Uri(policy.signer().into()))
        .skip_sct();
    if let Some(issuer) = policy.issuer() {
        signer_policy = signer_policy.require_issuer(issuer);
    }
    if policy.root == PinnedRoot::NativeRelease {
        // GitHub's release trust domain uses RFC3161, with no public Rekor/CT
        // proof. Chain, exact SAN, TSA token/signature and payload checks remain.
        signer_policy = signer_policy.skip_tlog_unsafe();
    }
    budget.check()?;
    let verified = Verifier::new(&root)
        .map_err(|_| TrustError::Refused)?
        .verify(
            Sha256Hash::from_hex(binding).map_err(|_| TrustError::Refused)?,
            &bundle,
            &signer_policy,
        )
        .map_err(|_| TrustError::Refused)?;
    budget.check()?;
    if !verified.certificate_verified()
        || !verified.identity_policy_checked()
        || verified.identity().map(|identity| identity.as_str()) != Some(policy.signer())
        || policy
            .issuer()
            .is_some_and(|issuer| verified.issuer() != Some(issuer))
        || verified.verified_timestamps().is_empty()
        || (policy.root == PinnedRoot::CandidateWorkflow && !verified.tlog_verified())
    {
        return Err(TrustError::Refused);
    }
    let statement = VerifiedStatement {
        payload: envelope.payload.as_bytes().to_vec(),
        policy: policy.clone(),
        bundle_sha256: sha256_hex(body),
    };
    budget.check()?;
    Ok(statement)
}

/// Authenticate the exact manifest bytes and the dedicated single subject name.
/// Its approval/release-qualification contents remain the lifecycle's contract.
pub fn verify_candidate_manifest(
    body: &[u8],
    manifest: &[u8],
    budget: &SelectionBudget,
) -> Result<VerifiedStatement> {
    if manifest.is_empty() || manifest.len() > 1 << 20 {
        return Err(TrustError::Refused);
    }
    json_object(manifest, 1 << 20)?;
    let policy = VerificationPolicy::candidate_manifest(&sha256_hex(manifest))?;
    let verified = verify_bundle(body, &policy, budget)?;
    inspect_candidate_statement(verified.payload(), manifest)?;
    budget.check()?;
    Ok(verified)
}

/// Matching metadata and a parsed identity remain unauthenticated inputs.
#[derive(Clone, Debug)]
pub struct ExpectedRelease {
    identity: ReleaseIdentity,
    assets: BTreeMap<String, AssetProof>,
}
impl ExpectedRelease {
    pub fn new(identity: ReleaseIdentity, assets: Vec<AssetProof>) -> Result<Self> {
        let mut exact = BTreeMap::new();
        for asset in assets {
            if exact.insert(asset.name().into(), asset).is_some() {
                return Err(TrustError::Refused);
            }
        }
        if exact.len() != RELEASE_ASSET_NAMES.len()
            || RELEASE_ASSET_NAMES
                .iter()
                .any(|name| !exact.contains_key(*name))
            || exact["release-index.json"].sha256() != identity.index_sha256()
        {
            return Err(TrustError::Refused);
        }
        Ok(Self {
            identity,
            assets: exact,
        })
    }
}

/// This type intentionally grants no authenticated-release capability.
#[derive(Debug)]
pub struct UnauthenticatedReleaseClaims {
    identity: ReleaseIdentity,
    proof_count: usize,
}
impl UnauthenticatedReleaseClaims {
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }
    pub fn proof_count(&self) -> usize {
        self.proof_count
    }
}

/// Ports ADR-0031 claim equivalence: inspect every statement, permit other valid
/// tags at this commit, require a target proof, refuse any conflicting target.
/// Only verify_native_release authenticates every statement before acceptance.
pub fn inspect_native_claim_set(
    statements: &[&[u8]],
    expected: &ExpectedRelease,
    budget: &SelectionBudget,
) -> Result<UnauthenticatedReleaseClaims> {
    budget.check()?;
    if statements.is_empty() || statements.len() > MAX_NATIVE_PROOFS {
        return Err(TrustError::Refused);
    }
    let mut matched = false;
    for body in statements {
        budget.check()?;
        matched |= native_claim_matches(body, expected)?;
        budget.check()?;
    }
    if !matched {
        return Err(TrustError::Refused);
    }
    budget.check()?;
    Ok(UnauthenticatedReleaseClaims {
        identity: expected.identity.clone(),
        proof_count: statements.len(),
    })
}

fn native_claim_matches(body: &[u8], expected: &ExpectedRelease) -> Result<bool> {
    let (tag, assets) = native_statement(body, expected.identity.commit())?;
    let matched = tag == expected.identity.tag();
    if matched
        && expected
            .assets
            .iter()
            .any(|(name, asset)| assets.get(name).map(String::as_str) != Some(asset.sha256()))
    {
        return Err(TrustError::Refused);
    }
    Ok(matched)
}

fn native_statement(body: &[u8], commit: &str) -> Result<(String, BTreeMap<String, String>)> {
    let value = json_object(body, MAX_BUNDLE_BYTES)?;
    let statement = fields(
        &value,
        &["_type", "predicateType", "subject", "predicate"],
        &[],
    )?;
    if string(&statement["_type"])? != "https://in-toto.io/Statement/v1"
        || string(&statement["predicateType"])? != "https://in-toto.io/attestation/release/v0.2"
    {
        return Err(TrustError::Refused);
    }
    let predicate = fields(
        &statement["predicate"],
        &[
            "databaseId",
            "ownerId",
            "packageId",
            "purl",
            "repository",
            "repositoryId",
            "tag",
        ],
        &[],
    )?;
    for name in ["databaseId", "ownerId", "packageId", "repositoryId"] {
        if string(&predicate[name])?.is_empty() {
            return Err(TrustError::Refused);
        }
    }
    let tag = string(&predicate["tag"])?;
    // Reuse the existing immutable-tag and source-commit validation.
    ReleaseIdentity::new(tag, commit, &"0".repeat(64)).map_err(|_| TrustError::Refused)?;
    let purl = format!("pkg:github/{REPOSITORY}@{tag}");
    if string(&predicate["repository"])? != REPOSITORY || string(&predicate["purl"])? != purl {
        return Err(TrustError::Refused);
    }
    let subjects = statement["subject"].as_array().ok_or(TrustError::Refused)?;
    if subjects.len() != RELEASE_ASSET_NAMES.len() + 1 {
        return Err(TrustError::Refused);
    }
    let release = fields(&subjects[0], &["uri", "digest"], &["name"])?;
    if release.get("name").is_some_and(|v| v.as_str() != Some(""))
        || string(&release["uri"])? != purl
        || digest(&release["digest"], "sha1", 40)? != commit
    {
        return Err(TrustError::Refused);
    }
    let mut assets = BTreeMap::new();
    for subject in &subjects[1..] {
        let asset = fields(subject, &["name", "digest"], &["uri"])?;
        let name = string(&asset["name"])?;
        if !RELEASE_ASSET_NAMES.contains(&name)
            || asset.get("uri").is_some_and(|v| v.as_str() != Some(""))
            || assets
                .insert(name.into(), digest(&asset["digest"], "sha256", 64)?.into())
                .is_some()
        {
            return Err(TrustError::Refused);
        }
    }
    Ok((tag.into(), assets))
}

/// Inspect only the subject binding; the enclosing DSSE signature is unverified.
/// Like Go, permits other in-toto predicate fields but checks all JSON duplicates.
pub fn inspect_candidate_statement(body: &[u8], manifest: &[u8]) -> Result<()> {
    if manifest.is_empty() || manifest.len() > 1 << 20 {
        return Err(TrustError::Refused);
    }
    let value = json_object(body, MAX_BUNDLE_BYTES)?;
    if value.get("_type").and_then(Value::as_str) != Some("https://in-toto.io/Statement/v1") {
        return Err(TrustError::Refused);
    }
    let subjects = value
        .get("subject")
        .and_then(Value::as_array)
        .ok_or(TrustError::Refused)?;
    if subjects.len() != 1 {
        return Err(TrustError::Refused);
    }
    let subject = subjects[0].as_object().ok_or(TrustError::Refused)?;
    if subject.get("name").and_then(Value::as_str) != Some("qualification-manifest.json")
        || digest(
            subject.get("digest").ok_or(TrustError::Refused)?,
            "sha256",
            64,
        )? != sha256_hex(manifest)
    {
        return Err(TrustError::Refused);
    }
    Ok(())
}

pub enum UnverifiedBundle {
    Inline(Vec<u8>),
    SnappyUrl(String),
}
impl fmt::Debug for UnverifiedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(_) => f.write_str("Inline(<unverified bundle>)"),
            Self::SnappyUrl(_) => f.write_str("SnappyUrl(<unverified URL>)"),
        }
    }
}
#[derive(Debug)]
pub struct NativeAttestations {
    bundles: Vec<UnverifiedBundle>,
}
impl NativeAttestations {
    pub fn decode(
        body: &[u8],
        link_header_present: bool,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        budget.check()?;
        if link_header_present {
            return Err(TrustError::Refused);
        }
        let response = json_object(body, MAX_BUNDLE_BYTES)?;
        let entries = response
            .get("attestations")
            .and_then(Value::as_array)
            .ok_or(TrustError::Refused)?;
        if entries.is_empty() || entries.len() > MAX_NATIVE_PROOFS {
            return Err(TrustError::Refused);
        }
        let mut bundles = Vec::with_capacity(entries.len());
        for entry in entries {
            budget.check()?;
            let entry = entry.as_object().ok_or(TrustError::Refused)?;
            if entry.get("initiator").and_then(Value::as_str) != Some("github") {
                return Err(TrustError::Refused);
            }
            let bundle = if let Some(inline) = entry.get("bundle").filter(|v| !v.is_null()) {
                if !inline.is_object() {
                    return Err(TrustError::Refused);
                }
                let bytes = serde_json::to_vec(inline).map_err(|_| TrustError::Refused)?;
                if bytes.len() > MAX_BUNDLE_BYTES {
                    return Err(TrustError::Refused);
                }
                UnverifiedBundle::Inline(bytes)
            } else {
                let url = entry
                    .get("bundle_url")
                    .and_then(Value::as_str)
                    .ok_or(TrustError::Refused)?;
                let path = url
                    .strip_prefix("https://tmaproduction.blob.core.windows.net/")
                    .ok_or(TrustError::Refused)?;
                if path.is_empty()
                    || !url.is_ascii()
                    || url
                        .bytes()
                        .any(|b| b <= b' ' || matches!(b, b'\\' | b'#' | 127))
                {
                    return Err(TrustError::Refused);
                }
                UnverifiedBundle::SnappyUrl(url.into())
            };
            bundles.push(bundle);
        }
        budget.check()?;
        Ok(Self { bundles })
    }
    pub fn bundles(&self) -> &[UnverifiedBundle] {
        &self.bundles
    }
    /// Acquire bounded, strict-JSON bundle bytes. The result is unverified.
    pub fn acquire_bundle(
        &self,
        index: usize,
        transport: &mut impl AcquisitionTransport,
        budget: &SelectionBudget,
    ) -> Result<Vec<u8>> {
        resolve_bundle(
            self.bundles.get(index).ok_or(TrustError::Refused)?,
            transport,
            budget,
        )
    }
}

/// Only canonical read-only public API requests are constructible here.
#[derive(Debug)]
pub struct AcquisitionRequest {
    url: String,
    limit: usize,
    json: bool,
}
impl AcquisitionRequest {
    pub(crate) fn latest_metadata() -> Self {
        Self {
            url: format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
            limit: crate::release_identity::MAX_INDEX_BYTES,
            json: true,
        }
    }
    pub(crate) fn release_metadata(tag: &str) -> Result<Self> {
        ReleaseIdentity::new(tag, &"a".repeat(40), &"b".repeat(64))
            .map_err(|_| TrustError::Refused)?;
        Ok(Self {
            url: format!("https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}"),
            limit: crate::release_identity::MAX_INDEX_BYTES,
            json: true,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn accept(&self) -> &'static str {
        if self.json {
            "application/vnd.github+json"
        } else {
            "application/octet-stream"
        }
    }
    pub fn max_bytes(&self) -> usize {
        self.limit
    }
    /// Transports must independently enforce HTTPS, reject userinfo and
    /// nondefault ports, and cap redirects at four. No request carries credentials.
    pub fn permits_redirect(&self, url: &str, hops: usize) -> bool {
        if hops > 4 {
            return false;
        }
        let Some(tail) = url.strip_prefix("https://") else {
            return false;
        };
        let authority = tail.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.strip_suffix(":443").unwrap_or(authority);
        !url.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\')
            && !tail.contains('#')
            && !host.is_empty()
            && (host == "release-assets.githubusercontent.com"
                || host
                    .strip_suffix(".githubusercontent.com")
                    .is_some_and(|prefix| {
                        prefix.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && !label.starts_with('-')
                                && !label.ends_with('-')
                                && label
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        })
                    }))
    }
}
pub struct AcquisitionResponse {
    status: u16,
    body: Box<dyn Read>,
    link_header_present: bool,
}
impl AcquisitionResponse {
    pub fn new(status: u16, body: impl Read + 'static, link_header_present: bool) -> Self {
        Self {
            status,
            body: Box::new(body),
            link_header_present,
        }
    }
}
/// Trusted code boundary for HTTP only; it must enforce request redirect policy,
/// the supplied deadline and cancellation throughout I/O. The native transport
/// is release_https::HttpsTransport. There is no signature-verification callback.
pub trait AcquisitionTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse>;
}
pub fn acquire_native_attestations(
    transport: &mut impl AcquisitionTransport,
    commit: &str,
    budget: &SelectionBudget,
) -> Result<NativeAttestations> {
    VerificationPolicy::native_release(commit)?;
    let request = AcquisitionRequest {
        url: format!(
            "https://api.github.com/repos/{REPOSITORY}/attestations/sha1:{commit}?predicate_type=release&per_page=100"
        ),
        limit: MAX_BUNDLE_BYTES,
        json: true,
    };
    budget.check()?;
    let response = transport.get(&request, budget)?;
    let paginated = response.link_header_present;
    let body = read_response(response, request.limit, budget)?;
    NativeAttestations::decode(&body, paginated, budget)
}
/// Reads exact bytes only. The AssetProof and returned bytes remain untrusted
/// until a cryptographic release verifier authenticates the proof's provenance.
pub fn acquire_digest_checked_asset(
    transport: &mut impl AcquisitionTransport,
    asset_id: u64,
    proof: &AssetProof,
    budget: &SelectionBudget,
) -> Result<Vec<u8>> {
    if asset_id == 0 {
        return Err(TrustError::Refused);
    }
    let size = usize::try_from(proof.size()).map_err(|_| TrustError::Refused)?;
    let request = AcquisitionRequest {
        url: format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"),
        limit: size,
        json: false,
    };
    budget.check()?;
    let response = transport.get(&request, budget)?;
    let body = read_response(response, size, budget)?;
    if body.len() != size || sha256_hex(&body) != proof.sha256() {
        return Err(TrustError::Refused);
    }
    budget.check()?;
    Ok(body)
}
/// All selected native claims were authenticated under the fixed release policy.
/// Index decoding, Acceptance Record, release metadata and qualification checks
/// remain required before treating the release as Qualified Stable Release.
#[derive(Debug)]
pub struct VerifiedNativeReleaseClaims {
    identity: ReleaseIdentity,
    proof_count: usize,
    assets: BTreeMap<String, AssetProof>,
}
impl VerifiedNativeReleaseClaims {
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }
    pub fn proof_count(&self) -> usize {
        self.proof_count
    }
    /// Use this authenticated proof for acquire_digest_checked_asset; metadata
    /// supplied independently by a server retains no authentication authority.
    pub fn asset(&self, name: &str) -> Option<&AssetProof> {
        self.assets.get(name)
    }
}

/// Authenticate EVERY proof before accepting the requested tag. Other-tag
/// proofs must also authenticate and pass strict repository/commit parsing.
pub fn verify_native_release(
    transport: &mut impl AcquisitionTransport,
    expected: &ExpectedRelease,
    budget: &SelectionBudget,
) -> Result<VerifiedNativeReleaseClaims> {
    let proofs = acquire_native_attestations(transport, expected.identity.commit(), budget)?;
    let policy = VerificationPolicy::native_release(expected.identity.commit())?;
    let mut matched = false;
    for index in 0..proofs.bundles.len() {
        budget.check()?;
        let body = proofs.acquire_bundle(index, transport, budget)?;
        let statement = verify_bundle(&body, &policy, budget)?;
        matched |= native_claim_matches(statement.payload(), expected)?;
        budget.check()?;
    }
    if !matched {
        return Err(TrustError::Refused);
    }
    budget.check()?;
    Ok(VerifiedNativeReleaseClaims {
        identity: expected.identity.clone(),
        proof_count: proofs.bundles.len(),
        assets: expected.assets.clone(),
    })
}

fn resolve_bundle(
    source: &UnverifiedBundle,
    transport: &mut impl AcquisitionTransport,
    budget: &SelectionBudget,
) -> Result<Vec<u8>> {
    budget.check()?;
    let body = match source {
        UnverifiedBundle::Inline(bytes) => bytes.clone(),
        UnverifiedBundle::SnappyUrl(url) => {
            let request = AcquisitionRequest {
                url: url.clone(),
                limit: MAX_BUNDLE_BYTES,
                json: false,
            };
            let response = transport.get(&request, budget)?;
            let compressed = read_response(response, request.limit, budget)?;
            let size = snap::raw::decompress_len(&compressed).map_err(|_| TrustError::Refused)?;
            if size == 0 || size > MAX_BUNDLE_BYTES {
                return Err(TrustError::Refused);
            }
            let mut body = vec![0; size];
            let written = snap::raw::Decoder::new()
                .decompress(&compressed, &mut body)
                .map_err(|_| TrustError::Refused)?;
            if written != size {
                return Err(TrustError::Refused);
            }
            body
        }
    };
    budget.check()?;
    json_object(&body, MAX_BUNDLE_BYTES)?;
    budget.check()?;
    Ok(body)
}
/// Exact metadata JSON must be a complete response. Binary asset readers do
/// not interpret Link, and native proof pages also validate it when decoding.
pub(crate) fn read_complete_json_response(
    response: AcquisitionResponse,
    limit: usize,
    budget: &SelectionBudget,
) -> Result<Vec<u8>> {
    budget.check()?;
    if response.link_header_present {
        return Err(TrustError::Refused);
    }
    read_response(response, limit, budget)
}
pub(crate) fn read_response(
    mut response: AcquisitionResponse,
    limit: usize,
    budget: &SelectionBudget,
) -> Result<Vec<u8>> {
    budget.check()?;
    if response.status == 408 || response.status == 429 || response.status >= 500 {
        return Err(TrustError::Unavailable);
    }
    if response.status != 200 {
        return Err(TrustError::Refused);
    }
    let mut body = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        budget.check()?;
        let available = chunk.len().min(limit + 1 - body.len());
        let count = response
            .body
            .read(&mut chunk[..available])
            .map_err(|_| TrustError::Unavailable)?;
        budget.check()?;
        if count > available {
            return Err(TrustError::Refused);
        }
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
        if body.len() > limit {
            return Err(TrustError::Refused);
        }
    }
    if body.is_empty() {
        return Err(TrustError::Refused);
    }
    Ok(body)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// The Go backend uses strict protojson. The maintained Rust backend accepts
// unknown Serde fields, so preserve the release bundle's wire-field boundary
// here; crypto, encodings, algorithms and semantic validity stay in the library.
fn bundle_fields(value: &Value) -> Result<()> {
    let bundle = fields(
        value,
        &["mediaType", "verificationMaterial", "dsseEnvelope"],
        &[],
    )?;
    let envelope = fields(
        &bundle["dsseEnvelope"],
        &["payload", "payloadType", "signatures"],
        &[],
    )?;
    for signature in envelope["signatures"]
        .as_array()
        .ok_or(TrustError::Refused)?
    {
        fields(signature, &["sig"], &["keyid"])?;
    }
    let material = fields(
        &bundle["verificationMaterial"],
        &[],
        &[
            "certificate",
            "x509CertificateChain",
            "tlogEntries",
            "timestampVerificationData",
        ],
    )?;
    let certificate = material.get("certificate").filter(|v| !v.is_null());
    let chain = material
        .get("x509CertificateChain")
        .filter(|v| !v.is_null());
    if certificate.is_some() == chain.is_some() {
        return Err(TrustError::Refused);
    }
    if let Some(certificate) = certificate {
        fields(certificate, &["rawBytes"], &[])?;
    }
    if let Some(chain) = chain {
        let chain = fields(chain, &["certificates"], &[])?;
        for certificate in chain["certificates"]
            .as_array()
            .ok_or(TrustError::Refused)?
        {
            fields(certificate, &["rawBytes"], &[])?;
        }
    }
    if let Some(timestamps) = material
        .get("timestampVerificationData")
        .filter(|v| !v.is_null())
    {
        let timestamps = fields(timestamps, &[], &["rfc3161Timestamps"])?;
        if let Some(tokens) = timestamps.get("rfc3161Timestamps").filter(|v| !v.is_null()) {
            for token in tokens.as_array().ok_or(TrustError::Refused)? {
                fields(token, &["signedTimestamp"], &[])?;
            }
        }
    }
    if let Some(entries) = material.get("tlogEntries").filter(|v| !v.is_null()) {
        for entry in entries.as_array().ok_or(TrustError::Refused)? {
            let entry = fields(
                entry,
                &[],
                &[
                    "logIndex",
                    "logId",
                    "kindVersion",
                    "integratedTime",
                    "inclusionPromise",
                    "inclusionProof",
                    "canonicalizedBody",
                ],
            )?;
            for (name, allowed) in [
                ("logId", &["keyId"][..]),
                ("kindVersion", &["kind", "version"][..]),
                ("inclusionPromise", &["signedEntryTimestamp"][..]),
            ] {
                if let Some(object) = entry.get(name).filter(|v| !v.is_null()) {
                    fields(object, &[], allowed)?;
                }
            }
            if let Some(proof) = entry.get("inclusionProof").filter(|v| !v.is_null()) {
                let proof = fields(
                    proof,
                    &[],
                    &["logIndex", "rootHash", "treeSize", "hashes", "checkpoint"],
                )?;
                if let Some(checkpoint) = proof.get("checkpoint").filter(|v| !v.is_null()) {
                    fields(checkpoint, &[], &["envelope"])?;
                }
            }
        }
    }
    Ok(())
}
fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or(TrustError::Refused)
}
fn fields<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value.as_object().ok_or(TrustError::Refused)?;
    if required.iter().any(|name| !object.contains_key(*name))
        || object
            .keys()
            .any(|name| !required.contains(&name.as_str()) && !optional.contains(&name.as_str()))
    {
        return Err(TrustError::Refused);
    }
    Ok(object)
}
fn digest<'a>(value: &'a Value, algorithm: &str, length: usize) -> Result<&'a str> {
    let object = fields(value, &[algorithm], &[])?;
    let digest = string(&object[algorithm])?;
    if !lower_hex(digest, length) {
        return Err(TrustError::Refused);
    }
    Ok(digest)
}

// Preserve every JSON key before conversion to Value, including escaped aliases
// in ignored API/predicate fields. serde_json's normal Value would overwrite it.
struct Unique<'a>(&'a mut usize);
impl<'de> DeserializeSeed<'de> for Unique<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<Value, D::Error> {
        if *self.0 == 0 {
            return Err(de::Error::custom("JSON node limit"));
        }
        *self.0 -= 1;
        struct UniqueVisitor<'a>(&'a mut usize);
        impl<'de> Visitor<'de> for UniqueVisitor<'_> {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique JSON")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut input: M,
            ) -> std::result::Result<Value, M::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = input.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    object.insert(key, input.next_value_seed(Unique(self.0))?);
                }
                Ok(Value::Object(object))
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut input: S,
            ) -> std::result::Result<Value, S::Error> {
                let mut values = Vec::new();
                while let Some(value) = input.next_element_seed(Unique(self.0))? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
                Ok(Value::String(value.into()))
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| de::Error::custom("invalid JSON number"))
            }
        }
        decoder.deserialize_any(UniqueVisitor(self.0))
    }
}
pub(crate) fn json_object(bytes: &[u8], limit: usize) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(TrustError::Refused);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut remaining_nodes = MAX_JSON_NODES;
    let value = Unique(&mut remaining_nodes)
        .deserialize(&mut decoder)
        .map_err(|_| TrustError::Refused)?;
    decoder.end().map_err(|_| TrustError::Refused)?;
    if !value.is_object() {
        return Err(TrustError::Refused);
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) fn fixture_claims(expected: &ExpectedRelease) -> VerifiedNativeReleaseClaims {
    // Only unit-test binaries can cross this fixture boundary. No runtime switch.
    VerifiedNativeReleaseClaims {
        identity: expected.identity.clone(),
        proof_count: 1,
        assets: expected.assets.clone(),
    }
}
