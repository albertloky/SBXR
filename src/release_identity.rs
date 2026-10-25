//! Offline release-index, executable-trailer and Linux artifact inspection.
//!
//! These checks bind supplied bytes. They do not verify an attestation, signer,
//! trusted root, transparency log, qualification or publication eligibility.
//! Rust inspection requires the explicit `.sbxr.rust` build statement below,
//! pinned compiler comment, static ELF64 and matching trailer/target/commit.
//! Historical Go artifacts retain their `.gopclntab` and Go 1.26.6 build proof.
use crate::records::{InstalledRecord, sha256_hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const REPOSITORY: &str = "albertloky/SBXR";
pub const MAX_INDEX_BYTES: usize = 1 << 20;
pub const MAX_EXECUTABLE_BYTES: usize = 256 << 20;
pub const MAX_IDENTITY_BYTES: usize = 4 << 10;
pub const IDENTITY_MAGIC: &[u8] = b"SBXR-IDENTITY-V1";
pub const INDEXED_ASSET_NAMES: [&str; 3] = [
    "install.sh",
    "sbxr-linux-amd64.tar.gz",
    "sbxr-linux-arm64.tar.gz",
];
pub const RELEASE_ASSET_NAMES: [&str; 4] = [
    "install.sh",
    "release-index.json",
    "sbxr-linux-amd64.tar.gz",
    "sbxr-linux-arm64.tar.gz",
];
pub const SUBSCRIPTION_UPDATE_CONTRACT: &str = "sbxr-subscription-update-v1";
pub const RUST_ARTIFACT_SECTION: &str = ".sbxr.rust";
pub const RUST_COMPILER: &str = crate::build_metadata::COMPILER;
pub const RUST_COMPILER_COMMENT: &[u8] = crate::build_metadata::COMPILER_COMMENT;

/// Secret-free refusal: raw documents, build settings and payloads are omitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseError;
impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid or unsupported release evidence")
    }
}
impl std::error::Error for ReleaseError {}
type Result<T> = std::result::Result<T, ReleaseError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    Amd64,
    Arm64,
}
impl Architecture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }
    pub fn rust_target(self) -> &'static str {
        match self {
            Self::Amd64 => "x86_64-unknown-linux-musl",
            Self::Arm64 => "aarch64-unknown-linux-musl",
        }
    }
}
fn lower_hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}
fn valid_release(tag: &str, commit: &str, sequence: u64) -> bool {
    valid_tag(tag) && lower_hex(commit, 40) && sequence > 0
}

// Typed struct visitors reject unknown/duplicate (also escaped duplicate) keys;
// map-only wrappers additionally refuse Serde's positional struct representation.
fn object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> std::result::Result<T, D::Error> {
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            map: M,
        ) -> std::result::Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(Visitor(std::marker::PhantomData))
}
fn objects<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> std::result::Result<Vec<T>, D::Error> {
    struct Entry<T>(T);
    impl<'de, T: Deserialize<'de>> Deserialize<'de> for Entry<T> {
        fn deserialize<D: serde::Deserializer<'de>>(
            decoder: D,
        ) -> std::result::Result<Self, D::Error> {
            object(decoder).map(Self)
        }
    }
    Vec::<Entry<T>>::deserialize(decoder)
        .map(|entries| entries.into_iter().map(|entry| entry.0).collect())
}
fn optional_object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> std::result::Result<Option<T>, D::Error> {
    object(decoder).map(Some)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ReleaseError);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = object(&mut decoder).map_err(|_| ReleaseError)?;
    decoder.end().map_err(|_| ReleaseError)?;
    Ok(value)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| ReleaseError)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssetProof {
    name: String,
    size: u64,
    sha256: String,
}
impl<'de> Deserialize<'de> for AssetProof {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: String,
            size: u64,
            sha256: String,
        }
        let wire: Wire = object(decoder)?;
        Self::new(&wire.name, wire.size, &wire.sha256).map_err(serde::de::Error::custom)
    }
}
impl AssetProof {
    pub fn new(name: &str, size: u64, sha256: &str) -> Result<Self> {
        let proof = Self {
            name: name.into(),
            size,
            sha256: sha256.into(),
        };
        if !proof.valid() {
            return Err(ReleaseError);
        }
        Ok(proof)
    }
    pub fn for_bytes(name: &str, bytes: &[u8]) -> Result<Self> {
        Self::new(name, bytes.len() as u64, &sha256_hex(bytes))
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    fn valid(&self) -> bool {
        RELEASE_ASSET_NAMES.contains(&self.name.as_str())
            && self.size > 0
            && self.size
                <= (if matches!(self.name.as_str(), "install.sh" | "release-index.json") {
                    MAX_INDEX_BYTES
                } else {
                    MAX_EXECUTABLE_BYTES
                }) as u64
            && lower_hex(&self.sha256, 64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupportScope {
    #[serde(rename = "first-subscription-clean-install")]
    FirstCleanInstall,
    #[serde(rename = "subscription-clean-install-repair")]
    CleanInstallRepair,
    #[serde(rename = "subscription-clean-install-only")]
    CleanInstallOnly,
    #[serde(rename = "recurring-subscription-upgrade")]
    RecurringUpgrade,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "Tag")]
    tag: String,
    #[serde(rename = "Commit")]
    commit: String,
    #[serde(rename = "IndexSHA256")]
    index_sha256: String,
}
impl SourceIdentity {
    fn identity(&self) -> Result<ReleaseIdentity> {
        if self.repository != REPOSITORY || !valid_tag(&self.tag) {
            return Err(ReleaseError);
        }
        ReleaseIdentity::new(&self.tag, &self.commit, &self.index_sha256)
    }
}
/// Exact stable release identity, including historical major-zero tags. Ownership
/// records impose their own resource-admission rules on release identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseIdentity(SourceIdentity);
impl ReleaseIdentity {
    pub fn new(tag: &str, commit: &str, index_sha256: &str) -> Result<Self> {
        if !valid_release(tag, commit, 1) || !lower_hex(index_sha256, 64) {
            return Err(ReleaseError);
        }
        Ok(Self(SourceIdentity {
            repository: REPOSITORY.into(),
            tag: tag.into(),
            commit: commit.into(),
            index_sha256: index_sha256.into(),
        }))
    }
    pub fn repository(&self) -> &str {
        &self.0.repository
    }
    pub fn tag(&self) -> &str {
        &self.0.tag
    }
    pub fn commit(&self) -> &str {
        &self.0.commit
    }
    pub fn index_sha256(&self) -> &str {
        &self.0.index_sha256
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReleaseSupport {
    scope: SupportScope,
    sources: Vec<SourceIdentity>,
    contract: String,
}
impl<'de> Deserialize<'de> for ReleaseSupport {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            scope: SupportScope,
            #[serde(deserialize_with = "objects")]
            sources: Vec<SourceIdentity>,
            contract: String,
        }
        let wire: Wire = object(decoder)?;
        let support = Self {
            scope: wire.scope,
            sources: wire.sources,
            contract: wire.contract,
        };
        support.validate().map_err(serde::de::Error::custom)?;
        Ok(support)
    }
}
impl ReleaseSupport {
    pub fn new(scope: SupportScope, sources: Vec<ReleaseIdentity>) -> Result<Self> {
        let support = Self {
            scope,
            sources: sources
                .iter()
                .map(|identity| SourceIdentity {
                    repository: identity.repository().into(),
                    tag: identity.tag().into(),
                    commit: identity.commit().into(),
                    index_sha256: identity.index_sha256().into(),
                })
                .collect(),
            contract: SUBSCRIPTION_UPDATE_CONTRACT.into(),
        };
        support.validate()?;
        Ok(support)
    }
    pub fn scope(&self) -> SupportScope {
        self.scope
    }
    pub fn sources(&self) -> Vec<ReleaseIdentity> {
        self.sources
            .iter()
            .map(|source| source.identity().expect("validated release support"))
            .collect()
    }
    pub fn contract(&self) -> &str {
        &self.contract
    }
    fn validate(&self) -> Result<()> {
        if self.contract != SUBSCRIPTION_UPDATE_CONTRACT
            || self.sources.len() > 32
            || (self.scope == SupportScope::RecurringUpgrade) == self.sources.is_empty()
        {
            return Err(ReleaseError);
        }
        let mut seen = BTreeSet::new();
        for source in &self.sources {
            source.identity()?;
            if !seen.insert((
                &source.repository,
                &source.tag,
                &source.commit,
                &source.index_sha256,
            )) {
                return Err(ReleaseError);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexDocument {
    schema: u32,
    repository: String,
    tag: String,
    commit: String,
    sequence: u64,
    #[serde(deserialize_with = "objects")]
    assets: Vec<AssetProof>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_object"
    )]
    support: Option<ReleaseSupport>,
}
impl IndexDocument {
    fn validate(&self) -> Result<()> {
        if self.repository != REPOSITORY
            || !valid_release(&self.tag, &self.commit, self.sequence)
            || !matches!((self.schema, &self.support), (1, None) | (2, Some(_)))
            || self.assets.len() != INDEXED_ASSET_NAMES.len()
        {
            return Err(ReleaseError);
        }
        for (asset, expected) in self.assets.iter().zip(INDEXED_ASSET_NAMES) {
            if !asset.valid() || asset.name != expected {
                return Err(ReleaseError);
            }
        }
        if let Some(support) = &self.support {
            support.validate()?;
        }
        Ok(())
    }
}
/// Parsed bytes and internally consistent claims; no external authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseIndex {
    document: IndexDocument,
    bytes: Vec<u8>,
}
impl ReleaseIndex {
    pub fn build(
        tag: &str,
        commit: &str,
        sequence: u64,
        assets: Vec<AssetProof>,
        support: Option<ReleaseSupport>,
    ) -> Result<Self> {
        let document = IndexDocument {
            schema: if support.is_some() { 2 } else { 1 },
            repository: REPOSITORY.into(),
            tag: tag.into(),
            commit: commit.into(),
            sequence,
            assets,
            support,
        };
        document.validate()?;
        Self::decode(&encode(&document)?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let document: IndexDocument = decode(bytes, MAX_INDEX_BYTES)?;
        document.validate()?;
        Ok(Self {
            document,
            bytes: bytes.to_vec(),
        })
    }
    /// Exact supplied bytes, including any whitespace, are the digest subject.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Go field order, compact JSON, no trailing newline. Does not change bytes().
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        encode(&self.document)
    }
    pub fn identity(&self) -> ReleaseIdentity {
        ReleaseIdentity::new(
            &self.document.tag,
            &self.document.commit,
            &sha256_hex(&self.bytes),
        )
        .expect("validated release index")
    }
    pub fn sequence(&self) -> u64 {
        self.document.sequence
    }
    pub fn assets(&self) -> &[AssetProof] {
        &self.document.assets
    }
    pub fn support(&self) -> Option<&ReleaseSupport> {
        self.document.support.as_ref()
    }
    /// Supplied proofs must come from a separately authenticated source.
    pub fn verify_asset_proofs(
        &self,
        expected: &ReleaseIdentity,
        proofs: &[AssetProof],
    ) -> Result<()> {
        if &self.identity() != expected || proofs.len() != RELEASE_ASSET_NAMES.len() {
            return Err(ReleaseError);
        }
        let mut by_name = BTreeMap::new();
        for proof in proofs {
            if !proof.valid() || by_name.insert(proof.name.as_str(), proof).is_some() {
                return Err(ReleaseError);
            }
        }
        let index_proof = AssetProof::for_bytes("release-index.json", &self.bytes)?;
        if by_name.get("release-index.json") != Some(&&index_proof) {
            return Err(ReleaseError);
        }
        for asset in &self.document.assets {
            if by_name.get(asset.name.as_str()) != Some(&asset) {
                return Err(ReleaseError);
            }
        }
        Ok(())
    }
}
pub fn verify_release_index(
    repository: &str,
    tag: &str,
    commit: &str,
    bytes: &[u8],
    proofs: &[AssetProof],
) -> Result<ReleaseIndex> {
    let index = ReleaseIndex::decode(bytes)?;
    if repository != REPOSITORY || index.document.tag != tag || index.document.commit != commit {
        return Err(ReleaseError);
    }
    index.verify_asset_proofs(&index.identity(), proofs)?;
    Ok(index)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedIdentity {
    schema: u32,
    repository: String,
    tag: String,
    commit: String,
    sequence: u64,
    architecture: Architecture,
    payload_sha256: String,
}
impl EmbeddedIdentity {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.repository != REPOSITORY
            || !valid_release(&self.tag, &self.commit, self.sequence)
            || !lower_hex(&self.payload_sha256, 64)
        {
            return Err(ReleaseError);
        }
        Ok(())
    }
}
/// Stamping binds bytes; it does not establish executable format or authenticity.
pub fn stamp_executable(
    payload: &[u8],
    tag: &str,
    commit: &str,
    sequence: u64,
    architecture: Architecture,
) -> Result<Vec<u8>> {
    if payload.is_empty()
        || payload.len() > MAX_EXECUTABLE_BYTES
        || payload.ends_with(IDENTITY_MAGIC)
    {
        return Err(ReleaseError);
    }
    let identity = EmbeddedIdentity {
        schema: 1,
        repository: REPOSITORY.into(),
        tag: tag.into(),
        commit: commit.into(),
        sequence,
        architecture,
        payload_sha256: sha256_hex(payload),
    };
    identity.validate()?;
    let document = encode(&identity)?;
    let total = payload
        .len()
        .checked_add(document.len() + 32 + 8 + IDENTITY_MAGIC.len())
        .ok_or(ReleaseError)?;
    if document.len() > MAX_IDENTITY_BYTES || total > MAX_EXECUTABLE_BYTES {
        return Err(ReleaseError);
    }
    let mut executable = Vec::with_capacity(total);
    executable.extend_from_slice(payload);
    executable.extend_from_slice(&document);
    executable.extend_from_slice(&Sha256::digest(&document));
    executable.extend_from_slice(&(document.len() as u64).to_le_bytes());
    executable.extend_from_slice(IDENTITY_MAGIC);
    Ok(executable)
}
#[derive(PartialEq, Eq)]
pub struct ExecutableIdentity<'a> {
    identity: EmbeddedIdentity,
    payload: &'a [u8],
}
impl fmt::Debug for ExecutableIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutableIdentity")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl<'a> ExecutableIdentity<'a> {
    pub fn repository(&self) -> &str {
        &self.identity.repository
    }
    pub fn tag(&self) -> &str {
        &self.identity.tag
    }
    pub fn commit(&self) -> &str {
        &self.identity.commit
    }
    pub fn sequence(&self) -> u64 {
        self.identity.sequence
    }
    pub fn architecture(&self) -> Architecture {
        self.identity.architecture
    }
    pub fn payload_sha256(&self) -> &str {
        &self.identity.payload_sha256
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}
pub fn read_executable_identity(executable: &[u8]) -> Result<ExecutableIdentity<'_>> {
    let tail_size = 32 + 8 + IDENTITY_MAGIC.len();
    if executable.len() <= tail_size
        || executable.len() > MAX_EXECUTABLE_BYTES
        || !executable.ends_with(IDENTITY_MAGIC)
    {
        return Err(ReleaseError);
    }
    let length_offset = executable.len() - IDENTITY_MAGIC.len() - 8;
    let length = usize::try_from(u64_at(executable, length_offset)?).map_err(|_| ReleaseError)?;
    if length == 0 || length > MAX_IDENTITY_BYTES || length + tail_size >= executable.len() {
        return Err(ReleaseError);
    }
    let document_offset = executable.len() - tail_size - length;
    let document = &executable[document_offset..document_offset + length];
    if executable[document_offset + length..length_offset] != Sha256::digest(document)[..] {
        return Err(ReleaseError);
    }
    let identity: EmbeddedIdentity = decode(document, MAX_IDENTITY_BYTES)?;
    identity.validate()?;
    let payload = &executable[..document_offset];
    if payload.ends_with(IDENTITY_MAGIC) || sha256_hex(payload) != identity.payload_sha256 {
        return Err(ReleaseError);
    }
    Ok(ExecutableIdentity { identity, payload })
}
/// Matches Go's installed-pair proof. The index digest still needs authentication.
pub fn verify_installed_pair<'a>(
    record: &InstalledRecord,
    executable: &'a [u8],
) -> Result<ExecutableIdentity<'a>> {
    let parsed = read_executable_identity(executable)?;
    let release = record.release_identity();
    if parsed.repository() != release.repository()
        || parsed.tag() != release.tag()
        || parsed.commit() != release.commit()
        || parsed.sequence() != record.sequence()
        || parsed.architecture().as_str() != record.architecture()
        || sha256_hex(executable) != record.executable_sha256()
    {
        return Err(ReleaseError);
    }
    Ok(parsed)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RustArtifactMetadata {
    schema: String,
    repository: String,
    package: String,
    compiler: String,
    target: String,
    profile: String,
    commit: String,
}
/// Build tooling must embed these bytes once as a retained PROGBITS section.
/// It must also retain rustc's `.comment`; this statement is not an attestation.
pub fn rust_artifact_metadata(commit: &str, architecture: Architecture) -> Result<Vec<u8>> {
    crate::build_metadata::metadata(commit, architecture.rust_target()).ok_or(ReleaseError)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    Rust,
    HistoricalGo,
}
/// Structural inspection only. No verifier or authenticated trust result exists here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactInspection {
    kind: ArtifactKind,
    architecture: Architecture,
}
impl ArtifactInspection {
    pub fn kind(self) -> ArtifactKind {
        self.kind
    }
    pub fn architecture(self) -> Architecture {
        self.architecture
    }
}
pub fn inspect_linux_artifact(
    executable: &[u8],
    architecture: Architecture,
) -> Result<ArtifactInspection> {
    let identity = read_executable_identity(executable)?;
    if identity.architecture() != architecture {
        return Err(ReleaseError);
    }
    let elf = Elf::parse(identity.payload(), architecture)?;
    let rust = elf.sections.get(RUST_ARTIFACT_SECTION);
    let go = elf.sections.get(".go.buildinfo");
    let kind = match (rust, go) {
        (Some(section), None) if !elf.sections.contains_key(".gopclntab") => {
            if section.kind != 1 {
                return Err(ReleaseError);
            }
            let metadata: RustArtifactMetadata = decode(section.bytes, MAX_IDENTITY_BYTES)?;
            let expected = rust_artifact_metadata(identity.commit(), architecture)?;
            if section.bytes != expected
                || metadata != decode::<RustArtifactMetadata>(&expected, MAX_IDENTITY_BYTES)?
            {
                return Err(ReleaseError);
            }
            let comment = elf.sections.get(".comment").ok_or(ReleaseError)?;
            if comment.kind != 1 {
                return Err(ReleaseError);
            }
            let mut compiler_comments = 0;
            for entry in comment
                .bytes
                .split(|b| *b == 0)
                .filter(|entry| entry.starts_with(b"rustc version "))
            {
                if entry != RUST_COMPILER_COMMENT {
                    return Err(ReleaseError);
                }
                compiler_comments += 1;
            }
            if compiler_comments != 1 {
                return Err(ReleaseError);
            }
            ArtifactKind::Rust
        }
        (None, Some(section)) => {
            if section.kind != 1
                || !section.address.is_multiple_of(16)
                || elf
                    .sections
                    .get(".gopclntab")
                    .is_none_or(|section| section.kind != 1 || section.bytes.is_empty())
            {
                return Err(ReleaseError);
            }
            inspect_go_build_info(section.bytes, architecture)?;
            ArtifactKind::HistoricalGo
        }
        _ => return Err(ReleaseError),
    };
    Ok(ArtifactInspection { kind, architecture })
}

/// Binds trailer repository/tag/commit/sequence/architecture to this exact index.
/// Archive digest/extraction and external authentication remain the caller's job.
pub fn inspect_release_executable(
    index: &ReleaseIndex,
    executable: &[u8],
    architecture: Architecture,
) -> Result<ArtifactInspection> {
    let identity = read_executable_identity(executable)?;
    if identity.repository() != index.document.repository
        || identity.tag() != index.document.tag
        || identity.commit() != index.document.commit
        || identity.sequence() != index.sequence()
        || identity.architecture() != architecture
    {
        return Err(ReleaseError);
    }
    inspect_linux_artifact(executable, architecture)
}

fn range(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let start = usize::try_from(offset).map_err(|_| ReleaseError)?;
    let count = usize::try_from(size).map_err(|_| ReleaseError)?;
    bytes
        .get(start..start.checked_add(count).ok_or(ReleaseError)?)
        .ok_or(ReleaseError)
}
fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(ReleaseError)?)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ReleaseError)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, offset)?))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, offset)?))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, offset)?))
}
struct Section<'a> {
    kind: u32,
    bytes: &'a [u8],
    flags: u64,
    address: u64,
    offset: u64,
}
struct Elf<'a> {
    sections: BTreeMap<&'a str, Section<'a>>,
}
impl<'a> Elf<'a> {
    fn parse(bytes: &'a [u8], architecture: Architecture) -> Result<Self> {
        if bytes.len() < 64
            || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
            || !matches!(bytes[7], 0 | 3)
            || bytes[8] != 0
            || bytes[9..16].iter().any(|b| *b != 0)
            || !matches!(u16_at(bytes, 16)?, 2 | 3)
            || u32_at(bytes, 20)? != 1
            || u32_at(bytes, 48)? != 0
            || u16_at(bytes, 52)? != 64
            || u16_at(bytes, 54)? != 56
            || u16_at(bytes, 58)? != 64
        {
            return Err(ReleaseError);
        }
        if u16_at(bytes, 18)?
            != match architecture {
                Architecture::Amd64 => 62,
                Architecture::Arm64 => 183,
            }
        {
            return Err(ReleaseError);
        }
        let entry = u64_at(bytes, 24)?;
        let phnum = u16_at(bytes, 56)?;
        let shnum = u16_at(bytes, 60)?;
        let shstrndx = u16_at(bytes, 62)?;
        if entry == 0
            || phnum == 0
            || phnum > 4096
            || !(2..=4096).contains(&shnum)
            || shstrndx == 0
            || shstrndx >= shnum
        {
            return Err(ReleaseError);
        }
        let programs = range(bytes, u64_at(bytes, 32)?, u64::from(phnum) * 56)?;
        let table = range(bytes, u64_at(bytes, 40)?, u64::from(shnum) * 64)?;
        if table[..64].iter().any(|b| *b != 0) {
            return Err(ReleaseError);
        }
        let mut executable_entry = false;
        for program in programs.chunks_exact(56) {
            let kind = u32_at(program, 0)?;
            if kind == 3 {
                return Err(ReleaseError);
            } // PT_INTERP
            let data = range(bytes, u64_at(program, 8)?, u64_at(program, 32)?)?;
            if kind == 2 {
                inspect_dynamic(data)?;
            }
            if kind == 1 {
                let file_size = u64_at(program, 32)?;
                let memory_size = u64_at(program, 40)?;
                let address = u64_at(program, 16)?;
                let align = u64_at(program, 48)?;
                if file_size > memory_size
                    || address.checked_add(memory_size).is_none()
                    || (align > 1
                        && (!align.is_power_of_two()
                            || address % align != u64_at(program, 8)? % align))
                {
                    return Err(ReleaseError);
                }
                if u32_at(program, 4)? & 1 != 0 && entry >= address && entry - address < file_size {
                    executable_entry = true;
                }
            }
        }
        if !executable_entry {
            return Err(ReleaseError);
        }
        let names_header = &table[usize::from(shstrndx) * 64..][..64];
        if u32_at(names_header, 4)? != 3 {
            return Err(ReleaseError);
        }
        let names = range(bytes, u64_at(names_header, 24)?, u64_at(names_header, 32)?)?;
        if names.first() != Some(&0) || names.last() != Some(&0) {
            return Err(ReleaseError);
        }
        let mut sections = BTreeMap::new();
        for header in table.chunks_exact(64).skip(1) {
            let kind = u32_at(header, 4)?;
            let flags = u64_at(header, 8)?;
            let suffix = names
                .get(u32_at(header, 0)? as usize..)
                .ok_or(ReleaseError)?;
            let end = suffix.iter().position(|b| *b == 0).ok_or(ReleaseError)?;
            let name = std::str::from_utf8(&suffix[..end]).map_err(|_| ReleaseError)?;
            if name.is_empty() {
                return Err(ReleaseError);
            }
            let data = if kind == 8 {
                &[]
            } else {
                range(bytes, u64_at(header, 24)?, u64_at(header, 32)?)?
            };
            if kind == 6 {
                inspect_dynamic(data)?;
            }
            if sections
                .insert(
                    name,
                    Section {
                        kind,
                        flags,
                        bytes: data,
                        address: u64_at(header, 16)?,
                        offset: u64_at(header, 24)?,
                    },
                )
                .is_some()
            {
                return Err(ReleaseError);
            }
        }
        for (name, required_flags) in [(".text", 6), (".rodata", 2)] {
            let section = sections.get(name).ok_or(ReleaseError)?;
            if section.kind != 1
                || section.flags & required_flags != required_flags
                || section.bytes.is_empty()
            {
                return Err(ReleaseError);
            }
        }
        let text = sections.get(".text").ok_or(ReleaseError)?;
        if entry < text.address || entry - text.address >= text.bytes.len() as u64 {
            return Err(ReleaseError);
        }
        let mut text_mapped = false;
        for program in programs.chunks_exact(56) {
            if u32_at(program, 0)? != 1 || u32_at(program, 4)? & 1 == 0 {
                continue;
            }
            let address = u64_at(program, 16)?;
            let offset = u64_at(program, 8)?;
            let file_size = u64_at(program, 32)?;
            if text.address >= address
                && text.offset >= offset
                && text.address - address == text.offset - offset
                && (text.offset - offset)
                    .checked_add(text.bytes.len() as u64)
                    .is_some_and(|end| end <= file_size)
            {
                text_mapped = true;
            }
        }
        if !text_mapped {
            return Err(ReleaseError);
        }
        Ok(Self { sections })
    }
}
fn inspect_dynamic(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
        return Err(ReleaseError);
    }
    let mut terminated = false;
    for entry in bytes.chunks_exact(16) {
        let tag = u64_at(entry, 0)?;
        if matches!(
            tag,
            1 | 0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc
        ) || (terminated && entry.iter().any(|b| *b != 0))
        {
            return Err(ReleaseError);
        }
        if tag == 0 {
            terminated = true;
        }
    }
    if !terminated {
        return Err(ReleaseError);
    }
    Ok(())
}

// Go 1.26.6 uses the post-1.18 inline (not pointer) build-info format.
// Source contract: debug/buildinfo and runtime/debug in the preserved toolchain.
fn varstring<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let mut length = 0_u64;
    for i in 0..10 {
        let byte = *bytes.get(*cursor).ok_or(ReleaseError)?;
        *cursor += 1;
        if i == 9 && byte > 1 {
            return Err(ReleaseError);
        }
        length |= u64::from(byte & 127) << (7 * i);
        if byte < 128 {
            if i > 0 && byte == 0 {
                return Err(ReleaseError);
            }
            let value = range(bytes, *cursor as u64, length)?;
            *cursor = cursor.checked_add(value.len()).ok_or(ReleaseError)?;
            return Ok(value);
        }
    }
    Err(ReleaseError)
}
fn inspect_go_build_info(bytes: &[u8], architecture: Architecture) -> Result<()> {
    if bytes.len() < 32
        || bytes.len() > MAX_INDEX_BYTES
        || &bytes[..14] != b"\xff Go buildinf:"
        || bytes[14] != 8
        || bytes[15] != 2
        || bytes[16..32].iter().any(|b| *b != 0)
    {
        return Err(ReleaseError);
    }
    let mut cursor = 32;
    if varstring(bytes, &mut cursor)? != b"go1.26.6" {
        return Err(ReleaseError);
    }
    let module = varstring(bytes, &mut cursor)?;
    if bytes[cursor..].iter().any(|b| *b != 0)
        || module.len() < 33
        || module[module.len() - 17] != b'\n'
    {
        return Err(ReleaseError);
    }
    const START: [u8; 16] = [
        0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18,
        0xe6,
    ];
    const END: [u8; 16] = [
        0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8,
        0xf2,
    ];
    if module[..16] != START || module[module.len() - 16..] != END {
        return Err(ReleaseError);
    }
    let text = std::str::from_utf8(&module[16..module.len() - 16]).map_err(|_| ReleaseError)?;
    let mut settings = BTreeMap::new();
    let mut replacement_allowed = false;
    for line in text.split_terminator('\n') {
        if let Some(setting) = line.strip_prefix("build\t") {
            let (key, value) = go_setting(setting)?;
            if settings.insert(key, value).is_some() {
                return Err(ReleaseError);
            }
        } else if let Some(module) = line
            .strip_prefix("mod\t")
            .or_else(|| line.strip_prefix("dep\t"))
        {
            if !matches!(module.split('\t').count(), 2 | 3) {
                return Err(ReleaseError);
            }
            replacement_allowed = true;
        } else if let Some(module) = line.strip_prefix("=>\t") {
            if !replacement_allowed || module.split('\t').count() != 3 {
                return Err(ReleaseError);
            }
            replacement_allowed = false;
        } else if !line.starts_with("path\t") {
            return Err(ReleaseError);
        }
    }
    for (key, value) in [
        ("GOOS", "linux"),
        ("GOARCH", architecture.as_str()),
        ("CGO_ENABLED", "0"),
    ] {
        if settings.get(key).map(String::as_str) != Some(value) {
            return Err(ReleaseError);
        }
    }
    Ok(())
}
fn go_setting(text: &str) -> Result<(String, String)> {
    let (key, remaining) = if text.starts_with(['"', '`']) {
        let (word, consumed) = go_quoted(text)?;
        (
            word,
            text.get(consumed..)
                .and_then(|rest| rest.strip_prefix('='))
                .ok_or(ReleaseError)?,
        )
    } else {
        let (key, value) = text.split_once('=').ok_or(ReleaseError)?;
        if key.is_empty()
            || key
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '`'))
        {
            return Err(ReleaseError);
        }
        (key.into(), value)
    };
    if key.is_empty() {
        return Err(ReleaseError);
    }
    let value = if remaining.starts_with(['"', '`']) {
        let (value, consumed) = go_quoted(remaining)?;
        if consumed != remaining.len() {
            return Err(ReleaseError);
        }
        value
    } else {
        if remaining
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '`'))
        {
            return Err(ReleaseError);
        }
        remaining.into()
    };
    Ok((key, value))
}
fn go_quoted(text: &str) -> Result<(String, usize)> {
    let bytes = text.as_bytes();
    let quote = *bytes.first().ok_or(ReleaseError)?;
    if quote == b'`' {
        let end = bytes[1..]
            .iter()
            .position(|b| *b == b'`')
            .ok_or(ReleaseError)?
            + 1;
        return Ok((text[1..end].replace('\r', ""), end + 1));
    }
    if quote != b'"' {
        return Err(ReleaseError);
    }
    let mut output = Vec::new();
    let mut i = 1;
    while let Some(&byte) = bytes.get(i) {
        i += 1;
        match byte {
            b'"' => return Ok((String::from_utf8(output).map_err(|_| ReleaseError)?, i)),
            b'\n' | b'\r' | 0..=8 | 11..=31 => return Err(ReleaseError),
            b'\\' => {
                let escape = *bytes.get(i).ok_or(ReleaseError)?;
                i += 1;
                match escape {
                    b'a' => output.push(7),
                    b'b' => output.push(8),
                    b'f' => output.push(12),
                    b'n' => output.push(10),
                    b'r' => output.push(13),
                    b't' => output.push(9),
                    b'v' => output.push(11),
                    b'\\' | b'"' => output.push(escape),
                    b'x' | b'u' | b'U' | b'0'..=b'7' => {
                        let (count, radix, start) = match escape {
                            b'x' => (2, 16, i),
                            b'u' => (4, 16, i),
                            b'U' => (8, 16, i),
                            _ => (3, 8, i - 1),
                        };
                        let digits = bytes.get(start..start + count).ok_or(ReleaseError)?;
                        let digits = std::str::from_utf8(digits).map_err(|_| ReleaseError)?;
                        let value = u32::from_str_radix(digits, radix).map_err(|_| ReleaseError)?;
                        i = start + count;
                        if radix == 8 || escape == b'x' {
                            output.push(u8::try_from(value).map_err(|_| ReleaseError)?);
                        } else {
                            let ch = char::from_u32(value).ok_or(ReleaseError)?;
                            let mut utf8 = [0; 4];
                            output.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                        }
                    }
                    _ => return Err(ReleaseError),
                }
            }
            _ => output.push(byte),
        }
    }
    Err(ReleaseError)
}
