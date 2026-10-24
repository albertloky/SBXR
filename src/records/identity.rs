use super::{RecordError, decode, encode, lower_hex};
use serde::{Deserialize, Serialize};

pub const REPOSITORY: &str = "albertloky/SBXR";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireReleaseIdentity {
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "Tag")]
    tag: String,
    #[serde(rename = "Commit")]
    commit: String,
    #[serde(rename = "IndexSHA256")]
    index_sha256: String,
}

impl WireReleaseIdentity {
    pub(super) fn valid(&self) -> bool {
        self.repository == REPOSITORY
            && valid_tag(&self.tag, false)
            && lower_hex(&self.commit, 40)
            && lower_hex(&self.index_sha256, 64)
    }
}

/// A validated release identity. Its codec never accepts arbitrary secret fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseIdentity(pub(super) WireReleaseIdentity);
impl ReleaseIdentity {
    pub fn new(tag: &str, commit: &str, index_sha256: &str) -> Result<Self, RecordError> {
        let wire = WireReleaseIdentity {
            repository: REPOSITORY.into(),
            tag: tag.into(),
            commit: commit.into(),
            index_sha256: index_sha256.into(),
        };
        if !wire.valid() {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn tag(&self) -> &str {
        &self.0.tag
    }
    pub fn repository(&self) -> &str {
        &self.0.repository
    }
    pub fn commit(&self) -> &str {
        &self.0.commit
    }
    pub fn index_sha256(&self) -> &str {
        &self.0.index_sha256
    }
}

fn valid_tag(tag: &str, stable: bool) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let (version, suffix) = version
        .split_once('-')
        .map_or((version, None), |(v, s)| (v, Some(s)));
    if suffix.is_some_and(|suffix| {
        stable
            || suffix.is_empty()
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }) {
        return false;
    }
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|s| {
            !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_digit())
                && (!stable || s.len() == 1 || !s.starts_with('0'))
        })
        && (stable || !parts[0].starts_with('0'))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInstalledRecord {
    schema: u32,
    repository: String,
    tag: String,
    commit: String,
    release_index_sha256: String,
    sequence: u64,
    architecture: String,
    executable_sha256: String,
}

/// Record syntax only: decoding does not authenticate a release or executable.
#[derive(Clone, PartialEq, Eq)]
pub struct InstalledRecord(WireInstalledRecord);
impl InstalledRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > 4 * 1024 {
            return Err(RecordError);
        }
        let wire: WireInstalledRecord = decode(bytes)?;
        if wire.schema != 1
            || wire.repository != REPOSITORY
            || !valid_tag(&wire.tag, true)
            || !lower_hex(&wire.commit, 40)
            || !lower_hex(&wire.release_index_sha256, 64)
            || wire.sequence == 0
            || !matches!(wire.architecture.as_str(), "amd64" | "arm64")
            || !lower_hex(&wire.executable_sha256, 64)
        {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let bytes = encode(&self.0)?;
        if bytes.len() > 4 * 1024 {
            return Err(RecordError);
        }
        Ok(bytes)
    }
    pub fn release_identity(&self) -> ReleaseIdentity {
        ReleaseIdentity(WireReleaseIdentity {
            repository: self.0.repository.clone(),
            tag: self.0.tag.clone(),
            commit: self.0.commit.clone(),
            index_sha256: self.0.release_index_sha256.clone(),
        })
    }
    pub fn sequence(&self) -> u64 {
        self.0.sequence
    }
    pub fn architecture(&self) -> &str {
        &self.0.architecture
    }
    pub fn executable_sha256(&self) -> &str {
        &self.0.executable_sha256
    }
}
