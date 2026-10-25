//! Fixed existing root-only qualification handoff. Selection is not authentication
//! or activation. NativeAdmission verifies the staged and delivered signatures.
use super::{
    HostError,
    filesystem::{Evidence, ProtectedFs},
};
use crate::{
    artifact_trust::{self as trust, SelectionBudget},
    records::{InstalledRecord, ReleaseIdentity, sha256_hex},
};
use rustix::fs::Mode;
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const DIRECTORY: &str = "root/sbxr-qualification-v3";
const FILES: [(&str, usize); 7] = [
    ("qualification-manifest.json", 1 << 20),
    ("qualification.bundle", trust::MAX_BUNDLE_BYTES),
    ("ca.crt", 32 << 10),
    ("staging-owned", 64),
    ("transport-owned", 0),
    ("deadline", 32),
    ("runtime-deadline", 32),
];
fn refused(_: impl std::fmt::Debug) -> HostError {
    HostError::Foreign
}
pub(in crate::host) fn now() -> Result<u64, HostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(refused)
}
type FileStamp = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
struct HeldFile {
    name: &'static str,
    limit: usize,
    mode: Mode,
    file: File,
    bytes: Vec<u8>,
    evidence: Evidence,
    stamp: FileStamp,
}
fn stamp(file: &File) -> Result<FileStamp, HostError> {
    let m = file.metadata().map_err(refused)?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.size(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
impl HeldFile {
    fn read(fs: &ProtectedFs, name: &'static str, limit: usize) -> Result<Self, HostError> {
        let modes: &[Mode] = if matches!(name, "ca.crt" | "staging-owned") {
            &[Mode::from_raw_mode(0o600), Mode::from_raw_mode(0o644)]
        } else {
            &[Mode::from_raw_mode(0o600)]
        };
        let mut chosen = None;
        for m in modes {
            if let Ok(file) = fs.retain_regular(name, *m, limit) {
                chosen = Some((file, *m));
                break;
            }
        }
        let ((file, bytes, evidence), mode) = chosen.ok_or(HostError::Foreign)?;
        if evidence.gid != fs.gid {
            return Err(HostError::Foreign);
        }
        let original = stamp(&file)?;
        Ok(Self {
            name,
            limit,
            mode,
            file,
            bytes,
            evidence,
            stamp: original,
        })
    }
    fn verify(&self, fs: &ProtectedFs) -> Result<(), HostError> {
        let current = fs
            .raw(self.name, self.mode, self.limit)?
            .ok_or(HostError::Foreign)?;
        if current.0 != self.bytes || current.1 != self.evidence || stamp(&self.file)? != self.stamp
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
pub(in crate::host) enum EntryInput {
    Stable,
    Candidate(Arc<ProtectedCandidateInput>),
}
/// The protected source selection remains unverified until real Sigstore checks.
/// This type cannot serve as InstalledEvidence or native activation authority.
pub(in crate::host) struct ProtectedCandidateInput {
    fs: ProtectedFs,
    files: Vec<HeldFile>,
    identity: ReleaseIdentity,
    sequence: u64,
    ca_sha256: String,
    manifest_sha256: String,
    runtime_deadline: u64,
    until: Instant,
}
impl std::fmt::Debug for ProtectedCandidateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Protected candidate input (unverified delivery)")
    }
}
fn positive(text: &str) -> Option<u64> {
    let n = text.parse::<u64>().ok()?;
    (n > 0 && n.to_string() == text).then_some(n)
}
fn deadline(bytes: &[u8]) -> Result<u64, HostError> {
    let s = std::str::from_utf8(bytes).map_err(refused)?;
    let s = s.strip_suffix('\n').ok_or(HostError::Foreign)?;
    positive(s).ok_or(HostError::Foreign)
}
/// Called by the actual zero-argument entry. Absence alone selects public stable;
/// any existing incomplete, unsafe, stale or contradictory handoff refuses.
pub(in crate::host) fn select(fs: &ProtectedFs, time: u64) -> Result<EntryInput, HostError> {
    if fs.metadata(DIRECTORY)?.is_none() {
        return Ok(EntryInput::Stable);
    }
    let directory = fs.path().join(DIRECTORY);
    let stage = ProtectedFs::open(&directory)?;
    if stage.uid != fs.uid || stage.gid != fs.gid {
        return Err(HostError::Foreign);
    }
    let files = FILES
        .iter()
        .map(|(name, limit)| HeldFile::read(&stage, name, *limit))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = &files[0].bytes;
    let (identity, sequence) =
        crate::release_acquisition::inspect_candidate_handoff(manifest).map_err(refused)?;
    let document = trust::json_object(manifest, 1 << 20).map_err(refused)?;
    let run = document["workflow"]["run_id"]
        .as_str()
        .filter(|v| positive(v).is_some())
        .ok_or(HostError::Foreign)?;
    let attempt = document["v3_attempt"]["run_attempt"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(HostError::Foreign)?;
    if files[3].bytes != format!("{run}-{attempt}\n").as_bytes() || !files[4].bytes.is_empty() {
        return Err(HostError::Foreign);
    }
    trust::json_object(&files[1].bytes, trust::MAX_BUNDLE_BYTES).map_err(refused)?;
    crate::release_https::inspect_gateway_ca(&files[2].bytes).map_err(refused)?;
    let finish = deadline(&files[5].bytes)?;
    let runtime = deadline(&files[6].bytes)?;
    if finish.checked_sub(60) != Some(runtime)
        || runtime <= time
        || finish > time.saturating_add(21600)
    {
        return Err(HostError::Foreign);
    }
    let value = ProtectedCandidateInput {
        ca_sha256: sha256_hex(&files[2].bytes),
        manifest_sha256: sha256_hex(manifest),
        fs: stage,
        files,
        identity,
        sequence,
        runtime_deadline: runtime,
        until: Instant::now() + Duration::from_secs(runtime - time),
    };
    value.verify(time)?;
    Ok(EntryInput::Candidate(Arc::new(value)))
}
impl ProtectedCandidateInput {
    pub(in crate::host) fn verify(&self, time: u64) -> Result<(), HostError> {
        if time >= self.runtime_deadline || Instant::now() >= self.until {
            return Err(HostError::Foreign);
        }
        for file in &self.files {
            file.verify(&self.fs)?;
        }
        Ok(())
    }
    pub(in crate::host) fn authenticate(&self, budget: &SelectionBudget) -> Result<(), HostError> {
        self.verify(now()?)?;
        trust::verify_candidate_manifest(&self.files[1].bytes, &self.files[0].bytes, budget)
            .map_err(|e| match e {
                trust::TrustError::Interrupted => HostError::Cancelled,
                _ => HostError::Foreign,
            })?;
        self.verify(now()?)
    }
    pub(in crate::host) fn ca_sha256(&self) -> &str {
        &self.ca_sha256
    }
    pub(in crate::host) fn verify_record(
        &self,
        record: &InstalledRecord,
        time: u64,
    ) -> Result<(), HostError> {
        self.verify(time)?;
        if record.release_identity() != self.identity || record.sequence() != self.sequence {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(in crate::host) fn verify_manifest(
        &self,
        digest: &str,
        time: u64,
    ) -> Result<(), HostError> {
        self.verify(time)?;
        if digest != self.manifest_sha256 {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(in crate::host) fn selection_deadline(&self) -> Instant {
        self.until
    }
}
#[cfg(test)]
#[path = "entry_input_tests.rs"]
pub(in crate::host) mod tests;
