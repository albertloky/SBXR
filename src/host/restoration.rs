//! Exact missing-member recovery under committed removal authority. This slice
//! supplies real protected filesystem effects only through an explicit injected
//! root. It does not select a latest release, start code or authorize native work.
use super::{HostError, filesystem::ProtectedFs, locks::HostLock};
use crate::{
    artifact_trust::SelectionBudget,
    durable::OwnershipStore,
    records::{InstalledRecord, MAX_RECORD_BYTES, ReleaseIdentity},
    release_acquisition::AuthenticatedArchive,
    removal::{AuthoritySnapshot, LifecycleFacts, exact_restoration},
};
use rustix::fs::Mode;
use std::path::Path;
const STATE: &str = "var/lib/sbxr";
const CURRENT: &str = "var/lib/sbxr/proxy-ownership.json";
const FINAL: &str = "var/lib/.sbxr-removal.json";
const INSTALLED: &str = "var/lib/sbxr/installed.json";
const EXECUTABLE: &str = "usr/local/bin/sbxr";
const PRIVATE: Mode = Mode::from_raw_mode(0o600);
const EXECUTABLE_MODE: Mode = Mode::from_raw_mode(0o755);
const DIRECTORY: Mode = Mode::from_raw_mode(0o700);

pub struct RestorationHost {
    fs: ProtectedFs,
    guard: HostLock,
    writer: Option<OwnershipStore>,
    authority: AuthoritySnapshot,
    release: ReleaseIdentity,
    #[cfg(test)]
    fault: Option<u8>,
}
/// Proves the restored file pair, never a running process. A native caller must
/// launch and independently authenticate the exact finisher before using it.
pub struct RestoredPair {
    installed: InstalledRecord,
    pub executable_restored: bool,
    pub installed_record_restored: bool,
}
impl RestoredPair {
    pub fn record(&self) -> &InstalledRecord {
        &self.installed
    }
    pub fn code(&self) -> &'static str {
        "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED"
    }
}
impl std::fmt::Debug for RestoredPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Exact removal finisher restored; proxy authority unchanged")
    }
}
fn refused(_: impl std::fmt::Debug) -> HostError {
    HostError::Foreign
}
fn budget_check(budget: &SelectionBudget) -> Result<(), HostError> {
    budget.check().map_err(|_| HostError::Cancelled)
}
impl RestorationHost {
    pub fn injected(root: &Path) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        let fs = ProtectedFs::open(root)?;
        let guard = HostLock::provision(root, fs.uid)?;
        let authority = read_authority(&fs)?;
        let release = authority.restoration_release().map_err(refused)?;
        let writer = if fs.directory_entries(STATE, DIRECTORY)?.is_some() {
            Some(OwnershipStore::open(&root.join(STATE), fs.uid).map_err(refused)?)
        } else {
            None
        };
        let host = Self {
            fs,
            guard,
            writer,
            authority,
            release,
            #[cfg(test)]
            fault: None,
        };
        host.recheck()?;
        Ok(host)
    }
    pub fn release(&self) -> &ReleaseIdentity {
        &self.release
    }
    fn recheck(&self) -> Result<(), HostError> {
        self.guard.verify()?;
        if read_authority(&self.fs)? != self.authority {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn checkpoint(&mut self, point: u8, budget: &SelectionBudget) -> Result<(), HostError> {
        self.recheck()?;
        budget_check(budget)?;
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(HostError::Injected);
        }
        let _ = point;
        Ok(())
    }
    pub fn restore(
        &mut self,
        archive: &AuthenticatedArchive,
        budget: &SelectionBudget,
    ) -> Result<RestoredPair, HostError> {
        self.recheck()?;
        budget_check(budget)?;
        if archive.record().release_identity() != self.release {
            return Err(HostError::Foreign);
        }
        let hash = archive.record().executable_sha256();
        let record = archive.record().encode().map_err(refused)?;
        let executable = archive.executable();
        self.validate_capabilities(executable)?;
        self.fs
            .sync_restoration_directory("usr/local/bin", Mode::from_raw_mode(0o755))?;
        self.fs
            .sync_restoration_directory("var/lib", Mode::from_raw_mode(0o755))?;
        self.check_children(hash)?;
        let present_record = self.member(INSTALLED, &record, PRIVATE)?;
        let present_executable = self.member(EXECUTABLE, executable, EXECUTABLE_MODE)?;
        // Go refuses executable-only residue even if its bytes match. Record
        // publication must precede every executable restoration.
        if present_executable && !present_record {
            return Err(HostError::Foreign);
        }
        let facts = LifecycleFacts {
            release: self.release.clone(),
            valid: true,
            executable_present: present_executable,
            installed_record_present: present_record,
            state_directory_empty: true,
        };
        exact_restoration(&self.authority, facts).map_err(refused)?;
        self.fs
            .validate_restoration_stage(INSTALLED, &record, PRIVATE, hash)?;
        self.fs
            .validate_restoration_stage(EXECUTABLE, executable, EXECUTABLE_MODE, hash)?;
        self.checkpoint(0, budget)?;
        if self.writer.is_none() {
            self.fs.create_restoration_directory(STATE)?;
            self.writer = Some(
                OwnershipStore::open(&self.fs.path().join(STATE), self.fs.uid).map_err(refused)?,
            );
            self.recheck()?;
        }
        if !present_record {
            self.fs
                .prepare_restoration_stage(INSTALLED, &record, PRIVATE, hash, budget)?;
        }
        self.checkpoint(1, budget)?;
        self.fs
            .publish_restoration_stage(INSTALLED, &record, PRIVATE, hash, budget)?;
        self.fs
            .sync_restoration_member(INSTALLED, &record, PRIVATE)?;
        self.fs.sync_restoration_directory(STATE, DIRECTORY)?;
        self.fs
            .sync_restoration_directory("var/lib", Mode::from_raw_mode(0o755))?;
        self.checkpoint(2, budget)?;
        if !present_executable {
            self.fs.prepare_restoration_stage(
                EXECUTABLE,
                executable,
                EXECUTABLE_MODE,
                hash,
                budget,
            )?;
        }
        self.checkpoint(3, budget)?;
        self.fs
            .publish_restoration_stage(EXECUTABLE, executable, EXECUTABLE_MODE, hash, budget)?;
        self.checkpoint(4, budget)?;
        self.fs
            .sync_restoration_member(INSTALLED, &record, PRIVATE)?;
        self.fs
            .sync_restoration_member(EXECUTABLE, executable, EXECUTABLE_MODE)?;
        self.fs.sync_restoration_directory(STATE, DIRECTORY)?;
        self.fs
            .sync_restoration_directory("usr/local/bin", Mode::from_raw_mode(0o755))?;
        self.fs
            .sync_restoration_directory("var/lib", Mode::from_raw_mode(0o755))?;
        self.recheck()?;
        self.check_children(hash)?;
        let (fresh, _) = self
            .fs
            .raw(EXECUTABLE, EXECUTABLE_MODE, executable.len())?
            .ok_or(HostError::Unsafe)?;
        if !self.member(INSTALLED, &record, PRIVATE)? {
            return Err(HostError::Unsafe);
        }
        if fresh != archive.executable() {
            return Err(HostError::Foreign);
        }
        budget_check(budget)?;
        Ok(RestoredPair {
            installed: archive.record().clone(),
            executable_restored: !present_executable,
            installed_record_restored: !present_record,
        })
    }
    fn member(&self, path: &str, body: &[u8], mode: Mode) -> Result<bool, HostError> {
        match self.fs.raw(path, mode, body.len())? {
            Some((bytes, proof)) if bytes == body && proof.gid == self.fs.gid => Ok(true),
            Some(_) => Err(HostError::Foreign),
            None => Ok(false),
        }
    }
    fn check_children(&self, hash: &str) -> Result<(), HostError> {
        let permitted_stage = format!("installed.json.sbxr-restore-{hash}");
        if self
            .fs
            .directory_entries(STATE, DIRECTORY)?
            .is_some_and(|children| {
                children.iter().any(|c| {
                    c != "proxy-ownership.json" && c != "installed.json" && c != &permitted_stage
                })
            })
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn validate_capabilities(&self, executable: &[u8]) -> Result<(), HostError> {
        let body = self
            .authority
            .current
            .as_ref()
            .or(self.authority.finalizer.as_ref())
            .ok_or(HostError::Foreign)?;
        let value: serde_json::Value = serde_json::from_slice(body).map_err(refused)?;
        let contains = |marker: &[u8]| executable.windows(marker.len()).any(|part| part == marker);
        if value.get("tunnel").is_some() && !contains(b"SBXR-DEDICATED-TUNNEL-V1")
            || has_http(&value) && !contains(b"SBXR-SUBSCRIPTION-HTTP-V1")
            || value.get("https_retirement").is_some()
                && !contains(b"SBXR-SUBSCRIPTION-HTTPS-RETIREMENT-V1")
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
fn has_http(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(v) => {
            v.get("http") == Some(&serde_json::Value::Bool(true)) || v.values().any(has_http)
        }
        serde_json::Value::Array(v) => v.iter().any(has_http),
        _ => false,
    }
}
fn read_authority(fs: &ProtectedFs) -> Result<AuthoritySnapshot, HostError> {
    for path in [
        "var/lib/sbxr/proxy-ownership.json.sbxr-next".to_owned(),
        format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
    ] {
        if fs.metadata(&path)?.is_some() {
            return Err(HostError::Foreign);
        }
    }
    let read = |path| -> Result<Option<Vec<u8>>, HostError> {
        Ok(fs
            .raw(path, PRIVATE, MAX_RECORD_BYTES)?
            .map(|(bytes, _)| bytes))
    };
    let result = AuthoritySnapshot {
        current: read(CURRENT)?,
        finalizer: read(FINAL)?,
        staged: None,
    };
    result.restoration_release().map_err(refused)?;
    Ok(result)
}
#[cfg(test)]
#[path = "restoration_tests.rs"]
mod tests;
