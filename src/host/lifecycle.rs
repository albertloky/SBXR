//! Protected local Software Lifecycle observations and exact removal recovery.
use super::{
    HostError,
    filesystem::{Kind, ProtectedFs, Resource},
    restoration::{RestorationHost, RestoredFinisher},
};
use crate::{
    artifact_trust::SelectionBudget,
    records::{InstalledRecord, ReleaseIdentity, sha256_hex},
    release_acquisition::AuthenticatedArchive,
    release_identity::{self, Architecture},
    removal::AuthoritySnapshot,
};
use rustix::fs::Mode;
use std::path::Path;
const INSTALLED: &str = "var/lib/sbxr/installed.json";
const EXECUTABLE: &str = "usr/local/bin/sbxr";
const TRANSACTIONS: [&str; 6] = [
    "usr/local/bin/.sbxr-update-prior",
    "usr/local/bin/.sbxr-update-candidate",
    "var/lib/sbxr/.installed.json.prior",
    "var/lib/sbxr/.installed.json.candidate",
    "var/lib/sbxr/update.json",
    "var/lib/sbxr/.update.json.next",
];
pub(in crate::host) fn transactions_absent(fs: &ProtectedFs) -> Result<bool, HostError> {
    for path in TRANSACTIONS {
        if fs.metadata(path)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub busy: bool,
    pub transaction: bool,
    pub installed: Option<InstalledRecord>,
    pub restoration: Option<ReleaseIdentity>,
    pub authority: AuthoritySnapshot,
    pub fingerprint: String,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Protected lifecycle snapshot (redacted)")
    }
}
pub struct LifecycleHost {
    fs: ProtectedFs,
}
impl LifecycleHost {
    pub fn injected(root: &Path) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        Ok(Self {
            fs: ProtectedFs::open(root)?,
        })
    }
    pub fn native_unreleased() -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        Ok(Self {
            fs: ProtectedFs::native()?,
        })
    }
    fn read(
        &self,
        path: &str,
        mode: u32,
        limit: usize,
    ) -> Result<Option<(Vec<u8>, String)>, HostError> {
        self.fs
            .raw(
                path,
                Mode::from_raw_mode(mode as rustix::fs::RawMode),
                limit,
            )?
            .map(|(b, p)| {
                if p.gid != self.fs.gid {
                    return Err(HostError::Foreign);
                }
                Ok((b, format!("{p:?}")))
            })
            .transpose()
    }
    pub(crate) fn inspect(&self) -> Result<Snapshot, HostError> {
        let mut s = Snapshot {
            busy: self.fs.lifecycle_lock_held()?,
            transaction: false,
            installed: None,
            restoration: None,
            authority: AuthoritySnapshot::default(),
            fingerprint: String::new(),
        };
        if s.busy {
            return Ok(s);
        }
        s.transaction = !transactions_absent(&self.fs)?;
        if s.transaction {
            return Ok(s);
        }
        if self.fs.metadata("var/lib/sbxr")?.is_some() {
            self.fs
                .observe(Resource {
                    path: "var/lib/sbxr",
                    kind: Kind::Directory(Mode::from_raw_mode(0o700)),
                })?
                .ok_or(HostError::Foreign)?;
            if self
                .fs
                .metadata("var/lib/sbxr")?
                .is_none_or(|m| m.gid != self.fs.gid)
            {
                return Err(HostError::Foreign);
            }
        }
        let record = self.read(INSTALLED, 0o600, 4096)?;
        let executable = self.read(EXECUTABLE, 0o755, release_identity::MAX_EXECUTABLE_BYTES)?;
        let installed = record
            .as_ref()
            .map(|(b, _)| InstalledRecord::decode(b).map_err(|_| HostError::Foreign))
            .transpose()?;
        let mut image = format!(
            "{:?}:{:?}",
            record.as_ref().map(|(b, p)| (sha256_hex(b), p)),
            executable.as_ref().map(|(b, p)| (sha256_hex(b), p))
        );
        match (&installed, &executable) {
            (Some(record), Some((bytes, _))) => {
                release_identity::verify_installed_pair(record, bytes)
                    .map_err(|_| HostError::Foreign)?;
                let arch = architecture(record.architecture())?;
                release_identity::inspect_linux_artifact(bytes, arch)
                    .map_err(|_| HostError::Foreign)?;
                s.installed = Some(record.clone());
            }
            (None, Some(_)) => return Err(HostError::Foreign),
            _ => {
                let read = |path| {
                    self.read(path, 0o600, crate::records::MAX_RECORD_BYTES)
                        .map(|v| v.map(|(b, _)| b))
                };
                s.authority = AuthoritySnapshot {
                    current: read("var/lib/sbxr/proxy-ownership.json")?,
                    staged: read("var/lib/sbxr/.proxy-ownership.json.next")?,
                    finalizer: read("var/lib/.sbxr-removal.json")?,
                };
                if let Ok(release) = s.authority.restoration_release() {
                    if installed
                        .as_ref()
                        .is_some_and(|r| r.release_identity() != release)
                    {
                        return Err(HostError::Foreign);
                    }
                    s.restoration = Some(release);
                }
                image.push_str(&format!("{:?}", s.authority));
            }
        }
        s.busy = self.fs.lifecycle_lock_held()?;
        s.fingerprint = sha256_hex(image.as_bytes());
        Ok(s)
    }
    pub(crate) fn restore(
        &self,
        expected: &Snapshot,
        archive: &AuthenticatedArchive,
        budget: &SelectionBudget,
    ) -> Result<RestoredFinisher, HostError> {
        if self.inspect()? != *expected
            || expected.busy
            || expected.transaction
            || expected.restoration.as_ref() != Some(&archive.record().release_identity())
        {
            return Err(HostError::Foreign);
        }
        if self.fs.path() == Path::new("/") {
            super::require_live_adapter()?;
        }
        let mut host = if self.fs.path() == Path::new("/") {
            RestorationHost::native_unreleased()?
        } else {
            RestorationHost::injected(self.fs.path())?
        };
        if !host.matches_authority(&expected.authority)
            || Some(host.release()) != expected.restoration.as_ref()
        {
            return Err(HostError::Foreign);
        }
        let pair = host.restore(archive, budget)?;
        host.prepare_finisher(pair, budget)
    }
}
pub(crate) fn architecture(value: &str) -> Result<Architecture, HostError> {
    match value {
        "amd64" => Ok(Architecture::Amd64),
        "arm64" => Ok(Architecture::Arm64),
        _ => Err(HostError::Foreign),
    }
}
