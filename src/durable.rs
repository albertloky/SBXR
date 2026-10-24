//! Protected filesystem publication for setup authority, disconnected from main.
//! The directory lock serializes this store only; it does not replace SBXR's
//! production whole-host/package locks or authorize any proxy resource effect.
use crate::records::{MAX_RECORD_BYTES, OwnershipRecord, RecoveryDirection, SetupPhase};
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat},
    io::Errno,
};
use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
};

pub const OWNERSHIP_FILE: &str = "proxy-ownership.json";
pub const STAGED_FILE: &str = ".proxy-ownership.json.next";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    Unchanged,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreErrorKind {
    Unsafe,
    Conflict,
    Busy,
    Io,
    InvalidAuthority,
    Injected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError {
    pub kind: StoreErrorKind,
    pub publication: Publication,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ownership store {:?}; publication {:?}. Reinspect authority before further effects.",
            self.kind, self.publication
        )
    }
}
impl std::error::Error for StoreError {}
fn error(kind: StoreErrorKind) -> StoreError {
    StoreError {
        kind,
        publication: Publication::Unchanged,
    }
}
fn io_error(_: impl fmt::Debug) -> StoreError {
    error(StoreErrorKind::Io)
}

pub struct StoredOwnership {
    pub record: OwnershipRecord,
    bytes: Vec<u8>,
}
impl StoredOwnership {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub struct Snapshot {
    pub current: Option<StoredOwnership>,
    pub staged: Option<StoredOwnership>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    Absent,
    Cleanup,
    FinishSetup,
    Running,
    Refused,
}
impl Snapshot {
    /// Inspection never promotes staging, rewrites bytes, or chooses a new target.
    pub fn recovery(&self) -> Recovery {
        let Some(current) = &self.current else {
            return if self.staged.is_none() {
                Recovery::Absent
            } else {
                Recovery::Refused
            };
        };
        if self.staged.as_ref().is_some_and(|staged| {
            !current.record.permits_successor(&staged.record)
                || current.record.recovery_direction() == RecoveryDirection::Cleanup
                    && staged.record.recovery_direction() != RecoveryDirection::Cleanup
        }) {
            return Recovery::Refused;
        }
        match current.record.recovery_direction() {
            RecoveryDirection::Cleanup => Recovery::Cleanup,
            RecoveryDirection::FinishSetup => Recovery::FinishSetup,
            RecoveryDirection::None => Recovery::Running,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPoint {
    AfterStageCreate,
    #[cfg(test)]
    AfterPartialStageWrite,
    AfterStageWrite,
    AfterStageSync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySync,
}

pub struct OwnershipStore {
    directory: OwnedFd,
    path: PathBuf,
    owner_uid: u32,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}
impl OwnershipStore {
    /// Open an existing 0700 directory. All paths must be absolute and every
    /// component must be a nonsymlink, trusted-owner, non-writable directory.
    /// No directory or lock file is created. Dropping releases the advisory lock.
    pub fn open(path: &Path, owner_uid: u32) -> Result<Self, StoreError> {
        let directory = open_directory(path, owner_uid)?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == Errno::WOULDBLOCK {
                error(StoreErrorKind::Busy)
            } else {
                io_error(e)
            }
        })?;
        Ok(Self {
            directory,
            path: path.into(),
            owner_uid,
            #[cfg(test)]
            fault: None,
        })
    }
    fn check_directory(&self) -> Result<(), StoreError> {
        let current = open_directory(&self.path, self.owner_uid)?;
        if !same_inode(
            &fs::fstat(current).map_err(io_error)?,
            &fs::fstat(&self.directory).map_err(io_error)?,
        ) {
            return Err(error(StoreErrorKind::Unsafe));
        }
        Ok(())
    }
    fn read_file(&self, name: &str) -> Result<Option<(File, Vec<u8>)>, StoreError> {
        self.check_directory()?;
        let before = match fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        if !safe_file(&before, self.owner_uid) {
            return Err(error(StoreErrorKind::Unsafe));
        }
        let fd = fs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io_error)?;
        let opened = fs::fstat(&fd).map_err(io_error)?;
        if !same_inode(&before, &opened) || !safe_file(&opened, self.owner_uid) {
            return Err(error(StoreErrorKind::Unsafe));
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let after =
            fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        if !same_inode(&before, &after)
            || !safe_file(&after, self.owner_uid)
            || bytes.is_empty()
            || bytes.len() > MAX_RECORD_BYTES
            || after.st_size as usize != bytes.len()
        {
            return Err(error(StoreErrorKind::Unsafe));
        }
        Ok(Some((file, bytes)))
    }
    pub fn load(&self) -> Result<Snapshot, StoreError> {
        fn decoded(file: Option<(File, Vec<u8>)>) -> Result<Option<StoredOwnership>, StoreError> {
            file.map(|(_, bytes)| {
                OwnershipRecord::decode(&bytes)
                    .map(|record| StoredOwnership { record, bytes })
                    .map_err(|_| error(StoreErrorKind::InvalidAuthority))
            })
            .transpose()
        }
        Ok(Snapshot {
            current: decoded(self.read_file(OWNERSHIP_FILE)?)?,
            staged: decoded(self.read_file(STAGED_FILE)?)?,
        })
    }
    /// Establish file and directory durability after an uncertain publication,
    /// before a caller performs any effect relying on this authority.
    pub fn synchronize(&self, expected: &[u8]) -> Result<(), StoreError> {
        let (file, bytes) = self
            .read_file(OWNERSHIP_FILE)?
            .ok_or(error(StoreErrorKind::Conflict))?;
        if bytes != expected {
            return Err(error(StoreErrorKind::Conflict));
        }
        file.sync_all().map_err(io_error)?;
        fs::fsync(&self.directory).map_err(io_error)?;
        self.expect_current(Some(expected))
    }
    fn expect_current(&self, expected: Option<&[u8]>) -> Result<(), StoreError> {
        let actual = self.read_file(OWNERSHIP_FILE)?;
        if actual.as_ref().map(|(_, bytes)| bytes.as_slice()) != expected {
            return Err(error(StoreErrorKind::Conflict));
        }
        Ok(())
    }
    /// Publish one exact supported setup/cleanup checkpoint. No external
    /// resource is changed and no missing installed authority is manufactured.
    /// On any error, callers must inspect current and staged files before retry.
    pub fn publish(
        &mut self,
        expected: Option<&[u8]>,
        next: &OwnershipRecord,
    ) -> Result<(), StoreError> {
        let bytes = next
            .encode()
            .map_err(|_| error(StoreErrorKind::InvalidAuthority))?;
        if let Some(expected) = expected {
            let source = OwnershipRecord::decode(expected)
                .map_err(|_| error(StoreErrorKind::InvalidAuthority))?;
            if source
                .encode()
                .map_err(|_| error(StoreErrorKind::InvalidAuthority))?
                != expected
                || !source.permits_successor(next)
            {
                return Err(error(StoreErrorKind::Conflict));
            }
            self.synchronize(expected)?;
        } else if next.phase() != SetupPhase::OwnershipRecorded || next.cleanup_checkpoint() != 0 {
            return Err(error(StoreErrorKind::InvalidAuthority));
        }
        self.expect_current(expected)?;
        let file = if let Some((file, staged)) = self.read_file(STAGED_FILE)? {
            if staged != bytes {
                return Err(error(StoreErrorKind::Conflict));
            }
            file
        } else {
            let fd = fs::openat(
                &self.directory,
                STAGED_FILE,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io_error)?;
            fs::fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(io_error)?;
            let mut file = File::from(fd);
            self.boundary(FaultPoint::AfterStageCreate, Publication::Unchanged)?;
            #[cfg(test)]
            if self.fault == Some(FaultPoint::AfterPartialStageWrite) {
                file.write_all(&bytes[..bytes.len() / 2])
                    .map_err(io_error)?;
                self.boundary(FaultPoint::AfterPartialStageWrite, Publication::Unchanged)?;
            }
            file.write_all(&bytes).map_err(io_error)?;
            self.boundary(FaultPoint::AfterStageWrite, Publication::Unchanged)?;
            file
        };
        file.sync_all().map_err(io_error)?;
        self.boundary(FaultPoint::AfterStageSync, Publication::Unchanged)?;
        self.expect_current(expected)?;
        if self
            .read_file(STAGED_FILE)?
            .as_ref()
            .map(|(_, b)| b.as_slice())
            != Some(bytes.as_slice())
        {
            return Err(error(StoreErrorKind::Conflict));
        }
        self.boundary(FaultPoint::BeforeRename, Publication::Unchanged)?;
        let renamed = if expected.is_none() {
            fs::renameat_with(
                &self.directory,
                STAGED_FILE,
                &self.directory,
                OWNERSHIP_FILE,
                RenameFlags::NOREPLACE,
            )
        } else {
            fs::renameat(
                &self.directory,
                STAGED_FILE,
                &self.directory,
                OWNERSHIP_FILE,
            )
        };
        renamed.map_err(|_| StoreError {
            kind: StoreErrorKind::Io,
            publication: Publication::Uncertain,
        })?;
        self.boundary(FaultPoint::AfterRename, Publication::Uncertain)?;
        self.boundary(FaultPoint::BeforeDirectorySync, Publication::Uncertain)?;
        fs::fsync(&self.directory).map_err(|_| StoreError {
            kind: StoreErrorKind::Io,
            publication: Publication::Uncertain,
        })?;
        self.boundary(FaultPoint::AfterDirectorySync, Publication::Uncertain)?;
        self.expect_current(Some(&bytes)).map_err(|e| StoreError {
            publication: Publication::Uncertain,
            ..e
        })
    }
    /// The journey must freshly prove all proxy resources absent first. This
    /// crate-private primitive cannot delete a partial/committed authority.
    pub(crate) fn remove_completed_cleanup(&mut self, expected: &[u8]) -> Result<(), StoreError> {
        let record = OwnershipRecord::decode(expected)
            .map_err(|_| error(StoreErrorKind::InvalidAuthority))?;
        if record.recovery_direction() != RecoveryDirection::Cleanup
            || record.cleanup_checkpoint() != 8
            || record
                .encode()
                .map_err(|_| error(StoreErrorKind::InvalidAuthority))?
                != expected
        {
            return Err(error(StoreErrorKind::Conflict));
        }
        self.synchronize(expected)?;
        let staged = self.read_file(STAGED_FILE)?;
        if staged.as_ref().is_some_and(|(_, bytes)| bytes != expected) {
            return Err(error(StoreErrorKind::Conflict));
        }
        self.expect_current(Some(expected))?;
        fs::unlinkat(&self.directory, OWNERSHIP_FILE, AtFlags::empty()).map_err(|_| {
            StoreError {
                kind: StoreErrorKind::Io,
                publication: Publication::Uncertain,
            }
        })?;
        if staged.is_some() {
            fs::unlinkat(&self.directory, STAGED_FILE, AtFlags::empty()).map_err(|_| {
                StoreError {
                    kind: StoreErrorKind::Io,
                    publication: Publication::Uncertain,
                }
            })?;
        }
        fs::fsync(&self.directory).map_err(|_| StoreError {
            kind: StoreErrorKind::Io,
            publication: Publication::Uncertain,
        })?;
        self.expect_current(None).map_err(|e| StoreError {
            publication: Publication::Uncertain,
            ..e
        })
    }
    fn boundary(&self, _point: FaultPoint, _publication: Publication) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.fault == Some(_point) {
            return Err(StoreError {
                kind: StoreErrorKind::Injected,
                publication: _publication,
            });
        }
        Ok(())
    }
}
fn same_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}
fn safe_file(stat: &Stat, uid: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_uid == uid
        && stat.st_nlink == 1
        && stat.st_size > 0
        && stat.st_size <= MAX_RECORD_BYTES as i64
}
pub(crate) fn open_directory(path: &Path, owner_uid: u32) -> Result<OwnedFd, StoreError> {
    if !path.is_absolute() {
        return Err(error(StoreErrorKind::Unsafe));
    }
    let mut directory = fs::open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io_error)?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                directory = fs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(io_error)?;
                let stat = fs::fstat(&directory).map_err(io_error)?;
                if stat.st_uid != 0 && stat.st_uid != owner_uid || stat.st_mode & 0o022 != 0 {
                    return Err(error(StoreErrorKind::Unsafe));
                }
            }
            _ => return Err(error(StoreErrorKind::Unsafe)),
        }
    }
    let stat = fs::fstat(&directory).map_err(io_error)?;
    if stat.st_uid != owner_uid || stat.st_mode & 0o7777 != 0o700 {
        return Err(error(StoreErrorKind::Unsafe));
    }
    Ok(directory)
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
