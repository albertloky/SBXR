//! Retained flock and POSIX package exclusion. Never replace/truncate a foreign
//! inode. Package guards are released before apt/dpkg take their own locks.
use super::HostError;
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
    io::Errno,
};
use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::Mutex,
};
pub const MUTATION_LOCK: &str = "run/lock/sbxr.lock";
pub const PACKAGE_LOCKS: &[&str] = &[
    "var/lib/dpkg/lock-frontend",
    "var/lib/dpkg/lock",
    "var/lib/apt/lists/lock",
    "var/cache/apt/archives/lock",
];
fn err(e: Errno) -> HostError {
    if matches!(e, Errno::AGAIN | Errno::ACCESS) {
        HostError::Busy
    } else {
        HostError::Unsafe
    }
}
fn io(_: impl std::fmt::Debug) -> HostError {
    HostError::Io
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}
fn safe_file(s: &Stat, uid: u32, coordination: bool) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
        && s.st_uid == uid
        && s.st_nlink == 1
        && s.st_mode & 0o7133 == 0
        && (!coordination || s.st_mode & 0o7777 == 0o600)
}
pub struct HostLock {
    root: OwnedFd,
    path: PathBuf,
    uid: u32,
    file: Option<OwnedFd>,
    package_guard: Mutex<bool>,
}
/// A runtime-start duplicate cannot outlive the original Owner guard.
pub struct OwnerStartLock<'a> {
    lock: crate::runtime_handoff::StartLock,
    _owner: &'a HostLock,
}
impl OwnerStartLock<'_> {
    pub fn start_lock(&self) -> &crate::runtime_handoff::StartLock {
        &self.lock
    }
}
impl HostLock {
    pub fn acquire(root: &Path, uid: u32) -> Result<Self, HostError> {
        Self::acquire_mode(root, uid, true, true)
    }
    pub fn existing(root: &Path, uid: u32) -> Result<Self, HostError> {
        Self::acquire_mode(root, uid, false, false)
    }
    pub fn provision(root: &Path, uid: u32) -> Result<Self, HostError> {
        Self::acquire_mode(root, uid, true, false)
    }
    fn acquire_mode(root: &Path, uid: u32, create: bool, parents: bool) -> Result<Self, HostError> {
        let descriptor = if root == Path::new("/") {
            super::linux::require_native_environment()?;
            if uid != 0 {
                return Err(HostError::Unsafe);
            }
            fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?
        } else {
            crate::durable::open_directory(root, uid).map_err(|_| HostError::Unsafe)?
        };
        let mut lock = Self {
            root: descriptor,
            path: root.into(),
            uid,
            file: None,
            package_guard: Mutex::new(false),
        };
        let (parent, name) = lock
            .parent(MUTATION_LOCK, parents)?
            .ok_or(HostError::Unsafe)?;
        let file = if create {
            match fs::openat(
                &parent,
                name.as_str(),
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(file) => {
                    fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(io)?;
                    fs::fsync(&file).map_err(io)?;
                    fs::fsync(&parent).map_err(io)?;
                    file
                }
                Err(Errno::EXIST) => fs::openat(
                    &parent,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(err)?,
                Err(e) => return Err(err(e)),
            }
        } else {
            fs::openat(
                &parent,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(err)?
        };
        let before = fs::fstat(&file).map_err(io)?;
        let path = fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if !safe_file(&before, uid, true) || !safe_file(&path, uid, true) || !same(&before, &path) {
            return Err(HostError::Unsafe);
        }
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(err)?;
        lock.file = Some(file);
        lock.verify()?;
        Ok(lock)
    }
    fn root_unchanged(&self) -> Result<(), HostError> {
        let current = if self.path == Path::new("/") {
            fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?
        } else {
            crate::durable::open_directory(&self.path, self.uid).map_err(|_| HostError::Unsafe)?
        };
        let current = fs::fstat(&current).map_err(io)?;
        let retained = fs::fstat(&self.root).map_err(io)?;
        if !same(&current, &retained)
            || current.st_uid != self.uid
            || retained.st_uid != self.uid
            || current.st_mode & 0o022 != 0
            || retained.st_mode & 0o022 != 0
        {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    fn parent(&self, path: &str, create: bool) -> Result<Option<(OwnedFd, String)>, HostError> {
        self.root_unchanged()?;
        let parts: Vec<_> = Path::new(path)
            .components()
            .map(|p| match p {
                std::path::Component::Normal(v) => v.to_str().ok_or(HostError::Unsafe),
                _ => Err(HostError::Unsafe),
            })
            .collect::<Result<_, _>>()?;
        let (name, parents) = parts.split_last().ok_or(HostError::Unsafe)?;
        let mut dir = fs::openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        let mut prefix = String::new();
        for part in parents {
            if create {
                match fs::mkdirat(&dir, *part, Mode::from_raw_mode(0o755)) {
                    Ok(()) => fs::fsync(&dir).map_err(io)?,
                    Err(Errno::EXIST) => (),
                    Err(e) => return Err(err(e)),
                }
            }
            dir = match fs::openat(
                &dir,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(v) => v,
                Err(Errno::NOENT) if !create => return Ok(None),
                Err(e) => return Err(err(e)),
            };
            if !prefix.is_empty() {
                prefix.push('/')
            }
            prefix.push_str(part);
            let s = fs::fstat(&dir).map_err(io)?;
            let sticky_coordination =
                path == MUTATION_LOCK && prefix == "run/lock" && s.st_mode & 0o1000 != 0;
            if s.st_uid != self.uid || s.st_mode & 0o022 != 0 && !sticky_coordination {
                return Err(HostError::Unsafe);
            }
        }
        Ok(Some((dir, (*name).into())))
    }
    pub fn verify(&self) -> Result<(), HostError> {
        let (parent, name) = self
            .parent(MUTATION_LOCK, false)?
            .ok_or(HostError::Unsafe)?;
        let opened = fs::fstat(self.file.as_ref().ok_or(HostError::Unsafe)?).map_err(io)?;
        let current = fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if !safe_file(&opened, self.uid, true)
            || !safe_file(&current, self.uid, true)
            || !same(&opened, &current)
        {
            return Err(HostError::Unsafe);
        }
        fs::flock(
            self.file.as_ref().ok_or(HostError::Unsafe)?,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(err)
    }
    /// The Owner guard must outlive this runtime-start scope. Duplicating the
    /// shared open-file description preserves exclusion; dropping StartLock
    /// closes its copy without explicitly unlocking the Owner.
    pub fn runtime_start_lock(&self) -> Result<OwnerStartLock<'_>, HostError> {
        self.verify()?;
        let fd = rustix::io::fcntl_dupfd_cloexec(self.file.as_ref().ok_or(HostError::Unsafe)?, 3)
            .map_err(io)?;
        let lock =
            crate::runtime_handoff::StartLock::from_owner_duplicate(&self.path, self.uid, fd)
                .map_err(|_| HostError::Unsafe)?;
        Ok(OwnerStartLock { lock, _owner: self })
    }
    pub fn root(&self) -> &Path {
        &self.path
    }
    pub fn acquire_packages(&self) -> Result<PackageLocks<'_>, HostError> {
        self.verify()?;
        let mut held = self.package_guard.lock().map_err(|_| HostError::Unsafe)?;
        if *held {
            return Err(HostError::Busy);
        }
        *held = true;
        drop(held);
        let mut guard = PackageLocks {
            host: HostReference::Borrowed(self),
            files: Vec::new(),
            release_lease: true,
        };
        for path in PACKAGE_LOCKS {
            let file = if let Some((parent, name)) = self.parent(path, false)? {
                match fs::openat(
                    &parent,
                    name.as_str(),
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => {
                        let current = fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                            .map_err(io)?;
                        let opened = fs::fstat(&fd).map_err(io)?;
                        if !safe_file(&current, self.uid, false)
                            || !safe_file(&opened, self.uid, false)
                            || !same(&current, &opened)
                        {
                            return Err(HostError::Unsafe);
                        }
                        fs::fcntl_lock(&fd, FlockOperation::NonBlockingLockExclusive)
                            .map_err(err)?;
                        Some(fd)
                    }
                    Err(Errno::NOENT) => None,
                    Err(e) => return Err(err(e)),
                }
            } else {
                None
            };
            guard.files.push((*path, file));
        }
        guard.verify()?;
        Ok(guard)
    }
    pub fn retain_packages(
        self: &std::sync::Arc<Self>,
    ) -> Result<PackageLocks<'static>, HostError> {
        let mut borrowed = self.acquire_packages()?;
        let files = std::mem::take(&mut borrowed.files);
        borrowed.release_lease = false;
        Ok(PackageLocks {
            host: HostReference::Owned(self.clone()),
            files,
            release_lease: true,
        })
    }
    pub fn packages_available(&self) -> Result<(), HostError> {
        drop(self.acquire_packages()?);
        Ok(())
    }
}
impl Drop for HostLock {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let _ = fs::flock(file, FlockOperation::Unlock);
        }
    }
}
enum HostReference<'a> {
    Borrowed(&'a HostLock),
    Owned(std::sync::Arc<HostLock>),
}
impl std::ops::Deref for HostReference<'_> {
    type Target = HostLock;
    fn deref(&self) -> &HostLock {
        match self {
            Self::Borrowed(h) => h,
            Self::Owned(h) => h,
        }
    }
}
pub struct PackageLocks<'a> {
    host: HostReference<'a>,
    files: Vec<(&'static str, Option<OwnedFd>)>,
    release_lease: bool,
}
impl PackageLocks<'_> {
    /// No open/close of package inodes: POSIX locks are per-process, not per-fd.
    pub fn verify(&self) -> Result<(), HostError> {
        self.host.verify()?;
        for (path, file) in &self.files {
            let current = if let Some((parent, name)) = self.host.parent(path, false)? {
                match fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(v) => Some(v),
                    Err(Errno::NOENT) => None,
                    Err(e) => return Err(err(e)),
                }
            } else {
                None
            };
            match (file, current) {
                (None, None) => (),
                (Some(fd), Some(current)) => {
                    let opened = fs::fstat(fd).map_err(io)?;
                    if !safe_file(&current, self.host.uid, false)
                        || !safe_file(&opened, self.host.uid, false)
                        || !same(&current, &opened)
                    {
                        return Err(HostError::Unsafe);
                    }
                }
                _ => return Err(HostError::Unsafe),
            }
        }
        Ok(())
    }
}
impl Drop for PackageLocks<'_> {
    fn drop(&mut self) {
        for (_, file) in self.files.drain(..) {
            if let Some(fd) = file {
                let _ = fs::fcntl_lock(&fd, FlockOperation::NonBlockingUnlock);
                drop(fd)
            }
        }
        if self.release_lease
            && let Ok(mut held) = self.host.package_guard.lock()
        {
            *held = false
        }
    }
}
#[cfg(test)]
#[path = "locks_tests.rs"]
mod tests;
