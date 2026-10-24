//! Descriptor-relative historical lineage reads/unlinks. No symlink following.
use super::*;
#[derive(Clone, PartialEq, Eq)]
struct LinkProof {
    target: String,
    identity: String,
}
impl ProtectedFs {
    fn historical_link_proof(&self, path: &str) -> Result<Option<LinkProof>, HostError> {
        let Some((parent, name)) = self.parent(path, false)? else {
            return Ok(None);
        };
        let stat = match fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Symlink
            || stat.st_uid != self.uid
            || stat.st_gid != self.gid
            || stat.st_nlink != 1
        {
            return Err(HostError::Foreign);
        }
        let target = fs::readlinkat(&parent, name.as_str(), Vec::new())
            .map_err(failure)?
            .to_str()
            .map_err(failure)?
            .to_owned();
        let fresh =
            fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        let identity = |s: &fs::Stat| {
            format!(
                "{}:{}:{}:{}:{}:{}",
                s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink
            )
        };
        if identity(&stat) != identity(&fresh) {
            return Err(HostError::Unsafe);
        }
        Ok(Some(LinkProof {
            target,
            identity: identity(&stat),
        }))
    }
    pub(in crate::host) fn historical_link(&self, path: &str) -> Result<Option<String>, HostError> {
        Ok(self.historical_link_proof(path)?.map(|p| p.target))
    }
    pub(in crate::host) fn remove_historical_link(
        &self,
        path: &str,
        target: &str,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let Some(proof) = self.historical_link_proof(path)? else {
            return Ok(());
        };
        if proof.target != target {
            return Err(HostError::Foreign);
        }
        let (parent, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        if self.historical_link_proof(path)? != Some(proof) {
            return Err(HostError::Unsafe);
        }
        fs::unlinkat(&parent, name.as_str(), AtFlags::empty()).map_err(failure)?;
        fs::fsync(parent).map_err(failure)
    }
    pub(in crate::host) fn remove_historical_directory(
        &self,
        path: &str,
        mode: Mode,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        if self.metadata(path)?.is_some_and(|m| m.gid != self.gid) {
            return Err(HostError::Foreign);
        }
        let Some(entries) = self.directory_entries(path, mode)? else {
            return Ok(());
        };
        if !entries.is_empty() {
            return Err(HostError::Foreign);
        }
        let (parent, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        fs::unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).map_err(failure)?;
        fs::fsync(parent).map_err(failure)
    }
    pub(in crate::host) fn historical_directory_entries(
        &self,
        path: &str,
    ) -> Result<Vec<String>, HostError> {
        let Some((parent, name)) = self.parent(path, false)? else {
            return Ok(Vec::new());
        };
        let fd = match fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(Vec::new()),
            Err(e) => return Err(failure(e)),
        };
        let stat = fs::fstat(&fd).map_err(failure)?;
        if stat.st_uid != self.uid || stat.st_gid != self.gid || stat.st_mode & 0o7022 != 0 {
            return Err(HostError::Foreign);
        }
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(&fd).map_err(failure)? {
            let entry = entry.map_err(failure)?;
            let name = entry.file_name().to_str().map_err(failure)?;
            if !matches!(name, "." | "..") {
                names.push(name.to_owned());
            }
            if names.len() > 128 {
                return Err(HostError::Foreign);
            }
        }
        let current =
            fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        if stat.st_dev != current.st_dev
            || stat.st_ino != current.st_ino
            || stat.st_mode != current.st_mode
            || stat.st_uid != current.st_uid
            || stat.st_gid != current.st_gid
        {
            return Err(HostError::Foreign);
        }
        names.sort();
        Ok(names)
    }
    pub(in crate::host) fn historical_configuration(
        &self,
        path: &str,
    ) -> Result<Option<(Vec<u8>, Mode)>, HostError> {
        self.historical_readable(path, false)
    }
    pub(in crate::host) fn historical_readable(
        &self,
        path: &str,
        executable: bool,
    ) -> Result<Option<(Vec<u8>, Mode)>, HostError> {
        let Some((parent, name)) = self.parent(path, false)? else {
            return Ok(None);
        };
        let stat = match fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        let mode = Mode::from_raw_mode(stat.st_mode & 0o7777);
        if mode.as_raw_mode() & (if executable { 0o7022 } else { 0o7133 }) != 0
            || mode.as_raw_mode() & 0o400 == 0
        {
            return Err(HostError::Foreign);
        }
        self.raw(path, mode, 64 << 10)?
            .map(|(bytes, p)| {
                if p.gid == self.gid {
                    Ok((bytes, mode))
                } else {
                    Err(HostError::Foreign)
                }
            })
            .transpose()
    }
}
fn lock_identity(s: &fs::Stat) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink
    )
}
struct HeldHistoricalLock {
    path: String,
    parent: OwnedFd,
    name: String,
    file: OwnedFd,
    created: bool,
    posix: bool,
    identity: String,
}
pub(in crate::host) struct HistoricalFileLocks {
    root: ProtectedFs,
    files: Vec<HeldHistoricalLock>,
    removed_renewal: bool,
}
fn historical_lock_parent(
    root: &ProtectedFs,
    lock: &HeldHistoricalLock,
) -> Result<Option<OwnedFd>, HostError> {
    let Some((parent, _)) = root.parent(&lock.path, false)? else {
        return Ok(None);
    };
    let held = fs::fstat(&lock.parent).map_err(failure)?;
    let current = fs::fstat(&parent).map_err(failure)?;
    if held.st_dev != current.st_dev || held.st_ino != current.st_ino {
        return Err(HostError::Foreign);
    }
    Ok(Some(parent))
}
impl HistoricalFileLocks {
    pub(in crate::host) fn permit_removed_renewal(&mut self) {
        self.removed_renewal = true;
    }
    pub(in crate::host) fn verify(&self) -> Result<(), HostError> {
        for h in &self.files {
            let parent = match historical_lock_parent(&self.root, h)? {
                Some(parent) => parent,
                None if !h.posix && self.removed_renewal => continue,
                None => return Err(HostError::Foreign),
            };
            let current = match fs::statat(&parent, h.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(s) => s,
                Err(Errno::NOENT) if !h.posix && self.removed_renewal => continue,
                Err(e) => return Err(failure(e)),
            };
            if lock_identity(&current) != h.identity
                || lock_identity(&fs::fstat(&h.file).map_err(failure)?) != h.identity
            {
                return Err(HostError::Foreign);
            }
        }
        Ok(())
    }
}
impl Drop for HistoricalFileLocks {
    fn drop(&mut self) {
        for h in self.files.drain(..).rev() {
            if h.created
                && h.posix
                && let Ok(Some(parent)) = historical_lock_parent(&self.root, &h)
                && fs::fcntl_lock(&h.file, fs::FlockOperation::NonBlockingLockExclusive).is_ok()
                && let (Ok(opened), Ok(current)) = (
                    fs::fstat(&h.file),
                    fs::statat(&parent, h.name.as_str(), AtFlags::SYMLINK_NOFOLLOW),
                )
                && lock_identity(&current) == h.identity
                && lock_identity(&opened) == h.identity
                && opened.st_size == 0
            {
                let _ = fs::unlinkat(&parent, h.name.as_str(), AtFlags::empty());
                let _ = fs::fsync(&parent);
            }
            if h.posix {
                let _ = fs::fcntl_lock(&h.file, fs::FlockOperation::NonBlockingUnlock);
            } else {
                let _ = fs::flock(&h.file, fs::FlockOperation::Unlock);
            }
        }
    }
}
impl ProtectedFs {
    pub(in crate::host) fn historical_exclusion(
        &self,
        renewal: bool,
        missing_renewal: bool,
    ) -> Result<HistoricalFileLocks, HostError> {
        self.write_allowed()?;
        let mut held = HistoricalFileLocks {
            root: if self.path() == Path::new("/") {
                ProtectedFs::native()?
            } else {
                ProtectedFs::open(self.path())?
            },
            files: Vec::new(),
            removed_renewal: false,
        };
        let mut paths = vec![
            ("etc/letsencrypt/.certbot.lock", true),
            ("var/lib/letsencrypt/.certbot.lock", true),
            ("var/log/letsencrypt/.certbot.lock", true),
        ];
        if renewal {
            paths.extend([
                ("var/lib/sbxr/renewal-admission.lock", false),
                ("var/lib/sbxr/renewal-writer.lock", false),
            ]);
        }
        for (path, posix) in paths {
            let (parent, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
            let mut created = false;
            let file = match fs::openat(
                &parent,
                name.as_str(),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if !posix && missing_renewal => continue,
                Err(Errno::NOENT) if posix => {
                    let fd = fs::openat(
                        &parent,
                        name.as_str(),
                        OFlags::RDWR
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(failure)?;
                    created = true;
                    fd
                }
                Err(e) => return Err(failure(e)),
            };
            let mut stat = fs::fstat(&file).map_err(failure)?;
            held.files.push(HeldHistoricalLock {
                path: path.into(),
                parent,
                name,
                file,
                created,
                posix,
                identity: lock_identity(&stat),
            });
            let h = held.files.last_mut().ok_or(HostError::Unsafe)?;
            // Register the exact newly created inode before fallible chmod or
            // validation, so error unwinding can remove only our own empty lock.
            if created {
                fs::fchmod(&h.file, Mode::from_raw_mode(0o600)).map_err(failure)?;
                stat.st_mode = (stat.st_mode & !0o7777) | 0o600;
                h.identity = lock_identity(&stat);
            }
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != self.uid
                || stat.st_gid != self.gid
                || stat.st_nlink != 1
                || stat.st_mode & 0o022 != 0
            {
                return Err(HostError::Foreign);
            }
            let result = if posix {
                fs::fcntl_lock(&h.file, fs::FlockOperation::NonBlockingLockExclusive)
            } else {
                fs::flock(&h.file, fs::FlockOperation::NonBlockingLockExclusive)
            };
            result.map_err(|e| {
                if matches!(e, Errno::AGAIN | Errno::ACCESS) {
                    HostError::Busy
                } else {
                    HostError::Io
                }
            })?;
        }
        held.verify()?;
        Ok(held)
    }
}
