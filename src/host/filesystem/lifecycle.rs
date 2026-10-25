//! Read-only whole-host exclusion probe. Never creates or lends authority.
use super::*;
impl ProtectedFs {
    pub(in crate::host) fn lifecycle_lock_held(&self) -> Result<bool, HostError> {
        let Some((parent, name)) = self.parent(super::super::locks::MUTATION_LOCK, false)? else {
            return Ok(false);
        };
        let fd = match fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            Err(e) => return Err(failure(e)),
        };
        let opened = fs::fstat(&fd).map_err(failure)?;
        let valid = |s: &fs::Stat| {
            FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
                && s.st_uid == self.uid
                && s.st_gid == self.gid
                && s.st_nlink == 1
                && s.st_mode & 0o7777 == 0o600
                && (0..=4096).contains(&s.st_size)
        };
        let fresh =
            fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        if !valid(&opened)
            || !valid(&fresh)
            || opened.st_dev != fresh.st_dev
            || opened.st_ino != fresh.st_ino
        {
            return Err(HostError::Foreign);
        }
        match fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive) {
            Err(Errno::AGAIN) => Ok(true),
            Err(e) => Err(failure(e)),
            Ok(()) => {
                let result = fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(failure)
                    .and_then(|s| {
                        if valid(&s) && s.st_dev == opened.st_dev && s.st_ino == opened.st_ino {
                            Ok(false)
                        } else {
                            Err(HostError::Foreign)
                        }
                    });
                // This disposable probe is never intentionally lent. Explicit
                // unlock also closes a concurrent fork's inherited window.
                fs::flock(&fd, fs::FlockOperation::Unlock).map_err(failure)?;
                result
            }
        }
    }
}
