//! Exact hash-named restoration staging. Every partial file is an authenticated
//! target prefix with protected metadata; publication never replaces a target.
use super::*;
use crate::artifact_trust::SelectionBudget;
use std::io::{Seek, SeekFrom};
fn check(budget: &SelectionBudget) -> Result<(), HostError> {
    budget.check().map_err(|_| HostError::Cancelled)
}
fn stage(path: &str, hash: &str) -> Result<String, HostError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HostError::Unsafe);
    }
    Ok(format!("{path}.sbxr-restore-{hash}"))
}
fn identity(stat: &fs::Stat) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        stat.st_dev, stat.st_ino, stat.st_uid, stat.st_gid, stat.st_mode, stat.st_nlink
    )
}
impl ProtectedFs {
    fn restoration_prefix(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<Option<(Vec<u8>, Evidence)>, HostError> {
        let result = match self.raw(path, Mode::from_raw_mode(0o600), body.len()) {
            Err(HostError::Foreign) if mode != Mode::from_raw_mode(0o600) => {
                let result = self.raw(path, mode, body.len())?;
                if result
                    .as_ref()
                    .is_some_and(|(bytes, _)| bytes.len() != body.len())
                {
                    return Err(HostError::Foreign);
                }
                result
            }
            other => other?,
        };
        if result
            .as_ref()
            .is_some_and(|(bytes, proof)| !body.starts_with(bytes) || proof.gid != self.gid)
        {
            return Err(HostError::Foreign);
        }
        Ok(result)
    }
    pub(in crate::host) fn validate_restoration_stage(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
        hash: &str,
    ) -> Result<(), HostError> {
        self.restoration_prefix(&stage(path, hash)?, body, mode)?;
        Ok(())
    }
    pub(in crate::host) fn prepare_restoration_stage(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
        hash: &str,
        budget: &SelectionBudget,
    ) -> Result<(), HostError> {
        check(budget)?;
        self.write_allowed()?;
        let path = stage(path, hash)?;
        let (dir, name) = self.parent(&path, false)?.ok_or(HostError::Unsafe)?;
        if self.restoration_prefix(&path, body, mode)?.is_none() {
            let fd = fs::openat(
                &dir,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(failure)?;
            fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(failure)?;
            fs::fchown(&fd, None, Some(rustix::process::Gid::from_raw(self.gid)))
                .map_err(failure)?;
            fs::fsync(fd).map_err(failure)?;
            fs::fsync(&dir).map_err(failure)?;
        }
        let (prefix, proof) = self
            .restoration_prefix(&path, body, mode)?
            .ok_or(HostError::Unsafe)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        if identity(&fs::fstat(&fd).map_err(failure)?) != proof.identity
            || self
                .restoration_prefix(&path, body, mode)?
                .as_ref()
                .map(|(_, p)| p)
                != Some(&proof)
        {
            return Err(HostError::Unsafe);
        }
        check(budget)?;
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(prefix.len() as u64))
            .map_err(failure)?;
        for chunk in body[prefix.len()..].chunks(65536) {
            check(budget)?;
            file.write_all(chunk).map_err(failure)?;
        }
        file.sync_all().map_err(failure)?;
        let (complete, fresh) = self
            .restoration_prefix(&path, body, mode)?
            .ok_or(HostError::Unsafe)?;
        if complete != body || fresh.identity != proof.identity {
            return Err(HostError::Unsafe);
        }
        fs::fchmod(&file, mode).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        fs::fsync(dir).map_err(failure)?;
        let (bytes, proof) = self
            .raw(&path, mode, body.len())?
            .ok_or(HostError::Unsafe)?;
        if bytes != body
            || proof.gid != self.gid
            || identity(&fs::fstat(&file).map_err(failure)?) != proof.identity
        {
            return Err(HostError::Unsafe);
        }
        check(budget)
    }
    pub(in crate::host) fn publish_restoration_stage(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
        hash: &str,
        budget: &SelectionBudget,
    ) -> Result<(), HostError> {
        check(budget)?;
        self.write_allowed()?;
        let staged = stage(path, hash)?;
        if let Some((bytes, proof)) = self.raw(path, mode, body.len())? {
            if bytes != body || proof.gid != self.gid {
                return Err(HostError::Foreign);
            }
            if let Some((_, proof)) = self.restoration_prefix(&staged, body, mode)? {
                let (dir, name) = self.parent(&staged, false)?.ok_or(HostError::Unsafe)?;
                if self
                    .restoration_prefix(&staged, body, mode)?
                    .as_ref()
                    .map(|(_, p)| p)
                    != Some(&proof)
                {
                    return Err(HostError::Unsafe);
                }
                check(budget)?;
                fs::unlinkat(&dir, name.as_str(), AtFlags::empty()).map_err(failure)?;
                fs::fsync(dir).map_err(failure)?;
            }
            return Ok(());
        }
        let (bytes, proof) = self
            .raw(&staged, mode, body.len())?
            .ok_or(HostError::Unsafe)?;
        if bytes != body || proof.gid != self.gid {
            return Err(HostError::Foreign);
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let staged_name = stage(&name, hash)?;
        if self
            .raw(&staged, mode, body.len())?
            .as_ref()
            .map(|(_, p)| p)
            != Some(&proof)
        {
            return Err(HostError::Unsafe);
        }
        check(budget)?;
        fs::renameat_with(
            &dir,
            staged_name.as_str(),
            &dir,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(failure)?;
        fs::fsync(dir).map_err(failure)?;
        self.sync_restoration_member(path, body, mode)?;
        check(budget)
    }
    pub(in crate::host) fn sync_restoration_member(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        let (bytes, proof) = self.raw(path, mode, body.len())?.ok_or(HostError::Unsafe)?;
        if bytes != body || proof.gid != self.gid {
            return Err(HostError::Foreign);
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        if identity(&fs::fstat(&fd).map_err(failure)?) != proof.identity
            || self.raw(path, mode, body.len())?.as_ref().map(|(_, p)| p) != Some(&proof)
        {
            return Err(HostError::Unsafe);
        }
        fs::fsync(fd).map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
    pub(in crate::host) fn create_restoration_directory(
        &self,
        path: &'static str,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        if self
            .observe(Resource {
                path,
                kind: Kind::Directory(Mode::from_raw_mode(0o700)),
            })?
            .is_some()
        {
            return Ok(());
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        fs::mkdirat(&dir, name.as_str(), Mode::from_raw_mode(0o700)).map_err(failure)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        fs::fchmod(&fd, Mode::from_raw_mode(0o700)).map_err(failure)?;
        fs::fchown(&fd, None, Some(rustix::process::Gid::from_raw(self.gid))).map_err(failure)?;
        fs::fsync(fd).map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
    pub(in crate::host) fn sync_restoration_directory(
        &self,
        path: &str,
        mode: Mode,
    ) -> Result<(), HostError> {
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let before = fs::fstat(&fd).map_err(failure)?;
        let after = fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        if before.st_uid != self.uid
            || before.st_gid != self.gid
            || before.st_mode & 0o7777 != mode.bits()
            || identity(&before) != identity(&after)
        {
            return Err(HostError::Unsafe);
        }
        fs::fsync(fd).map_err(failure)
    }
}
