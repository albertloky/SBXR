use super::*;
impl ProtectedFs {
    /// Retain the exact named executable descriptor; parents/namespace are checked
    /// separately by raw() and rechecked throughout the admission lifetime.
    pub(in crate::host) fn admission_executable(&self) -> Result<File, HostError> {
        self.check_root()?;
        let (dir, name) = self
            .parent("usr/local/bin/sbxr", false)?
            .ok_or(HostError::Foreign)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        Ok(File::from(fd))
    }
}

impl ProtectedFs {
    pub(in crate::host) fn retain_regular(
        &self,
        path: &str,
        mode: Mode,
        limit: usize,
    ) -> Result<(File, Vec<u8>, Evidence), HostError> {
        let first = self.raw(path, mode, limit)?.ok_or(HostError::Foreign)?;
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Foreign)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let s = fs::fstat(&fd).map_err(failure)?;
        let identity = format!(
            "{}:{}:{}:{}:{}:{}",
            s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink
        );
        if identity != first.1.identity || self.raw(path, mode, limit)?.as_ref() != Some(&first) {
            return Err(HostError::Foreign);
        }
        Ok((File::from(fd), first.0, first.1))
    }
}
