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
