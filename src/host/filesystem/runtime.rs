//! One fixed volatile cutover gate. Borrowing grants this single consume effect,
//! never general write access, lock creation or record publication.
use super::*;
use crate::runtime_handoff::{Error, StartContext, StartLock};
pub(in crate::host) const PROXY_GATE: &str = "run/sbxr-client-identity-start";
impl ProtectedFs {
    pub(in crate::host) fn consume_proxy_gate(
        &self,
        expected: &str,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<(), Error> {
        context.check()?;
        lock.verify()?;
        if !lock.is_borrowed()
            || lock.root() != self.path()
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Refused);
        }
        if self.path() == Path::new("/") {
            super::super::linux::require_native_environment().map_err(|_| Error::Refused)?;
        }
        self.check_root().map_err(|_| Error::Refused)?;
        let mode = Mode::from_raw_mode(0o600);
        let (bytes, proof) = self
            .raw(PROXY_GATE, mode, 65)
            .map_err(|_| Error::Refused)?
            .ok_or(Error::Refused)?;
        if bytes != format!("{expected}\n").as_bytes() || proof.gid != self.gid {
            return Err(Error::Refused);
        }
        let (parent, name) = self
            .parent(PROXY_GATE, false)
            .map_err(|_| Error::Refused)?
            .ok_or(Error::Refused)?;
        if self
            .raw(PROXY_GATE, mode, 65)
            .map_err(|_| Error::Refused)?
            .as_ref()
            .map(|(_, p)| p)
            != Some(&proof)
        {
            return Err(Error::Refused);
        }
        context.check()?;
        lock.verify()?;
        fs::unlinkat(&parent, name.as_str(), AtFlags::empty()).map_err(|_| Error::Refused)?;
        fs::fsync(parent).map_err(|_| Error::Refused)?;
        lock.verify()?;
        context.check()
    }
}

impl ProtectedFs {
    /// Fixed cgroup virtual files report size zero even when reads return data.
    /// Keep inode/owner/mode/link checks; bound actual bytes rather than st_size.
    pub(in crate::host) fn cgroup_bytes(
        &self,
        unit: crate::host::owner_runtime::Unit,
        events: bool,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let path = format!(
            "sys/fs/cgroup{}/{}",
            unit.cgroup(),
            if events {
                "cgroup.events"
            } else {
                "cgroup.procs"
            }
        );
        let Some((parent, name)) = self.parent(&path, false)? else {
            return Ok(None);
        };
        let fd = match fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        let before = fs::fstat(&fd).map_err(failure)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != self.uid
            || before.st_gid != self.gid
            || before.st_nlink != 1
            || before.st_mode & 0o022 != 0
        {
            return Err(HostError::Foreign);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        let after = fs::fstat(&file).map_err(failure)?;
        if bytes.len() > 4096
            || (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_mode,
                before.st_nlink,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                after.st_gid,
                after.st_mode,
                after.st_nlink,
            )
        {
            return Err(HostError::Unsafe);
        }
        self.check_root()?;
        Ok(Some(bytes))
    }
}
