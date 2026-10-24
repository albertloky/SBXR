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
