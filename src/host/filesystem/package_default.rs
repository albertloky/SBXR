//! Fixed conffile transition: exact authenticated public default -> private target.
use super::*;
const CONFIG: &str = "etc/sing-box/config.json";
const STAGE: &str = "etc/sing-box/config.json.sbxr-next";
impl ProtectedFs {
    fn package_default_proof(&self) -> Result<Evidence, HostError> {
        let (bytes, proof) = self
            .raw(CONFIG, Mode::from_raw_mode(0o644), 635)?
            .ok_or(HostError::Foreign)?;
        if bytes != crate::package_acquisition::DEFAULT_CONFIGURATION || proof.gid != self.gid {
            return Err(HostError::Foreign);
        }
        Ok(proof)
    }
    pub(in crate::host) fn replace_package_default(
        &self,
        target: &[u8],
        gid: u32,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let source = self.package_default_proof()?;
        let mode = Mode::from_raw_mode(0o640);
        if let Some((bytes, proof)) = self.raw(STAGE, mode, 1 << 20)? {
            if bytes != target || proof.gid != gid {
                return Err(HostError::Foreign);
            }
        } else {
            self.install_bytes_group(STAGE, target, mode, gid)?;
        }
        self.sync_bytes(STAGE, target, mode)?;
        self.package_replacement_checkpoint(1)?;
        let (_, prepared) = self.raw(STAGE, mode, 1 << 20)?.ok_or(HostError::Foreign)?;
        let (parent, name) = self.parent(CONFIG, false)?.ok_or(HostError::Unsafe)?;
        if self.package_default_proof()? != source
            || self.raw(STAGE, mode, 1 << 20)?.map(|(_, p)| p) != Some(prepared)
        {
            return Err(HostError::Unsafe);
        }
        fs::renameat(&parent, "config.json.sbxr-next", &parent, name.as_str()).map_err(failure)?;
        self.package_replacement_checkpoint(2)?;
        fs::fsync(&parent).map_err(failure)?;
        self.sync_bytes(CONFIG, target, mode)?;
        if self
            .raw(CONFIG, mode, 1 << 20)?
            .is_none_or(|(bytes, proof)| bytes != target || proof.gid != gid)
        {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    pub(in crate::host) fn remove_package_default(&self) -> Result<(), HostError> {
        self.write_allowed()?;
        let proof = self.package_default_proof()?;
        let (parent, name) = self.parent(CONFIG, false)?.ok_or(HostError::Unsafe)?;
        if self.package_default_proof()? != proof {
            return Err(HostError::Unsafe);
        }
        fs::unlinkat(&parent, name.as_str(), AtFlags::empty()).map_err(failure)?;
        fs::fsync(parent).map_err(failure)
    }
    fn package_replacement_checkpoint(&self, _point: u8) -> Result<(), HostError> {
        #[cfg(test)]
        if self
            .package_replacement_fault
            .load(std::sync::atomic::Ordering::Relaxed)
            == _point
        {
            self.package_replacement_fault
                .store(0, std::sync::atomic::Ordering::Relaxed);
            return Err(HostError::Injected);
        }
        Ok(())
    }
}
