//! Fresh protected runtime files shared by the private proxy/serving adapters.
use super::*;
use crate::host::linux::observation;
pub(super) struct RuntimeFiles<'a> {
    pub fs: ProtectedFs,
    pub record: &'a crate::records::InstalledRecord,
    bound: Option<&'a dyn InstalledEvidence>,
    offline: Option<&'a crate::host::admission_private::OfflinePrivateAdmission>,
}
impl<'a> RuntimeFiles<'a> {
    pub fn injected(
        root: &Path,
        authenticated: &'a dyn InstalledEvidence,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        let files = Self {
            fs: ProtectedFs::open(root)?,
            record: authenticated.record(),
            bound: Some(authenticated),
            offline: None,
        };
        files.installed().map_err(|_| HostError::Foreign)?;
        Ok(files)
    }
    pub fn native(authenticated: &'a dyn InstalledEvidence) -> Result<Self, HostError> {
        crate::host::linux::require_native_environment()?;
        let files = Self {
            fs: ProtectedFs::native()?,
            record: authenticated.record(),
            bound: Some(authenticated),
            offline: None,
        };
        files.installed().map_err(|_| HostError::Foreign)?;
        Ok(files)
    }
    pub fn archive(
        root: &Path,
        archive: &'a crate::release_acquisition::AuthenticatedArchive,
    ) -> Result<Self, HostError> {
        let fs = if root == Path::new("/") {
            crate::host::linux::require_native_environment()?;
            ProtectedFs::native()?
        } else {
            ProtectedFs::open(root)?
        };
        let files = Self {
            fs,
            record: archive.record(),
            bound: None,
            offline: None,
        };
        files.installed().map_err(|_| HostError::Foreign)?;
        Ok(files)
    }
    pub fn native_record(
        proof: &'a crate::host::admission_private::OfflinePrivateAdmission,
    ) -> Result<Self, HostError> {
        crate::host::linux::require_native_environment()?;
        let files = Self {
            fs: ProtectedFs::native()?,
            record: proof.record(),
            bound: None,
            offline: Some(proof),
        };
        files.installed().map_err(|_| HostError::Foreign)?;
        Ok(files)
    }
    pub fn start(&self, role: Role, lock: &StartLock, context: &StartContext) -> Result<(), Error> {
        context.check()?;
        lock.verify()?;
        if let Some(proof) = self.offline {
            proof.verify_start(role, lock, context).map_err(refused)?;
        }
        self.installed()?;
        context.check()
    }
    pub fn installed(&self) -> Result<(), Error> {
        if let Some(proof) = self.offline {
            proof.verify().map_err(refused)?;
        }
        if let Some(proof) = self.bound {
            proof.verify_binding().map_err(refused)?;
        }
        if observation::read_installed(&self.fs)
            .map_err(refused)?
            .as_ref()
            != Some(self.record)
        {
            return Err(Error::Refused);
        }
        for path in [
            "usr/local/bin/.sbxr-update-prior",
            "usr/local/bin/.sbxr-update-candidate",
            "var/lib/sbxr/.installed.json.prior",
            "var/lib/sbxr/.installed.json.candidate",
            "var/lib/sbxr/update.json",
            "var/lib/sbxr/.update.json.next",
        ] {
            if self.fs.metadata(path).map_err(refused)?.is_some() {
                return Err(Error::Refused);
            }
        }
        Ok(())
    }
    pub fn pending_absent(&self) -> Result<bool, Error> {
        for path in [
            "var/lib/sbxr/proxy-ownership.json.sbxr-next".to_owned(),
            format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
            "var/lib/.sbxr-removal.json".to_owned(),
        ] {
            if self.fs.metadata(&path).map_err(refused)?.is_some() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn ownership(&self) -> Result<Vec<u8>, Error> {
        self.installed()?;
        if !self.pending_absent()? {
            return Err(Error::Refused);
        }
        self.fs
            .directory_entries("var/lib/sbxr", Mode::from_raw_mode(0o700))
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        self.fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )
            .map_err(refused)?
            .map(|(b, _)| b)
            .ok_or(Error::Refused)
    }
    pub fn configuration(&self) -> Result<Vec<u8>, Error> {
        let (group, _) = self
            .fs
            .raw("etc/group", Mode::from_raw_mode(0o644), 1 << 20)
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        let group = std::str::from_utf8(&group).map_err(refused)?;
        let entry = group
            .lines()
            .find(|line| line.starts_with("sing-box:"))
            .ok_or(Error::Refused)?;
        let gid = entry
            .split(':')
            .nth(2)
            .ok_or(Error::Refused)?
            .parse::<u32>()
            .map_err(refused)?;
        let (bytes, proof) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if proof.gid != gid {
            return Err(Error::Refused);
        }
        Ok(bytes)
    }
    pub fn startup(&self, record: &OwnershipRecord) -> Result<(), Error> {
        let wire: serde_json::Value =
            serde_json::from_slice(&record.encode().map_err(refused)?).map_err(refused)?;
        if wire["proxy_startup"]["drop_in_sha256"].as_str() != Some(sha256_hex(STARTUP).as_str()) {
            return Err(Error::Refused);
        }
        let (bytes, _) = self
            .fs
            .raw(
                "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
                Mode::from_raw_mode(0o644),
                4096,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if bytes != STARTUP {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
