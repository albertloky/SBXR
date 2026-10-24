//! Private-role protected-file integration. Injected roots remain explicit fixtures.
use super::{HostError, filesystem::ProtectedFs, linux::observation, locks::HostLock};
use crate::{
    private_roles::{Role, Runtime},
    records::{OwnershipRecord, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
};
use rustix::fs::Mode;
use std::path::Path;
const STARTUP: &[u8] = b"[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n";
pub struct InjectedRuntime<'a> {
    fs: ProtectedFs,
    authenticated: &'a AuthenticatedInstalled,
}
impl<'a> InjectedRuntime<'a> {
    pub fn open(root: &Path, authenticated: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        let runtime = Self {
            fs: ProtectedFs::open(root)?,
            authenticated,
        };
        runtime.installed()?;
        Ok(runtime)
    }
    fn installed(&self) -> Result<(), HostError> {
        if observation::read_installed(&self.fs)?.as_ref() != Some(self.authenticated.record()) {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn provision(&self) -> Result<(), HostError> {
        self.installed()?;
        let lock = HostLock::provision(self.fs.path(), self.fs.uid)?;
        self.installed()?;
        lock.verify()
    }
    fn proxy_start(&self) -> Result<(), HostError> {
        let lock = HostLock::existing(self.fs.path(), self.fs.uid)?;
        self.installed()?;
        if self
            .fs
            .metadata("var/lib/sbxr/proxy-ownership.json.sbxr-next")?
            .is_some()
            || self
                .fs
                .metadata(&format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE))?
                .is_some()
        {
            return Err(HostError::Foreign);
        }
        let (body, _) = self
            .fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .ok_or(HostError::Unsafe)?;
        let record = OwnershipRecord::decode(&body).map_err(|_| HostError::Foreign)?;
        if record.release_identity() != self.authenticated.record().release_identity() {
            return Err(HostError::Foreign);
        }
        let expected = record
            .ordinary_proxy_start_sha256()
            .ok_or(HostError::LiveUnavailable)?;
        if expected != sha256_hex(STARTUP) {
            return Err(HostError::Foreign);
        }
        let (drop_in, _) = self
            .fs
            .raw(
                "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
                Mode::from_raw_mode(0o644),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        if drop_in != STARTUP {
            return Err(HostError::Foreign);
        }
        let (config, proof) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if sha256_hex(&config) != record.configuration_sha256() {
            return Err(HostError::Foreign);
        }
        // The fixture account must match the owned fixture files. Native NSS and
        // runtime-start descriptor lending are separate prerequisites.
        if proof.gid != self.fs.gid {
            return Err(HostError::Foreign);
        }
        crate::server_configuration::ServerConfiguration::decode_standard(&config)
            .map_err(|_| HostError::Foreign)?;
        let (after, _) = self
            .fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .ok_or(HostError::Foreign)?;
        if after != body {
            return Err(HostError::Foreign);
        }
        self.installed()?;
        lock.verify()
    }
}
impl Runtime for InjectedRuntime<'_> {
    fn invoke(&mut self, role: Role) -> u8 {
        let result = match role {
            Role::ProvisionMutationLock => self.provision(),
            Role::ProxyStartAuthorize => self.proxy_start(),
            _ => Err(HostError::LiveUnavailable),
        };
        if result.is_ok() {
            0
        } else {
            role.refused_code()
        }
    }
}
