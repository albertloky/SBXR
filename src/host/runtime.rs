//! Private-role protected-file integration. Injected roots remain explicit fixtures.
use super::{HostError, filesystem::ProtectedFs, linux::observation, locks::HostLock};
use crate::{
    private_roles::{Role, Runtime},
    records::{OwnershipRecord, ReleaseIdentity, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
    runtime_handoff::{self, Error, ProxyStartHost, StartContext, StartLock},
    subscription_serving::Cancellation,
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
        let context = StartContext::new(
            Cancellation::new(),
            std::time::Instant::now() + runtime_handoff::START_TIMEOUT,
        );
        runtime_handoff::authorize_proxy_start(self, &context).map_err(|_| HostError::Foreign)
    }
}
fn refused(_: impl std::fmt::Debug) -> Error {
    Error::Refused
}
impl ProxyStartHost for InjectedRuntime<'_> {
    fn acquire_start(&self, context: &StartContext) -> Result<StartLock, Error> {
        context.check()?;
        StartLock::existing(self.fs.path(), self.fs.uid)
    }
    fn installed_identity(
        &self,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<ReleaseIdentity, Error> {
        context.check()?;
        lock.verify()?;
        self.installed().map_err(refused)?;
        Ok(self.authenticated.record().release_identity())
    }
    fn ownership(&self) -> Result<Vec<u8>, Error> {
        self.installed().map_err(refused)?;
        for path in [
            "var/lib/sbxr/proxy-ownership.json.sbxr-next".to_owned(),
            format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
            "var/lib/.sbxr-removal.json".to_owned(),
        ] {
            if self.fs.metadata(&path).map_err(refused)?.is_some() {
                return Err(Error::Refused);
            }
        }
        self.fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )
            .map_err(refused)?
            .map(|(body, _)| body)
            .ok_or(Error::Refused)
    }
    fn verify_startup(&self, record: &OwnershipRecord) -> Result<(), Error> {
        // This concrete fixture bridge supports only ordinary starts. Borrowed
        // cutover and native systemd/NSS observations remain separate adapters.
        if record.ordinary_proxy_start_sha256() != Some(sha256_hex(STARTUP).as_str()) {
            return Err(Error::Refused);
        }
        let (drop_in, _) = self
            .fs
            .raw(
                "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
                Mode::from_raw_mode(0o644),
                4096,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if drop_in != STARTUP {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn configuration(&self) -> Result<Vec<u8>, Error> {
        let (config, proof) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )
            .map_err(refused)?
            .ok_or(Error::Refused)?;
        if proof.gid != self.fs.gid {
            return Err(Error::Refused);
        }
        Ok(config)
    }
    fn mutation_in_progress(&self) -> Result<bool, Error> {
        Err(Error::Refused)
    }
    fn consume_authorization(&self, _: &str) -> Result<(), Error> {
        Err(Error::Refused)
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
