//! Owner-only volatile gate publication and checked cleanup. No journal change,
//! arbitrary path/command, source revocation or general filesystem capability.
use super::{material::RuntimeFiles, *};
use std::sync::Arc;
#[must_use = "retain the gate through the scoped start, then finish its cleanup"]
pub struct CutoverGate {
    fs: ProtectedFs,
    owner: Arc<HostLock>,
    body: Vec<u8>,
    finished: bool,
    executable_sha256: String,
}
impl CutoverGate {
    pub(super) fn prepare(
        files: &RuntimeFiles<'_>,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
        context: &StartContext,
    ) -> Result<Self, Error> {
        context.check()?;
        owner.verify().map_err(refused)?;
        if owner.root() != files.fs.path() {
            return Err(Error::Refused);
        }
        let hash = runtime_handoff::cutover_configuration(record)?.ok_or(Error::Refused)?;
        let mut fs = if files.fs.path() == Path::new("/") {
            ProtectedFs::native().map_err(refused)?
        } else {
            ProtectedFs::open(files.fs.path()).map_err(refused)?
        };
        if files.fs.path() == Path::new("/") {
            fs.authorize_native_writes(Some(owner.clone()))
                .map_err(refused)?;
        }
        let gate = Self {
            fs,
            owner: owner.clone(),
            body: format!("{hash}\n").into_bytes(),
            finished: false,
            executable_sha256: files.authenticated.record().executable_sha256().into(),
        };
        gate.fs
            .publish_bytes(
                crate::host::filesystem::PROXY_GATE,
                &gate.body,
                Mode::from_raw_mode(0o600),
            )
            .map_err(refused)?;
        context.check()?;
        gate.owner.verify().map_err(refused)?;
        Ok(gate)
    }
    fn lend_start(
        &self,
        listener: std::os::unix::net::UnixListener,
        authenticated: &AuthenticatedInstalled,
        peers: &(impl runtime_handoff::PeerObservations + Sync),
        context: &StartContext,
        start: impl FnOnce(&StartContext) -> bool,
    ) -> bool {
        if authenticated.record().executable_sha256() != self.executable_sha256
            || context.check().is_err()
        {
            return false;
        }
        let present = self.fs.raw(
            crate::host::filesystem::PROXY_GATE,
            Mode::from_raw_mode(0o600),
            65,
        );
        if present
            .ok()
            .flatten()
            .is_none_or(|(bytes, _)| bytes != self.body)
        {
            return false;
        }
        let Ok(duplicate) = self.owner.runtime_start_lock() else {
            return false;
        };
        let Ok(offer) = runtime_handoff::Handoff::service(
            listener,
            duplicate.start_lock(),
            Role::ProxyStartAuthorize,
            authenticated,
        ) else {
            return false;
        };
        runtime_handoff::with_runtime_start(offer, peers, context, start)
    }
    /// Native fixed-channel start. The callback must be the bounded fixed
    /// systemd start effect; this API does not accept a command or path.
    pub fn start_native(
        &self,
        authenticated: &AuthenticatedInstalled,
        context: &StartContext,
        start: impl FnOnce(&StartContext) -> bool,
    ) -> bool {
        if self.fs.path() != Path::new("/") {
            return false;
        }
        let Ok(listener) = crate::host::runtime_io::bind_native(self.fs.path()) else {
            return false;
        };
        self.lend_start(
            listener,
            authenticated,
            &runtime_handoff::LinuxPeers,
            context,
            start,
        )
    }
    /// Explicit temporary-root integration; never selected by native dispatch.
    pub fn start_fixture(
        &self,
        socket: &Path,
        authenticated: &AuthenticatedInstalled,
        peers: &(impl runtime_handoff::PeerObservations + Sync),
        context: &StartContext,
        start: impl FnOnce(&StartContext) -> bool,
    ) -> bool {
        if self.fs.path() == Path::new("/") {
            return false;
        }
        let Ok(listener) = crate::host::runtime_io::bind_fixture(self.fs.path(), socket) else {
            return false;
        };
        self.lend_start(listener, authenticated, peers, context, start)
    }
    fn cleanup(&self) -> Result<(), Error> {
        self.owner.verify().map_err(refused)?;
        for path in [
            format!("{}.sbxr-next", crate::host::filesystem::PROXY_GATE),
            crate::host::filesystem::PROXY_GATE.to_owned(),
        ] {
            self.fs
                .remove_bytes(&path, &self.body, Mode::from_raw_mode(0o600))
                .map_err(refused)?;
        }
        self.owner.verify().map_err(refused)
    }
    pub fn finish(mut self) -> Result<(), Error> {
        let result = self.cleanup();
        // Explicit cleanup has one reported outcome; Drop must not retry an
        // uncertain failure behind the caller's back.
        self.finished = true;
        result
    }
    pub fn runtime_start_lock(&self) -> Result<crate::host::locks::OwnerStartLock<'_>, HostError> {
        self.owner.runtime_start_lock()
    }
}
impl Drop for CutoverGate {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}
