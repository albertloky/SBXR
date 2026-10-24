//! Concrete protected proxy-start checks and atomic one-use cutover gate.
use super::{material::RuntimeFiles, *};
use crate::{
    host::process::{CommandRunner, NativeReadOnly, Query},
    private_roles::Role,
    runtime_handoff::{LinuxPeers, PeerObservations},
};
use std::path::PathBuf;
pub struct ProxyRuntimeHost<'a, P, R> {
    files: RuntimeFiles<'a>,
    peers: P,
    runner: R,
    socket: Option<PathBuf>,
}
impl<'a> ProxyRuntimeHost<'a, LinuxPeers, NativeReadOnly> {
    /// Local private startup revalidates an already installed protected pair.
    /// This is not signed acquisition or permission to install supplied bytes.
    pub fn native_local_unreleased(
        record: &'a crate::records::InstalledRecord,
    ) -> Result<Self, HostError> {
        Ok(Self {
            files: RuntimeFiles::native_record(record)?,
            peers: LinuxPeers,
            runner: NativeReadOnly,
            socket: None,
        })
    }
    /// Real Linux observations/effects are implemented but public dispatch remains
    /// closed. The caller must supply proof of the actual native current process.
    pub fn native_unreleased(authenticated: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        Ok(Self {
            files: RuntimeFiles::native(authenticated)?,
            peers: LinuxPeers,
            runner: NativeReadOnly,
            socket: None,
        })
    }
}
impl<'a, P: PeerObservations, R: CommandRunner> ProxyRuntimeHost<'a, P, R> {
    pub fn injected(
        root: &Path,
        authenticated: &'a AuthenticatedInstalled,
        peers: P,
        runner: R,
        socket: PathBuf,
    ) -> Result<Self, HostError> {
        if !socket.is_absolute() || !socket.starts_with(root) {
            return Err(HostError::Unsafe);
        }
        Ok(Self {
            files: RuntimeFiles::injected(root, authenticated)?,
            peers,
            runner,
            socket: Some(socket),
        })
    }
    /// A recorded gated configuration and actual Owner scope are required before
    /// publication. Hold the returned lease through handoff/start and call finish.
    pub fn prepare_cutover(
        &self,
        owner: &std::sync::Arc<HostLock>,
        context: &StartContext,
    ) -> Result<super::CutoverGate, Error> {
        context.check()?;
        owner.verify().map_err(refused)?;
        if owner.root() != self.files.fs.path() {
            return Err(Error::Refused);
        }
        let body = self.files.ownership()?;
        let current = self.peers.current()?;
        if current.uid != self.files.fs.uid
            || current.executable_sha256 != self.files.record.executable_sha256()
        {
            return Err(Error::Refused);
        }
        context.check()?;
        let record = OwnershipRecord::decode(&body).map_err(refused)?;
        if record.release_identity() != self.files.record.release_identity() {
            return Err(Error::Refused);
        }
        self.verify_startup(&record, context)?;
        let configuration = self.files.configuration()?;
        if sha256_hex(&configuration) != record.configuration_sha256() {
            return Err(Error::Refused);
        }
        crate::server_configuration::ServerConfiguration::decode_standard(&configuration)
            .map_err(refused)?;
        let gate = super::CutoverGate::prepare(&self.files, &record, owner, context)?;
        if self.files.ownership()? != body {
            return Err(Error::Refused);
        }
        context.check()?;
        Ok(gate)
    }
    fn condition(&self, context: &StartContext) -> Result<Vec<u8>, Error> {
        let output = super::command::run(context, |stop| {
            self.runner.query(Query::ProxyStartCondition, stop)
        })?;
        if output.code() != 0 {
            return Err(Error::Refused);
        }
        Ok(output.text().map_err(refused)?.as_bytes().to_vec())
    }
}
impl<P: PeerObservations, R: CommandRunner> ProxyStartHost for ProxyRuntimeHost<'_, P, R> {
    fn acquire_start(&self, context: &StartContext) -> Result<StartLock, Error> {
        runtime_handoff::acquire_runtime_start(
            self.files.fs.path(),
            self.files.fs.uid,
            Role::ProxyStartAuthorize,
            &self.peers,
            context,
            || {
                let stream = if let Some(path) = &self.socket {
                    crate::host::runtime_io::connect_fixture(self.files.fs.path(), path, context)?
                } else {
                    crate::host::runtime_io::connect_native(self.files.fs.path(), context)?
                };
                let expected = self.peers.peer(&stream)?;
                if expected.uid != self.files.fs.uid
                    || expected.executable_sha256 != self.files.record.executable_sha256()
                {
                    return Err(Error::Refused);
                }
                Ok((stream, expected))
            },
        )
    }
    fn installed_identity(
        &self,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<ReleaseIdentity, Error> {
        context.check()?;
        lock.verify()?;
        self.files.installed()?;
        let current = self.peers.current()?;
        if current.uid != self.files.fs.uid
            || current.executable_sha256 != self.files.record.executable_sha256()
        {
            return Err(Error::Refused);
        }
        context.check()?;
        Ok(self.files.record.release_identity())
    }
    fn ownership(&self) -> Result<Vec<u8>, Error> {
        self.files.ownership()
    }
    fn verify_startup(
        &self,
        record: &OwnershipRecord,
        context: &StartContext,
    ) -> Result<(), Error> {
        self.files.startup(record)?;
        let condition = self.condition(context)?;
        if !exact_start_condition(std::str::from_utf8(&condition).map_err(refused)?) {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn configuration(&self) -> Result<Vec<u8>, Error> {
        self.files.configuration()
    }
    fn mutation_in_progress(&self) -> Result<bool, Error> {
        match StartLock::existing(self.files.fs.path(), self.files.fs.uid) {
            Ok(_) => Ok(false),
            Err(Error::Busy) => Ok(true),
            Err(error) => Err(error),
        }
    }
    fn consume_authorization(
        &self,
        hash: &str,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<(), Error> {
        self.files.fs.consume_proxy_gate(hash, lock, context)
    }
}
pub(super) fn exact_start_condition(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.matches('{').count() != 1 || raw.matches('}').count() != 1 {
        return false;
    }
    let (mut path, mut arguments, mut required) = (false, false, false);
    for field in raw.trim_matches(['{', '}', ' ']).split(';').map(str::trim) {
        match field {
            "path=/usr/local/bin/sbxr" => {
                if path {
                    return false;
                }
                path = true;
            }
            "argv[]=/usr/local/bin/sbxr --proxy-start-authorize" => {
                if arguments {
                    return false;
                }
                arguments = true;
            }
            "ignore_errors=no" => {
                if required {
                    return false;
                }
                required = true;
            }
            other => {
                if ["path=", "argv[]=", "ignore_errors="]
                    .iter()
                    .any(|p| other.starts_with(p))
                {
                    return false;
                }
            }
        }
    }
    path && arguments && required
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
