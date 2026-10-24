//! Concrete fixed Linux Owner runtime, tested through its closed I/O boundary.
//! Injected roots never call native commands; native construction is unavailable
//! on unsupported hosts. Public dispatch additionally requires released build proof.
mod command;
mod disclosure;
mod effects;
mod historical;
mod observation;
mod probe;
mod removal;
mod tunnel;
use super::{
    HostError,
    filesystem::ProtectedFs,
    locks::HostLock,
    process::{Cancellation as CommandCancellation, CommandOutput, CommandRunner, Query},
    runtime::{CutoverGate, ServiceAction, ServiceCommands, ServiceController},
};
use crate::{
    client_identity as ci,
    records::{OwnershipRecord, ServingAuthority, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
    runtime_handoff::{self, PeerObservations, StartContext},
    subscription_artifact::SubscriptionCredential,
    subscription_serving::Cancellation,
};
pub use command::{HistoricalObservation, NativeIo, Observation, OwnerIo, Property, Unit};
use rustix::fs::Mode;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn refused(_: impl std::fmt::Debug) -> HostError {
    HostError::Foreign
}
pub struct OwnerRuntime<'a, I> {
    fs: ProtectedFs,
    proof: &'a AuthenticatedInstalled,
    io: I,
    probe: Option<std::net::SocketAddr>,
    stop: Cancellation,
}
impl<'a> OwnerRuntime<'a, NativeIo> {
    pub fn native_unreleased(proof: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        let runtime = Self {
            fs: ProtectedFs::native()?,
            proof,
            io: NativeIo,
            probe: None,
            stop: Cancellation::new(),
        };
        runtime.installed()?;
        Ok(runtime)
    }
}
impl<'a, I: OwnerIo> OwnerRuntime<'a, I> {
    pub fn injected(
        root: &Path,
        proof: &'a AuthenticatedInstalled,
        io: I,
        probe: std::net::SocketAddr,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || !probe.ip().is_loopback() || probe.port() < 1024 {
            return Err(HostError::LiveUnavailable);
        }
        let runtime = Self {
            fs: ProtectedFs::open(root)?,
            proof,
            io,
            probe: Some(probe),
            stop: Cancellation::new(),
        };
        runtime.installed()?;
        Ok(runtime)
    }
    pub fn with_cancellation(mut self, stop: Cancellation) -> Self {
        self.stop = stop;
        self
    }
    pub fn io(&self) -> &I {
        &self.io
    }
    fn context(&self) -> StartContext {
        StartContext::new(
            self.stop.clone(),
            Instant::now() + runtime_handoff::START_TIMEOUT,
        )
    }
    pub(in crate::host) fn installed(&self) -> Result<(), HostError> {
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        if !super::lifecycle::transactions_absent(&self.fs)? {
            return Err(HostError::Foreign);
        }
        if super::linux::observation::read_installed(&self.fs)?.as_ref()
            != Some(self.proof.record())
        {
            return Err(HostError::Foreign);
        }
        let current = self.io.current().map_err(refused)?;
        if current.uid != self.fs.uid
            || current.executable_sha256 != self.proof.record().executable_sha256()
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn text(&self, q: Observation, ctx: &StartContext) -> Result<String, HostError> {
        let out = self.io.query(q, ctx)?;
        if out.code() != 0 {
            return Err(HostError::Foreign);
        }
        Ok(out.text()?.to_owned())
    }
    fn property(&self, u: Unit, p: Property, ctx: &StartContext) -> Result<String, HostError> {
        self.text(Observation::Property(u, p), ctx)
    }
    fn record(&self) -> Result<OwnershipRecord, HostError> {
        super::linux::observation::read_ownership(&self.fs)?.ok_or(HostError::Foreign)
    }
}
impl<I: OwnerIo> PeerObservations for OwnerRuntime<'_, I> {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        self.io.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        self.io.peer(s)
    }
}
impl<I: OwnerIo> CommandRunner for OwnerRuntime<'_, I> {
    fn query(&self, q: Query, stop: &CommandCancellation) -> Result<CommandOutput, HostError> {
        if self.stop.is_cancelled() || stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        if q != Query::ProxyStartCondition {
            return Err(HostError::LiveUnavailable);
        }
        self.io.query(
            Observation::Property(Unit::Proxy, Property::ExecCondition),
            &self.context(),
        )
    }
}
struct Peers<'a, I>(&'a I);
impl<I: PeerObservations> PeerObservations for Peers<'_, I> {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        self.0.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        self.0.peer(s)
    }
}
struct Commands<'a, I> {
    io: &'a I,
    owner: &'a Arc<HostLock>,
    socket: Option<&'a Path>,
}
impl<I: OwnerIo> ServiceCommands for Commands<'_, I> {
    fn execute(&self, a: ServiceAction, c: &StartContext) -> Result<(), runtime_handoff::Error> {
        self.io
            .service(a, self.owner, self.socket, c)
            .map_err(|_| runtime_handoff::Error::Refused)
    }
}

#[cfg(test)]
#[path = "owner_runtime/tests.rs"]
mod tests;

pub(in crate::host) use observation::exact_exec as exact_connector_exec;
