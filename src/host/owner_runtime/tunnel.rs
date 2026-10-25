//! Independent native process/cgroup/loopback observations for tunnel setup.
use super::*;
use crate::host::linux::{TunnelRuntime, TunnelRuntimeFacts};
impl<I: OwnerIo> TunnelRuntime for OwnerRuntime<'_, I> {
    fn root(&self) -> &Path {
        self.fs.path()
    }
    fn public_ipv4(&self, owner: &Arc<HostLock>) -> Result<String, HostError> {
        self.installed()?;
        owner.verify()?;
        if owner.root() != self.fs.path() {
            return Err(HostError::Foreign);
        }
        self.io.public_ipv4(&self.context()).map(|p| p.to_string())
    }
    fn observe(
        &self,
        record: Option<&OwnershipRecord>,
        stop: &CommandCancellation,
    ) -> Result<TunnelRuntimeFacts, HostError> {
        use command::{Property as P, Unit as U};
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        self.installed()?;
        let context = self.context();
        let listener = self.text(Observation::Listener10000, &context)?;
        let active = self.property(U::Proxy, P::ActiveState, &context)?;
        let pid = self.property(U::Proxy, P::MainPid, &context)?;
        let control = self.property(U::Proxy, P::ControlPid, &context)?;
        if control != "0" {
            return Err(HostError::Foreign);
        }
        let mut image = String::new();
        let running = if active == "active" {
            let record = record.ok_or(HostError::Foreign)?;
            if !self.proxy_running(record, &context)? {
                return Err(HostError::Foreign);
            }
            let pid = pid.parse::<u32>().map_err(refused)?;
            let process = self.io.process(pid)?;
            let members = self
                .fs
                .cgroup_bytes(U::Proxy, false)?
                .ok_or(HostError::Foreign)?;
            if std::str::from_utf8(&members)
                .map_err(refused)?
                .split_whitespace()
                .collect::<Vec<_>>()
                != vec![pid.to_string()]
                || listener.lines().count() != 1
                || !observation::listener_pid(listener.trim(), 10000, Some("127.0.0.1"), pid)
                || self.io.process(pid)? != process
            {
                return Err(HostError::Foreign);
            }
            image = format!("{process:?}");
            true
        } else {
            if !matches!(active.as_str(), "inactive" | "failed") || pid != "0" {
                return Err(HostError::Foreign);
            }
            let process = self.io.query(Observation::ProxyProcesses, &context)?;
            if process.code() != 1 || !process.text()?.is_empty() {
                return Err(HostError::Foreign);
            }
            if let Some(events) = self.fs.cgroup_bytes(U::Proxy, true)?
                && !observation::population_empty(&events)
            {
                return Err(HostError::Foreign);
            }
            false
        };
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        Ok(TunnelRuntimeFacts {
            fingerprint: sha256_hex(
                format!("{active}:{pid}:{control}:{listener}:{image}").as_bytes(),
            ),
            loopback_empty: listener.is_empty(),
            running,
        })
    }
    fn start(&self, owner: &Arc<HostLock>, context: &StartContext) -> Result<(), HostError> {
        let record = self.record()?;
        runtime_handoff::setup_start_configuration(&record).map_err(refused)?;
        self.package(context)?;
        self.known_unit(command::Unit::Proxy, context)?;
        if !self
            .property(
                command::Unit::Proxy,
                command::Property::ExecCondition,
                context,
            )?
            .is_empty()
            || self.property(command::Unit::Proxy, command::Property::KillMode, context)?
                != "control-group"
            || !observation::exact_exec(
                &self.property(command::Unit::Proxy, command::Property::ExecStart, context)?,
                "/usr/bin/sing-box",
                "/usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run",
            )
        {
            return Err(HostError::Foreign);
        }
        self.service(ServiceAction::StartProxy, owner, None, context)
    }
}
