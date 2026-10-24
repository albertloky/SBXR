use super::command::{Property as P, Unit as U};
use super::*;
use crate::host::subscription::{HttpRuntime, RuntimeFacts, SystemEffect};
impl<I: OwnerIo> OwnerRuntime<'_, I> {
    fn service(
        &self,
        a: ServiceAction,
        owner: &Arc<HostLock>,
        gate: Option<&CutoverGate>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.installed()?;
        owner.verify()?;
        if owner.root() != self.fs.path() {
            return Err(HostError::Unsafe);
        }
        let socket = self.probe.map(|_| {
            self.fs.path().join(format!(
                "owner-{}.sock",
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        });
        let commands = Commands {
            io: &self.io,
            owner,
            socket: socket.as_deref(),
        };
        let controller = if let Some(path) = &socket {
            ServiceController::injected(
                self.fs.path(),
                self.proof,
                owner.clone(),
                Peers(&self.io),
                commands,
                path.clone(),
            )
        } else {
            ServiceController::native_with_commands(
                self.proof,
                owner.clone(),
                Peers(&self.io),
                commands,
            )
        }?;
        match a {
            ServiceAction::EnableSubscription => {
                controller.enable_subscription(c).map_err(refused)?
            }
            ServiceAction::StartSubscription => {
                controller.start_subscription(false, c).map_err(refused)?
            }
            ServiceAction::RestartSubscription => {
                controller.start_subscription(true, c).map_err(refused)?
            }
            ServiceAction::StartProxy | ServiceAction::RestartProxy => {
                if let Some(gate) = gate {
                    controller.start_proxy_cutover(gate, a == ServiceAction::RestartProxy, c)
                } else {
                    controller.start_proxy(a == ServiceAction::RestartProxy, c)
                }
                .map_err(refused)?;
            }
            ServiceAction::Reload => controller.reload(c).map_err(refused)?,
            ServiceAction::StopSubscription => controller.stop_subscription(c).map_err(refused)?,
            _ => self.io.service(a, owner, None, c)?,
        }
        owner.verify()?;
        self.installed()
    }
    fn stop_proxy(&self, owner: &Arc<HostLock>, c: &StartContext) -> Result<(), HostError> {
        if self.property(U::Proxy, P::KillMode, c)? != "control-group"
            || self.property(U::Proxy, P::ControlGroup, c)? != U::Proxy.cgroup()
        {
            return Err(HostError::Foreign);
        }
        self.service(ServiceAction::StopProxy, owner, None, c)
    }
}
impl<I: OwnerIo> HttpRuntime for OwnerRuntime<'_, I> {
    fn facts(&self) -> Result<RuntimeFacts, HostError> {
        let c = Self::context();
        self.installed()?;
        let r = self.record()?;
        let ip = self.io.public_ipv4(&c)?.to_string();
        let proxy = self.proxy_running(&r, &c)?;
        let rules = self.text(Observation::Firewall, &c)?;
        let serving = self.property(U::Subscription, P::ActiveState, &c)? == "active";
        let quiet = if serving {
            false
        } else {
            self.quiescence(U::Subscription, &c)? && self.io.port_available(8443, &c)?
        };
        Ok(RuntimeFacts {
            public_ipv4: ip,
            proxy_running: proxy,
            firewall_rules: rules,
            serving_running: serving,
            quiescent: quiet,
        })
    }
    fn effect(
        &mut self,
        e: SystemEffect,
        r: &OwnershipRecord,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.installed()?;
        if self.record()? != *r {
            return Err(HostError::Foreign);
        }
        match e {
            SystemEffect::Reload => self.service(ServiceAction::Reload, owner, None, c)?,
            SystemEffect::EnableFirewall => {
                self.firewall_effective(r, c)?;
                self.service(ServiceAction::EnableFirewall, owner, None, c)?;
            }
            SystemEffect::DisableFirewall => {
                self.firewall_effective(r, c)?;
                self.service(ServiceAction::DisableFirewall, owner, None, c)?;
            }
            SystemEffect::ActivateServing => {
                self.serving_routes(c)?;
                let authority = runtime_handoff::select_http_authority(r, true).map_err(refused)?;
                let token = self.credential(&authority)?;
                if self.loaded(r, &authority, &token, c).is_err() {
                    if self.property(U::Subscription, P::ActiveState, c)? == "active" {
                        self.service(ServiceAction::StopSubscription, owner, None, c)?;
                        if !self.quiescence(U::Subscription, c)?
                            || !self.io.port_available(8443, c)?
                        {
                            return Err(HostError::Foreign);
                        }
                    }
                    self.service(ServiceAction::EnableSubscription, owner, None, c)?;
                }
                self.loaded(r, &authority, &token, c)?;
            }
            SystemEffect::StopServing | SystemEffect::DisableServing => {
                if self.fs.metadata(crate::host::subscription::UNIT)?.is_none() {
                    if !self.quiescence(U::Subscription, c)? || !self.io.port_available(8443, c)? {
                        return Err(HostError::Foreign);
                    }
                    return Ok(());
                }
                self.serving_routes(c)?;
                self.service(
                    if e == SystemEffect::StopServing {
                        ServiceAction::StopSubscription
                    } else {
                        ServiceAction::DisableSubscription
                    },
                    owner,
                    None,
                    c,
                )?;
                if !self.quiescence(U::Subscription, c)? || !self.io.port_available(8443, c)? {
                    return Err(HostError::Foreign);
                }
            }
        }
        if self.record()? != *r {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn probe(
        &self,
        r: &OwnershipRecord,
        a: &ServingAuthority,
        token: &SubscriptionCredential,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.loaded(r, a, token, c)
    }
}
impl<I: OwnerIo> OwnerRuntime<'_, I> {
    fn credential(&self, a: &ServingAuthority) -> Result<SubscriptionCredential, HostError> {
        let (b, _) = self
            .fs
            .raw(
                super::super::subscription::TOKEN,
                Mode::from_raw_mode(0o600),
                44,
            )?
            .ok_or(HostError::Foreign)?;
        let token = SubscriptionCredential::parse(
            std::str::from_utf8(b.strip_suffix(b"\n").ok_or(HostError::Foreign)?)
                .map_err(refused)?,
        )
        .map_err(refused)?;
        if sha256_hex(token.as_str().as_bytes()) != a.credential_sha256() {
            return Err(HostError::Foreign);
        }
        Ok(token)
    }
}
impl<I: OwnerIo> crate::host::identity::IdentityRuntime for OwnerRuntime<'_, I> {
    fn reload_identity(
        &mut self,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.service(ServiceAction::Reload, owner, None, c)
    }
    fn admit_identity(&self, r: &OwnershipRecord) -> Result<(), HostError> {
        let c = Self::context();
        self.installed()?;
        if self.io.public_ipv4(&c)?.to_string() != r.public_ipv4() || !self.proxy_running(r, &c)? {
            return Err(HostError::Foreign);
        }
        if r.serving_authority().is_some() {
            // Exact protected token/state are proved by ProtectedIdentityHost.
            // A serving fault must not disable the independent identity journey.
            // Validate start routes here; target readiness is proved after cutover.
            self.serving_routes(&c)?;
        }
        Ok(())
    }
    fn subscription_route(&self, _: &OwnershipRecord) -> Result<bool, HostError> {
        self.serving_routes(&Self::context())?;
        Ok(true)
    }
    fn identity_quiescence(&self, r: &OwnershipRecord) -> Result<ci::Quiescence, HostError> {
        let c = Self::context();
        let proxy = self.quiescence(U::Proxy, &c)?;
        let serving = r.serving_authority().is_none()
            || self.quiescence(U::Subscription, &c)? && self.io.port_available(8443, &c)?;
        Ok(ci::Quiescence {
            inactive: proxy,
            main_pid_zero: proxy,
            processes_absent: proxy,
            listener_absent: proxy,
            descendants_empty: proxy,
            subscription_requests_drained: serving,
            subscription_descendants_empty: serving,
            subscription_listener_absent: serving,
            subscription_inactive: serving,
        })
    }
    fn stop_identity_source(
        &mut self,
        r: &OwnershipRecord,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        if r.serving_authority().is_some() {
            self.service(ServiceAction::StopSubscription, owner, None, c)?;
        }
        self.stop_proxy(owner, c)
    }
    fn start_identity_proxy(
        &mut self,
        _: &OwnershipRecord,
        owner: &Arc<HostLock>,
        gate: Option<&CutoverGate>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.service(ServiceAction::StartProxy, owner, gate, c)
    }
    fn finish_identity_subscription(
        &mut self,
        r: &OwnershipRecord,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        if let Some(a) = r.serving_authority() {
            let token = self.credential(&a)?;
            if self.loaded(r, &a, &token, c).is_err() {
                self.service(ServiceAction::RestartSubscription, owner, None, c)?;
            }
            self.loaded(r, &a, &token, c)?;
        }
        Ok(())
    }
    fn verify_identity_running(&self, r: &OwnershipRecord) -> Result<(), HostError> {
        if self.proxy_running(r, &Self::context())? {
            Ok(())
        } else {
            Err(HostError::Foreign)
        }
    }
}
