//! Shared Owner/terminal bridge over the existing durable tunnel orchestration.
use super::*;
use crate::{
    host::process::Cancellation,
    identity_generation::{Entropy, Identity, OsEntropy},
    records::{OwnershipRecord, RecoveryDirection, SetupPhase},
    tunnel_setup as t,
};
pub(super) enum TunnelPrepared {
    Setup(Box<t::PreparedAction>),
    Check(t::Snapshot),
}
pub struct TunnelOwnerInstallation<H: t::Host> {
    module: RefCell<t::TunnelInstallation<H>>,
    owner: RefCell<Rc<()>>,
    entropy: RefCell<Box<dyn Entropy>>,
    stop: Cancellation,
    mode: ExecutionMode,
    last_check: Option<t::ConnectionCheck>,
}
impl<H: t::Host> TunnelOwnerInstallation<H> {
    pub fn new(host: H, mode: ExecutionMode) -> Self {
        Self::with_entropy(host, mode, Box::new(OsEntropy))
    }
    pub fn with_entropy(host: H, mode: ExecutionMode, entropy: Box<dyn Entropy>) -> Self {
        Self {
            module: RefCell::new(t::TunnelInstallation::new(host)),
            owner: RefCell::new(Rc::new(())),
            entropy: RefCell::new(entropy),
            stop: Cancellation::new(),
            mode,
            last_check: None,
        }
    }
    pub fn with_cancellation(mut self, stop: Cancellation) -> Self {
        self.stop = stop;
        *self.owner.get_mut() = Rc::new(());
        self
    }
    pub fn host_mut(&mut self) -> &mut H {
        *self.owner.get_mut() = Rc::new(());
        self.module.get_mut().host_mut()
    }
    fn state(&self) -> std::result::Result<(t::Snapshot, Status, Option<Action>), t::Error> {
        let (snapshot, facts) = self.module.borrow_mut().status(&self.stop)?;
        let (status, action) = if let Some(bytes) = &snapshot.current {
            let r = OwnershipRecord::decode(bytes).map_err(|_| t::Error::Authority)?;
            match r.recovery_direction() {
                RecoveryDirection::Cleanup => {
                    (Status::SetupIncomplete, Some(Action::FinishCleanup))
                }
                RecoveryDirection::FinishSetup => {
                    (Status::SetupIncomplete, Some(Action::FinishSetup))
                }
                RecoveryDirection::None if r.phase() == SetupPhase::Running && facts.running => {
                    (Status::Running, Some(Action::CheckVmessTunnel))
                }
                _ => return Err(t::Error::Authority),
            }
        } else if facts.empty {
            (Status::NotSetUp, Some(Action::StartSetup))
        } else {
            return Err(t::Error::Authority);
        };
        Ok((snapshot, status, action))
    }
    fn refused(&self) -> Review {
        Review {mode:self.mode,status:Status::ProblemDetected,details:vec!["Tunnel ownership, package or local runtime could not be verified. Preserve foreign state.".into()],legal_actions:vec![Action::ViewDetails],plan:vec![],refusal:Some("Restore exact recorded local prerequisites and review again."),prepared:None}
    }
    fn result(
        &self,
        outcome: Outcome,
        status: Status,
        message: &'static str,
    ) -> crate::domain::Result {
        crate::domain::Result {
            outcome,
            status,
            proxy_traffic: if status == Status::Running {
                Availability::ProvedWorking
            } else {
                Availability::CannotBeVerified
            },
            message,
        }
    }
}
impl<H: t::Host> Interface for TunnelOwnerInstallation<H> {
    fn supports_tunnel(&self) -> bool {
        true
    }
    fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let Ok((snapshot, status, legal)) = self.state() else {
            return self.refused();
        };
        let mut prepared = None;
        if legal == Some(action) {
            let token = if action == Action::CheckVmessTunnel {
                Some(TunnelPrepared::Check(snapshot))
            } else if matches!(action, Action::FinishSetup | Action::FinishCleanup) {
                self.module
                    .borrow_mut()
                    .review_finish(&self.stop)
                    .ok()
                    .map(|p| TunnelPrepared::Setup(Box::new(p)))
            } else {
                None
            };
            if let Some(token) = token {
                prepared = Some(PreparedAction {
                    owner: self.owner.borrow().clone(),
                    action,
                    basis: PreparedBasis::Tunnel(Box::new(token)),
                });
            }
        }
        Review {mode:self.mode,status,details:vec!["Standard + dedicated VMess WebSocket uses only the Owner's tunnel. Local Running is distinct from a fresh public connection check.".into()],legal_actions:legal.into_iter().chain([Action::ViewDetails]).collect(),plan:vec!["Apply only the reviewed dedicated connector and exact recorded Standard effects. Preserve the Owner token, cloudflared, DNS and tunnel account. Recover only in the recorded direction.".into()],refusal:None,prepared}
    }
    fn review_tunnel_setup(&self, hostname: &str) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        if !crate::subscription_artifact::valid_vmess_hostname(hostname) {
            return self.refused();
        }
        let config = (|| {
            let identity = Identity::generate_with_entropy(self.entropy.borrow_mut().as_mut())
                .map_err(|_| t::Error::Authority)?;
            crate::server_configuration::ServerConfiguration::standard(
                &identity
                    .server_identity()
                    .map_err(|_| t::Error::Authority)?,
            )
            .and_then(|c| c.with_vmess_websocket(hostname))
            .map_err(|_| t::Error::Authority)
        })();
        let Ok(config) = config else {
            return self.refused();
        };
        let token = self
            .module
            .borrow_mut()
            .review_setup(hostname, config, &self.stop);
        let Ok(token) = token else {
            return self.refused();
        };
        let Ok(id) = token.tunnel_id() else {
            return self.refused();
        };
        Review {mode:self.mode,status:Status::NotSetUp,details:vec![],legal_actions:vec![Action::StartSetup,Action::ViewDetails],plan:vec![format!("Standard + Cloudflare: hostname {hostname}; dedicated tunnel {id}."),"Install only sbxr-tunnel.service using the protected existing token file. Preserve cloudflared, token, DNS and Cloudflare account resources. Local setup and public connection results remain separate.".into()],refusal:None,prepared:Some(PreparedAction {owner:self.owner.borrow().clone(),action:Action::StartSetup,basis:PreparedBasis::Tunnel(Box::new(TunnelPrepared::Setup(Box::new(token))))})}
    }
    fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
    ) -> crate::domain::Result {
        self.last_check = None;
        if !Rc::ptr_eq(self.owner.get_mut(), &prepared.owner)
            || self.mode == ExecutionMode::NativeUnavailable
        {
            return self.result(
                Outcome::Refused,
                Status::ProblemDetected,
                "Prepared tunnel authority expired or native execution remains unavailable.",
            );
        }
        *self.owner.get_mut() = Rc::new(());
        let PreparedBasis::Tunnel(token) = prepared.basis else {
            return self.result(
                Outcome::Refused,
                Status::ProblemDetected,
                "Prepared action belongs to another adapter.",
            );
        };
        if confirmation == Confirmation::Declined {
            let status = self
                .state()
                .map(|(_, s, _)| s)
                .unwrap_or(Status::ProblemDetected);
            return self.result(
                Outcome::Cancelled,
                status,
                "Tunnel action cancelled. No change was authorized.",
            );
        }
        let result = match *token {
            TunnelPrepared::Setup(token) => {
                self.module
                    .get_mut()
                    .execute_and_check(*token, confirmation, &self.stop)
            }
            TunnelPrepared::Check(expected) => {
                if self
                    .module
                    .get_mut()
                    .status(&self.stop)
                    .map_or(true, |(fresh, _)| fresh != expected)
                {
                    return self.result(
                        Outcome::Refused,
                        Status::ProblemDetected,
                        "Tunnel authority changed. Review again.",
                    );
                }
                Ok((
                    t::SetupOutcome::RunningConnectionPending,
                    Some(self.module.get_mut().check_connection(&self.stop)),
                ))
            }
        };
        match result {
            Ok((t::SetupOutcome::Cancelled,_))=>self.result(Outcome::Cancelled,Status::NotSetUp,"Tunnel setup cancelled."),
            Ok((t::SetupOutcome::CleanedUp,_))=>self.result(Outcome::CleanedUp,Status::NotSetUp,"Recorded setup resources were cleaned; Owner token, cloudflared and account resources remain unchanged."),
            Ok((t::SetupOutcome::RunningConnectionPending,Some(check)))=> {
                let result = self.result(if check.verified(){Outcome::VmessConnectionVerified}else{Outcome::VmessConnectionPending},if check.local_running(){Status::Running}else{Status::ProblemDetected},check.message());
                self.last_check = Some(check);
                result
            },
            Ok(_)=>self.result(Outcome::VmessConnectionPending,Status::Running,"Local setup is running; public VMess connection remains pending."),
            Err(t::Error::StaleReview)=>self.result(Outcome::Refused,Status::ProblemDetected,"Prepared tunnel facts changed. Review again."),
            Err(_)=>match self.state(){
                Ok((_,_,Some(Action::FinishCleanup)))=>self.result(Outcome::NeedsCleanup,Status::SetupIncomplete,"Uncommitted tunnel setup requires Finish cleanup."),
                Ok((_,_,Some(Action::FinishSetup)))=>self.result(Outcome::NeedsCompletion,Status::SetupIncomplete,"Activation is committed. Only Finish setup is legal."),
                _=>self.result(Outcome::Refused,Status::ProblemDetected,"Tunnel authority or effects could not be verified. Preserve exact state."),
            }
        }
    }
    fn execute_output(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
        output: &mut dyn std::io::Write,
    ) -> std::io::Result<crate::domain::Result> {
        let result = self.execute(prepared, confirmation);
        if let Some(check) = self.last_check.take() {
            // Only typed stages and fixed problem descriptions reach the terminal.
            writeln!(output, "VMess connection check stage: {:?}", check.stage())?;
            if let Some(problem) = check.problem() {
                writeln!(output, "VMess connection check problem: {problem}")?;
            }
        }
        Ok(result)
    }
}
