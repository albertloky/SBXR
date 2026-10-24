//! Proxy Installation owns review, confirmation, setup direction, and recovery.
//! Explicit simulation and filesystem-fixture adapters share Review/Execute.
//! No live host adapter or deployment capability is implemented.
mod fixture;
pub use fixture::{FixtureInstallation, StandardInstallation};
mod simulation;
pub use simulation::{Facts, SimulatedHost, SimulationFault};

use crate::configuration::STANDARD;
use crate::domain::{Action, Availability, Confirmation, Outcome, Phase, Result, Status};
use std::{cell::RefCell, rc::Rc};

/// Opaque, instance-bound authority. Rust ownership makes execution single-use.
/// It is deliberately neither Clone nor serializable.
///
/// ```compile_fail
/// use sbxr::{domain::{Action, Confirmation}, proxyinstallation::Installation};
/// let mut installation = Installation::simulation();
/// let prepared = installation.review(Action::StartSetup).prepared.unwrap();
/// installation.execute(prepared, Confirmation::Declined);
/// installation.execute(prepared, Confirmation::Approved);
/// ```
pub struct PreparedAction {
    owner: Rc<()>,
    action: Action,
    basis: PreparedBasis,
}
enum PreparedBasis {
    Simulation {
        facts: Facts,
        phase: Phase,
        revision: u64,
    },
    Fixture(fixture::FixturePrepared),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Simulation,
    Fixture,
    InjectedHost,
}

/// The existing two-operation product boundary, shared by concrete adapters.
pub trait Interface {
    fn review(&self, action: Action) -> Review;
    fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> Result;
}

pub struct Review {
    pub mode: ExecutionMode,
    pub details: Vec<String>,
    pub status: Status,
    pub legal_actions: Vec<Action>,
    pub plan: Vec<String>,
    pub refusal: Option<&'static str>,
    pub prepared: Option<PreparedAction>,
}

pub struct Installation {
    owner: RefCell<Rc<()>>,
    host: SimulatedHost,
    revision: u64,
}

impl Installation {
    pub fn simulation() -> Self {
        Self {
            owner: RefCell::new(Rc::new(())),
            host: SimulatedHost::default(),
            revision: 0,
        }
    }

    pub fn host(&self) -> &SimulatedHost {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut SimulatedHost {
        &mut self.host
    }
    pub fn phase(&self) -> Phase {
        self.host.phase
    }

    pub fn status(&self) -> Status {
        match self.phase() {
            Phase::Absent => Status::NotSetUp,
            Phase::Preparing | Phase::ActivationCommitted => Status::SetupIncomplete,
            Phase::Running => Status::Running,
        }
    }

    fn mutation_action(&self) -> Option<Action> {
        match self.phase() {
            Phase::Absent => Some(Action::StartSetup),
            Phase::Preparing => Some(Action::FinishCleanup),
            Phase::ActivationCommitted => Some(Action::FinishSetup),
            Phase::Running => None,
        }
    }

    pub fn review(&self, action: Action) -> Review {
        // Every fresh Review expires all earlier memory-only authority.
        *self.owner.borrow_mut() = Rc::new(());
        let refusal = self.host.facts.refusal(self.phase());
        let mut legal_actions = vec![Action::ViewDetails];
        if refusal.is_none() {
            legal_actions.extend(self.mutation_action());
        }
        let prepared = if legal_actions.contains(&action) && action != Action::ViewDetails {
            Some(PreparedAction {
                owner: Rc::clone(&self.owner.borrow()),
                action,
                basis: PreparedBasis::Simulation {
                    facts: self.host.facts,
                    phase: self.phase(),
                    revision: self.revision,
                },
            })
        } else {
            None
        };
        let plan = match action {
            Action::StartSetup => vec![
                format!("SIMULATION: prepare sing-box {} for Standard VLESS REALITY Vision.", STANDARD.package_version),
                format!("Model protected configuration {} and ownership {}.", STANDARD.configuration_path, STANDARD.ownership_path),
                format!("Model {} and public TCP {}; SSH and unrelated resources remain outside this operation.", STANDARD.service, STANDARD.listen_port),
                format!("Production setup would require package HTTPS access and a compatible {} handshake.", STANDARD.handshake_address),
                "No domain or subscription is needed for Standard. No subscription is enabled here.".into(),
                "Before Activation committed: Finish cleanup. After it: Finish setup only.".into(),
                "No credential is generated or disclosed. No file, package, service or firewall is changed.".into(),
            ],
            Action::FinishCleanup => vec!["SIMULATION: discard only the pre-activation simulated setup; return to Not set up.".into()],
            Action::FinishSetup => vec!["SIMULATION: complete only the committed activation forward; rollback is forbidden.".into()],
            _ => vec![],
        };
        Review {
            mode: ExecutionMode::Simulation,
            details: vec![format!(
                "Simulation phase: {:?}. No credential or real runtime is present.",
                self.phase()
            )],
            status: self.status(),
            legal_actions,
            plan,
            refusal,
            prepared,
        }
    }

    pub fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> Result {
        let PreparedBasis::Simulation {
            facts,
            phase,
            revision,
        } = prepared.basis
        else {
            return self.result(
                Outcome::Refused,
                "Prepared authority belongs to a different adapter.",
            );
        };
        if !Rc::ptr_eq(&self.owner.borrow(), &prepared.owner)
            || revision != self.revision
            || facts != self.host.facts
            || phase != self.phase()
            || self.host.facts.refusal(self.phase()).is_some()
            || self.mutation_action() != Some(prepared.action)
        {
            return self.result(
                Outcome::Refused,
                "Safety facts changed or authority is invalid. Review again.",
            );
        }
        if confirmation == Confirmation::Declined {
            return self.result(Outcome::Cancelled, "Setup cancelled. No changes were made.");
        }
        self.revision += 1;
        if prepared.action == Action::FinishCleanup {
            self.host.transition(Phase::Absent);
            return self.result(
                Outcome::CleanedUp,
                "Simulated cleanup complete. No host resources were changed.",
            );
        }
        if prepared.action == Action::StartSetup {
            self.host.transition(Phase::Preparing);
            if self.host.fault == Some(SimulationFault::BeforeActivation) {
                return self.result(
                    Outcome::NeedsCleanup,
                    "Simulated setup interrupted before activation. Choose Finish cleanup.",
                );
            }
            self.host.transition(Phase::ActivationCommitted);
        }
        if self.host.fault == Some(SimulationFault::AfterActivation) {
            return self.result(
                Outcome::NeedsCompletion,
                "Simulated activation committed. Choose Finish setup; cleanup is forbidden.",
            );
        }
        self.host.transition(Phase::Running);
        self.result(Outcome::SetupComplete, "Simulation complete. No software was installed. Outside-client and Karing tests were not run.")
    }

    fn result(&self, outcome: Outcome, message: &'static str) -> Result {
        Result {
            outcome,
            status: self.status(),
            proxy_traffic: Availability::CannotBeVerified,
            message,
        }
    }
}

impl Interface for Installation {
    fn review(&self, action: Action) -> Review {
        Installation::review(self, action)
    }
    fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> Result {
        Installation::execute(self, prepared, confirmation)
    }
}
