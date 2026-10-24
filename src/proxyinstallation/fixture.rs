//! Durable Standard setup/recovery over the concrete SetupHost contract.
//! The original FixtureInstallation alias preserves the explicit fixture adapter.
use super::{ExecutionMode, Interface, PreparedAction, PreparedBasis, Review};
use crate::{
    domain::{Action, Availability, Confirmation, Outcome, Result as ActionResult, Status},
    durable::{OwnershipStore, Recovery, Snapshot},
    host::{FixtureHost, HostError, Operation, SetupHost, SetupObservation},
    records::{OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase},
};
#[cfg(test)]
use crate::{host::FIXTURE_CONFIGURATION, records::sha256_hex};
use std::{cell::RefCell, rc::Rc};

pub(super) struct FixturePrepared {
    current: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
    observation: SetupObservation,
}
struct State {
    snapshot: Snapshot,
    observation: SetupObservation,
    status: Status,
    action: Option<Action>,
}

pub struct StandardInstallation<H: SetupHost> {
    owner: RefCell<Rc<()>>,
    host: H,
    store: OwnershipStore,
    release: ReleaseIdentity,
}
pub type FixtureInstallation = StandardInstallation<FixtureHost>;
impl<H: SetupHost> StandardInstallation<H> {
    pub fn new(host: H, release: ReleaseIdentity) -> Result<Self, HostError> {
        let store = OwnershipStore::open(&host.root().join("var/lib/sbxr"), host.uid())
            .map_err(|_| HostError::Unsafe)?;
        Ok(Self {
            owner: RefCell::new(Rc::new(())),
            host,
            store,
            release,
        })
    }
    pub fn into_host(self) -> H {
        self.host
    }
    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }
    fn mode(&self) -> ExecutionMode {
        if self.host.is_native_system() {
            ExecutionMode::NativeUnavailable
        } else if self.host.is_injected_system() {
            ExecutionMode::InjectedHost
        } else {
            ExecutionMode::Fixture
        }
    }
    fn state(&self) -> Result<State, ()> {
        if !self.host.effects_available() {
            return Err(());
        }
        let snapshot = self.store.load().map_err(|_| ())?;
        let observation = self.host.inspect_setup(&self.release).map_err(|_| ())?;
        if snapshot.current.as_ref().is_some_and(|current| {
            current.record.schema() != 1
                || current.record.tunnel_authority().is_some()
                || current.record.release_identity() != self.release
                || current.record.configuration_sha256() != self.host.configuration_sha256()
                || current.record.lock_provisioning_sha256().is_none()
        }) {
            return Err(());
        }
        let (status, action) = match snapshot.recovery() {
            Recovery::Absent if observation.empty() => (Status::NotSetUp, Some(Action::StartSetup)),
            Recovery::Cleanup => (Status::SetupIncomplete, Some(Action::FinishCleanup)),
            Recovery::FinishSetup if observation.ready_to_activate() => {
                let phase = snapshot.current.as_ref().ok_or(())?.record.phase();
                if phase == SetupPhase::ServiceEnabled && !observation.service_enabled()
                    || phase == SetupPhase::ServiceStarted && !observation.running()
                {
                    return Err(());
                }
                (Status::SetupIncomplete, Some(Action::FinishSetup))
            }
            Recovery::Running if observation.running() => (Status::Running, None),
            _ => return Err(()),
        };
        Ok(State {
            snapshot,
            observation,
            status,
            action,
        })
    }
    pub fn review(&self, action: Action) -> Review {
        *self.owner.borrow_mut() = Rc::new(());
        let Ok(state) = self.state() else {
            return Review{mode:self.mode(),details:vec!["Host authority could not be verified. Preserve unknown state; real deployment is unavailable.".into()],status:Status::ProblemDetected,legal_actions:vec![Action::ViewDetails],plan:vec![],refusal:Some("Host ownership or observations are unsafe or unsupported. No deployment action is available."),prepared:None};
        };
        let mut legal_actions = vec![Action::ViewDetails];
        legal_actions.extend(state.action);
        let prepared = if state.action == Some(action) {
            Some(PreparedAction {
                owner: Rc::clone(&self.owner.borrow()),
                action,
                basis: PreparedBasis::Fixture(FixturePrepared {
                    current: state.snapshot.current.as_ref().map(|r| r.bytes().to_vec()),
                    staged: state.snapshot.staged.as_ref().map(|r| r.bytes().to_vec()),
                    observation: state.observation,
                }),
            })
        } else {
            None
        };
        let mut plan=match action {
            Action::StartSetup=>vec!["FIXTURE ONLY: write the Standard setup footprint beneath the marked temporary root. No Ubuntu command is executed.".into(),"Before Activation committed, recover with Finish cleanup. After commitment, only Finish setup is legal.".into(),"Synthetic package/configuration facts do not prove real package trust, traffic, deployment or Karing.".into()],
            Action::FinishCleanup=>vec!["FIXTURE ONLY: remove only exactly matched recorded proxy resources; retain unknown files and the installed software pair.".into()],
            Action::FinishSetup=>vec!["FIXTURE ONLY: finish the committed activation forward using fresh exact resource checks.".into()],
            _=>vec![],
        };
        if self.host.is_injected_system() && !plan.is_empty() {
            plan=vec!["INJECTED LINUX HOST: only the supplied runner and protected test-root files may change. Native deployment remains unavailable.".into(),"Keep cleanup before activation commitment and forward completion afterward; these checks do not qualify Ubuntu, traffic or Karing.".into()];
        }
        Review {
            mode: self.mode(),
            details: vec![format!(
                "{} durable phase: {:?}. Injected or synthetic host facts prove no real runtime or release qualification.",
                if self.host.is_injected_system() {
                    "Injected Linux host"
                } else {
                    "Fixture"
                },
                state.snapshot.current.as_ref().map(|r| r.record.phase())
            )],
            status: state.status,
            legal_actions,
            plan,
            refusal: None,
            prepared,
        }
    }
    pub fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
    ) -> ActionResult {
        let PreparedBasis::Fixture(basis) = prepared.basis else {
            return self.result(
                Outcome::Refused,
                "Prepared authority belongs to another adapter.",
            );
        };
        let Ok(state) = self.state() else {
            return self.result(
                Outcome::Refused,
                "Fixture facts cannot be verified. Review again.",
            );
        };
        if !Rc::ptr_eq(&self.owner.borrow(), &prepared.owner)
            || state.action != Some(prepared.action)
            || state.observation != basis.observation
            || state.snapshot.current.as_ref().map(|r| r.bytes()) != basis.current.as_deref()
            || state.snapshot.staged.as_ref().map(|r| r.bytes()) != basis.staged.as_deref()
        {
            return self.result(
                Outcome::Refused,
                "Fixture safety facts changed or prepared authority expired. Review again.",
            );
        }
        if confirmation == Confirmation::Declined {
            return self.result(
                Outcome::Cancelled,
                "Fixture action cancelled. No changes were made.",
            );
        }
        if self.host.begin_change().is_err() {
            return self.result(
                Outcome::Refused,
                "Whole-host exclusion could not be retained. Review again.",
            );
        }
        let result = match self.state() {
            Ok(locked)
                if locked.action == Some(prepared.action)
                    && locked.observation == basis.observation
                    && locked.snapshot.current.as_ref().map(|r| r.bytes())
                        == basis.current.as_deref()
                    && locked.snapshot.staged.as_ref().map(|r| r.bytes())
                        == basis.staged.as_deref() =>
            {
                self.execute_approved(prepared.action, locked)
            }
            _ => self.result(
                Outcome::Refused,
                "Facts changed while acquiring whole-host exclusion. Review again.",
            ),
        };
        self.host.end_change();
        result
    }
    fn execute_approved(&mut self, action: Action, state: State) -> ActionResult {
        if action == Action::StartSetup {
            let Ok(record) = OwnershipRecord::new_standard(
                self.release.clone(),
                self.host.public_ipv4(),
                &self.host.configuration_sha256(),
            ) else {
                return self.result(
                    Outcome::Refused,
                    "Fixture setup authority could not be prepared.",
                );
            };
            if !self.publish(None, &record) {
                return self.pending();
            }
            if self.host.interrupted(record.phase()) {
                return self.pending();
            }
            return self.run_setup(record);
        }
        let Some(current) = state.snapshot.current else {
            return self.result(Outcome::Refused, "Fixture ownership disappeared.");
        };
        if action == Action::FinishCleanup {
            self.cleanup(current.record)
        } else {
            self.run_setup(current.record)
        }
    }
    fn run_setup(&mut self, mut record: OwnershipRecord) -> ActionResult {
        if self
            .store
            .synchronize(&record.encode().expect("validated record"))
            .is_err()
        {
            return self.pending();
        }
        loop {
            let Ok(next) = record.next_setup_checkpoint() else {
                return self.result(Outcome::Refused, "No setup checkpoint is authorized.");
            };
            let operation = match next.phase() {
                SetupPhase::AptKeyInstalled => Some(Operation::InstallAptKey),
                SetupPhase::AptSourceInstalled => Some(Operation::InstallAptSource),
                SetupPhase::ServiceMasked => Some(Operation::MaskService),
                SetupPhase::PackageInstalled => Some(Operation::InstallPackage),
                SetupPhase::PackageHeld => Some(Operation::HoldPackage),
                SetupPhase::StateDirectoryCreated => Some(Operation::CreateStateDirectory),
                SetupPhase::ConfigurationInstalled => Some(Operation::InstallConfiguration),
                SetupPhase::ConfigurationValidated => Some(Operation::ValidateConfiguration),
                SetupPhase::ServiceUnmasked => Some(Operation::UnmaskService),
                SetupPhase::ServiceEnabled => Some(Operation::EnableService),
                SetupPhase::ServiceStarted => Some(Operation::StartService),
                _ => None,
            };
            if let Some(operation) = operation {
                if self.host.apply_setup(operation, &record).is_err() {
                    return if record.recovery_direction() == RecoveryDirection::Cleanup {
                        self.cleanup(record)
                    } else {
                        self.pending()
                    };
                }
            } else if next.phase() == SetupPhase::ActivationCommitted {
                if !self
                    .host
                    .inspect_setup(&self.release)
                    .is_ok_and(|o| o.ready_to_activate() && o.stopped())
                {
                    return self.pending();
                }
            } else if next.phase() == SetupPhase::Running
                && !self
                    .host
                    .inspect_setup(&self.release)
                    .is_ok_and(|o| o.running())
            {
                return self.pending();
            }
            let bytes = record.encode().expect("validated record");
            if !self.publish(Some(&bytes), &next) {
                return self.pending();
            }
            record = next;
            if record.phase() == SetupPhase::Running {
                return self.result(Outcome::SetupComplete,"Fixture setup is complete and its files are verified. No real software, traffic or outside client was tested.");
            }
            if self.host.interrupted(record.phase()) {
                return self.pending();
            }
        }
    }
    fn cleanup(&mut self, mut record: OwnershipRecord) -> ActionResult {
        if record.recovery_direction() != RecoveryDirection::Cleanup {
            return self.result(
                Outcome::Refused,
                "Committed activation cannot be cleaned up.",
            );
        }
        let Ok(snapshot) = self.store.load() else {
            return self.pending();
        };
        if let Some(staged) = snapshot.staged {
            if !record.permits_successor(&staged.record)
                || staged.record.recovery_direction() != RecoveryDirection::Cleanup
            {
                return self.pending();
            }
            if !self.publish(
                Some(&record.encode().expect("validated record")),
                &staged.record,
            ) {
                return self.pending();
            }
            record = staged.record;
        }
        if self
            .store
            .synchronize(&record.encode().expect("validated record"))
            .is_err()
        {
            return self.pending();
        }
        const STEPS: [Operation; 8] = [
            Operation::StopDisableService,
            Operation::UnmaskService,
            Operation::RemovePackageArtifact,
            Operation::RemovePackage,
            Operation::RemoveConfigurationState,
            Operation::RemovePackageIdentity,
            Operation::RemoveAptSource,
            Operation::RemoveAptKey,
        ];
        while (record.cleanup_checkpoint() as usize) < STEPS.len() {
            let operation = STEPS[record.cleanup_checkpoint() as usize];
            if self.host.apply_setup(operation, &record).is_err() {
                return self.pending();
            }
            let next = record
                .next_cleanup_checkpoint()
                .expect("bounded cleanup checkpoint");
            if !self.publish(Some(&record.encode().expect("validated record")), &next) {
                return self.pending();
            }
            record = next;
        }
        if !self
            .host
            .inspect_setup(&self.release)
            .is_ok_and(|o| o.empty())
        {
            return self.pending();
        }
        if self
            .store
            .remove_completed_cleanup(&record.encode().expect("validated record"))
            .is_err()
        {
            return self.pending();
        }
        if !self
            .host
            .inspect_setup(&self.release)
            .is_ok_and(|o| o.empty())
        {
            return self.result(
                Outcome::Refused,
                "Fixture cleanup ended without a proved empty footprint.",
            );
        }
        self.result(Outcome::CleanedUp,"Fixture cleanup completed. Recorded proxy resources are absent; installed software and foreign files are preserved.")
    }
    fn publish(&mut self, source: Option<&[u8]>, target: &OwnershipRecord) -> bool {
        if self.store.publish(source, target).is_ok() {
            return true;
        }
        // A visible target after a rename error is selected only after exact
        // reread and successful durability synchronization, never by guessing.
        let Ok(bytes) = target.encode() else {
            return false;
        };
        let Ok(snapshot) = self.store.load() else {
            return false;
        };
        snapshot.staged.is_none()
            && snapshot
                .current
                .is_some_and(|current| current.bytes() == bytes)
            && self.store.synchronize(&bytes).is_ok()
    }
    fn pending(&self) -> ActionResult {
        match self.state() {
            Ok(state) if state.action == Some(Action::FinishCleanup) => self.result(
                Outcome::NeedsCleanup,
                "Fixture setup requires Finish cleanup; no activation is committed.",
            ),
            Ok(state) if state.action == Some(Action::FinishSetup) => self.result(
                Outcome::NeedsCompletion,
                "Fixture activation is committed. Only Finish setup is legal.",
            ),
            _ => self.result(
                Outcome::Refused,
                "Fixture authority is incomplete, unsafe or ambiguous. Preserve it and inspect before further effects.",
            ),
        }
    }
    fn result(&self, outcome: Outcome, message: &'static str) -> ActionResult {
        let message = if self.host.is_injected_system() {
            match outcome {
                Outcome::RemovalComplete | Outcome::RemovalNeedsCompletion => message,
                Outcome::Cancelled => "Injected host action cancelled; no changes made.",
                Outcome::Refused => {
                    "Injected host authority refused. Preserve unknown state; native deployment is unavailable."
                }
                Outcome::SetupComplete => {
                    "Injected Linux host setup completed with durable checks. Native Ubuntu deployment and outside traffic remain unverified."
                }
                Outcome::NeedsCleanup => {
                    "Injected host setup requires Finish cleanup before activation commitment."
                }
                Outcome::NeedsCompletion => {
                    "Injected host activation is committed. Only Finish setup is legal."
                }
                Outcome::CleanedUp => {
                    "Injected host cleanup completed; exact recorded resources are absent and foreign files are preserved."
                }
            }
        } else {
            message
        };
        ActionResult {
            outcome,
            status: self
                .state()
                .map(|s| s.status)
                .unwrap_or(Status::ProblemDetected),
            proxy_traffic: Availability::CannotBeVerified,
            message,
        }
    }
}

#[cfg(test)]
#[path = "fixture_tests.rs"]
mod tests;

impl<H: SetupHost> Interface for StandardInstallation<H> {
    fn review(&self, action: Action) -> Review {
        StandardInstallation::review(self, action)
    }
    fn execute(&mut self, prepared: PreparedAction, confirmation: Confirmation) -> ActionResult {
        StandardInstallation::execute(self, prepared, confirmation)
    }
}
