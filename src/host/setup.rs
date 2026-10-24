//! One Standard setup contract shared by concrete host implementations. This is
//! not a deployment capability: native read-only observers never grant effects.
use super::{FixtureHost, HostError, Operation};
use crate::records::{OwnershipRecord, ReleaseIdentity, SetupPhase, sha256_hex};
use std::path::Path;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupObservation {
    pub(super) fingerprint: String,
    pub(super) empty: bool,
    pub(super) ready: bool,
    pub(super) running: bool,
    pub(super) enabled: bool,
    pub(super) stopped: bool,
}
impl SetupObservation {
    pub fn empty(&self) -> bool {
        self.empty
    }
    pub fn ready_to_activate(&self) -> bool {
        self.ready
    }
    pub fn running(&self) -> bool {
        self.running
    }
    pub fn service_enabled(&self) -> bool {
        self.enabled
    }
    pub fn stopped(&self) -> bool {
        self.stopped
    }
}
pub trait SetupHost {
    fn root(&self) -> &Path;
    fn uid(&self) -> u32;
    fn public_ipv4(&self) -> &str;
    fn configuration_sha256(&self) -> String;
    fn inspect_setup(&self, release: &ReleaseIdentity) -> Result<SetupObservation, HostError>;
    fn apply_setup(
        &mut self,
        operation: Operation,
        authority: &OwnershipRecord,
    ) -> Result<(), HostError>;
    fn begin_change(&mut self) -> Result<(), HostError> {
        Ok(())
    }
    fn end_change(&mut self) {}
    fn interrupted(&self, _phase: SetupPhase) -> bool {
        false
    }
    fn is_native_system(&self) -> bool {
        false
    }
    fn is_injected_system(&self) -> bool {
        false
    }
    fn effects_available(&self) -> bool {
        false
    }
}
impl SetupHost for FixtureHost {
    fn effects_available(&self) -> bool {
        true
    }
    fn root(&self) -> &Path {
        self.root()
    }
    fn uid(&self) -> u32 {
        self.uid()
    }
    fn public_ipv4(&self) -> &str {
        "8.8.8.8"
    }
    fn configuration_sha256(&self) -> String {
        sha256_hex(super::FIXTURE_CONFIGURATION)
    }
    fn inspect_setup(&self, release: &ReleaseIdentity) -> Result<SetupObservation, HostError> {
        let o = self.inspect(release)?;
        Ok(SetupObservation {
            fingerprint: sha256_hex(format!("{o:?}").as_bytes()),
            empty: o.empty(),
            ready: o.ready_to_activate(),
            running: o.running(),
            enabled: o.service_enabled(),
            stopped: o.stopped(),
        })
    }
    fn apply_setup(
        &mut self,
        operation: Operation,
        authority: &OwnershipRecord,
    ) -> Result<(), HostError> {
        self.apply(operation, authority)
    }
    fn interrupted(&self, phase: SetupPhase) -> bool {
        self.interrupted(phase)
    }
}
