//! Clean-install Software Lifecycle. No new Update or transport-conversion writer.
use crate::{
    artifact_trust::{AcquisitionTransport, SelectionBudget, TrustError},
    domain::Confirmation,
    host::{
        HostError,
        lifecycle::{LifecycleHost, Snapshot},
        restoration::RestoredFinisher,
    },
    records::ReleaseIdentity,
    release_acquisition::AuthenticatedArchive,
    release_identity::Architecture,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    UpdateInProgress,
    RecoveryRequired,
}
impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ready => "Ready",
            Self::UpdateInProgress => "Update in progress",
            Self::RecoveryRequired => "Recovery required",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    StatusReady,
    StatusUpdateInProgress,
    StatusRecoveryRequired,
    CheckAlreadyCurrent,
    CheckReleaseRefused,
    CheckReleaseUnavailable,
    CheckConcurrentChange,
    CheckNotReady,
    UpdateReleaseRefused,
    UpdateNotReady,
    RecoverNotRequired,
    RecoverRefused,
    RecoverFailed,
    RecoverConcurrentMutation,
    RemovalRestored,
}
impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StatusReady => "SOFTWARE-LIFECYCLE-STATUS-READY",
            Self::StatusUpdateInProgress => "SOFTWARE-LIFECYCLE-STATUS-UPDATE-IN-PROGRESS",
            Self::StatusRecoveryRequired => "SOFTWARE-LIFECYCLE-STATUS-RECOVERY-REQUIRED",
            Self::CheckAlreadyCurrent => "SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT",
            Self::CheckReleaseRefused => "SOFTWARE-LIFECYCLE-CHECK-RELEASE-REFUSED",
            Self::CheckReleaseUnavailable => "SOFTWARE-LIFECYCLE-CHECK-RELEASE-UNAVAILABLE",
            Self::CheckConcurrentChange => "SOFTWARE-LIFECYCLE-CHECK-CONCURRENT-CHANGE",
            Self::CheckNotReady => "SOFTWARE-LIFECYCLE-CHECK-NOT-READY",
            Self::UpdateReleaseRefused => "SOFTWARE-LIFECYCLE-UPDATE-RELEASE-REFUSED",
            Self::UpdateNotReady => "SOFTWARE-LIFECYCLE-UPDATE-NOT-READY",
            Self::RecoverNotRequired => "SOFTWARE-LIFECYCLE-RECOVER-NOT-REQUIRED",
            Self::RecoverRefused => "SOFTWARE-LIFECYCLE-RECOVER-REFUSED",
            Self::RecoverFailed => "SOFTWARE-LIFECYCLE-RECOVER-FAILED",
            Self::RecoverConcurrentMutation => "SOFTWARE-LIFECYCLE-RECOVER-CONCURRENT-MUTATION",
            Self::RemovalRestored => "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Result {
    pub state: State,
    pub installed: Option<ReleaseIdentity>,
    pub latest: Option<ReleaseIdentity>,
    pub code: Code,
    pub message: &'static str,
    pub recovery_direction: Option<&'static str>,
}
pub const CLEAN_INSTALL_CORRECTION: &str = "This SBXR release supports clean installation only. Use reviewed Complete removal, finish any interrupted removal with its exact release, then install and set up fresh. This causes downtime, new proxy credentials, and new client setup. Do not install over remaining authority or resources.";
fn recovery() -> Result {
    Result {
        state: State::RecoveryRequired,
        installed: None,
        latest: None,
        code: Code::StatusRecoveryRequired,
        message: "SBXR needs recovery before normal operations can continue.",
        recovery_direction: None,
    }
}
fn status(snapshot: &std::result::Result<Snapshot, HostError>) -> Result {
    let Ok(s) = snapshot else {
        return recovery();
    };
    if s.busy {
        return Result {
            state: State::UpdateInProgress,
            code: Code::StatusUpdateInProgress,
            message: "Another Software Lifecycle change is in progress.",
            ..recovery()
        };
    }
    if s.transaction {
        return Result {
            message: "Retained software transaction evidence requires its original exact SBXR release. This clean-install Rust release preserves it and refuses transaction mutation.",
            ..recovery()
        };
    }
    if let Some(record) = &s.installed {
        return Result {
            state: State::Ready,
            installed: Some(record.release_identity()),
            latest: None,
            code: Code::StatusReady,
            message: "SBXR is ready.",
            recovery_direction: None,
        };
    }
    let mut result = recovery();
    if s.restoration.is_some() {
        result.recovery_direction = Some(
            "Restore only the exact committed-removal finisher; keep removal authority unchanged.",
        );
    }
    result
}
/// Complete current Owner seam. Update exists only as a compatibility refusal;
/// it is never a menu action. Review never grants authority through result data.
pub trait Interface {
    fn status(&mut self) -> Result;
    fn check(&mut self) -> Result;
    fn update(&mut self) -> Result;
    fn review_recover(&mut self) -> Result;
    fn recover(&mut self, confirmation: Confirmation) -> Result;
    fn take_finisher(&mut self) -> Option<RestoredFinisher> {
        None
    }
}
pub struct Installed<T> {
    host: LifecycleHost,
    transport: T,
    prepared: Option<Snapshot>,
    finisher: Option<RestoredFinisher>,
    stop: crate::subscription_serving::Cancellation,
}
impl<T: AcquisitionTransport> Installed<T> {
    pub fn new(host: LifecycleHost, transport: T) -> Self {
        Self {
            host,
            transport,
            prepared: None,
            finisher: None,
            stop: crate::subscription_serving::Cancellation::new(),
        }
    }
    pub fn with_cancellation(mut self, stop: crate::subscription_serving::Cancellation) -> Self {
        self.stop = stop;
        self.prepared = None;
        self.finisher = None;
        self
    }
    fn finish_check(
        &self,
        before: &Snapshot,
        latest: std::result::Result<AuthenticatedArchive, TrustError>,
    ) -> Result {
        let after = self.host.inspect();
        if after.as_ref() != Ok(before) {
            return Result {
                code: Code::CheckConcurrentChange,
                message: "Local Software Lifecycle facts changed during the check.",
                ..status(&after)
            };
        }
        let mut base = status(&after);
        match latest {
            Ok(archive) => {
                let Some(installed) = before.installed.as_ref() else {
                    return recovery();
                };
                if archive.record().release_identity() == installed.release_identity()
                    && archive.record().sequence() == installed.sequence()
                {
                    base.latest = Some(installed.release_identity());
                    base.code = Code::CheckAlreadyCurrent;
                    base.message = "SBXR is already current.";
                } else {
                    base.code = Code::CheckReleaseRefused;
                    base.message = if archive.record().sequence() > installed.sequence()
                        && archive.record().release_identity() != installed.release_identity()
                    {
                        CLEAN_INSTALL_CORRECTION
                    } else {
                        "The latest SBXR release was refused."
                    };
                }
            }
            Err(TrustError::Unavailable) => {
                base.code = Code::CheckReleaseUnavailable;
                base.message = "The latest SBXR release is unavailable. Check again later.";
            }
            Err(_) => {
                base.code = Code::CheckReleaseRefused;
                base.message = "The latest SBXR release was refused.";
            }
        }
        base
    }
    fn finish_recovery(
        &mut self,
        prepared: Snapshot,
        archive: &AuthenticatedArchive,
        budget: &SelectionBudget,
    ) -> Result {
        match self.host.restore(&prepared, archive, budget) {
            Ok(finisher) => {
                self.finisher = Some(finisher);
                Result {
                    code: Code::RemovalRestored,
                    message: "Exact removal finisher restored and prepared. Removal remains incomplete.",
                    ..recovery()
                }
            }
            Err(HostError::Busy) => Result {
                state: State::UpdateInProgress,
                code: Code::RecoverConcurrentMutation,
                message: "Another Software Lifecycle change is in progress.",
                ..recovery()
            },
            Err(
                HostError::Foreign
                | HostError::Unsafe
                | HostError::LiveUnavailable
                | HostError::UnsupportedHost,
            ) => Result {
                code: Code::RecoverRefused,
                message: "SBXR recovery was refused because safe recovery could not be proven.",
                ..recovery()
            },
            Err(_) => Result {
                code: Code::RecoverFailed,
                message: "Exact removal-finisher recovery remains incomplete. Preserve the authority and review again.",
                ..recovery()
            },
        }
    }
}
impl<T: AcquisitionTransport> Interface for Installed<T> {
    fn status(&mut self) -> Result {
        self.prepared = None;
        status(&self.host.inspect())
    }
    fn check(&mut self) -> Result {
        self.prepared = None;
        let inspected = self.host.inspect();
        let result = status(&inspected);
        if result.state != State::Ready {
            return Result {
                code: Code::CheckNotReady,
                message: "SBXR is not ready to check for updates.",
                ..result
            };
        }
        let before = inspected.expect("Ready requires a protected snapshot");
        let Ok(arch) = crate::host::lifecycle::architecture(
            before
                .installed
                .as_ref()
                .expect("Ready requires installed pair")
                .architecture(),
        ) else {
            return Result {
                code: Code::CheckReleaseRefused,
                message: "The installed architecture is unsupported.",
                ..result
            };
        };
        let latest = AuthenticatedArchive::acquire_latest(
            &mut self.transport,
            arch,
            &SelectionBudget::new().with_cancellation(self.stop.clone()),
        );
        self.finish_check(&before, latest)
    }
    fn update(&mut self) -> Result {
        let result = self.status();
        if result.state == State::Ready {
            Result {
                code: Code::UpdateReleaseRefused,
                message: CLEAN_INSTALL_CORRECTION,
                ..result
            }
        } else {
            Result {
                code: Code::UpdateNotReady,
                message: "SBXR is not ready. Finish the existing change or its proved recovery before Complete removal.",
                ..result
            }
        }
    }
    fn review_recover(&mut self) -> Result {
        self.prepared = None;
        let snapshot = self.host.inspect();
        let result = status(&snapshot);
        if result.recovery_direction.is_some() {
            self.prepared = snapshot.ok();
        }
        result
    }
    fn recover(&mut self, confirmation: Confirmation) -> Result {
        let prepared = self.prepared.take();
        if confirmation != Confirmation::Approved {
            return Result {
                code: Code::RecoverRefused,
                message: "Recovery cancelled. No changes were made.",
                ..status(&self.host.inspect())
            };
        }
        let inspected = self.host.inspect();
        let result = status(&inspected);
        if result.state == State::Ready {
            return Result {
                code: Code::RecoverNotRequired,
                message: "SBXR does not need recovery.",
                ..result
            };
        }
        if result.state == State::UpdateInProgress {
            return Result {
                code: Code::RecoverConcurrentMutation,
                ..result
            };
        }
        let Some(prepared) = prepared.filter(|p| inspected.as_ref() == Ok(p)) else {
            return Result {
                code: Code::RecoverRefused,
                message: "SBXR recovery was refused because safe recovery could not be proven.",
                ..result
            };
        };
        let Some(release) = prepared.restoration.as_ref() else {
            return Result {
                code: Code::RecoverRefused,
                ..result
            };
        };
        let budget = SelectionBudget::new().with_cancellation(self.stop.clone());
        let archive = match AuthenticatedArchive::acquire(
            &mut self.transport,
            release,
            Architecture::Amd64,
            &budget,
        ) {
            Ok(a) => a,
            Err(_) => {
                return Result {
                    code: Code::RecoverFailed,
                    message: "The exact removal-finisher release could not be authenticated. No substitution is allowed.",
                    ..result
                };
            }
        };
        self.finish_recovery(prepared, &archive, &budget)
    }
    fn take_finisher(&mut self) -> Option<RestoredFinisher> {
        if self.stop.is_cancelled() {
            self.finisher = None;
            return None;
        }
        self.finisher.take()
    }
}

#[cfg(test)]
#[path = "software_lifecycle_tests.rs"]
mod tests;
