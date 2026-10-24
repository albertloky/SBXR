use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotSetUp,
    Running,
    SetupIncomplete,
    ProblemDetected,
    RemovalIncomplete,
    NotInstalled,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotSetUp => "Not set up",
            Self::Running => "Running",
            Self::SetupIncomplete => "Setup incomplete",
            Self::ProblemDetected => "Problem detected",
            Self::RemovalIncomplete => "Removal incomplete",
            Self::NotInstalled => "Not installed",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    ProvedWorking,
    ProvedStopped,
    CannotBeVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Absent,
    Preparing,
    ActivationCommitted,
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Status,
    ViewDetails,
    StartSetup,
    FinishCleanup,
    FinishSetup,
    CompleteRemoval,
    FinishRemoval,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Status => "Status",
            Self::ViewDetails => "View details",
            Self::StartSetup => "Start setup",
            Self::FinishCleanup => "Finish cleanup",
            Self::FinishSetup => "Finish setup",
            Self::CompleteRemoval => "Complete removal",
            Self::FinishRemoval => "Finish removal",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    Approved,
    Declined,
}

impl Confirmation {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "y" => Some(Self::Approved),
            "" | "n" => Some(Self::Declined),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Cancelled,
    Refused,
    SetupComplete,
    NeedsCleanup,
    NeedsCompletion,
    CleanedUp,
    RemovalComplete,
    RemovalNeedsCompletion,
}

impl Outcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "PROXY-INSTALLATION-ACTION-CANCELLED",
            Self::Refused => "PROXY-INSTALLATION-ACTION-REFUSED",
            Self::SetupComplete => "PROXY-INSTALLATION-SETUP-COMPLETE",
            Self::NeedsCleanup => "PROXY-INSTALLATION-SETUP-CLEANUP-REQUIRED",
            Self::NeedsCompletion => "PROXY-INSTALLATION-SETUP-COMPLETION-REQUIRED",
            Self::CleanedUp => "PROXY-INSTALLATION-SETUP-CLEANED-UP",
            Self::RemovalComplete => "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED",
            Self::RemovalNeedsCompletion => "PROXY-INSTALLATION-REMOVAL-COMPLETION-REQUIRED",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Result {
    pub outcome: Outcome,
    pub status: Status,
    pub proxy_traffic: Availability,
    pub message: &'static str,
}
