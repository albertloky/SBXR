use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotSetUp,
    Running,
    SetupIncomplete,
    ProblemDetected,
    RemovalIncomplete,
    NotInstalled,
    ChangeIncomplete,
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
            Self::ChangeIncomplete => "Change incomplete",
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
    EnableSubscription,
    RotateSubscriptionLink,
    RepairSubscription,
    FinishSubscriptionChange,
    RotateClientIdentity,
    FinishClientIdentityRotation,
    ShowClientConfiguration,
    MarkSubscriptionCompromised,
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
            Self::EnableSubscription => "Enable subscription",
            Self::RotateSubscriptionLink => "Rotate subscription link",
            Self::RepairSubscription => "Repair subscription",
            Self::FinishSubscriptionChange => "Finish subscription change",
            Self::RotateClientIdentity => "Rotate Client Identity",
            Self::FinishClientIdentityRotation => "Finish Client Identity rotation",
            Self::ShowClientConfiguration => "Show client configuration",
            Self::MarkSubscriptionCompromised => "Mark subscription link compromised",
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
    SubscriptionEnabled,
    SubscriptionLinkRotated,
    SubscriptionRepaired,
    SubscriptionChangeFinished,
    SubscriptionChangeCleanedUp,
    SubscriptionChangeIncomplete,
    SubscriptionLinkDisplayIncomplete,
    SubscriptionProblemDetected,
    ClientIdentityRotated,
    ClientIdentityRotationFinished,
    ClientIdentityRotationCleanedUp,
    ClientIdentityRotationIncomplete,
    ClientIdentityRotationFailed,
    ClientConfigurationDisclosed,
    SubscriptionCompromised,
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
            Self::SubscriptionEnabled => "PROXY-INSTALLATION-SUBSCRIPTION-ENABLED",
            Self::SubscriptionLinkRotated => "PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED",
            Self::SubscriptionRepaired => "PROXY-INSTALLATION-SUBSCRIPTION-REPAIRED",
            Self::SubscriptionChangeFinished => "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-FINISHED",
            Self::SubscriptionChangeCleanedUp => {
                "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP"
            }
            Self::SubscriptionChangeIncomplete => {
                "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE"
            }
            Self::SubscriptionLinkDisplayIncomplete => {
                "PROXY-INSTALLATION-SUBSCRIPTION-LINK-DISPLAY-INCOMPLETE"
            }
            Self::SubscriptionProblemDetected => {
                "PROXY-INSTALLATION-SUBSCRIPTION-STATUS-PROBLEM-DETECTED"
            }
            Self::ClientIdentityRotated => "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED",
            Self::ClientIdentityRotationFinished => {
                "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FINISHED"
            }
            Self::ClientIdentityRotationCleanedUp => {
                "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-CLEANED-UP"
            }
            Self::ClientIdentityRotationIncomplete => {
                "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-INCOMPLETE"
            }
            Self::ClientIdentityRotationFailed => {
                "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FAILED"
            }
            Self::ClientConfigurationDisclosed => {
                "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
            }
            Self::SubscriptionCompromised => "PROXY-INSTALLATION-SUBSCRIPTION-COMPROMISED",
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
