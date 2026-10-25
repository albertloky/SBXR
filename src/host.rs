//! Standard Ubuntu command plans and an explicit filesystem-fixture adapter.
//! Fixed native command/file effects and retained guards are implemented, with
//! fixture-only integration tests. The production entry remains unavailable.
pub mod disclosure;
mod filesystem;
mod fixture;
pub mod historical;
pub mod identity;
mod input;
pub mod lifecycle;
pub mod linux;
pub mod locks;
pub mod network;
pub mod owner;
pub mod owner_runtime;
pub mod process;
pub mod restoration;
pub mod runtime;
pub mod runtime_io;
mod setup;
pub mod subscription;
pub mod system;
use crate::records::SetupPhase;
pub use fixture::{FIXTURE_CONFIGURATION, FixtureHost, HostObservation};
pub use setup::{SetupHost, SetupObservation};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    Unsafe,
    Foreign,
    Io,
    Injected,
    LiveUnavailable,
    UnsupportedHost,
    Cancelled,
    Timeout,
    OutputLimit,
    Busy,
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LiveUnavailable => "Real deployment is unavailable in this Rust increment.",
            Self::UnsupportedHost => "This host is unsupported; Linux Ubuntu 24.04 amd64 and root are required. No simulation fallback is selected.",
            Self::Cancelled => "Host operation cancelled; reinspect before further effects.",
            Self::Timeout => "Host operation timed out; reinspect before further effects.",
            Self::OutputLimit => "Host command exceeded its bounded output contract.",
            _ => "Host facts or effects could not be safely verified.",
        })
    }
}
impl std::error::Error for HostError {}

/// Explicit capability refusal; never substitutes the fixture adapter for live work.
pub fn require_live_adapter() -> Result<(), HostError> {
    linux::require_native_environment()?;
    Err(HostError::LiveUnavailable)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    InstallAptKey,
    InstallAptSource,
    MaskService,
    InstallPackage,
    HoldPackage,
    CreateStateDirectory,
    InstallConfiguration,
    ValidateConfiguration,
    UnmaskService,
    EnableService,
    StartService,
    StopDisableService,
    RemovePackageArtifact,
    RemovePackage,
    RemovePackageHold,
    RemoveConfigurationState,
    RemovePackageIdentity,
    RemoveAptSource,
    RemoveAptKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureFault {
    FailBefore(Operation),
    FailAfter(Operation),
    InterruptAfter(SetupPhase),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: &'static str,
    pub arguments: Vec<&'static str>,
    pub working_directory: Option<&'static str>,
}
fn command(program: &'static str, arguments: &[&'static str]) -> CommandPlan {
    CommandPlan {
        program,
        arguments: arguments.to_vec(),
        working_directory: None,
    }
}

/// Fixed argv templates from Go, not an executable or authorized command plan.
/// Conditional/dynamic ownership checks must be ported before a live runner is
/// possible. File/download effects use the explicit fixture resource contract.
pub fn planned_commands(operation: Operation) -> Vec<CommandPlan> {
    use Operation::*;
    match operation {
        InstallPackage => vec![
            command("apt-get", &["update"]),
            CommandPlan {
                working_directory: Some("/var/lib/sbxr"),
                ..command("apt-get", &["download", "sing-box=1.14.3"])
            },
            command(
                "dpkg",
                &["--install", "/var/lib/sbxr/sing-box_1.14.3_amd64.deb"],
            ),
            command("systemctl", &["is-enabled", "sing-box.service"]),
            command("systemctl", &["is-active", "sing-box.service"]),
        ],
        MaskService => vec![
            command("systemctl", &["mask", "sing-box.service"]),
            command("systemctl", &["daemon-reload"]),
        ],
        HoldPackage => vec![command("apt-mark", &["hold", "sing-box"])],
        ValidateConfiguration => vec![command(
            "sing-box",
            &["-D", "/var/lib/sing-box", "-C", "/etc/sing-box", "check"],
        )],
        UnmaskService => vec![
            command("systemctl", &["is-enabled", "sing-box.service"]),
            command("systemctl", &["unmask", "sing-box.service"]),
        ],
        EnableService => vec![command("systemctl", &["enable", "sing-box.service"])],
        StartService => vec![command("systemctl", &["start", "sing-box.service"])],
        StopDisableService => vec![
            command("systemctl", &["disable", "--now", "sing-box.service"]),
            command(
                "systemctl",
                &[
                    "show",
                    "--property=LoadState",
                    "--value",
                    "sing-box.service",
                ],
            ),
            command("systemctl", &["is-enabled", "sing-box.service"]),
            command("systemctl", &["is-active", "sing-box.service"]),
            command("pgrep", &["-x", "sing-box"]),
            command("ss", &["-H", "-ltnp", "sport", "=", ":443"]),
        ],
        RemovePackage => vec![
            command(
                "dpkg-query",
                &[
                    "--show",
                    "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}",
                    "sing-box",
                ],
            ),
            command("apt-mark", &["showhold"]),
            command("apt-mark", &["unhold", "sing-box"]),
            command("apt-get", &["purge", "-y", "sing-box=1.14.3"]),
        ],
        RemovePackageIdentity => vec![
            command("getent", &["passwd", "sing-box"]),
            command("getent", &["group", "sing-box"]),
            command("userdel", &["sing-box"]),
            command("groupdel", &["sing-box"]),
        ],
        _ => vec![],
    }
}

pub fn planned_observation_commands() -> Vec<CommandPlan> {
    vec![
        command(
            "dpkg-query",
            &[
                "--show",
                "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}",
                "sing-box",
            ],
        ),
        command("apt-mark", &["showhold"]),
        command("systemctl", &["is-enabled", "sing-box.service"]),
        command("systemctl", &["is-active", "sing-box.service"]),
        command("ss", &["-H", "-ltnp", "sport", "=", ":443"]),
    ]
}

#[path = "tunnel_native.rs"]
pub mod tunnel_native;
