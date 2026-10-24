//! Numbered terminal presentation; all effects go through Review and Execute.
use crate::domain::{Action, Confirmation, Outcome, Result};
use crate::proxyinstallation::{ExecutionMode, Interface};
use std::io::{self, BufRead, Write};

pub fn run(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut impl Interface,
) -> io::Result<()> {
    run_inner(input, output, installation, None)
}

/// Compose the existing Proxy Installation and Software Lifecycle modules.
/// Each module retains its own prepared authority; no lifecycle Update menu.
pub fn run_with_lifecycle(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut impl Interface,
    lifecycle: &mut dyn crate::software_lifecycle::Interface,
) -> io::Result<()> {
    run_inner(input, output, installation, Some(lifecycle))
}
fn run_inner(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut impl Interface,
    mut lifecycle: Option<&mut dyn crate::software_lifecycle::Interface>,
) -> io::Result<()> {
    match installation.review(Action::Status).mode {
        ExecutionMode::Native => writeln!(output, "SBXR")?,
        ExecutionMode::NativeUnavailable => {
            writeln!(output, "SBXR Rust — native installation unavailable")?;
            writeln!(
                output,
                "Authenticated acquisition and production prerequisites are incomplete. No native action is enabled."
            )?;
        }
        ExecutionMode::InjectedHost => {
            writeln!(output, "SBXR Rust — injected Linux host only")?;
            writeln!(
                output,
                "Test-root files and an injected effect runner. Native deployment is unavailable."
            )?;
        }
        ExecutionMode::Simulation => {
            writeln!(output, "SBXR Rust — local simulation only")?;
            writeln!(
                output,
                "All host facts and setup effects are in memory. No live installation is available."
            )?;
        }
        ExecutionMode::Fixture => {
            writeln!(output, "SBXR Rust — filesystem fixture only")?;
            writeln!(
                output,
                "Effects stay under a marked temporary root. No Ubuntu command or real deployment is available."
            )?;
        }
    }
    loop {
        let mut current = installation.review(Action::Status);
        let qualifier = match current.mode {
            ExecutionMode::Native => "local",
            ExecutionMode::Simulation => "simulated",
            ExecutionMode::Fixture => "fixture",
            ExecutionMode::InjectedHost => "injected host",
            ExecutionMode::NativeUnavailable => "native unavailable",
        };
        writeln!(output, "Proxy status: {} ({qualifier})", current.status)?;
        writeln!(
            output,
            "Subscription status: {} ({qualifier})",
            installation.subscription_status()
        )?;
        if let Some(module) = &mut lifecycle {
            let state = module.status().state;
            writeln!(output, "Software Lifecycle status: {state}")?;
            if state != crate::software_lifecycle::State::Ready {
                current.prepared = None;
                current.legal_actions.retain(|a| *a == Action::ViewDetails);
                writeln!(
                    output,
                    "Software Lifecycle must be Ready before proxy actions can continue."
                )?;
            }
        } else {
            match current.mode {
                ExecutionMode::Native => {
                    writeln!(output, "Software Lifecycle status: Not inspected")?
                }
                ExecutionMode::NativeUnavailable => writeln!(
                    output,
                    "Software Lifecycle status: Native authentication incomplete"
                )?,
                ExecutionMode::InjectedHost => writeln!(
                    output,
                    "Software Lifecycle status: Injected host pair (not release authenticated)"
                )?,
                ExecutionMode::Simulation => writeln!(
                    output,
                    "Software Lifecycle status: Not inspected (simulation)"
                )?,
                ExecutionMode::Fixture => writeln!(
                    output,
                    "Software Lifecycle status: Fixture pair only (not release authenticated)"
                )?,
            }
        }
        writeln!(output, "Proxy traffic: cannot be verified")?;
        if let Some(refusal) = current.refusal {
            writeln!(output, "Failed safety check: {refusal}")?;
        }
        for (index, action) in current.legal_actions.iter().enumerate() {
            writeln!(output, "{}. {action}", index + 1)?;
        }
        if lifecycle.is_some() {
            writeln!(output, "{}. Check SBXR", current.legal_actions.len() + 1)?;
            writeln!(output, "{}. Recover SBXR", current.legal_actions.len() + 2)?;
        }
        writeln!(output, "0. Exit")?;
        let Some(line) = prompt(input, output, "Choose:")? else {
            return Ok(());
        };
        if line == "0" {
            return Ok(());
        }
        let number = line.parse::<usize>().ok().filter(|n| n.to_string() == line);
        if let (Some(number), Some(module)) = (number, &mut lifecycle)
            && (number == current.legal_actions.len() + 1
                || number == current.legal_actions.len() + 2)
        {
            // Expire every outstanding proxy review before a lifecycle call.
            installation.review(Action::Status);
            if run_lifecycle(
                input,
                output,
                *module,
                number == current.legal_actions.len() + 1,
            )? {
                return Ok(());
            }
            continue;
        }
        let Some(action) = number
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| current.legal_actions.get(i))
            .copied()
        else {
            writeln!(output, "Enter one of the displayed numbers.")?;
            continue;
        };
        match action {
            Action::ViewDetails => {
                writeln!(
                    output,
                    "Standard uses VLESS REALITY Vision. No domain is needed."
                )?;
                installation.write_details(output)?;
            }
            Action::StartSetup => setup(input, output, installation)?,
            Action::CheckVmessTunnel => {
                let review = installation.review(action);
                if let Some(prepared) = review.prepared {
                    let result = installation.execute(prepared, Confirmation::Approved);
                    write_result(output, &result)?;
                } else {
                    writeln!(
                        output,
                        "VMess connection check is unavailable. Review details."
                    )?;
                }
            }
            Action::FinishCleanup | Action::FinishSetup => {
                let review = installation.review(action);
                for line in review.plan {
                    writeln!(output, "{line}")?;
                }
                let Some(prepared) = review.prepared else {
                    writeln!(output, "Action refused. Review again.")?;
                    continue;
                };
                let question = format!("{action}? [y/N]");
                let confirmation = confirmation(input, output, &question)?;
                let result = installation.execute(prepared, confirmation);
                write_result(output, &result)?;
            }
            Action::CompleteRemoval | Action::FinishRemoval => {
                let review = installation.review(action);
                for line in review.plan {
                    writeln!(output, "{line}")?;
                }
                let Some(prepared) = review.prepared else {
                    writeln!(output, "Action refused. Review again.")?;
                    continue;
                };
                let approval = if action == Action::CompleteRemoval {
                    if prompt(
                        input,
                        output,
                        "Type REMOVE SBXR to confirm Complete removal. Any other input cancels.",
                    )?
                    .as_deref()
                        == Some("REMOVE SBXR")
                    {
                        Confirmation::Approved
                    } else {
                        Confirmation::Declined
                    }
                } else {
                    Confirmation::Approved
                };
                let result = installation.execute(prepared, approval);
                write_result(output, &result)?;
                if result.outcome == crate::domain::Outcome::RemovalComplete {
                    return Ok(());
                }
            }
            Action::EnableSubscription
            | Action::RotateSubscriptionLink
            | Action::RepairSubscription
            | Action::FinishSubscriptionChange
            | Action::RotateClientIdentity
            | Action::FinishClientIdentityRotation
            | Action::ShowClientConfiguration
            | Action::MarkSubscriptionCompromised => {
                let review = installation.review(action);
                for line in review.plan {
                    writeln!(output, "{line}")?;
                }
                let Some(prepared) = review.prepared else {
                    writeln!(output, "Action refused. Review again.")?;
                    continue;
                };
                let approval = if matches!(
                    action,
                    Action::FinishSubscriptionChange | Action::FinishClientIdentityRotation
                ) {
                    Confirmation::Approved
                } else {
                    confirmation(input, output, &format!("{action}? [y/N]"))?
                };
                let result = installation.execute_output(prepared, approval, output)?;
                write_result(output, &result)?;
                if result.outcome==Outcome::ClientConfigurationDisclosed && prompt(input,output,"Press Enter to preserve this configuration in terminal scrollback and return to the menu.")?.is_none(){return Ok(())}
                if let Some(link) = installation.take_subscription_link() {
                    writeln!(output, "Subscription Link (sensitive): {}", link.as_str())?;
                }
            }
            Action::Status => unreachable!("Status is not a menu action"),
        }
    }
}

fn lifecycle_result(
    output: &mut impl Write,
    result: &crate::software_lifecycle::Result,
) -> io::Result<()> {
    writeln!(
        output,
        "Software Lifecycle: {}\nResult: {}\nCode: {}",
        result.state,
        result.message,
        result.code.as_str()
    )
}
fn run_lifecycle(
    input: &mut impl BufRead,
    output: &mut impl Write,
    module: &mut dyn crate::software_lifecycle::Interface,
    check: bool,
) -> io::Result<bool> {
    if check {
        writeln!(output, "Progress: Checking the qualified latest release")?;
        output.flush()?;
        let result = module.check();
        lifecycle_result(output, &result)?;
        return Ok(false);
    }
    let reviewed = module.review_recover();
    lifecycle_result(output, &reviewed)?;
    let Some(direction) = reviewed.recovery_direction else {
        writeln!(
            output,
            "No recovery is available. If a change is in progress, wait for it to finish."
        )?;
        return Ok(false);
    };
    writeln!(output, "Recovery direction: {direction}")?;
    let approval = confirmation(input, output, "Recover SBXR? [y/N]")?;
    if approval != Confirmation::Approved {
        module.recover(approval);
        writeln!(output, "No changes were made.")?;
        return Ok(false);
    }
    let result = module.recover(approval);
    lifecycle_result(output, &result)?;
    Ok(result.code == crate::software_lifecycle::Code::RemovalRestored)
}

fn setup(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut impl Interface,
) -> io::Result<()> {
    'profile: loop {
        writeln!(
            output,
            "Setup 1 — Choose connection\nSet up a proxy on this server. No changes until Apply.\n1. Standard (default; no domain needed)"
        )?;
        if installation.supports_tunnel() {
            writeln!(
                output,
                "2. Standard + Cloudflare (your dedicated VMess tunnel)"
            )?;
        }
        loop {
            match prompt(input, output, "Connection [1] (h Help, c Cancel):")?.as_deref() {
                Some("") | Some("1") => break,
                Some("2") if installation.supports_tunnel() => {
                    if tunnel_setup(input, output, installation)? {
                        continue 'profile;
                    }
                    return Ok(());
                }
                Some("h") => writeln!(
                    output,
                    "{}",
                    if installation.supports_tunnel() {
                        "Standard uses VLESS REALITY Vision for a direct connection and needs no domain. Optional Standard + Cloudflare requires your own dedicated tunnel and protected token preparation."
                    } else {
                        "Standard uses VLESS REALITY Vision for a direct connection. It needs no domain. Only Standard is implemented in this Rust increment."
                    }
                )?,
                None | Some("c") => return cancelled(output),
                _ => writeln!(
                    output,
                    "Choose a displayed connection number, h for help, or c to cancel."
                )?,
            }
        }
        writeln!(
            output,
            "Setup 2 — Review\nConnection: Standard — no domain needed"
        )?;
        let review = installation.review(Action::StartSetup);
        let Some(prepared) = review.prepared else {
            writeln!(
                output,
                "Failed safety check: {}",
                review
                    .refusal
                    .unwrap_or("Setup is no longer legal. Review again.")
            )?;
            return Ok(());
        };
        for line in review.plan {
            writeln!(output, "{line}")?;
        }
        writeln!(
            output,
            "b Back to edit, c Cancel. Only y applies these changes."
        )?;
        loop {
            match prompt(input, output, "Apply setup? [y/N]")?.as_deref() {
                Some("y") => {
                    match review.mode {
                        ExecutionMode::Native => writeln!(output, "Setup 3 — Install and check")?,
                        ExecutionMode::NativeUnavailable => {
                            writeln!(output, "Native setup is unavailable.")?;
                            return Ok(());
                        }
                        ExecutionMode::InjectedHost => {
                            writeln!(output, "Setup 3 — Apply injected host effects and check")?
                        }
                        ExecutionMode::Simulation => {
                            writeln!(output, "Setup 3 — Simulate install and check")?
                        }
                        ExecutionMode::Fixture => {
                            writeln!(output, "Setup 3 — Apply fixture install and check")?
                        }
                    }
                    let result = installation.execute(prepared, Confirmation::Approved);
                    write_result(output, &result)?;
                    return Ok(());
                }
                None | Some("") | Some("n") | Some("c") => return cancelled(output),
                Some("b") => break,
                _ => writeln!(
                    output,
                    "Enter y to apply, n to cancel, b to go back, or c to cancel."
                )?,
            }
        }
    }
}

fn tunnel_setup(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut impl Interface,
) -> io::Result<bool> {
    let mut hostname = String::new();
    loop {
        writeln!(
            output,
            "Setup 2 — Prepare Cloudflare\nUse a dedicated remotely managed tunnel in your own account. Route your hostname to http://127.0.0.1:10000 with no path. Keep official cloudflared >=2025.4.0 and the protected root-owned 0600 /etc/cloudflared/sbxr.token prepared in a separate trusted terminal. Never paste a token here or install a shared cloudflared service. See docs/setup-vmess-tunnel.md."
        )?;
        loop {
            match prompt(input, output, "Ready? [y/N] (b Back, c Cancel):")?.as_deref() {
                Some("y") => break,
                Some("b") => return Ok(true),
                Some("") | Some("n") | Some("c") | None => {
                    cancelled(output)?;
                    return Ok(false);
                }
                _ => writeln!(
                    output,
                    "Enter y to continue, n/c to cancel, or b to go back."
                )?,
            }
        }
        loop {
            writeln!(
                output,
                "Setup 3 — Hostname\nEnter only a lowercase DNS hostname, with no scheme, port, path or token. Draft: {hostname}"
            )?;
            let Some(draft) = prompt(
                input,
                output,
                "Hostname (Enter keeps draft, b Back, c Cancel):",
            )?
            else {
                cancelled(output)?;
                return Ok(false);
            };
            match draft.as_str() {
                "c" => {
                    cancelled(output)?;
                    return Ok(false);
                }
                "b" => break,
                _ => {}
            }
            let candidate = if draft.is_empty() {
                hostname.as_str()
            } else {
                draft.as_str()
            };
            if !crate::subscription_artifact::valid_vmess_hostname(candidate) {
                writeln!(
                    output,
                    "Enter a valid hostname only; never enter a credential."
                )?;
                continue;
            }
            hostname = candidate.into();
            let review = installation.review_tunnel_setup(&hostname);
            let Some(prepared) = review.prepared else {
                writeln!(
                    output,
                    "Failed safety check: {}",
                    review
                        .refusal
                        .unwrap_or("Review again after restoring prerequisites.")
                )?;
                continue;
            };
            writeln!(output, "Setup 4 — Review")?;
            for line in review.plan {
                writeln!(output, "{line}")?;
            }
            loop {
                match prompt(input, output, "Apply setup? [y/N] (b Back, c Cancel):")?.as_deref() {
                    Some("y") => {
                        if review.mode == ExecutionMode::NativeUnavailable {
                            writeln!(output, "Native setup is unavailable.")?;
                            return Ok(false);
                        }
                        let result = installation.execute(prepared, Confirmation::Approved);
                        write_result(output, &result)?;
                        return Ok(false);
                    }
                    Some("b") => break,
                    Some("") | Some("n") | Some("c") | None => {
                        cancelled(output)?;
                        return Ok(false);
                    }
                    _ => writeln!(output, "Only y applies. Enter n to cancel or b to go back.")?,
                }
            }
        }
    }
}

fn write_result(output: &mut impl Write, result: &Result) -> io::Result<()> {
    writeln!(output, "Result: {}", result.message)?;
    writeln!(output, "Code: {}", result.outcome.code())
}

fn cancelled(output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "Result: Setup cancelled. No changes were made.\nCode: {}",
        Outcome::Cancelled.code()
    )
}

fn confirmation(
    input: &mut impl BufRead,
    output: &mut impl Write,
    question: &str,
) -> io::Result<Confirmation> {
    loop {
        let Some(line) = prompt(input, output, question)? else {
            return Ok(Confirmation::Declined);
        };
        if let Some(confirmation) = Confirmation::parse(&line) {
            return Ok(confirmation);
        }
        writeln!(output, "Only y approves. Enter y or n.")?;
    }
}

fn prompt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    question: &str,
) -> io::Result<Option<String>> {
    loop {
        writeln!(output, "{question}")?;
        output.flush()?;
        let mut bytes = Vec::new();
        let mut too_long = false;
        loop {
            let available = input.fill_buf()?;
            // An unterminated final fragment cannot approve an action.
            if available.is_empty() {
                return Ok(None);
            }
            let length = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            let complete = available[length - 1] == b'\n';
            too_long |= bytes.len() + length > 256;
            if !too_long {
                bytes.extend_from_slice(&available[..length]);
            }
            input.consume(length);
            if complete {
                break;
            }
        }
        if too_long {
            writeln!(
                output,
                "Input is too long. Enter a short choice; never paste a token here."
            )?;
            continue;
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        return String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Input is not UTF-8"));
    }
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
