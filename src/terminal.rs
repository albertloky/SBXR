//! Numbered terminal presentation; all effects go through Review and Execute.
use crate::domain::{Action, Confirmation, Outcome, Result};
use crate::proxyinstallation::Installation;
use std::io::{self, BufRead, Write};

pub fn run(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut Installation,
) -> io::Result<()> {
    writeln!(output, "SBXR Rust — local simulation only")?;
    writeln!(
        output,
        "All host facts and setup effects are in memory. No live installation is available."
    )?;
    loop {
        let current = installation.review(Action::Status);
        writeln!(output, "Proxy status: {} (simulated)", current.status)?;
        writeln!(output, "Subscription status: Not enabled (simulated)")?;
        writeln!(
            output,
            "Software Lifecycle status: Not inspected (simulation)"
        )?;
        writeln!(output, "Proxy traffic: cannot be verified")?;
        if let Some(refusal) = current.refusal {
            writeln!(output, "Failed safety check: {refusal}")?;
        }
        for (index, action) in current.legal_actions.iter().enumerate() {
            writeln!(output, "{}. {action}", index + 1)?;
        }
        writeln!(output, "0. Exit")?;
        let Some(line) = prompt(input, output, "Choose:")? else {
            return Ok(());
        };
        if line == "0" {
            return Ok(());
        }
        let number = line.parse::<usize>().ok().filter(|n| n.to_string() == line);
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
                writeln!(
                    output,
                    "Simulation phase: {:?}. No credential or real runtime is present.",
                    installation.phase()
                )?;
            }
            Action::StartSetup => setup(input, output, installation)?,
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
            Action::Status => unreachable!("Status is not a menu action"),
        }
    }
}

fn setup(
    input: &mut impl BufRead,
    output: &mut impl Write,
    installation: &mut Installation,
) -> io::Result<()> {
    loop {
        writeln!(
            output,
            "Setup 1 — Choose connection\nSet up a proxy on this server. No changes until Apply.\n1. Standard (default; no domain needed)"
        )?;
        loop {
            match prompt(input, output, "Connection [1] (h Help, c Cancel):")?.as_deref() {
                Some("") | Some("1") => break,
                Some("h") => writeln!(
                    output,
                    "Standard uses VLESS REALITY Vision for a direct connection. It needs no domain. Only Standard is implemented in this Rust increment."
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
                    writeln!(output, "Setup 3 — Simulate install and check")?;
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
