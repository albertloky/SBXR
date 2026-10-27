//! Diagnostic-only; build/inspect now. Execution requires separate approval.
#![forbid(unsafe_code)]
#[path = "../../../../src/host/dns_observer.rs"]
mod dns_observer;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};

fn gate(expected: u8) -> io::Result<()> {
    let mut byte = [0];
    io::stdin().read_exact(&mut byte)?;
    if byte[0] != expected { return Err(io::ErrorKind::InvalidInput.into()); }
    Ok(())
}
fn spawn(wait: bool) -> io::Result<Child> {
    Command::new("/proc/self/exe")
        .arg(if wait { "child-wait" } else { "child-exit" })
        .env_clear().stdin(if wait { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn()
}
fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 { return Err(io::ErrorKind::InvalidInput.into()); }
    let case = args[1].as_str();
    if case == "child-exit" { return Ok(()); }
    if case == "child-wait" {
        let mut byte = [0];
        return match io::stdin().read(&mut byte)? {
            0 => Ok(()), _ => Err(io::ErrorKind::InvalidData.into())
        };
    }
    if !matches!(case, "immediate" | "pipe-wait" | "unrelated") {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Ordinary Child handles retain wait ownership. On error, the independently
    // approved supervisor owns cleanup; this fixture never sends a signal.
    println!("GATED {}", std::process::id());
    io::stdout().flush()?;
    gate(b'G')?;
    // Same executable, forked outside the selected query scope. Remains alive
    // during the selected child; no process-name inference is valid.
    let mut unrelated = if case == "unrelated" { Some(spawn(true)?) } else { None };
    if let Some(ref other) = unrelated {
        println!("UNRELATED {}", other.id());
        io::stdout().flush()?;
    }
    let scope = dns_observer::Scope::begin(Some(7));
    let mut child = spawn(case == "pipe-wait")?;
    // Deliberately confirm this case only after exit/reap, to test the observer's
    // short-lived-child ordering. This is a fixture variation, not product flow.
    if case == "immediate" { child.wait()?; }
    scope.spawned(child.id());
    println!("CHILD {}", child.id());
    io::stdout().flush()?;
    if case == "pipe-wait" {
        gate(b'C')?;
        drop(child.stdin.take());
    }
    let status = child.wait()?;
    drop(scope);
    if let Some(ref mut other) = unrelated {
        drop(other.stdin.take());
        if !other.wait()?.success() { return Err(io::ErrorKind::Other.into()); }
    }
    if !status.success() { return Err(io::ErrorKind::Other.into()); }
    println!("COMPLETE");
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("fixture refused; supervisor must prove cleanup");
        std::process::exit(2);
    }
}
