use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(code) =
        sbxr::private_roles::dispatch(&arguments, &mut sbxr::host::runtime::NativePrivateRuntime)
    {
        return ExitCode::from(code);
    }
    if !arguments.is_empty() {
        eprintln!("SBXR accepts no arguments.");
        return ExitCode::FAILURE;
    }
    match sbxr::host::owner::run_public_unreleased(
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("SBXR: {error}");
            ExitCode::FAILURE
        }
    }
}
