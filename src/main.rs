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
    let mut installation = sbxr::proxyinstallation::Installation::simulation();
    match sbxr::terminal::run(
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut installation,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Terminal session failed: {error}");
            ExitCode::FAILURE
        }
    }
}
