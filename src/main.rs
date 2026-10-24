use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
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
