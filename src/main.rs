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
    let result =
        sbxr::host::owner::run_public_unreleased(&mut io::stdin().lock(), &mut io::stdout().lock());
    finish_public(result, &mut io::stderr())
}

fn finish_public(
    result: Result<(), sbxr::host::owner::PublicEntryError>,
    diagnostics: &mut impl io::Write,
) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Cancellation must not re-enter a blocking stderr write after the
        // native output adapter has escaped terminal backpressure.
        Err(sbxr::host::owner::PublicEntryError::Host(sbxr::host::HostError::Cancelled)) => {
            ExitCode::FAILURE
        }
        Err(error) => {
            let _ = writeln!(diagnostics, "SBXR: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_public_entry_never_writes_or_flushes_stderr() {
        struct Unavailable;
        impl io::Write for Unavailable {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("cancelled exit must not write diagnostics")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("cancelled exit must not flush diagnostics")
            }
        }
        assert_eq!(
            finish_public(
                Err(sbxr::host::owner::PublicEntryError::Host(
                    sbxr::host::HostError::Cancelled,
                )),
                &mut Unavailable,
            ),
            ExitCode::FAILURE
        );
        let mut output = Vec::new();
        assert_eq!(
            finish_public(
                Err(sbxr::host::owner::PublicEntryError::Terminal(
                    io::Error::other("private")
                )),
                &mut output,
            ),
            ExitCode::FAILURE
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("SBXR: Terminal session failed;"));
        assert!(!output.contains("private"));
    }
}
