//! Joins cancellation propagation around one fixed bounded process effect.
use super::super::process::Cancellation as CommandCancellation;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
pub(in crate::host) fn run<T>(
    context: &StartContext,
    effect: impl FnOnce(&CommandCancellation) -> Result<T, HostError>,
) -> Result<T, Error> {
    context.check()?;
    let stop = CommandCancellation::new();
    let done = AtomicBool::new(false);
    struct Finish<'a>(&'a AtomicBool);
    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    std::thread::scope(|scope| {
        let finished = Finish(&done);
        let forward = std::thread::Builder::new()
            .name("sbxr-service-cancel".into())
            .spawn_scoped(scope, || {
                while !done.load(Ordering::Acquire) {
                    if context.check().is_err() {
                        stop.cancel();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            })
            .map_err(refused)?;
        let result = effect(&stop);
        drop(finished);
        forward.join().map_err(refused)?;
        context.check()?;
        result.map_err(refused)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_stalled_process_is_cancelled_reaped_and_cannot_report_late_success() {
        for cancelled in [false, true] {
            let stop = Cancellation::new();
            let context = StartContext::new(
                stop.clone(),
                std::time::Instant::now()
                    + std::time::Duration::from_millis(if cancelled { 1000 } else { 65 }),
            );
            let started = std::time::Instant::now();
            std::thread::scope(|scope| {
                if cancelled {
                    scope.spawn(|| {
                        std::thread::sleep(std::time::Duration::from_millis(30));
                        stop.cancel();
                    });
                }
                let result = run(&context, |cancel| {
                    crate::host::process::run_in(
                        "/bin/sh",
                        &["-c", "exec sleep 10"],
                        "/",
                        std::time::Duration::from_secs(2),
                        4096,
                        cancel,
                    )
                });
                assert!(matches!(result, Err(Error::Cancelled | Error::Deadline)));
            });
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
        }
    }
}
