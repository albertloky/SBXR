//! Scoped SIGINT/SIGTERM cancellation for the native fixed private role.
//! Registration occurs only after native/released-build admission. No handler
//! or thread is installed by ordinary Mac tests or unavailable-role dispatch.
use super::*;
pub(super) struct Signals {
    stop: Cancellation,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Signals {
    pub fn native(stop: Cancellation) -> Result<Self, Error> {
        super::super::linux::require_native_environment().map_err(refused)?;
        #[cfg(target_os = "linux")]
        {
            let (ready, registered) = std::sync::mpsc::sync_channel(1);
            let shutdown = stop.clone();
            let worker = std::thread::Builder::new()
                .name("sbxr-shutdown-signals".into())
                .spawn(move || {
                    let result = (|| -> Result<(), Error> {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(refused)?;
                        runtime.block_on(watch_signals(&shutdown, &ready))
                    })();
                    if result.is_err() {
                        let _ = ready.send(Err(Error::Refused));
                        shutdown.cancel();
                    }
                })
                .map_err(refused)?;
            if !matches!(
                registered.recv_timeout(std::time::Duration::from_secs(1)),
                Ok(Ok(()))
            ) {
                stop.cancel();
                let _ = worker.join();
                return Err(Error::Refused);
            }
            Ok(Self {
                stop,
                worker: Some(worker),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stop;
            Err(Error::Refused)
        }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(target_os = "linux")]
async fn watch_signals(
    stop: &Cancellation,
    ready: &std::sync::mpsc::SyncSender<Result<(), Error>>,
) -> Result<(), Error> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).map_err(refused)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(refused)?;
    ready.send(Ok(())).map_err(refused)?;
    loop {
        tokio::select! {
            _ = terminate.recv() => { stop.cancel(); return Ok(()); }
            _ = interrupt.recv() => { stop.cancel(); return Ok(()); }
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                if stop.is_cancelled() { return Ok(()); }
            }
        }
    }
}
