//! Fixed vocabulary only. Diagnostics never authorize startup or alter its result.
use super::Error;
use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Instant,
};
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Stage {
    Build,
    Admission,
    Lock,
    Connect,
    Peer,
    Descriptor,
    Installed,
    Authority,
    Material,
    Unit,
    Sandbox,
    PublicIp,
    Configuration,
    Bind,
    Ready,
    LenderBinding,
    LenderPeer,
    LenderRole,
    LenderRecheck,
    LenderSend,
    LenderAccept,
}
const NAMES: [&str; 21] = [
    "build",
    "admission",
    "lock",
    "connect",
    "peer",
    "descriptor",
    "installed",
    "authority",
    "material",
    "unit",
    "sandbox",
    "public-ip",
    "configuration",
    "bind",
    "ready",
    "lender-binding",
    "lender-peer",
    "lender-role",
    "lender-recheck",
    "lender-send",
    "lender-accept",
];
pub struct Diagnostics {
    started: Instant,
    stage: AtomicU8,
    stage_at: AtomicU64,
    first: AtomicU8,
}
impl Default for Diagnostics {
    fn default() -> Self {
        Self::new()
    }
}
impl Diagnostics {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            stage: AtomicU8::new(0),
            stage_at: AtomicU64::new(0),
            first: AtomicU8::new(0),
        }
    }
    fn elapsed(&self) -> u64 {
        self.started.elapsed().as_millis().min(1_200_000) as u64
    }
    pub fn stage(&self, stage: Stage) {
        self.stage_at.store(self.elapsed(), Ordering::Relaxed);
        self.stage.store(stage as u8, Ordering::Relaxed);
    }
    pub(super) fn rejected_current(&self) {
        let _ = self.first.compare_exchange(
            0,
            self.stage.load(Ordering::Relaxed) + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
    pub fn rejected(&self, stage: Stage) {
        let _ =
            self.first
                .compare_exchange(0, stage as u8 + 1, Ordering::Relaxed, Ordering::Relaxed);
    }
    /// Accepts no caller-supplied text, process identity, address or payload.
    pub fn record(&self, lender: bool, result: Result<(), Error>) -> String {
        let elapsed = self.elapsed();
        let stage = NAMES[self.stage.load(Ordering::Relaxed) as usize];
        let first = self.first.load(Ordering::Relaxed);
        let first = if first == 0 {
            "none"
        } else {
            NAMES[(first - 1) as usize]
        };
        let outcome = match result {
            Ok(()) => "ok",
            Err(Error::Refused) => "refused",
            Err(Error::Busy) => "busy",
            Err(Error::Cancelled) => "cancelled",
            Err(Error::Deadline) => "deadline",
        };
        format!(
            "SBXR_START_V1 role={} stage={} result={} first={} elapsed_ms={} stage_ms={}\n",
            if lender { "lender" } else { "serving" },
            stage,
            outcome,
            first,
            elapsed,
            elapsed.saturating_sub(self.stage_at.load(Ordering::Relaxed))
        )
    }
    pub(crate) fn emit(&self, lender: bool, result: Result<(), Error>) {
        let line = self.record(lender, result);
        // systemd's journal stderr is an AF_UNIX stream. A single bounded,
        // nonblocking send: no retries, fallback file, fd flag changes or flush.
        // Non-socket stderr and a full/unavailable journal simply lose diagnostics.
        #[cfg(target_os = "linux")]
        {
            send_record(std::io::stderr(), line.as_bytes());
        }
        #[cfg(not(target_os = "linux"))]
        let _ = line;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_record_is_bounded_and_first_rejection_is_retained() {
        let d = Diagnostics::new();
        d.stage(Stage::Connect);
        d.rejected(Stage::Peer);
        d.rejected(Stage::Descriptor);
        for result in [
            Ok(()),
            Err(Error::Refused),
            Err(Error::Busy),
            Err(Error::Cancelled),
            Err(Error::Deadline),
        ] {
            let line = d.record(false, result);
            assert!(line.len() < 256);
            assert!(line.contains("stage=connect"));
            assert!(line.contains("first=peer"));
            assert_eq!(line.lines().count(), 1);
            assert!(line.bytes().all(|b| b.is_ascii_lowercase()
                || b.is_ascii_uppercase()
                || b.is_ascii_digit()
                || b"_=- \n".contains(&b)));
        }
        for (i, name) in NAMES.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(i < 256);
        }
        assert_eq!(NAMES[Stage::Ready as usize], "ready");
    }
}

#[cfg(target_os = "linux")]
fn send_record(fd: impl std::os::fd::AsFd, line: &[u8]) {
    let _ = rustix::net::send(
        fd,
        line,
        rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
    );
}
#[cfg(all(test, target_os = "linux"))]
mod socket_tests {
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream};
    #[test]
    fn journal_socket_send_is_bounded_and_closed_or_full_socket_does_not_block() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let line = Diagnostics::new().record(false, Err(Error::Deadline));
        send_record(&sender, line.as_bytes());
        let mut bytes = vec![0; line.len()];
        receiver.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, line.as_bytes());
        let fill = [0; 4096];
        while rustix::net::send(
            &sender,
            &fill,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        )
        .is_ok()
        {}
        let before = Instant::now();
        send_record(&sender, line.as_bytes());
        assert!(before.elapsed() < std::time::Duration::from_secs(1));
        drop(receiver);
        send_record(&sender, line.as_bytes());
        let file = std::fs::File::open("/dev/null").unwrap();
        send_record(file, line.as_bytes());
    }
}
