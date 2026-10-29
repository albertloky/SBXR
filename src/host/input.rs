//! Native terminal I/O polls private descriptors and the Owner stop handle.
//! No process-wide descriptor flags or terminal/security settings are changed.
use crate::subscription_serving::Cancellation;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    io::{self, BufRead, Read},
    os::fd::{AsFd, OwnedFd},
};
pub(super) struct InterruptibleInput {
    fd: OwnedFd,
    stop: Cancellation,
    buffer: [u8; 4096],
    position: usize,
    length: usize,
}
impl InterruptibleInput {
    pub fn new(input: &impl AsFd, stop: Cancellation) -> io::Result<Self> {
        Ok(Self {
            fd: rustix::io::fcntl_dupfd_cloexec(input, 3)?,
            stop,
            buffer: [0; 4096],
            position: 0,
            length: 0,
        })
    }
    fn check(&self) -> io::Result<()> {
        if self.stop.is_cancelled() {
            Err(io::Error::other("Owner session cancelled"))
        } else {
            Ok(())
        }
    }
}
impl BufRead for InterruptibleInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.check()?;
        if self.position == self.length {
            loop {
                self.check()?;
                let mut ready = [PollFd::new(&self.fd, PollFlags::IN)];
                let timeout = Timespec {
                    tv_sec: 0,
                    tv_nsec: 20_000_000,
                };
                match poll(&mut ready, Some(&timeout)) {
                    Ok(0) => continue,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                    Ok(_) => {}
                }
                self.check()?;
                match rustix::io::read(&self.fd, &mut self.buffer) {
                    Ok(n) => {
                        self.length = n;
                        self.position = 0;
                        break;
                    }
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        self.check()?;
        Ok(&self.buffer[self.position..self.length])
    }
    fn consume(&mut self, count: usize) {
        self.position = (self.position + count).min(self.length);
    }
}
impl Read for InterruptibleInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let data = self.fill_buf()?;
        let n = data.len().min(output.len());
        output[..n].copy_from_slice(&data[..n]);
        self.consume(n);
        Ok(n)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };
    #[test]
    fn cancelled_terminal_does_not_wait_for_another_line_or_return_buffered_approval() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let stop = Cancellation::new();
        let mut input = InterruptibleInput::new(&reader, stop.clone()).unwrap();
        writer.write_all(b"menu\ny\n").unwrap();
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        assert_eq!(line, "menu\n");
        stop.cancel();
        assert_eq!(
            input.read_line(&mut String::new()).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        let stop = Cancellation::new();
        let mut input = InterruptibleInput::new(&reader, stop.clone()).unwrap();
        let start = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(30));
                stop.cancel();
            });
            assert_eq!(
                input.read_line(&mut String::new()).unwrap_err().kind(),
                io::ErrorKind::Other
            );
        });
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn terminal_eof_and_descriptor_flags_are_preserved() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let flags = rustix::fs::fcntl_getfl(&reader).unwrap();
        let mut input = InterruptibleInput::new(&reader, Cancellation::new()).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&input.fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        drop(writer);
        assert_eq!(input.read_line(&mut String::new()).unwrap(), 0);
        assert_eq!(rustix::fs::fcntl_getfl(&reader).unwrap(), flags);
    }
}

/// Output failure follows the existing disclosure contract. Native stream output
/// is unbuffered: after cancellation is observed, neither flush nor drop emits
/// more bytes. Bytes already accepted by the kernel cannot be recalled.
/// Regular files/other destinations retain the caller's Write implementation;
/// cancellation cannot interrupt an in-progress blocking write/flush there.
pub(super) struct InterruptibleOutput<'a, W> {
    output: &'a mut W,
    stop: Cancellation,
    native: Option<NativeOutput>,
}
impl<'a, W: std::io::Write> InterruptibleOutput<'a, W> {
    pub fn new(output: &'a mut W, stop: Cancellation) -> Self {
        Self {
            output,
            stop,
            native: None,
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.stop.is_cancelled() {
            Err(io::Error::other("Owner session cancelled"))
        } else {
            Ok(())
        }
    }
}
impl<'a, W: std::io::Write + AsFd> InterruptibleOutput<'a, W> {
    /// The native caller supplies fresh stdout, before any buffered writes.
    /// Do not wrap a writer with pre-existing buffered or transforming output:
    /// stream writes go directly to its descriptor, bypassing its Write adapter.
    pub fn native(output: &'a mut W, stop: Cancellation) -> io::Result<Self> {
        let native = NativeOutput::new(output)?;
        Ok(Self {
            native,
            ..Self::new(output, stop)
        })
    }
}

struct NativeOutput {
    fd: OwnedFd,
    socket: bool,
}
impl NativeOutput {
    #[cfg(not(target_os = "linux"))]
    fn new(_: &impl AsFd) -> io::Result<Option<Self>> {
        // Native Owner entry is Linux-only. Other hosts retain the old writer;
        // do not assume their per-call nonblocking socket semantics match Linux.
        Ok(None)
    }
    #[cfg(target_os = "linux")]
    fn new(output: &impl AsFd) -> io::Result<Option<Self>> {
        use rustix::fs::{FileType, fstat};
        // Pin before inspection: descriptor replacement cannot redirect reopen.
        let pinned = rustix::io::fcntl_dupfd_cloexec(output, 3)?;
        let before = fstat(&pinned)?;
        // Reopening the PTY multiplexer creates a different terminal pair even
        // when fstat reports the same device/inode. Never redirect output there.
        if FileType::from_raw_mode(before.st_mode) == FileType::CharacterDevice
            && rustix::fs::major(before.st_rdev) == 5
            && rustix::fs::minor(before.st_rdev) == 2
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if FileType::from_raw_mode(before.st_mode) == FileType::Socket {
            return Ok(Some(Self {
                fd: pinned,
                socket: true,
            }));
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, fcntl_getfl, open};
            use std::{io::IsTerminal, os::fd::AsRawFd};
            let pinned = std::fs::File::from(pinned);
            if FileType::from_raw_mode(before.st_mode) == FileType::Fifo || pinned.is_terminal() {
                // A dup shares status flags. Reopen the pinned pipe/terminal to
                // obtain an independent open file description; never F_SETFL on
                // inherited output. O_NOCTTY avoids acquiring a controlling tty.
                // Do not upgrade a read-only descriptor to writable authority.
                if fcntl_getfl(&pinned)? & OFlags::ACCMODE == OFlags::RDONLY {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let fd = open(
                    format!("/proc/self/fd/{}", pinned.as_raw_fd()),
                    OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
                    Mode::empty(),
                )?;
                let after = fstat(&fd)?;
                if (before.st_dev, before.st_ino, before.st_rdev, before.st_mode)
                    != (after.st_dev, after.st_ino, after.st_rdev, after.st_mode)
                    || !fcntl_getfl(&fd)?.contains(OFlags::NONBLOCK)
                {
                    return Err(io::Error::other("Terminal output descriptor changed"));
                }
                return Ok(Some(Self { fd, socket: false }));
            }
        }
        // O_NONBLOCK does not bound regular-file I/O. Preserve its buffering,
        // shared offset and append semantics instead of reopening it.
        Ok(None)
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, rustix::io::Errno> {
        if self.socket {
            let flags = rustix::net::SendFlags::DONTWAIT;
            #[cfg(target_os = "linux")]
            let flags = flags | rustix::net::SendFlags::NOSIGNAL;
            rustix::net::send(&self.fd, bytes, flags)
        } else {
            rustix::io::write(&self.fd, bytes)
        }
    }
}

impl<W: std::io::Write> std::io::Write for InterruptibleOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let Some(native) = &self.native else {
            return self.output.write(bytes);
        };
        loop {
            self.check()?;
            match native.write(bytes) {
                Ok(n) => return Ok(n),
                Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::AGAIN) => {}
                Err(e) => return Err(e.into()),
            }
            let mut ready = [PollFd::new(&native.fd, PollFlags::OUT)];
            let timeout = Timespec {
                tv_sec: 0,
                tv_nsec: 20_000_000,
            };
            match poll(&mut ready, Some(&timeout)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        if self.native.is_some() {
            // No userspace buffering, fsync or tcdrain. Write has already handed
            // accepted bytes to the kernel, just like an unbuffered File sink.
            Ok(())
        } else {
            self.output.flush()
        }
    }
}
#[cfg(test)]
mod output_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn cancelled_output_preserves_prior_evidence_but_does_not_disclose_more() {
        let stop = Cancellation::new();
        let mut evidence = Vec::new();
        let mut out = InterruptibleOutput::new(&mut evidence, stop.clone());
        out.write_all(b"pending\n").unwrap();
        stop.cancel();
        assert_eq!(
            out.write_all(b"synthetic-sensitive-artifact")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(out.flush().unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(evidence, b"pending\n");
    }

    // Every potentially blocking fixture runs in an owned child. The parent
    // kills AND reaps on timeout or assertion failure; no hanging test threads.
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            self.0.wait().expect("reap output fixture");
        }
    }
    fn bounded_child(mode: &str) {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "host::input::output_tests::blocked_output_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SBXR_OUTPUT_TEST", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "output fixture {mode}: {status}");
                // try_wait reaped this owned child; Drop also covers failures.
                assert_eq!(child.0.wait().unwrap(), status);
                return;
            }
            assert!(Instant::now() < deadline, "output fixture {mode} timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn socket_backpressure_cancels_without_disclosure_or_flag_changes() {
        bounded_child("socket");
    }
    #[test]
    fn private_nonblocking_pipe_backpressure_cancels_without_buffered_flush() {
        // Portable coverage of the pipe write/poll loop. Linux's independent
        // procfs reopen is exercised separately, never emulated on macOS.
        bounded_child("private-pipe");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_pipe_backpressure_cancels_without_inherited_flag_changes() {
        bounded_child("native-pipe");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_pty_slave_backpressure_cancels_without_descriptor_changes() {
        bounded_child("pty-slave");
    }

    #[cfg(target_os = "linux")]
    fn pty_slave_child() {
        use rustix::{
            fs::{OFlags, fcntl_getfl, fstat},
            io::fcntl_getfd,
            pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt},
        };
        use std::{
            fs::File,
            io::IsTerminal,
            time::{Duration, Instant},
        };

        // Allocate only this child's pair. Linux needs no grantpt/chmod/chown;
        // unlock affects only the newly allocated master's slave-open lock.
        // NOCTTY prevents controlling-terminal acquisition. No tcsetattr or
        // existing terminal is involved, and master is never used as output.
        let open_flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = openpt(open_flags).unwrap();
        unlockpt(&master).unwrap();
        let mut slave = File::from(ioctl_tiocgptpeer(&master, open_flags).unwrap());
        assert!(slave.is_terminal());
        let identity = |fd: &dyn AsFd| {
            let stat = fstat(fd).unwrap();
            (stat.st_dev, stat.st_ino, stat.st_rdev, stat.st_mode)
        };
        let slave_identity = identity(&slave);
        let master_identity = identity(&master);
        let slave_flags = fcntl_getfl(&slave).unwrap();
        let slave_fd_flags = fcntl_getfd(&slave).unwrap();
        let master_flags = fcntl_getfl(&master).unwrap();
        let master_fd_flags = fcntl_getfd(&master).unwrap();
        assert!(!slave_flags.contains(OFlags::NONBLOCK));
        let stop = Cancellation::new();
        let mut out = InterruptibleOutput::native(&mut slave, stop.clone()).unwrap();
        let native = out
            .native
            .as_ref()
            .expect("PTY slave must use native output");
        assert_eq!(identity(&native.fd), slave_identity);
        assert!(fcntl_getfl(&native.fd).unwrap().contains(OFlags::NONBLOCK));
        assert!(
            fcntl_getfd(&native.fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert_eq!(fcntl_getfl(&*out.output).unwrap(), slave_flags);
        assert_eq!(fcntl_getfd(&*out.output).unwrap(), slave_fd_flags);

        // Never drain the master while filling/writing. Plain x is unaffected
        // by default output postprocessing; no fixture termios changes needed.
        let mut filled = 0;
        loop {
            match native.write(&[b'x'; 4096]) {
                Ok(n) => {
                    assert!(n > 0);
                    filled += n;
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(rustix::io::Errno::INTR) => continue,
                other => panic!("fill PTY slave: {other:?}"),
            }
            assert!(filled <= 4 * 1024 * 1024, "PTY fixture did not fill");
        }
        assert!(filled > 0);
        out.flush().unwrap(); // Must not wait for the unread master to drain.
        let payload = vec![b'x'; 8 * 1024 * 1024];
        let cancel = stop.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        });
        let started = Instant::now();
        let result = out.write_all(&payload);
        worker.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(stop.is_cancelled());
        assert_eq!(result.unwrap_err().to_string(), "Owner session cancelled");
        assert!(out.write_all(b"synthetic-sensitive-artifact").is_err());
        assert!(out.flush().is_err());
        drop(out);
        assert_eq!(identity(&slave), slave_identity);
        assert_eq!(fcntl_getfl(&slave).unwrap(), slave_flags);
        assert_eq!(fcntl_getfd(&slave).unwrap(), slave_fd_flags);
        assert_eq!(identity(&master), master_identity);
        assert_eq!(fcntl_getfl(&master).unwrap(), master_flags);
        assert_eq!(fcntl_getfd(&master).unwrap(), master_fd_flags);
        drop(slave);

        // Drain after cancellation/drop. Linux returns EIO after the final slave
        // closes; a leaked adapter descriptor would instead hang, caught by the
        // parent's three-second timeout and kill/reap guard.
        let mut received = 0;
        let mut bytes = [0; 4096];
        loop {
            match rustix::io::read(&master, &mut bytes) {
                Ok(0) | Err(rustix::io::Errno::IO) => break,
                Ok(n) => {
                    assert!(bytes[..n].iter().all(|b| *b == b'x'));
                    received += n;
                    assert!(received <= filled + payload.len());
                }
                Err(rustix::io::Errno::INTR) => continue,
                other => panic!("drain PTY master: {other:?}"),
            }
        }
        assert!(received > 0);
        drop(master);
    }

    #[test]
    #[ignore = "invoked only by timeout-controlled parent tests"]
    fn blocked_output_child() {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        use std::{
            fs::File,
            os::unix::net::UnixStream,
            time::{Duration, Instant},
        };
        let mode = std::env::var("SBXR_OUTPUT_TEST").unwrap();
        #[cfg(target_os = "linux")]
        if mode == "pty-slave" {
            pty_slave_child();
            return;
        }
        let (mut reader, mut writer): (File, File) = if mode == "socket" {
            let (r, w) = UnixStream::pair().unwrap();
            (OwnedFd::from(r).into(), OwnedFd::from(w).into())
        } else {
            let (r, w) = std::io::pipe().unwrap();
            (OwnedFd::from(r).into(), OwnedFd::from(w).into())
        };
        let private = mode == "private-pipe";
        if private {
            // Only this newly created fixture's open file description changes.
            fcntl_setfl(&writer, fcntl_getfl(&writer).unwrap() | OFlags::NONBLOCK).unwrap();
        }
        let observer = writer.try_clone().unwrap();
        let original_flags = fcntl_getfl(&observer).unwrap();
        let fd_flags = rustix::io::fcntl_getfd(&writer).unwrap();
        let filler = if private {
            NativeOutput {
                fd: rustix::io::fcntl_dupfd_cloexec(&writer, 3).unwrap(),
                socket: false,
            }
        } else {
            NativeOutput::new(&writer).unwrap().unwrap()
        };
        assert_eq!(fcntl_getfl(&observer).unwrap(), original_flags);
        let mut filled = 0;
        loop {
            match filler.write(&[b'x'; 4096]) {
                Ok(n) => {
                    assert!(n > 0);
                    filled += n;
                }
                Err(rustix::io::Errno::AGAIN) => break,
                other => panic!("fill output: {other:?}"),
            }
            assert!(filled <= 4 * 1024 * 1024, "fixture did not fill");
        }
        assert!(filled > 0);
        // Darwin exposes an additional kernel status bit after any raw pipe
        // write, including Python os.write. Compare the filled fixture's flags
        // across the adapter operation, not pristine vs written pipe state.
        let flags = fcntl_getfl(&observer).unwrap();
        let stop = Cancellation::new();
        let mut out = if private {
            InterruptibleOutput {
                output: &mut writer,
                stop: stop.clone(),
                native: Some(filler),
            }
        } else {
            drop(filler);
            InterruptibleOutput::native(&mut writer, stop.clone()).unwrap()
        };
        // Full kernel buffers must not turn flush into a drain operation.
        out.flush().unwrap();
        let cancel = stop.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        });
        let start = Instant::now();
        let result = out.write_all(&vec![b'x'; 8 * 1024 * 1024]);
        worker.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(
            out.write_all(b"synthetic-sensitive-artifact")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(out.flush().unwrap_err().kind(), io::ErrorKind::Other);
        drop(out);
        assert_eq!(fcntl_getfl(&observer).unwrap(), flags);
        assert_eq!(rustix::io::fcntl_getfd(&writer).unwrap(), fd_flags);
        drop(observer);
        drop(writer);
        let mut evidence = Vec::new();
        reader.read_to_end(&mut evidence).unwrap();
        assert!(!evidence.is_empty());
        assert!(evidence.iter().all(|b| *b == b'x'));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_output_refuses_pty_master_reopen() {
        use rustix::fs::{Mode, OFlags, fcntl_getfl, open};
        // A fresh, private master only: no grant/unlock, terminal settings,
        // controlling-terminal acquisition or existing terminal interaction.
        let master = open(
            "/dev/ptmx",
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let flags = fcntl_getfl(&master).unwrap();
        let error = match NativeOutput::new(&master) {
            Err(error) => error,
            Ok(_) => panic!("PTY master reopen accepted"),
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fcntl_getfl(&master).unwrap(), flags);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_socket_preserves_bytes_and_reports_closed_peer() {
        use std::os::unix::net::UnixStream;
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let stop = Cancellation::new();
        let mut out = InterruptibleOutput::native(&mut writer, stop).unwrap();
        out.write_all(b"pending\n").unwrap();
        out.flush().unwrap();
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"pending\n");
        reader.shutdown(std::net::Shutdown::Both).unwrap();
        drop(reader);
        assert_eq!(
            out.write(b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn regular_file_retains_shared_offset_append_and_cancellation_behavior() {
        use std::{
            fs::OpenOptions,
            io::{Seek, SeekFrom},
        };
        let path = std::env::temp_dir().join(format!("sbxr-output-{}", std::process::id()));
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                std::fs::remove_file(&self.0).unwrap();
            }
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let _remove = Remove(path.clone());
        file.write_all(b"prior").unwrap();
        file.seek(SeekFrom::Start(2)).unwrap();
        let stop = Cancellation::new();
        let mut out = InterruptibleOutput::native(&mut file, stop.clone()).unwrap();
        assert!(out.native.is_none());
        out.write_all(b"X").unwrap();
        out.flush().unwrap();
        stop.cancel();
        assert!(out.write_all(b"secret").is_err());
        assert!(out.flush().is_err());
        drop(out);
        assert_eq!(file.stream_position().unwrap(), 3);
        let mut append = OpenOptions::new().append(true).open(&path).unwrap();
        append.seek(SeekFrom::Start(0)).unwrap();
        InterruptibleOutput::native(&mut append, Cancellation::new())
            .unwrap()
            .write_all(b"!")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"prXor!");
    }
}
