//! Diagnostics must never wait for stdio locks or sink capacity. Linux can reopen
//! a pinned pipe through procfs with a private nonblocking open file description.
//! A dup alone would share flags with inherited stderr. All other sinks/platforms
//! are refused; no inherited descriptor flags, terminal or security state changes.
use std::{
    io::{self, Write},
    os::fd::{AsFd, OwnedFd},
};

pub(super) struct NativeSink {
    fd: OwnedFd,
}
impl NativeSink {
    #[cfg(target_os = "linux")]
    pub(super) fn new(stderr: &impl AsFd) -> io::Result<Self> {
        use rustix::fs::{FileType, Mode, OFlags, fstat, open};
        use std::os::fd::AsRawFd;
        // Pin the descriptor before inspecting/reopening it: stderr may be
        // replaced concurrently, but this owned duplicate cannot be reused.
        let pinned = rustix::io::fcntl_dupfd_cloexec(stderr, 3)?;
        let before = fstat(&pinned)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::Fifo {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let fd = open(
            format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let after = fstat(&fd)?;
        if FileType::from_raw_mode(after.st_mode) != FileType::Fifo
            || (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            || !rustix::fs::fcntl_getfl(&fd)?.contains(OFlags::NONBLOCK)
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok(Self { fd })
    }
    #[cfg(not(target_os = "linux"))]
    pub(super) fn new(_: &impl AsFd) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
impl Write for NativeSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // 512 is the POSIX minimum PIPE_BUF. One nonblocking write is atomic or
        // refuses on capacity; never poll, retry, flush or acquire a stdio lock.
        if bytes.len() > 512 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        rustix::io::write(&self.fd, bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use std::{io::Read, time::Duration};

    // Only owned anonymous pipes; keep both ends alive, so there is no signal,
    // socket, child, inherited flag mutation or external I/O in these tests.
    fn private_pipe() -> (std::io::PipeReader, NativeSink) {
        let (reader, writer) = std::io::pipe().unwrap();
        let fd: OwnedFd = writer.into();
        fcntl_setfl(&fd, fcntl_getfl(&fd).unwrap() | OFlags::NONBLOCK).unwrap();
        (reader, NativeSink { fd })
    }

    #[test]
    fn query_diagnostic_native_sink_refuses_full_pipe_without_partial_record() {
        let (mut reader, mut sink) = private_pipe();
        let record = [b'x'; 512];
        let mut written = 0;
        let started = std::time::Instant::now();
        loop {
            match sink.write(&record) {
                Ok(512) => written += 512,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                other => panic!("unexpected pipe result: {other:?}"),
            }
            assert!(written <= 4 * 1024 * 1024, "fixture pipe did not fill");
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(written > 0);
        assert_eq!(
            sink.write(&[0; 513]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let mut bytes = vec![0; written];
        reader.read_exact(&mut bytes).unwrap();
        assert!(bytes.iter().all(|b| *b == b'x'));
    }

    #[test]
    fn query_diagnostic_native_sink_never_acquires_stderr_lock() {
        let (mut reader, mut sink) = private_pipe();
        let stderr = std::io::stderr();
        let locked = stderr.lock();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            sender.send(sink.write(b"fixed-record")).unwrap();
        });
        let result = receiver.recv_timeout(Duration::from_secs(1));
        // Always release before joining, including regression failure.
        drop(locked);
        worker.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), 12);
        let mut bytes = [0; 12];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"fixed-record");
    }

    #[test]
    fn query_diagnostic_native_sink_rejects_regular_files_without_flag_changes() {
        let file = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let before = fcntl_getfl(&file).unwrap();
        assert!(NativeSink::new(&file).is_err());
        assert_eq!(fcntl_getfl(&file).unwrap(), before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn query_diagnostic_native_sink_reopens_pipe_without_sharing_flags() {
        let (mut reader, writer) = std::io::pipe().unwrap();
        let before = fcntl_getfl(&writer).unwrap();
        assert!(!before.contains(OFlags::NONBLOCK));
        let mut sink = NativeSink::new(&writer).unwrap();
        assert_eq!(fcntl_getfl(&writer).unwrap(), before);
        assert!(fcntl_getfl(&sink.fd).unwrap().contains(OFlags::NONBLOCK));
        // Changing only the owned fixture's inherited side cannot change sink flags.
        fcntl_setfl(&writer, before | OFlags::NONBLOCK).unwrap();
        fcntl_setfl(&writer, before).unwrap();
        assert!(fcntl_getfl(&sink.fd).unwrap().contains(OFlags::NONBLOCK));
        assert_eq!(sink.write(b"ok").unwrap(), 2);
        let mut bytes = [0; 2];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
    }
}
