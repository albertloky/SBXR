//! Native terminal reads poll a private descriptor and the Owner stop handle.
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

/// Output failure follows the existing disclosure contract; cancellation cannot
/// emit buffered client credentials after the Owner session has been stopped.
pub(super) struct InterruptibleOutput<'a, W> {
    output: &'a mut W,
    stop: Cancellation,
}
impl<'a, W: std::io::Write> InterruptibleOutput<'a, W> {
    pub fn new(output: &'a mut W, stop: Cancellation) -> Self {
        Self { output, stop }
    }
    fn check(&self) -> io::Result<()> {
        if self.stop.is_cancelled() {
            Err(io::Error::other("Owner session cancelled"))
        } else {
            Ok(())
        }
    }
}
impl<W: std::io::Write> std::io::Write for InterruptibleOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.output.flush()
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
}
