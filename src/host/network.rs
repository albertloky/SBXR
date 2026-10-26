//! Verified TLS1.3 network admission with bounded direct sockets. Native entry
//! probes only fixed product endpoints; fixtures use private loopback helpers.
use super::{
    HostError,
    process::{Cancellation, CommandRunner, NativeReadOnly, Query},
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationObservation {
    pub dns: bool,
    pub tcp: bool,
    pub tls13: bool,
    pub http2: bool,
    pub certificate_name: bool,
}
impl DestinationObservation {
    pub fn compatible(&self) -> bool {
        self.dns && self.tcp && self.tls13 && self.http2 && self.certificate_name
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAdmission {
    ipv4: Ipv4Addr,
    destination: DestinationObservation,
    bound: bool,
}
impl NetworkAdmission {
    pub fn public_ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }
    pub fn destination(&self) -> &DestinationObservation {
        &self.destination
    }
    pub fn bind_proved(&self) -> bool {
        self.bound
    }
    /// Real implementation, never called by Mac/VPS development tests. Running
    /// inspection omits the occupied listener bind; setup/activation must require it.
    pub fn native(stop: &Cancellation, require_bind: bool) -> Result<Self, HostError> {
        let _phase = super::timing::span(super::timing::Phase::Network);
        super::linux::require_native_environment()?;
        let roots = native_roots()?;
        let runner = NativeReadOnly;
        let deadline = Instant::now() + TIMEOUT;
        let addresses = resolve(&runner, Query::PublicIpDns, 443, stop)?;
        let ipv4 = fetch_ipv4(&roots, "api.ipify.org", &addresses, deadline, stop)?;
        let deadline = Instant::now() + TIMEOUT;
        let addresses = resolve(&runner, Query::DestinationDns, 443, stop)?;
        let (_, destination) = tls(&roots, "google.com", &addresses, b"h2", deadline, stop)?;
        if !destination.compatible() {
            return Err(HostError::Unsafe);
        }
        let bound = if require_bind {
            bind(SocketAddr::from((ipv4, 443)))?;
            true
        } else {
            false
        };
        Ok(Self {
            ipv4,
            destination,
            bound,
        })
    }
}
fn resolve(
    runner: &impl CommandRunner,
    query: Query,
    port: u16,
    stop: &Cancellation,
) -> Result<Vec<SocketAddr>, HostError> {
    let _phase = super::timing::span(super::timing::Phase::Dns);
    let output = runner.query(query, stop)?;
    if output.code() != 0 {
        return Err(HostError::Unsafe);
    }
    let mut addresses = Vec::new();
    for line in output.text()?.lines() {
        let text = line.split_whitespace().next().ok_or(HostError::Unsafe)?;
        let ip: IpAddr = text.parse().map_err(|_| HostError::Unsafe)?;
        let addr = SocketAddr::new(ip, port);
        if !addresses.contains(&addr) {
            addresses.push(addr)
        }
        if addresses.len() > 64 {
            return Err(HostError::OutputLimit);
        }
    }
    if addresses.is_empty() {
        return Err(HostError::Unsafe);
    }
    Ok(addresses)
}
fn native_roots() -> Result<RootCertStore, HostError> {
    let _phase = super::timing::span(super::timing::Phase::Roots);
    let fs = super::filesystem::ProtectedFs::native()?;
    let (bytes, evidence) = fs
        .raw(
            "etc/ssl/certs/ca-certificates.crt",
            rustix::fs::Mode::from_raw_mode(0o644),
            1 << 20,
        )?
        .ok_or(HostError::Unsafe)?;
    if evidence.gid != 0 {
        return Err(HostError::Unsafe);
    }
    roots_from_pem(&bytes)
}
fn roots_from_pem(mut bytes: &[u8]) -> Result<RootCertStore, HostError> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut bytes) {
        roots
            .add(cert.map_err(|_| HostError::Unsafe)?)
            .map_err(|_| HostError::Unsafe)?;
    }
    if roots.is_empty() {
        return Err(HostError::Unsafe);
    }
    Ok(roots)
}
fn remaining(deadline: Instant, stop: &Cancellation) -> io::Result<Duration> {
    if stop.cancelled() {
        return Err(io::Error::other("cancelled"));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}
struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
    stop: Cancellation,
}
impl Read for DeadlineTcp {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(
                remaining(self.deadline, &self.stop)?.min(Duration::from_millis(100)),
            ))?;
            match self.stream.read(buffer) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(
                remaining(self.deadline, &self.stop)?.min(Duration::from_millis(100)),
            ))?;
            match self.stream.write(buffer) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn tls(
    roots: &RootCertStore,
    hostname: &str,
    addresses: &[SocketAddr],
    alpn: &[u8],
    deadline: Instant,
    stop: &Cancellation,
) -> Result<
    (
        StreamOwned<ClientConnection, DeadlineTcp>,
        DestinationObservation,
    ),
    HostError,
> {
    let _phase = super::timing::span(super::timing::Phase::Tls);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| HostError::Unsafe)?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let name = ServerName::try_from(hostname.to_owned()).map_err(|_| HostError::Unsafe)?;
    let mut connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| HostError::Unsafe)?;
    let _connect = super::timing::span(super::timing::Phase::Connect);
    let mut stream = None;
    for address in addresses {
        let timeout = remaining(deadline, stop).map_err(|_| {
            if stop.cancelled() {
                HostError::Cancelled
            } else {
                HostError::Timeout
            }
        })?;
        match TcpStream::connect_timeout(address, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => continue,
        }
    }
    drop(_connect);
    let mut stream = DeadlineTcp {
        stream: stream.ok_or(HostError::Unsafe)?,
        deadline,
        stop: stop.clone(),
    };
    let _handshake = super::timing::span(super::timing::Phase::Handshake);
    while connection.is_handshaking() {
        connection.complete_io(&mut stream).map_err(|_| {
            if stop.cancelled() {
                HostError::Cancelled
            } else {
                HostError::Unsafe
            }
        })?;
    }
    drop(_handshake);
    let result = DestinationObservation {
        dns: !addresses.is_empty(),
        tcp: true,
        tls13: connection.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        http2: connection.alpn_protocol() == Some(b"h2"),
        certificate_name: connection
            .peer_certificates()
            .is_some_and(|v| !v.is_empty()),
    };
    Ok((StreamOwned::new(connection, stream), result))
}
fn line(stream: &mut impl Read, limit: usize) -> Result<Vec<u8>, HostError> {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n") {
        if result.len() >= limit {
            return Err(HostError::OutputLimit);
        }
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_| HostError::Unsafe)?;
        result.push(byte[0]);
    }
    Ok(result)
}
fn fetch_ipv4(
    roots: &RootCertStore,
    hostname: &str,
    addresses: &[SocketAddr],
    deadline: Instant,
    stop: &Cancellation,
) -> Result<Ipv4Addr, HostError> {
    let _phase = super::timing::span(super::timing::Phase::IpHttp);
    let (mut stream, _) = tls(roots, hostname, addresses, b"http/1.1", deadline, stop)?;
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| HostError::Unsafe)?;
    stream.flush().map_err(|_| HostError::Unsafe)?;
    let mut header = Vec::new();
    loop {
        let part = line(&mut stream, 8192usize.saturating_sub(header.len()))?;
        header.extend_from_slice(&part);
        if part == b"\r\n" {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(&header), Ok(httparse::Status::Complete(_)))
        || response.code != Some(200)
    {
        return Err(HostError::Unsafe);
    }
    let mut length = None;
    let mut chunked = false;
    for field in response.headers {
        if field.name.eq_ignore_ascii_case("Content-Length") {
            let lexical = field.value.trim_ascii();
            if lexical.is_empty() || !lexical.iter().all(u8::is_ascii_digit) {
                return Err(HostError::Unsafe);
            }
            let value = std::str::from_utf8(lexical)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|v| *v <= 64)
                .ok_or(HostError::Unsafe)?;
            if length.replace(value).is_some_and(|old| old != value) {
                return Err(HostError::Unsafe);
            }
        }
        if field.name.eq_ignore_ascii_case("Transfer-Encoding") {
            if chunked || !field.value.eq_ignore_ascii_case(b"chunked") {
                return Err(HostError::Unsafe);
            }
            chunked = true;
        }
    }
    if chunked && length.is_some() {
        return Err(HostError::Unsafe);
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let size = line(&mut stream, 1024)?;
            let size = std::str::from_utf8(&size)
                .map_err(|_| HostError::Unsafe)?
                .trim_end_matches("\r\n")
                .split(';')
                .next()
                .ok_or(HostError::Unsafe)?;
            let count = usize::from_str_radix(size, 16).map_err(|_| HostError::Unsafe)?;
            if count > 64usize.saturating_sub(body.len()) {
                return Err(HostError::OutputLimit);
            }
            if count == 0 {
                let mut trailer = 0;
                loop {
                    let entry = line(&mut stream, 8192usize.saturating_sub(trailer))?;
                    trailer += entry.len();
                    if entry == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let start = body.len();
            body.resize(start + count, 0);
            stream
                .read_exact(&mut body[start..])
                .map_err(|_| HostError::Unsafe)?;
            if line(&mut stream, 2)? != b"\r\n" {
                return Err(HostError::Unsafe);
            }
        }
    } else if let Some(length) = length {
        body.resize(length, 0);
        stream
            .read_exact(&mut body)
            .map_err(|_| HostError::Unsafe)?;
    } else {
        stream
            .take(65)
            .read_to_end(&mut body)
            .map_err(|_| HostError::Unsafe)?;
        if body.len() > 64 {
            return Err(HostError::OutputLimit);
        }
    }
    let text = std::str::from_utf8(&body)
        .map_err(|_| HostError::Unsafe)?
        .trim();
    let ipv4: Ipv4Addr = text.parse().map_err(|_| HostError::Unsafe)?;
    if ipv4.to_string() != text || !crate::records::ownership_public_ipv4(text) {
        return Err(HostError::Unsafe);
    }
    Ok(ipv4)
}
fn bind(address: SocketAddr) -> Result<(), HostError> {
    let _phase = super::timing::span(super::timing::Phase::Bind);
    let listener = TcpListener::bind(address).map_err(|_| HostError::Busy)?;
    drop(listener);
    Ok(())
}
#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
