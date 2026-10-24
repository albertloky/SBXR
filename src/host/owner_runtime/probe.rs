use super::*;
use std::io::{Read, Write};
impl<I: OwnerIo> OwnerRuntime<'_, I> {
    pub(super) fn loaded(
        &self,
        r: &OwnershipRecord,
        a: &ServingAuthority,
        token: &SubscriptionCredential,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.installed()?;
        self.serving_routes(c)?;
        if self.property(Unit::Subscription, Property::ActiveState, c)? != "active" {
            return Err(HostError::Foreign);
        }
        let pid = self
            .property(Unit::Subscription, Property::MainPid, c)?
            .parse::<u32>()
            .map_err(refused)?;
        if pid < 2
            || self.property(Unit::Subscription, Property::ControlGroup, c)?
                != Unit::Subscription.cgroup()
        {
            return Err(HostError::Foreign);
        }
        let procs = self
            .fs
            .cgroup_bytes(Unit::Subscription, false)?
            .ok_or(HostError::Foreign)?;
        if std::str::from_utf8(&procs).map_err(refused)?.trim() != pid.to_string() {
            return Err(HostError::Foreign);
        }
        let listeners = self.text(Observation::Listener8443, c)?;
        if listeners.lines().count() != 1
            || !super::observation::listener_pid(&listeners, 8443, Some(r.public_ipv4()), pid)
        {
            return Err(HostError::Foreign);
        }
        let process = self.io.process(pid)?;
        if process.uid != self.fs.uid
            || process.cgroup != Unit::Subscription.cgroup()
            || process.executable_sha256 != self.proof.record().executable_sha256()
            || sha256_hex(token.as_str().as_bytes()) != a.credential_sha256()
        {
            return Err(HostError::Foreign);
        }
        let (config, _) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if sha256_hex(&config) != r.configuration_sha256() {
            return Err(HostError::Foreign);
        }
        let expected = crate::server_configuration::ServerConfiguration::decode_supported(&config)
            .map_err(refused)?
            .connection_facts(r.public_ipv4())
            .map_err(refused)?
            .subscription_artifact()
            .map_err(refused)?;
        let address = self.probe.unwrap_or(std::net::SocketAddr::new(
            r.public_ipv4().parse().map_err(refused)?,
            8443,
        ));
        http_probe(address, token, expected.as_bytes(), c)?;
        if self.io.process(pid)? != process
            || self.property(Unit::Subscription, Property::MainPid, c)? != pid.to_string()
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
pub(super) fn http_probe(
    address: std::net::SocketAddr,
    token: &SubscriptionCredential,
    expected: &[u8],
    ctx: &StartContext,
) -> Result<(), HostError> {
    ctx.check().map_err(refused)?;
    let mut socket = std::net::TcpStream::connect_timeout(
        &address,
        ctx.deadline()
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(3)),
    )
    .map_err(refused)?;
    let timeout = Some(Duration::from_millis(100));
    socket.set_read_timeout(timeout).map_err(refused)?;
    socket.set_write_timeout(timeout).map_err(refused)?;
    let request = format!(
        "GET /s/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        token.as_str(),
        address
    );
    let mut sent = 0;
    while sent < request.len() {
        ctx.check().map_err(refused)?;
        match socket.write(&request.as_bytes()[sent..]) {
            Ok(0) => return Err(HostError::Io),
            Ok(n) => sent += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(HostError::Io),
        }
    }
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        ctx.check().map_err(refused)?;
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if response.len() + n > 12288 {
                    return Err(HostError::OutputLimit);
                }
                response.extend_from_slice(&buffer[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(HostError::Io),
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    let offset = match parsed.parse(&response).map_err(refused)? {
        httparse::Status::Complete(n) => n,
        _ => return Err(HostError::Foreign),
    };
    if offset > 8192
        || parsed.code != Some(200)
        || response[offset..] != *expected
        || expected.is_empty()
        || expected.len() > 4096
    {
        return Err(HostError::Foreign);
    }
    for (key, value) in [
        ("content-type", b"text/plain; charset=utf-8".as_slice()),
        ("cache-control", b"no-store".as_slice()),
        ("x-content-type-options", b"nosniff".as_slice()),
    ] {
        let values = parsed
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(key))
            .collect::<Vec<_>>();
        if values.len() != 1 || values[0].value != value {
            return Err(HostError::Foreign);
        }
    }
    if parsed
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(HostError::Foreign);
    }
    let lengths = parsed
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .collect::<Vec<_>>();
    if lengths.len() != 1 || lengths[0].value != expected.len().to_string().as_bytes() {
        return Err(HostError::Foreign);
    }
    ctx.check().map_err(refused)
}
