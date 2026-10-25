//! Private, bounded HTTP Subscription Serving. No durable or host authority.
//!
//! This module does not implement the retained legacy TLS preparation/expiry
//! contract. HTTP exposes bearer and client credentials to network observers.
use crate::subscription_artifact::{ConnectionFacts, SubscriptionCredential};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const MAX_WORKERS: usize = 8;
const MAX_HEADER_BYTES: usize = 8192;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const OVERLOAD_TIMEOUT: Duration = Duration::from_secs(1);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const MAX_SOURCES: usize = 1024;
const SOURCE_IDLE: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Ready,
    Refused,
    Stopped,
    Failed,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "SUBSCRIPTION-SERVING-READY",
            Self::Refused => "SUBSCRIPTION-SERVING-REFUSED",
            Self::Stopped => "SUBSCRIPTION-SERVING-STOPPED",
            Self::Failed => "SUBSCRIPTION-SERVING-FAILED",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for Code {}

/// Supplied authority only; generates no credential and publishes no record.
pub struct Generation {
    link_id: String,
    credential_sha256: [u8; 32],
}

impl Generation {
    pub fn new(link_id: &str, credential_sha256: [u8; 32]) -> Result<Self, Code> {
        if link_id.len() != 32
            || !link_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || credential_sha256 == [0; 32]
        {
            return Err(Code::Refused);
        }
        Ok(Self {
            link_id: link_id.into(),
            credential_sha256,
        })
    }
}

/// Immutable prepared HTTP bytes. Preparation does not prove serving readiness.
pub struct State {
    ipv4: Ipv4Addr,
    artifact: Vec<u8>,
    generation: Generation,
}

impl State {
    #[cfg(test)]
    pub(crate) fn prepare_http_loopback_fixture(
        root: &std::path::Path,
        facts: &ConnectionFacts,
        generation: Generation,
    ) -> Result<Self, Code> {
        if !root.is_absolute() || root == std::path::Path::new("/") {
            return Err(Code::Refused);
        }
        let mut state = Self::prepare_http(facts, generation)?;
        state.ipv4 = Ipv4Addr::LOCALHOST;
        Ok(state)
    }
    pub fn prepare_http(facts: &ConnectionFacts, generation: Generation) -> Result<Self, Code> {
        let artifact = facts.subscription_artifact().map_err(|_| Code::Refused)?;
        Ok(Self {
            ipv4: facts.public_ipv4(),
            artifact: artifact.as_bytes().to_vec(),
            generation,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    Unknown,
    Serving,
    Stopped,
}

impl Runtime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "cannot be verified",
            Self::Serving => "serving",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Facts {
    pub code: Code,
    pub link_id: String,
    pub runtime: Runtime,
}

#[derive(Default)]
struct RuntimeState {
    loaded: Option<Arc<State>>,
    running: bool,
}

pub struct Module {
    runtime: Mutex<RuntimeState>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for Module {
    fn default() -> Self {
        Self::new()
    }
}

impl Module {
    pub fn new() -> Self {
        Self::with_clock(Instant::now)
    }

    /// The clock controls rate accounting only. I/O deadlines use real time.
    pub fn with_clock(clock: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self {
            runtime: Mutex::new(RuntimeState::default()),
            clock: Arc::new(clock),
        }
    }

    pub fn inspect(&self, state: &Arc<State>) -> Facts {
        let loaded = lock(&self.runtime);
        let runtime = if loaded
            .loaded
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, state))
        {
            if loaded.running {
                Runtime::Serving
            } else {
                Runtime::Stopped
            }
        } else {
            Runtime::Unknown
        };
        Facts {
            code: Code::Ready,
            link_id: state.generation.link_id.clone(),
            runtime,
        }
    }

    /// Consumes and closes the listener on every path. The caller must prove
    /// recorded-address, port, host, profile and process authority before calling.
    /// Port zero is allowed for isolated tests; production must select TCP 8443.
    /// A Cancellation belongs to one serving session (and its cloned stop handles).
    pub fn serve(&self, state: Arc<State>, listener: TcpListener, stop: &Cancellation) -> Code {
        if listener.local_addr().ok().map(|address| address.ip()) != Some(IpAddr::V4(state.ipv4)) {
            return Code::Refused;
        }
        if listener.set_nonblocking(true).is_err() {
            return Code::Failed;
        }
        {
            let mut loaded = lock(&self.runtime);
            if loaded.running {
                return Code::Refused;
            }
            loaded.loaded = Some(state.clone());
            loaded.running = true;
        }
        let mut workers = Vec::with_capacity(MAX_WORKERS);
        let result = self.accept(&state, &listener, stop, &mut workers);
        drop(listener);
        stop.cancel();
        let mut joined = true;
        for worker in workers {
            joined &= worker.join().is_ok();
        }
        lock(&self.runtime).running = false;
        if joined { result } else { Code::Failed }
    }

    fn accept(
        &self,
        state: &Arc<State>,
        listener: &TcpListener,
        stop: &Cancellation,
        workers: &mut Vec<JoinHandle<()>>,
    ) -> Code {
        let limiter = Arc::new(Mutex::new(SourceLimiter::default()));
        loop {
            if stop.is_cancelled() {
                return Code::Stopped;
            }
            if !join_finished(workers) {
                return Code::Failed;
            }
            let (stream, remote) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    stop.wait(ACCEPT_POLL);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Code::Failed,
            };
            if !join_finished(workers) {
                return Code::Failed;
            }
            let overloaded = workers.len() >= MAX_WORKERS;
            let deadline = Instant::now()
                + if overloaded {
                    OVERLOAD_TIMEOUT
                } else {
                    CONNECTION_TIMEOUT
                };
            let connection = match stop.register(stream) {
                Ok(Some(connection)) => connection,
                Ok(None) => return Code::Stopped,
                Err(()) => return Code::Failed,
            };
            if overloaded {
                // No thread, request parse or credential access on the ninth socket.
                let mut connection = connection;
                write_response(&mut connection.stream, 503, &[], deadline, stop);
                continue;
            }
            let state = state.clone();
            let limiter = limiter.clone();
            let clock = self.clock.clone();
            let worker = thread::Builder::new()
                .name("sbxr-subscription".into())
                .spawn(move || {
                    respond(connection, &state, remote.ip(), &limiter, clock(), deadline);
                });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(_) => return Code::Failed,
            }
        }
    }
}

fn join_finished(workers: &mut Vec<JoinHandle<()>>) -> bool {
    let mut success = true;
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            success &= workers.swap_remove(index).join().is_ok();
        } else {
            index += 1;
        }
    }
    success
}

#[derive(Default)]
struct StopState {
    cancelled: bool,
    next_id: u64,
    sockets: BTreeMap<u64, TcpStream>,
}

#[derive(Clone, Default)]
pub struct Cancellation {
    shared: Arc<(Mutex<StopState>, Condvar)>,
}

impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shuts down all registered sockets and wakes the accept loop. Serve joins
    /// workers before reporting Stopped; sent bytes/client caches are irrevocable.
    pub fn cancel(&self) {
        let mut state = lock(&self.shared.0);
        state.cancelled = true;
        for stream in state.sockets.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.shared.1.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        lock(&self.shared.0).cancelled
    }

    fn register(&self, stream: TcpStream) -> Result<Option<Connection>, ()> {
        let mut state = lock(&self.shared.0);
        if state.cancelled {
            return Ok(None);
        }
        stream.set_nonblocking(false).map_err(|_| ())?;
        let cloned = stream.try_clone().map_err(|_| ())?;
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(())?;
        state.sockets.insert(id, cloned);
        Ok(Some(Connection {
            stream,
            stop: self.clone(),
            id,
        }))
    }

    fn wait(&self, timeout: Duration) {
        let state = lock(&self.shared.0);
        if !state.cancelled {
            let _ = self
                .shared
                .1
                .wait_timeout(state, timeout)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

struct Connection {
    stream: TcpStream,
    stop: Cancellation,
    id: u64,
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        lock(&self.stop.shared.0).sockets.remove(&self.id);
    }
}

fn respond(
    mut connection: Connection,
    state: &State,
    remote: IpAddr,
    limiter: &Mutex<SourceLimiter>,
    now: Instant,
    deadline: Instant,
) {
    let Connection { stream, stop, .. } = &mut connection;
    if !lock(limiter).allow(remote.to_canonical(), now) {
        write_response(stream, 429, &[], deadline, stop);
        return;
    }
    let mut bytes = [0; MAX_HEADER_BYTES];
    let mut length = 0;
    let authenticated = loop {
        if stop.is_cancelled() || set_read_deadline(stream, deadline).is_err() {
            break false;
        }
        match stream.read(&mut bytes[length..]) {
            Ok(0) => break false,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break false,
        }
        if header_complete(&bytes[..length]) {
            break authorized(&bytes[..length], state);
        }
        if length == bytes.len() {
            break false;
        }
    };
    if authenticated && !stop.is_cancelled() {
        write_response(stream, 200, &state.artifact, deadline, stop);
    } else {
        write_response(stream, 404, &[], deadline, stop);
    }
}

fn header_complete(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|part| part == b"\n\n") || bytes.windows(3).any(|part| part == b"\n\r\n")
}

fn authorized(bytes: &[u8], state: &State) -> bool {
    // Even a minimal LF-delimited header needs three bytes ("a:\n").
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_HEADER_BYTES / 3];
    let mut request = httparse::Request::new(&mut headers);
    if !matches!(request.parse(bytes), Ok(httparse::Status::Complete(end)) if end <= MAX_HEADER_BYTES)
        || request.method != Some("GET")
        || request.version != Some(1)
    {
        return false;
    }
    let mut host = None;
    let mut content_length = None;
    for header in request.headers.iter() {
        let value = header.value.trim_ascii();
        if header.name.eq_ignore_ascii_case("Host") {
            // The Go boundary requires only one nonempty Host; it is never used.
            if host.replace(value).is_some() || value.is_empty() {
                return false;
            }
        } else if header.name.eq_ignore_ascii_case("Content-Length") {
            if value.is_empty()
                || value.iter().any(|byte| *byte != b'0')
                || content_length.is_some_and(|old| old != value)
            {
                return false;
            }
            content_length = Some(value);
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            return false;
        }
    }
    if host.is_none() {
        return false;
    }
    let Some(token) = request.path.and_then(|path| path.strip_prefix("/s/")) else {
        return false;
    };
    if SubscriptionCredential::parse(token).is_err() {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    bool::from(digest.ct_eq(&state.generation.credential_sha256))
}

fn set_read_deadline(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(io::ErrorKind::TimedOut)?;
    stream.set_read_timeout(Some(remaining))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    artifact: &[u8],
    deadline: Instant,
    stop: &Cancellation,
) {
    let text = match status {
        200 => "OK",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Not Found",
    };
    let refusal = format!("{text}\n");
    let body = if status == 200 {
        artifact
    } else {
        refusal.as_bytes()
    };
    let retry = if status == 429 || status == 503 {
        "Retry-After: 10\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 {status} {text}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{retry}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    for mut bytes in [header.as_bytes(), body] {
        while !bytes.is_empty() {
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
            else {
                return;
            };
            if stop.is_cancelled() || stream.set_write_timeout(Some(remaining)).is_err() {
                return;
            }
            match stream.write(bytes) {
                Ok(0) => return,
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

struct Source {
    tokens: f64,
    refill: Instant,
    last: Instant,
}

#[derive(Default)]
struct SourceLimiter {
    entries: HashMap<IpAddr, Source>,
}

impl SourceLimiter {
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.entries
            .retain(|_, source| now.saturating_duration_since(source.last) < SOURCE_IDLE);
        if !self.entries.contains_key(&ip) && self.entries.len() >= MAX_SOURCES {
            return false;
        }
        let source = self.entries.entry(ip).or_insert(Source {
            tokens: 6.0,
            refill: now,
            last: now,
        });
        source.tokens = (source.tokens
            + now.saturating_duration_since(source.refill).as_secs_f64() / 10.0)
            .min(6.0);
        source.refill = now.max(source.refill);
        source.last = now.max(source.last);
        let allowed = source.tokens >= 1.0;
        if allowed {
            source.tokens -= 1.0;
        }
        allowed
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

macro_rules! redacted {
    ($type:ty, $text:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
    };
}
redacted!(Generation, "Subscription generation (redacted)");
redacted!(State, "Subscription state (redacted)");
redacted!(Module, "Subscription serving module (redacted)");
redacted!(Cancellation, "Subscription cancellation (redacted)");

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn prepared(digest: [u8; 32]) -> State {
        let facts = ConnectionFacts::new(
            "127.0.0.1",
            "12345678-1234-4234-8234-123456789abc",
            "www.example.com",
            "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q",
            "01020304",
            None,
        )
        .unwrap();
        State::prepare_http(&facts, Generation::new(&"a".repeat(32), digest).unwrap()).unwrap()
    }

    #[test]
    fn parser_matches_synthetic_request_contract() {
        let state = prepared(SubscriptionCredential::parse(TOKEN).unwrap().sha256());
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/testdata/subscription_serving/requests.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let request = case["request"].as_str().unwrap().replace("@TOKEN@", TOKEN);
            assert_eq!(
                authorized(request.as_bytes(), &state),
                case["status"] == 200,
                "case: {}",
                case["name"]
            );
        }
    }

    #[test]
    fn credentials_hash_encoded_text_and_reject_every_changed_position() {
        let state = prepared(SubscriptionCredential::parse(TOKEN).unwrap().sha256());
        let request = |token| format!("GET /s/{token} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        for index in 0..43 {
            let mut token = TOKEN.as_bytes().to_vec();
            token[index] = b'E';
            assert!(!authorized(
                request(String::from_utf8(token).unwrap()).as_bytes(),
                &state
            ));
        }
        let decoded_digest: [u8; 32] = Sha256::digest([0; 32]).into();
        assert!(!authorized(
            request(TOKEN.to_owned()).as_bytes(),
            &prepared(decoded_digest)
        ));
    }

    #[test]
    fn rate_burst_fractional_refill_capacity_and_idle_expiry_are_bounded() {
        let mut limiter = SourceLimiter::default();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let now = Instant::now();
        for _ in 0..6 {
            assert!(limiter.allow(ip, now));
        }
        assert!(!limiter.allow(ip, now));
        assert!(!limiter.allow(ip, now + Duration::from_secs(9)));
        assert!(limiter.allow(ip, now + Duration::from_secs(10)));
        assert!(!limiter.allow(ip, now + Duration::from_secs(10)));
        // An accounting-clock reversal cannot mint an extra token on recovery.
        assert!(!limiter.allow(ip, now));
        assert!(!limiter.allow(ip, now + Duration::from_secs(10)));
        for index in 1..1024 {
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(index as u32)), now));
        }
        let unknown = IpAddr::V4(Ipv4Addr::from(1024));
        assert!(!limiter.allow(unknown, now));
        assert_eq!(limiter.entries.len(), MAX_SOURCES);
        assert!(limiter.allow(ip, now + Duration::from_secs(20)));
        assert!(limiter.allow(unknown, now + SOURCE_IDLE));
        assert_eq!(limiter.entries.len(), 2);
        assert_eq!(limiter.entries[&unknown].tokens, 5.0);
    }

    #[test]
    fn incomplete_header_markers_do_not_end_headers() {
        for bytes in [b"GET / HTTP/1.1\r\n".as_slice(), b"\r", b"\n\r"] {
            assert!(!header_complete(bytes));
        }
        for bytes in [b"\r\n\r\n".as_slice(), b"\n\n", b"\r\n\n"] {
            assert!(header_complete(bytes));
        }
    }
}
