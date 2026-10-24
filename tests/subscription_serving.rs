#![forbid(unsafe_code)]

use sbxr::subscription_artifact::{ConnectionFacts, SubscriptionCredential};
use sbxr::subscription_serving::{Cancellation, Code, Generation, Module, Runtime, State};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const UUID: &str = "12345678-1234-4234-8234-123456789abc";
const PUBLIC_KEY: &str = "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q";

fn profile(hostname: Option<&str>) -> ConnectionFacts {
    ConnectionFacts::new(
        "127.0.0.1",
        UUID,
        "www.example.com",
        PUBLIC_KEY,
        "01020304",
        hostname,
    )
    .unwrap()
}

fn state(hostname: Option<&str>) -> Arc<State> {
    let credential = SubscriptionCredential::parse(TOKEN).unwrap();
    Arc::new(
        State::prepare_http(
            &profile(hostname),
            Generation::new(&"a".repeat(32), credential.sha256()).unwrap(),
        )
        .unwrap(),
    )
}

struct Server {
    module: Arc<Module>,
    state: Arc<State>,
    address: SocketAddr,
    cancellation: Cancellation,
    worker: Option<JoinHandle<Code>>,
}

impl Server {
    fn start(hostname: Option<&str>) -> Self {
        Self::with_module(hostname, Module::new())
    }

    fn with_module(hostname: Option<&str>, module: Module) -> Self {
        let module = Arc::new(module);
        let state = state(hostname);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = Cancellation::new();
        let worker = {
            let module = module.clone();
            let state = state.clone();
            let cancellation = cancellation.clone();
            thread::spawn(move || module.serve(state, listener, &cancellation))
        };
        let server = Self {
            module,
            state,
            address,
            cancellation,
            worker: Some(worker),
        };
        server.wait_serving();
        server
    }

    fn wait_serving(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.module.inspect(&self.state).runtime != Runtime::Serving {
            assert!(Instant::now() < deadline, "server did not become ready");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(1)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(7)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
    }

    fn request(&self, raw: &[u8]) -> Vec<u8> {
        let mut stream = self.connect();
        stream.write_all(raw).unwrap();
        let mut response = Vec::new();
        match stream.read_to_end(&mut response) {
            Ok(_) => {}
            // Closing without draining an explicitly refused body may reset TCP.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("loopback response read failed: {:?}", error.kind()),
        }
        response
    }

    fn stop(&mut self) {
        self.cancellation.cancel();
        if let Some(worker) = self.worker.take() {
            assert_eq!(worker.join().unwrap(), Code::Stopped);
            assert_eq!(self.module.inspect(&self.state).runtime, Runtime::Stopped);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn request(extra: &str) -> String {
    format!("GET /s/{TOKEN} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n")
}

fn split_response(response: &[u8]) -> (&str, &[u8]) {
    let end = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    (
        std::str::from_utf8(&response[..end]).unwrap(),
        &response[end..],
    )
}

#[test]
fn exact_authenticated_http_artifact_needs_no_certificate() {
    for hostname in [None, Some("tunnel.example.com")] {
        let server = Server::start(hostname);
        let response = server.request(request("").as_bytes());
        let (headers, body) = split_response(&response);
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains("Cache-Control: no-store\r\n"));
        assert!(headers.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(headers.contains("Connection: close\r\n"));
        assert_eq!(
            body,
            profile(hostname)
                .subscription_artifact()
                .unwrap()
                .as_bytes()
        );
    }
}

#[test]
fn prepared_state_is_not_a_running_service() {
    let module = Module::new();
    let state = state(None);
    let facts = module.inspect(&state);
    assert_eq!(facts.code, Code::Ready);
    assert_eq!(facts.runtime, Runtime::Unknown);
    assert_eq!(facts.link_id, "a".repeat(32));
    assert_eq!(Code::Refused.as_str(), "SUBSCRIPTION-SERVING-REFUSED");
}

#[test]
fn every_invalid_request_gets_the_same_concealed_response() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("testdata/subscription_serving/requests.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let server = Server::start(None);
        let raw = case["request"].as_str().unwrap().replace("@TOKEN@", TOKEN);
        let response = server.request(raw.as_bytes());
        let expected = case["status"].as_u64().unwrap();
        let (headers, body) = split_response(&response);
        assert!(
            headers.starts_with(&format!("HTTP/1.1 {expected} ")),
            "case: {}",
            case["name"]
        );
        assert!(headers.contains("Cache-Control: no-store\r\n"));
        assert!(headers.contains("Connection: close\r\n"));
        if expected == 404 {
            assert_eq!(
                response,
                include_bytes!("testdata/subscription_serving/404.txt"),
                "case: {}",
                case["name"]
            );
            for secret in [TOKEN, UUID, PUBLIC_KEY] {
                assert!(!String::from_utf8_lossy(body).contains(secret));
            }
        } else {
            assert_eq!(
                body,
                profile(None).subscription_artifact().unwrap().as_bytes()
            );
        }
    }
}

#[test]
fn header_limit_is_exactly_8192_bytes() {
    for (length, expected) in [(8192, 200), (8193, 404)] {
        let server = Server::start(None);
        let skeleton = request("X-Pad: \r\n");
        let raw = request(&format!(
            "X-Pad: {}\r\n",
            "x".repeat(length - skeleton.len())
        ));
        assert_eq!(raw.len(), length);
        let response = server.request(raw.as_bytes());
        assert!(
            split_response(&response)
                .0
                .starts_with(&format!("HTTP/1.1 {expected} "))
        );
    }
}

#[test]
fn a_connection_serves_one_request_and_closes_even_with_keepalive_and_pipeline() {
    let server = Server::start(None);
    let raw = request("Connection: keep-alive\r\n").repeat(3);
    let response = server.request(raw.as_bytes());
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(headers.contains("Connection: close\r\n"));
    assert_eq!(
        body,
        profile(None).subscription_artifact().unwrap().as_bytes()
    );
}

#[test]
fn actual_remote_source_limits_apply_before_parsing_and_ignore_forwarding() {
    let server = Server::start(None);
    for index in 0..7 {
        let raw = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nForwarded: for=192.0.2.{index}\r\nX-Forwarded-For: 198.51.100.{index}\r\n\r\n"
        );
        let response = server.request(raw.as_bytes());
        if index < 6 {
            assert_eq!(
                response,
                include_bytes!("testdata/subscription_serving/404.txt")
            );
        } else {
            assert_eq!(
                response,
                include_bytes!("testdata/subscription_serving/429.txt")
            );
        }
    }
}

#[test]
fn eight_workers_plus_synchronous_overload_and_complete_shutdown() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let base = Instant::now();
    let clock_calls = calls.clone();
    let module = Module::with_clock(move || {
        base + Duration::from_secs(10 * clock_calls.fetch_add(1, Ordering::SeqCst) as u64)
    });
    let mut server = Server::with_module(None, module);
    let mut stalled = Vec::new();
    for index in 0..8 {
        let mut stream = server.connect();
        stream.write_all(b"G").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let mut byte = [0];
        assert!(
            matches!(stream.read(&mut byte), Err(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock))
        );
        assert_eq!(calls.load(Ordering::SeqCst), index + 1);
        stalled.push(stream);
    }
    for _ in 0..2 {
        let response = server.request(request("").as_bytes());
        assert_eq!(
            response,
            include_bytes!("testdata/subscription_serving/503.txt")
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            8,
            "overload must not run normal workers"
        );
    }
    let started = Instant::now();
    server.stop();
    assert!(started.elapsed() < Duration::from_secs(2));
    for mut stream in stalled {
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        match stream.read(&mut [0]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            _ => panic!("accepted socket remained open after Serve returned"),
        }
    }
    assert!(TcpStream::connect_timeout(&server.address, Duration::from_millis(200)).is_err());
}

#[test]
fn partial_headers_do_not_extend_the_five_second_absolute_deadline() {
    let server = Server::start(None);
    let mut stream = server.connect();
    let started = Instant::now();
    stream.write_all(b"G").unwrap();
    thread::sleep(Duration::from_secs(3));
    stream.write_all(b"E").unwrap();
    let mut response = Vec::new();
    assert!(stream.read_to_end(&mut response).is_ok());
    assert!(started.elapsed() >= Duration::from_millis(4500));
    assert!(started.elapsed() < Duration::from_millis(6750));
    assert!(!String::from_utf8_lossy(&response).contains(UUID));
}

#[test]
fn listener_mismatch_and_concurrent_serve_refuse_without_disturbing_current_state() {
    let server = Server::start(None);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    assert_eq!(
        server
            .module
            .serve(server.state.clone(), listener, &Cancellation::new()),
        Code::Refused
    );
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
    assert_eq!(
        server.module.inspect(&server.state).runtime,
        Runtime::Serving
    );
    assert!(
        split_response(&server.request(request("").as_bytes()))
            .0
            .starts_with("HTTP/1.1 200 ")
    );

    let facts = ConnectionFacts::new(
        "198.51.100.42",
        UUID,
        "www.example.com",
        PUBLIC_KEY,
        "01020304",
        None,
    )
    .unwrap();
    let generation = Generation::new(
        &"a".repeat(32),
        SubscriptionCredential::parse(TOKEN).unwrap().sha256(),
    )
    .unwrap();
    let state = Arc::new(State::prepare_http(&facts, generation).unwrap());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let module = Module::new();
    assert_eq!(
        module.serve(state.clone(), listener, &Cancellation::new()),
        Code::Refused
    );
    assert_eq!(module.inspect(&state).runtime, Runtime::Unknown);
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
}

#[test]
fn precancelled_serve_closes_listener_and_reports_stopped() {
    let module = Module::new();
    let state = state(None);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Cancellation::new();
    stop.cancel();
    assert_eq!(module.serve(state.clone(), listener, &stop), Code::Stopped);
    assert_eq!(module.inspect(&state).runtime, Runtime::Stopped);
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
}

#[test]
fn many_small_headers_remain_valid_within_the_byte_bound() {
    let server = Server::start(None);
    let raw = format!(
        "GET /s/{TOKEN} HTTP/1.1\nHost: localhost\n{}\n",
        "a:\n".repeat(2600)
    );
    assert!(raw.len() <= 8192);
    assert!(
        split_response(&server.request(raw.as_bytes()))
            .0
            .starts_with("HTTP/1.1 200 ")
    );
}

#[test]
fn declared_body_is_refused_without_reading_it_or_sending_continue() {
    let server = Server::start(None);
    let raw = request("Content-Length: 999999999\r\nExpect: 100-continue\r\n");
    let started = Instant::now();
    let response = server.request(raw.as_bytes());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        response,
        include_bytes!("testdata/subscription_serving/404.txt")
    );
}

#[test]
fn preparation_and_diagnostics_never_echo_secrets() {
    let digest = SubscriptionCredential::parse(TOKEN).unwrap().sha256();
    for link in ["", &"a".repeat(31), &"A".repeat(32), &"x".repeat(32)] {
        assert_eq!(Generation::new(link, digest).unwrap_err(), Code::Refused);
    }
    assert_eq!(
        Generation::new(&"a".repeat(32), [0; 32]).unwrap_err(),
        Code::Refused
    );
    let oversized_key = format!("{PUBLIC_KEY}{}", "\n".repeat(2000));
    let facts = ConnectionFacts::new(
        "127.0.0.1",
        UUID,
        "www.example.com",
        &oversized_key,
        "01020304",
        None,
    )
    .unwrap();
    let generation = Generation::new(&"a".repeat(32), digest).unwrap();
    assert_eq!(
        State::prepare_http(&facts, generation).unwrap_err(),
        Code::Refused
    );
    let generation = Generation::new(&"a".repeat(32), digest).unwrap();
    let state = state(None);
    let module = Module::new();
    let diagnostic = format!(
        "{generation} {generation:?} {state} {state:?} {module} {module:?} {} {:?} {}",
        Cancellation::new(),
        module.inspect(&state),
        Code::Refused
    );
    for secret in [TOKEN, UUID, PUBLIC_KEY, &format!("{digest:?}")] {
        assert!(!diagnostic.contains(secret));
    }
}

#[test]
fn serving_diagnostics_child() {
    if std::env::var_os("SBXR_SERVING_TEST_CHILD").is_none() {
        return;
    }
    let server = Server::start(None);
    let _ = server.request(request("").as_bytes());
    let raw = request("").replace("GET", "POST");
    let _ = server.request(raw.as_bytes());
}

#[test]
fn ordinary_serving_process_prints_no_credentials_or_raw_errors() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "serving_diagnostics_child", "--nocapture"])
        .env("SBXR_SERVING_TEST_CHILD", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let diagnostic = [output.stdout, output.stderr].concat();
    let diagnostic = String::from_utf8_lossy(&diagnostic);
    for secret in [
        TOKEN,
        UUID,
        PUBLIC_KEY,
        "/s/",
        "127.0.0.1",
        "Connection reset",
        "os error",
    ] {
        assert!(!diagnostic.contains(secret));
    }
}
