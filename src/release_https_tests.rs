use super::*;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    thread,
};
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &include_bytes!("release_https/testdata/ca.pem")[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    roots
}
pub(super) fn server(response: Vec<u8>, stall: bool) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let join = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let certs =
            rustls_pemfile::certs(&mut &include_bytes!("release_https/testdata/server.pem")[..])
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
        let key = rustls_pemfile::private_key(
            &mut &include_bytes!("release_https/testdata/server-key.pem")[..],
        )
        .unwrap()
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        );
        let mut request = vec![];
        while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if !matches!(stream.read(&mut byte), Ok(1)) {
                return request;
            }
            request.push(byte[0]);
        }
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        if stall {
            thread::sleep(Duration::from_millis(250));
        }
        request
    });
    (addr, join)
}
fn transport(v: Vec<(&str, SocketAddr)>) -> HttpsTransport {
    HttpsTransport::configured(roots(), Some(v)).unwrap()
}
fn request() -> AcquisitionRequest {
    AcquisitionRequest::release_metadata("v3.1.118").unwrap()
}
#[test]
fn tls_headers_and_raw_body_are_real_and_credential_free() {
    let (a, s) = server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata".to_vec(),
        false,
    );
    let mut t = transport(vec![("api.github.com", a)]);
    let r = t.get(&request(), &SelectionBudget::new()).unwrap();
    assert_eq!(
        crate::artifact_trust::read_response(r, 4, &SelectionBudget::new()).unwrap(),
        b"data"
    );
    let raw = String::from_utf8(s.join().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(raw.contains("x-github-api-version: 2026-03-10\r\n"));
    assert!(
        raw.contains("accept: application/vnd.github+json\r\n")
            && raw.contains("accept-encoding: identity\r\n")
    );
    assert!(
        !raw.contains("authorization:") && !raw.contains("cookie:") && !raw.contains("referer:")
    );
}
#[test]
fn redirect_policy_and_body_limits_are_enforced() {
    let (last, end) = server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        false,
    );
    let(first,start)=server(b"HTTP/1.1 302 Found\r\nLocation: https://release-assets.githubusercontent.com/x?public=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),false);
    let mut t = transport(vec![
        ("api.github.com", first),
        ("release-assets.githubusercontent.com", last),
    ]);
    assert!(t.get(&request(), &SelectionBudget::new()).is_ok());
    start.join().unwrap();
    assert!(
        !String::from_utf8(end.join().unwrap())
            .unwrap()
            .to_ascii_lowercase()
            .contains("x-github-api-version:")
    );
    for response in [b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n".to_vec(),b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()]{let(a,s)=server(response,false);let mut t=transport(vec![("api.github.com",a)]);assert!(matches!(t.get(&request(),&SelectionBudget::new()),Err(TrustError::Refused)));s.join().unwrap();}
}
#[test]
fn stalled_reads_cancel_and_time_out_without_late_acceptance() {
    for cancel in [false, true] {
        let (a, s) = server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n".to_vec(),
            true,
        );
        let mut t = transport(vec![("api.github.com", a)]);
        let b = if cancel {
            SelectionBudget::new()
        } else {
            SelectionBudget::until(std::time::Instant::now() + Duration::from_millis(65))
        };
        let start = std::time::Instant::now();
        thread::scope(|scope| {
            if cancel {
                scope.spawn(|| {
                    thread::sleep(Duration::from_millis(45));
                    b.cancel();
                });
            }
            assert!(matches!(
                t.get(&request(), &b),
                Err(TrustError::Interrupted)
            ));
        });
        assert!(start.elapsed() < Duration::from_millis(200));
        s.join().unwrap();
    }
}
#[test]
fn url_certificate_and_nested_runtime_refusals_are_closed() {
    for u in [
        "http://api.github.com/",
        "https://user@api.github.com/",
        "https://api.github.com:444/",
        "https://%61pi.github.com/",
        "https://api.github.com/x#y",
        "https://example.invalid/",
    ] {
        assert!(initial(u).is_err());
    }
    let (a, s) = server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        false,
    );
    let mut t = HttpsTransport::configured(
        rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
        Some(vec![("api.github.com", a)]),
    )
    .unwrap();
    assert!(t.get(&request(), &SelectionBudget::new()).is_err());
    s.join().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(HttpsTransport::new().is_err());
    });
}

#[test]
fn incomplete_pages_and_chunked_oversize_are_refused() {
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100001\r\n"
            .to_vec();
    chunked.extend(vec![b'x'; request().max_bytes() + 1]);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let (a, s) = server(chunked, false);
    let mut t = transport(vec![("api.github.com", a)]);
    assert!(matches!(
        t.get(&request(), &SelectionBudget::new()),
        Err(TrustError::Refused)
    ));
    s.join().unwrap();
    let (a, s) = server(b"HTTP/1.1 200 OK\r\nLink: <https://api.github.com/next>; rel=next\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(), false);
    let mut t = transport(vec![("api.github.com", a)]);
    let b = SelectionBudget::new();
    let response = t.get(&request(), &b).unwrap();
    assert!(matches!(
        crate::artifact_trust::read_complete_json_response(response, request().max_bytes(), &b),
        Err(TrustError::Refused)
    ));
    s.join().unwrap();
}

#[test]
fn unresolved_dns_is_cancelled_before_any_socket_or_late_success() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Pending(Arc<AtomicBool>);
    impl reqwest::dns::Resolve for Pending {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            struct Dropped(Arc<AtomicBool>);
            impl Drop for Dropped {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let guard = Dropped(self.0.clone());
            Box::pin(async move {
                let _guard = guard;
                std::future::pending().await
            })
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots())
    .with_no_client_auth();
    let mut t = HttpsTransport {
        scope: Scope::Public,
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        client: Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .dns_resolver(Arc::new(Pending(dropped.clone())))
            .build()
            .unwrap(),
    };
    let budget = SelectionBudget::until(std::time::Instant::now() + Duration::from_millis(65));
    let started = std::time::Instant::now();
    assert!(matches!(
        t.get(&request(), &budget),
        Err(TrustError::Interrupted)
    ));
    assert!(started.elapsed() < Duration::from_millis(200));
    drop(t);
    assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn serving_ipv4_probe_uses_real_tls_bounded_canonical_body_and_no_redirect() {
    for (response, accepted) in [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n8.8.8.8\n".to_vec(),true),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n127.0.0.1".to_vec(),false),
        (b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),false),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\nConnection: close\r\n\r\n".to_vec(),false),
        (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),false),
    ] {
        let (address,server)=server(response,false);
        let transport=transport(vec![("api.github.com",address)]);
        let result=transport.ipv4_at("https://api.github.com/",&SelectionBudget::new());
        assert_eq!(result.is_ok(),accepted);
        if accepted {assert_eq!(result.unwrap(),std::net::Ipv4Addr::new(8,8,8,8));}
        let request=String::from_utf8(server.join().unwrap()).unwrap().to_ascii_lowercase();
        assert!(!request.contains("authorization:") && !request.contains("cookie:"));
    }
}
#[test]
fn serving_public_ip_cancellation_interrupts_actual_stalled_tls_body() {
    let (address, server) = server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n".to_vec(),
        true,
    );
    let transport = transport(vec![("api.github.com", address)]);
    let budget = SelectionBudget::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(65));
            budget.cancel();
        });
        assert!(matches!(
            transport.ipv4_at("https://api.github.com/", &budget),
            Err(TrustError::Interrupted)
        ));
    });
    server.join().unwrap();
}
