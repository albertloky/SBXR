use super::*;
use rustls::{ServerConfig, ServerConnection};
use std::thread;
fn server(alpn: &[u8], body: Option<Vec<u8>>) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let certs =
        rustls_pemfile::certs(&mut include_bytes!("testdata/admission/server.pem").as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("testdata/admission/server-key.pem").as_slice(),
    )
    .unwrap()
    .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    config.alpn_protocols = vec![alpn.into()];
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        if let Some(body) = body {
            let mut request = Vec::new();
            let mut b = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if tls.read_exact(&mut b).is_err() {
                    return;
                }
                request.push(b[0]);
                if request.len() > 8192 {
                    return;
                }
            }
            let _ = tls.write_all(&body);
            let _ = tls.flush();
        } else {
            while tls.conn.is_handshaking() {
                if tls.conn.complete_io(&mut tls.sock).is_err() {
                    return;
                }
            }
        }
        tls.conn.send_close_notify();
        let _ = tls.conn.complete_io(&mut tls.sock);
    });
    (address, worker)
}
fn roots() -> RootCertStore {
    roots_from_pem(include_bytes!("testdata/admission/ca.pem")).unwrap()
}
#[test]
fn tls13_certificate_name_and_h2_are_real_loopback_proofs() {
    let (address, worker) = server(b"h2", None);
    let (_, facts) = tls(
        &roots(),
        "localhost",
        &[address],
        b"h2",
        Instant::now() + Duration::from_secs(2),
        &Cancellation::new(),
    )
    .unwrap();
    assert!(facts.compatible());
    worker.join().unwrap();
}
#[test]
fn wrong_name_untrusted_ca_and_alpn_cannot_admit() {
    for wrong_name in [true, false] {
        let (address, worker) = server(b"h2", None);
        let root = if wrong_name {
            roots()
        } else {
            RootCertStore::empty()
        };
        assert!(
            tls(
                &root,
                if wrong_name {
                    "wrong.local"
                } else {
                    "localhost"
                },
                &[address],
                b"h2",
                Instant::now() + Duration::from_secs(2),
                &Cancellation::new()
            )
            .is_err()
        );
        worker.join().unwrap();
    }
    let (address, worker) = server(b"http/1.1", None);
    assert!(
        tls(
            &roots(),
            "localhost",
            &[address],
            b"h2",
            Instant::now() + Duration::from_secs(2),
            &Cancellation::new()
        )
        .is_err()
    );
    worker.join().unwrap();
}
#[test]
fn public_ipv4_http_framing_and_bounds_match_admission() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n8.8.8.8".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n8.8.8.8\r\n0\r\n\r\n".to_vec(),
    ] {
        let (address, worker) = server(b"http/1.1", Some(response));
        assert_eq!(
            fetch_ipv4(
                &roots(),
                "localhost",
                &[address],
                Instant::now() + Duration::from_secs(2),
                &Cancellation::new()
            )
            .unwrap(),
            Ipv4Addr::new(8, 8, 8, 8)
        );
        worker.join().unwrap();
    }
    for response in [
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n127.0.0.1".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 7\r\n\r\n8.8.8.8"
            .to_vec(),
    ] {
        let (address, worker) = server(b"http/1.1", Some(response));
        assert!(
            fetch_ipv4(
                &roots(),
                "localhost",
                &[address],
                Instant::now() + Duration::from_secs(2),
                &Cancellation::new()
            )
            .is_err()
        );
        worker.join().unwrap();
    }
}
#[test]
fn bind_busy_is_observed_on_unprivileged_loopback_only() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(bind(addr), Err(HostError::Busy));
    drop(listener);
    bind(addr).unwrap();
}
#[test]
fn stalled_handshake_deadline_and_cancellation_are_bounded() {
    for cancel in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Cancellation::new();
        let cloned = stop.clone();
        let worker = thread::spawn(move || {
            tls(
                &roots(),
                "localhost",
                &[addr],
                b"h2",
                Instant::now() + Duration::from_millis(250),
                &cloned,
            )
        });
        let (stream, _) = listener.accept().unwrap();
        if cancel {
            stop.cancel()
        }
        assert!(worker.join().unwrap().is_err());
        drop(stream);
    }
}
#[test]
fn native_admission_refuses_mac_before_network() {
    if !cfg!(target_os = "linux") {
        assert!(matches!(
            NetworkAdmission::native(&Cancellation::new(), true),
            Err(HostError::UnsupportedHost)
        ))
    }
}

#[test]
fn timing_brackets_real_loopback_tls_and_http_without_endpoint_or_payload() {
    let (address, worker) = server(
        b"http/1.1",
        Some(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n8.8.8.8".to_vec()),
    );
    let (result, bytes) = crate::host::timing::capture(|| {
        fetch_ipv4(
            &roots(),
            "localhost",
            &[address],
            Instant::now() + Duration::from_secs(2),
            &Cancellation::new(),
        )
    });
    assert_eq!(result.unwrap(), Ipv4Addr::new(8, 8, 8, 8));
    worker.join().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in [
        "localhost",
        "8.8.8.8",
        "HTTP",
        "GET",
        "server-key",
        "/private/",
    ] {
        assert!(!text.contains(forbidden));
    }
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line.strip_prefix("SBXR_NATIVE_PHASE ").unwrap()).unwrap())
        .collect();
    let phases: Vec<_> = rows
        .iter()
        .map(|r| (r["phase"].as_str().unwrap(), r["event"].as_str().unwrap()))
        .collect();
    assert_eq!(
        phases,
        vec![
            ("network-ip-http", "begin"),
            ("network-tls", "begin"),
            ("network-connect", "begin"),
            ("network-connect", "end"),
            ("network-handshake", "begin"),
            ("network-handshake", "end"),
            ("network-tls", "end"),
            ("network-ip-http", "end")
        ]
    );
    for pair in [(0, 7), (1, 6), (2, 3), (4, 5)] {
        assert_eq!(rows[pair.0]["id"], rows[pair.1]["id"]);
    }
}
