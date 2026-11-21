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
const CANDIDATE_PREFLIGHT_TOKEN: &str = "synthetic-preflight-token";

fn candidate_preflight_transport(endpoints: Vec<(&str, SocketAddr)>) -> PublicProbeTransport {
    PublicProbeTransport::with_candidate_preflight_token(
        transport(endpoints),
        CANDIDATE_PREFLIGHT_TOKEN,
    )
    .unwrap()
}

fn assert_candidate_preflight_header(request: Vec<u8>, expected: bool) {
    let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
    if expected {
        assert!(request.contains("authorization: bearer synthetic-preflight-token\r\n"));
    } else {
        assert!(!request.contains("authorization:"));
        assert!(!request.contains(CANDIDATE_PREFLIGHT_TOKEN));
    }
}

#[test]
fn candidate_preflight_latest_refusal_is_redacted_and_stays_refused() {
    let (endpoint, request) = server(
        b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        false,
    );
    let mut transport = candidate_preflight_transport(vec![("api.github.com", endpoint)]);
    let result = crate::release_acquisition::AuthenticatedArchive::acquire_latest(
        &mut transport,
        crate::release_identity::Architecture::Amd64,
        &SelectionBudget::new(),
    );
    assert!(matches!(result, Err(TrustError::Refused)));
    assert_candidate_preflight_header(request.join().unwrap(), true);
    let diagnostic = serde_json::to_value(transport.diagnostic()).unwrap();
    assert_eq!(diagnostic["http_status"], 403);
    assert_eq!(diagnostic["rate_limit_exhausted"], true);
    assert!(!diagnostic.to_string().contains(CANDIDATE_PREFLIGHT_TOKEN));
    assert!(!diagnostic.to_string().contains("authorization"));
}

#[test]
fn candidate_preflight_keeps_bundle_gets_credential_free_and_refuses_pagination() {
    use crate::artifact_trust::acquire_native_attestations;

    let body = br#"{"attestations":[{"initiator":"github","bundle_url":"https://tmaproduction.blob.core.windows.net/fixture"}]}"#;
    let response = |link: &str| {
        [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{link}\r\n",
                body.len(),
            )
            .as_bytes(),
            body,
        ]
        .concat()
    };
    let (api, api_request) = server(response(""), false);
    let (storage, storage_request) = server(
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        false,
    );
    let mut transport = candidate_preflight_transport(vec![
        ("api.github.com", api),
        ("tmaproduction.blob.core.windows.net", storage),
    ]);
    let budget = SelectionBudget::new();
    let attestations =
        acquire_native_attestations(&mut transport, &"a".repeat(40), &budget).unwrap();
    assert_eq!(
        attestations
            .acquire_bundle(0, &mut transport, &budget)
            .err(),
        Some(TrustError::Refused)
    );
    assert_candidate_preflight_header(api_request.join().unwrap(), true);
    assert_candidate_preflight_header(storage_request.join().unwrap(), false);

    let (api, api_request) = server(
        response("Link: <https://api.github.com/fixture?page=2>; rel=\"next\"\r\n"),
        false,
    );
    let mut transport = candidate_preflight_transport(vec![("api.github.com", api)]);
    assert_eq!(
        acquire_native_attestations(&mut transport, &"a".repeat(40), &budget).err(),
        Some(TrustError::Refused)
    );
    assert_candidate_preflight_header(api_request.join().unwrap(), true);
}

#[test]
fn candidate_preflight_keeps_asset_redirects_credential_free_and_checks_digest() {
    use crate::artifact_trust::acquire_digest_checked_asset;
    use crate::release_identity::AssetProof;

    for (name, body, accepted) in [
        ("release-index.json", b"data", true),
        ("sbxr-linux-amd64.tar.gz", b"DATA", false),
    ] {
        let (api, api_request) = server(
            b"HTTP/1.1 302 Found\r\nLocation: https://release-assets.githubusercontent.com/fixture?query=synthetic-redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            false,
        );
        let (cdn, cdn_request) = server(
            [
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n".as_slice(),
                body,
            ]
            .concat(),
            false,
        );
        let mut transport = candidate_preflight_transport(vec![
            ("api.github.com", api),
            ("release-assets.githubusercontent.com", cdn),
        ]);
        let proof = AssetProof::new(name, 4, &crate::records::sha256_hex(b"data")).unwrap();
        let result =
            acquire_digest_checked_asset(&mut transport, 1, &proof, &SelectionBudget::new());
        if accepted {
            assert_eq!(result.unwrap(), b"data");
        } else {
            assert_eq!(result.err(), Some(TrustError::Refused));
        }
        assert_candidate_preflight_header(api_request.join().unwrap(), true);
        assert_candidate_preflight_header(cdn_request.join().unwrap(), false);
        let receipt = serde_json::to_string(&transport.diagnostic()).unwrap();
        assert!(!receipt.contains(CANDIDATE_PREFLIGHT_TOKEN));
        assert!(!receipt.contains("synthetic-redirect"));
    }
}

#[test]
fn candidate_preflight_refuses_unexpected_auth_destinations_and_invalid_tokens() {
    let latest = AcquisitionRequest::latest_metadata();
    for (url, expected) in [
        (
            "https://api.github.com:443/repos/albertloky/SBXR/releases/latest",
            true,
        ),
        (
            "http://api.github.com/repos/albertloky/SBXR/releases/latest",
            false,
        ),
        (
            "https://api.github.com:444/repos/albertloky/SBXR/releases/latest",
            false,
        ),
        (
            "https://api.github.com.invalid/repos/albertloky/SBXR/releases/latest",
            false,
        ),
        (
            "https://api.github.com/repos/albertloky/other/releases/latest",
            false,
        ),
        (
            "https://api.github.com/repos/albertloky/SBXR/releases/latest?other=1",
            false,
        ),
        (
            "https://api.github.com/repos/albertloky/SBXR/releases/assets/1",
            false,
        ),
        (
            "https://someone@api.github.com/repos/albertloky/SBXR/releases/latest",
            false,
        ),
    ] {
        assert_eq!(
            candidate_preflight_api_request(&latest, &Url::parse(url).unwrap()),
            expected,
        );
    }
    assert!(!candidate_preflight_api_request(
        &request(),
        &Url::parse(request().url()).unwrap(),
    ));
    for token in ["", " ", "==", "invalid token", "synthetic\r\nInjected"] {
        assert!(matches!(
            PublicProbeTransport::with_candidate_preflight_token(transport(vec![]), token),
            Err(TrustError::Refused)
        ));
    }
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
fn native_attestations_accept_only_the_single_github_deprecation_advisory() {
    const DEPRECATION: &str = "Link: <https://docs.github.com/en/rest/about-the-rest-api/api-versions>; rel=\"deprecation\"; type=\"text/html\"\r\n";
    const NEXT: &str = "Link: <https://api.github.com/next>; rel=next\r\n";
    let commit = "abb3975c4f1c3fb376ed4a61020d935f8669863b";
    let proofs = include_str!("../tests/testdata/public_release/attestations.json");
    for (description, headers, body, accept) in [
        ("no Link", String::new(), proofs, true),
        ("GitHub deprecation", DEPRECATION.into(), proofs, true),
        ("pagination", NEXT.into(), proofs, false),
        (
            "mixed fields",
            format!("{DEPRECATION}{NEXT}"),
            proofs,
            false,
        ),
        ("repeated advisory", DEPRECATION.repeat(2), proofs, false),
        (
            "mixed links in one field",
            format!(
                "{}, <https://api.github.com/next>; rel=next\r\n",
                DEPRECATION.trim_end()
            ),
            proofs,
            false,
        ),
        (
            "malformed relation",
            DEPRECATION.replace("rel=\"deprecation\"", "rel=\"deprecation"),
            proofs,
            false,
        ),
        (
            "unknown relation",
            DEPRECATION.replace("\"deprecation\"", "\"help\""),
            proofs,
            false,
        ),
        (
            "ambiguous relation",
            DEPRECATION.replace("\"deprecation\"", "\"deprecation next\""),
            proofs,
            false,
        ),
        (
            "advisory with missing proof",
            DEPRECATION.into(),
            r#"{"attestations":[]}"#,
            false,
        ),
    ] {
        let response = format!(
            "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (address, handle) = server(response.into_bytes(), false);
        let mut transport = transport(vec![("api.github.com", address)]);
        let result = crate::artifact_trust::acquire_native_attestations(
            &mut transport,
            commit,
            &SelectionBudget::new(),
        );
        handle.join().unwrap();
        if accept {
            assert_eq!(
                result
                    .unwrap_or_else(|e| panic!("{description}: {e}"))
                    .bundles()
                    .len(),
                3
            );
        } else {
            assert!(matches!(result, Err(TrustError::Refused)), "{description}");
        }
    }
}

#[test]
fn public_probe_reports_only_bounded_failure_fields() {
    for (response, status, expected_remaining, retry_hint) in [
        (
            "HTTP/1.1 403 Forbidden\r\nx-ratelimit-remaining: 0\r\nRetry-After: 60\r\nSet-Cookie: private-header\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprivate-body",
            403,
            Some(true),
            true,
        ),
        (
            "HTTP/1.1 429 Too Many Requests\r\nx-ratelimit-remaining: 0\r\nx-ratelimit-remaining: private-quota\r\nRetry-After: private-hint\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            429,
            None,
            true,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ratelimit-remaining: 7\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprivate-body",
            200,
            Some(false),
            false,
        ),
    ] {
        let (address, handle) = server(response.as_bytes().to_vec(), false);
        let mut probe =
            PublicProbeTransport::from_transport(transport(vec![("api.github.com", address)]));
        let budget = SelectionBudget::new();
        let result = crate::release_acquisition::AuthenticatedArchive::acquire_latest(
            &mut probe,
            crate::release_identity::Architecture::Amd64,
            &budget,
        );
        handle.join().unwrap();
        let expected_error = if status == 429 {
            TrustError::Unavailable
        } else {
            TrustError::Refused
        };
        assert_eq!(result.err(), Some(expected_error));
        let observed = serde_json::to_value(probe.diagnostic()).unwrap();
        let expected = serde_json::json!({
            "stage":"latest_metadata", "destination":"github_api", "redirect_count":0,
            "http_status":status, "rate_limit_exhausted":expected_remaining, "retry_after_present":retry_hint,
        });
        assert!(
            observed == expected,
            "unexpected diagnostic fields on HTTP failure"
        );
    }
}

#[test]
fn public_probe_counts_accepted_redirects_without_recording_locations() {
    let (cdn, cdn_handle) = server(
        b"HTTP/1.1 403 Forbidden\r\nRetry-After: private-hint\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        false,
    );
    let (api, api_handle) = server(
        b"HTTP/1.1 302 Found\r\nLocation: https://release-assets.githubusercontent.com/private-path?fixture=private-query\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        false,
    );
    let mut probe = PublicProbeTransport::from_transport(transport(vec![
        ("api.github.com", api),
        ("release-assets.githubusercontent.com", cdn),
    ]));
    let proof =
        crate::release_identity::AssetProof::new("sbxr-linux-amd64.tar.gz", 1, &"0".repeat(64))
            .unwrap();
    let result = crate::artifact_trust::acquire_digest_checked_asset(
        &mut probe,
        1,
        &proof,
        &SelectionBudget::new(),
    );
    assert_eq!(result.err(), Some(TrustError::Refused));
    for request in [api_handle.join().unwrap(), cdn_handle.join().unwrap()] {
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(!request.contains("authorization:"));
    }
    let observed = serde_json::to_value(probe.diagnostic()).unwrap();
    let expected = serde_json::json!({
        "stage":"release_archive", "destination":"github_release_cdn", "redirect_count":1,
        "http_status":403, "rate_limit_exhausted":null, "retry_after_present":true,
    });
    assert!(
        observed == expected,
        "unexpected diagnostic fields after redirect"
    );

    let (api, api_handle) = server(
        b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/private-path?fixture=private-query\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        false,
    );
    let mut probe = PublicProbeTransport::from_transport(transport(vec![("api.github.com", api)]));
    assert!(matches!(
        probe.get(&request(), &SelectionBudget::new()),
        Err(TrustError::Refused)
    ));
    api_handle.join().unwrap();
    let observed = serde_json::to_value(probe.diagnostic()).unwrap();
    let expected = serde_json::json!({
        "stage":"tagged_metadata", "destination":"github_api", "redirect_count":0,
        "http_status":302, "rate_limit_exhausted":null, "retry_after_present":false,
    });
    assert!(
        observed == expected,
        "unexpected diagnostic fields for a refused redirect"
    );
}

#[test]
fn public_probe_distinguishes_attestation_storage_from_release_downloads() {
    use crate::{
        artifact_trust::{NativeAttestations, acquire_digest_checked_asset},
        release_identity::AssetProof,
    };
    let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let budget = SelectionBudget::new();
    let attestation = NativeAttestations::decode(
        br#"{"attestations":[{"initiator":"github","bundle_url":"https://tmaproduction.blob.core.windows.net/private-path?fixture=private-query"}]}"#,
        false,
        &budget,
    )
    .unwrap();
    let (address, handle) = server(response.to_vec(), false);
    let mut probe = PublicProbeTransport::from_transport(transport(vec![(
        "tmaproduction.blob.core.windows.net",
        address,
    )]));
    assert_eq!(
        attestation.acquire_bundle(0, &mut probe, &budget).err(),
        Some(TrustError::Refused)
    );
    handle.join().unwrap();
    let observed = serde_json::to_value(probe.diagnostic()).unwrap();
    let expected = serde_json::json!({
        "stage":"attestation_bundle", "destination":"attestation_storage", "redirect_count":0,
        "http_status":403, "rate_limit_exhausted":null, "retry_after_present":false,
    });
    assert!(
        observed == expected,
        "unexpected diagnostic for attestation storage"
    );

    for (name, stage) in [
        ("release-index.json", "release_index"),
        ("sbxr-linux-amd64.tar.gz", "release_archive"),
    ] {
        let (address, handle) = server(response.to_vec(), false);
        let mut probe =
            PublicProbeTransport::from_transport(transport(vec![("api.github.com", address)]));
        let proof = AssetProof::new(name, 1, &"0".repeat(64)).unwrap();
        assert_eq!(
            acquire_digest_checked_asset(&mut probe, 1, &proof, &budget).err(),
            Some(TrustError::Refused)
        );
        handle.join().unwrap();
        let observed = serde_json::to_value(probe.diagnostic()).unwrap();
        let expected = serde_json::json!({
            "stage":stage, "destination":"github_api", "redirect_count":0,
            "http_status":403, "rate_limit_exhausted":null, "retry_after_present":false,
        });
        assert!(
            observed == expected,
            "unexpected diagnostic for release asset"
        );
    }
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
        candidate_preflight_auth: None,
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
