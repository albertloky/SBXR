use super::*;
use std::{
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};
const CA: &[u8] = include_bytes!("testdata/ca.pem");
const LEAF: &[u8] = include_bytes!("testdata/server.pem");
const KEY: &[u8] = include_bytes!("testdata/server-key.pem");
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "gateway-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(p.join(CA_FILE), CA).unwrap();
        std::fs::set_permissions(p.join(CA_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        Self(p)
    }
    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
    fn roots(&self) -> Result<rustls::RootCertStore> {
        protected_roots(
            &self.0,
            self.uid(),
            &crate::records::sha256_hex(CA),
            &SelectionBudget::new(),
        )
    }
    fn transport(&self, b: &SelectionBudget) -> CandidateGatewayTransport {
        CandidateGatewayTransport::from_directory(
            &self.0,
            self.uid(),
            &crate::records::sha256_hex(CA),
            b,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn protected_ca_is_an_exact_private_snapshot_without_ambient_roots() {
    let f = Fixture::new();
    assert_eq!(f.roots().unwrap().len(), 1);
    for mode in [0o600, 0o644] {
        std::fs::set_permissions(f.0.join(CA_FILE), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(f.roots().is_ok());
    }
    for digest in ["".into(), "F".repeat(64), "1".repeat(64), "a".repeat(63)] {
        assert!(protected_roots(&f.0, f.uid(), &digest, &SelectionBudget::new()).is_err());
    }
    assert!(
        protected_roots(
            &f.0,
            f.uid().saturating_add(1),
            &crate::records::sha256_hex(CA),
            &SelectionBudget::new()
        )
        .is_err()
    );
    let budget = SelectionBudget::new();
    let t = f.transport(&budget);
    std::fs::write(f.0.join(CA_FILE), b"changed").unwrap();
    assert!(f.roots().is_err());
    // Only the immutable reviewed snapshot is retained; no file is reread as trust.
    assert!(
        t.inner
            .admit(
                "https://api.github.com/repos/albertloky/SBXR/releases/latest",
                &budget
            )
            .is_ok()
    );
    assert!(!format!("{t:?}").contains(&crate::records::sha256_hex(CA)));
}
#[test]
fn unsafe_ca_files_and_parents_are_preserved_and_refused() {
    for mode in [0o666, 0o640, 0o400, 0o4644] {
        let f = Fixture::new();
        std::fs::set_permissions(f.0.join(CA_FILE), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(f.roots().is_err());
        assert_eq!(std::fs::read(f.0.join(CA_FILE)).unwrap(), CA);
    }
    let f = Fixture::new();
    let original = f.0.join("original");
    std::fs::rename(f.0.join(CA_FILE), &original).unwrap();
    std::os::unix::fs::symlink(&original, f.0.join(CA_FILE)).unwrap();
    assert!(f.roots().is_err());
    assert_eq!(std::fs::read(&original).unwrap(), CA);
    std::fs::remove_file(f.0.join(CA_FILE)).unwrap();
    std::fs::hard_link(&original, f.0.join(CA_FILE)).unwrap();
    assert!(f.roots().is_err());
    std::fs::remove_file(f.0.join(CA_FILE)).unwrap();
    std::fs::rename(&original, f.0.join(CA_FILE)).unwrap();
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(f.roots().is_err());
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = f.0.join("link");
    std::os::unix::fs::symlink(&f.0, &link).unwrap();
    assert!(
        protected_roots(
            &link,
            f.uid(),
            &crate::records::sha256_hex(CA),
            &SelectionBudget::new()
        )
        .is_err()
    );
    std::fs::remove_file(f.0.join(CA_FILE)).unwrap();
    std::fs::create_dir(f.0.join(CA_FILE)).unwrap();
    assert!(f.roots().is_err());
}
#[test]
fn ca_encoding_and_size_are_strict_even_when_the_digest_matches() {
    let f = Fixture::new();
    for bytes in [
        vec![],
        vec![b'x'; MAX_CA_BYTES + 1],
        [CA, CA].concat(),
        [CA, KEY].concat(),
        [b"junk\n".as_slice(), CA].concat(),
        [CA, b"junk"].concat(),
        b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n".to_vec(),
    ] {
        std::fs::write(f.0.join(CA_FILE), &bytes).unwrap();
        assert!(
            protected_roots(
                &f.0,
                f.uid(),
                &crate::records::sha256_hex(&bytes),
                &SelectionBudget::new()
            )
            .is_err()
        );
    }
}
#[test]
fn only_the_retained_fixed_api_routes_are_allowed_without_redirects() {
    let f = Fixture::new();
    let b = SelectionBudget::new();
    let t = f.transport(&b);
    assert_eq!(ROUTE.0, "api.github.com");
    assert_eq!(
        ROUTE.1,
        "127.0.0.2:443".parse::<std::net::SocketAddr>().unwrap()
    );
    let prefix = "https://api.github.com/repos/albertloky/SBXR/releases/";
    for path in ["latest", "assets/1", "assets/2", "assets/3", "assets/4"] {
        assert!(t.inner.admit(&format!("{prefix}{path}"), &b).is_ok());
    }
    for raw in [
        "http://api.github.com/repos/albertloky/SBXR/releases/latest",
        "https://api.github.com:443/repos/albertloky/SBXR/releases/latest",
        "https://user@api.github.com/repos/albertloky/SBXR/releases/latest",
        "https://api.github.com/repos/foreign/SBXR/releases/latest",
        "https://api.github.com/repos/albertloky/SBXR/releases/latest?x=1",
        "https://api.github.com/repos/albertloky/SBXR/releases/latest#x",
        "https://api.github.com/repos/albertloky/SBXR/releases/%6catest",
        "https://api.github.com/repos/albertloky/SBXR/releases/assets/01",
        "https://api.github.com/repos/albertloky/SBXR/releases/assets/5",
        "https://api.github.com/repos/albertloky/SBXR/releases/tags/v3.1.118",
        "https://github.com/albertloky/SBXR/releases/latest/download/install.sh",
        "https://release-assets.githubusercontent.com/x",
        "https://tmaproduction.blob.core.windows.net/x",
    ] {
        assert!(t.inner.admit(raw, &b).is_err(), "{raw}");
    }
    let request = AcquisitionRequest::latest_metadata();
    assert!(!t.inner.permits_redirect(
        &request,
        "https://release-assets.githubusercontent.com/x",
        1
    ));
    assert!(
        !t.inner
            .permits_redirect(&request, &format!("{prefix}assets/1"), 1)
    );
    assert!(t.inner.ipv4_at("https://api.ipify.org/", &b).is_err());
}
#[test]
fn refused_routes_cancelled_and_expired_scopes_never_reach_network() {
    let f = Fixture::new();
    let b = SelectionBudget::new();
    let mut t = f.transport(&b);
    assert_eq!(
        t.get(
            &AcquisitionRequest::release_metadata("v3.1.118").unwrap(),
            &b
        )
        .err(),
        Some(TrustError::Refused)
    );
    let cancelled = SelectionBudget::new();
    cancelled.cancel();
    assert_eq!(
        t.get(&AcquisitionRequest::latest_metadata(), &cancelled)
            .err(),
        Some(TrustError::Interrupted)
    );
    assert!(
        CandidateGatewayTransport::from_directory(
            &f.0,
            f.uid(),
            &crate::records::sha256_hex(CA),
            &cancelled
        )
        .is_err()
    );
    t.inner.scope = Scope::CandidateGateway(std::time::Instant::now());
    assert_eq!(
        t.get(
            &AcquisitionRequest::latest_metadata(),
            &SelectionBudget::new()
        )
        .err(),
        Some(TrustError::Interrupted)
    );
    let selected =
        crate::records::ReleaseIdentity::new("v9.0.0", &"a".repeat(40), &"b".repeat(64)).unwrap();
    assert_eq!(
        crate::release_acquisition::AuthenticatedCandidateArchive::acquire(
            &mut t,
            &selected,
            crate::release_identity::Architecture::Amd64,
            &SelectionBudget::new()
        )
        .unwrap_err(),
        TrustError::Interrupted
    );
    assert!(t.inner.check_budget(&SelectionBudget::new()).is_err());
    assert!(t.inner.deadline(&SelectionBudget::new()) <= std::time::Instant::now());
}
fn handshake(
    config: rustls::ClientConfig,
    host: &str,
    tamper: bool,
) -> std::result::Result<(), rustls::Error> {
    let mut leaf = LEAF;
    let mut certs = rustls_pemfile::certs(&mut leaf)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    if tamper {
        let mut bytes = certs.remove(0).to_vec();
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        certs.push(bytes.into());
    }
    let mut pem_key = KEY;
    let key = rustls_pemfile::private_key(&mut pem_key).unwrap().unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    let mut client = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap(),
    )
    .unwrap();
    for _ in 0..16 {
        let mut outbound = Vec::new();
        client.write_tls(&mut outbound).unwrap();
        server.read_tls(&mut Cursor::new(outbound)).unwrap();
        server.process_new_packets()?;
        let mut inbound = Vec::new();
        server.write_tls(&mut inbound).unwrap();
        client.read_tls(&mut Cursor::new(inbound)).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("bounded in-memory TLS handshake did not finish")
}
#[test]
fn normal_chain_hostname_validity_and_signature_checks_run_in_memory() {
    let f = Fixture::new();
    assert!(
        handshake(
            tls_config(f.roots().unwrap()).unwrap(),
            "api.github.com",
            false
        )
        .is_ok()
    );
    assert!(
        handshake(
            tls_config(f.roots().unwrap()).unwrap(),
            "foreign.example.invalid",
            false
        )
        .is_err()
    );
    assert!(
        handshake(
            tls_config(f.roots().unwrap()).unwrap(),
            "api.github.com",
            true
        )
        .is_err()
    );
    let public = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    assert!(handshake(tls_config(public).unwrap(), "api.github.com", false).is_err());
    #[derive(Debug)]
    struct FutureTime;
    impl rustls::time_provider::TimeProvider for FutureTime {
        fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
            Some(rustls::pki_types::UnixTime::since_unix_epoch(
                Duration::from_secs(4_200_000_000),
            ))
        }
    }
    let mut expired = tls_config(f.roots().unwrap()).unwrap();
    expired.time_provider = Arc::new(FutureTime);
    assert!(handshake(expired, "api.github.com", false).is_err());
}
#[test]
fn native_trust_entry_stays_unavailable_off_linux_root_and_never_uses_ambient_ca() {
    if !cfg!(target_os = "linux") || rustix::process::geteuid().as_raw() != 0 {
        assert_eq!(
            CandidateGatewayTransport::from_retained_gateway(
                &crate::records::sha256_hex(CA),
                &SelectionBudget::new()
            )
            .err(),
            Some(TrustError::Unavailable)
        );
    }
}
