use super::*;
use std::{fs, os::unix::fs::PermissionsExt};
struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "native-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn write(&self, p: &str, b: &[u8], mode: u32) {
        let p = self.0.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn link(&self, p: &str, t: &str) {
        let p = self.0.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(t, p).unwrap();
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn cgroup_virtual_reads_are_bounded_and_do_not_relax_regular_file_ownership() {
    let root = Root::new();
    let p = "sys/fs/cgroup/system.slice/sbxr-subscription.service/cgroup.events";
    root.write(p, b"populated 0\nfrozen 0\n", 0o444);
    let protected = ProtectedFs::open(&root.0).unwrap();
    assert_eq!(
        protected
            .cgroup_bytes(Unit::Subscription, true)
            .unwrap()
            .unwrap(),
        b"populated 0\nfrozen 0\n"
    );
    fs::set_permissions(root.0.join(p), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.0.join(p), vec![0; 4097]).unwrap();
    assert!(protected.cgroup_bytes(Unit::Subscription, true).is_err());
    fs::remove_file(root.0.join(p)).unwrap();
    root.write("foreign", b"populated 0\n", 0o444);
    root.link(p, "../../../../../foreign");
    assert!(protected.cgroup_bytes(Unit::Subscription, true).is_err());
}
#[test]
fn exact_systemd_exec_matches_go_field_and_shell_separator_contract() {
    use observation::exact_exec;
    let argv = "/bin/sh -ec while command; do other; done";
    let good = format!(
        "{{ path=/bin/sh ; argv[]={argv} ; ignore_errors=no ; pid=0 ; code=(null) ; status=0 }}"
    );
    assert!(exact_exec(&good, "/bin/sh", argv));
    assert!(exact_exec(argv, "/bin/sh", argv));
    for bad in [
        good.replace("ignore_errors=no", "ignore_errors=yes"),
        good.replace(" ; pid=0", " ; path=/bin/sh"),
        good.replace(" ; pid=0", " ; foreign=0"),
        format!("{good} {good}"),
        good.replace("/bin/sh", "/tmp/sh"),
    ] {
        assert!(!exact_exec(&bad, "/bin/sh", argv));
    }
}
#[test]
fn population_and_listener_proofs_reject_partial_duplicate_and_unrelated_facts() {
    assert!(observation::population_empty(b"populated 0\nfrozen 0\n"));
    for bad in [
        b"populated 1\n".as_slice(),
        b"populated 0\npopulated 1\n",
        b"populated 0\npopulated 0\n",
        b"populated 00\n",
        b"frozen 0\n",
    ] {
        assert!(!observation::population_empty(bad));
    }
    let listener = "LISTEN 0 4096 8.8.8.8:8443 *:* users:((\"sbxr\",pid=123,fd=3))";
    assert!(observation::listener_pid(
        listener,
        8443,
        Some("8.8.8.8"),
        123
    ));
    assert!(!observation::listener_pid(
        listener,
        8443,
        Some("9.9.9.9"),
        123
    ));
    assert!(!observation::listener_pid(
        listener,
        8443,
        Some("8.8.8.8"),
        12
    ));
}
#[test]
fn firewall_program_proof_accepts_only_exact_protected_ubuntu_alternatives() {
    for (binary, target) in [
        ("iptables-nft-save", "xtables-nft-multi"),
        ("iptables-legacy-save", "xtables-legacy-multi"),
    ] {
        let root = Root::new();
        root.link("usr/sbin/iptables-save", "/etc/alternatives/iptables-save");
        let canonical = format!("/usr/sbin/{binary}");
        root.link("etc/alternatives/iptables-save", &canonical);
        root.link(&format!("usr/sbin/{binary}"), target);
        root.write(&format!("usr/sbin/{target}"), b"inert executable", 0o755);
        let protected = ProtectedFs::open(&root.0).unwrap();
        let expected = command::firewall_program(&protected).unwrap();
        assert_eq!(expected.len(), 4);
        fs::remove_file(root.0.join("etc/alternatives/iptables-save")).unwrap();
        root.link("etc/alternatives/iptables-save", "/tmp/foreign");
        assert!(command::firewall_program(&protected).is_err());
        assert!(root.0.join(format!("usr/sbin/{target}")).exists());
    }
}
#[test]
fn unsupported_native_owner_construction_refuses_before_commands_or_network() {
    if cfg!(target_os = "linux") {
        return;
    }
    let a = crate::release_acquisition::fixture_archive();
    let proof = a
        .bind_current(
            a.executable(),
            a.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    assert!(matches!(
        OwnerRuntime::native_unreleased(&proof),
        Err(HostError::UnsupportedHost)
    ));
    assert!(matches!(
        crate::host::owner::NativeOwnerSources::authenticated_unreleased(&proof),
        Err(HostError::UnsupportedHost)
    ));
}
#[test]
fn bounded_http_probe_requires_actual_artifact_and_rejects_changed_envelope() {
    use std::io::{Read, Write};
    for bad in [false, true] {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = socket.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut buf = [0; 1024];
            let _ = s.read(&mut buf);
            let body = b"expected artifact\n";
            write!(s,"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: {}\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\r\n",if bad{"public"}else{"no-store"},body.len()).unwrap();
            s.write_all(body).unwrap();
        });
        let credential = SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
        let result = probe::http_probe(
            address,
            &credential,
            b"expected artifact\n",
            &OwnerRuntime::<NativeIo>::context(),
        );
        server.join().unwrap();
        assert_eq!(result.is_ok(), !bad);
    }
}
#[test]
fn http_probe_cancellation_closes_stalled_peer_within_absolute_deadline() {
    use std::io::Read;
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = socket.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut b = [0; 1024];
        let _ = s.read(&mut b);
        loop {
            match s.read(&mut b) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    let token = SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    let context = StartContext::new(
        Cancellation::new(),
        Instant::now() + Duration::from_millis(70),
    );
    let started = Instant::now();
    assert!(probe::http_probe(address, &token, b"expected", &context).is_err());
    server.join().unwrap();
    assert!(started.elapsed() < Duration::from_millis(600));
}
