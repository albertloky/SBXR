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

struct RenewalIo {
    process: runtime_handoff::ProcessIdentity,
    bad: Option<(HistoricalObservation, &'static str)>,
    official: bool,
    exists: bool,
    reused: bool,
    routes: bool,
}
impl PeerObservations for RenewalIo {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        Ok(self.process.clone())
    }
    fn peer(
        &self,
        _: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        Err(runtime_handoff::Error::Refused)
    }
}
impl OwnerIo for RenewalIo {
    fn query(&self, q: Observation, _: &StartContext) -> Result<CommandOutput, HostError> {
        assert!(self.routes, "unexpected ordinary observation");
        let body = match q {
            Observation::Property(Unit::Subscription, Property::LoadState) => "loaded",
            Observation::Property(Unit::Subscription, Property::FragmentPath) => {
                "/etc/systemd/system/sbxr-subscription.service"
            }
            Observation::Property(Unit::Subscription, Property::DropInPaths) => "",
            Observation::Property(Unit::Subscription, Property::ExecStart) => {
                "/usr/local/bin/sbxr --subscription-serving"
            }
            Observation::Property(Unit::Subscription, Property::KillMode) => "control-group",
            _ => panic!("unexpected route query"),
        };
        CommandOutput::completed(0, body.as_bytes().to_vec())
    }
    fn service(
        &self,
        _: ServiceAction,
        _: &Arc<HostLock>,
        _: Option<&Path>,
        _: &StartContext,
    ) -> Result<(), HostError> {
        panic!("historical inspection must not execute services")
    }
    fn port_available(&self, _: u16, _: &StartContext) -> Result<bool, HostError> {
        panic!("no bind required")
    }
    fn process(&self, _: u32) -> Result<runtime_handoff::ProcessIdentity, HostError> {
        let mut p = self.process.clone();
        if self.reused {
            p.start_ticks += 1;
        }
        Ok(p)
    }
    fn historical(
        &self,
        q: HistoricalObservation,
        c: &StartContext,
    ) -> Result<CommandOutput, HostError> {
        c.check().map_err(refused)?;
        use HistoricalObservation as Q;
        let body = if let Some((bad, body)) = self.bad.filter(|(bad, _)| *bad == q) {
            let _ = bad;
            body
        } else {
            match q {
                Q::Service("ExecStart") if self.official => {
                    "/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew"
                }
                Q::Service("ExecStart") => "/usr/local/bin/sbxr --certbot-recorder",
                Q::Service("FragmentPath") => "/etc/systemd/system/snap.certbot.renew.service",
                Q::Timer("FragmentPath") => "/etc/systemd/system/snap.certbot.renew.timer",
                Q::Timer("LoadState") => "loaded",
                Q::Timer("DropInPaths") => "",
                Q::Timer("Unit") => "snap.certbot.renew.service",
                Q::Timer("UnitFileState") => "enabled",
                Q::Timer("ActiveState") => "active",
                Q::Timer("TimersCalendar") => {
                    "{ OnCalendar=*-*-* 05:11:22 ; next_elapse=... } { OnCalendar=*-*-* 17:00:33 ; next_elapse=... }"
                }
                Q::Snap => {
                    "Name Version Rev Tracking Publisher Notes\ncertbot 5.4.0 123 latest/stable certbot-eff✓ classic"
                }
                Q::Changes => "ID Status Spawn Ready Summary\n1 Done then now completed change",
                Q::Boot => "fixture-boot",
                Q::ProcessExists(_) => "",
                _ => panic!("unexpected fixed query"),
            }
        };
        CommandOutput::completed(
            if matches!(q, Q::ProcessExists(_)) && !self.exists {
                1
            } else {
                0
            },
            body.as_bytes().to_vec(),
        )
    }
    fn public_ipv4(&self, _: &StartContext) -> Result<std::net::Ipv4Addr, HostError> {
        panic!("no external connection")
    }
    fn validate_configuration(
        &self,
        _: &Arc<HostLock>,
        _: &str,
        _: &StartContext,
    ) -> Result<bool, HostError> {
        panic!("no config execution")
    }
}
#[test]
fn historical_native_observation_refuses_foreign_routes_and_identifies_live_attempts() {
    let root = Root::new();
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        include_bytes!("../../records/testdata/authority/https-activation-b.json"),
        0o600,
    );
    std::fs::set_permissions(
        root.0.join("var/lib/sbxr"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let a = crate::release_acquisition::fixture_archive();
    let proof = a
        .bind_current(
            a.executable(),
            a.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let fs = ProtectedFs::open(&root.0).unwrap();
    let process = runtime_handoff::ProcessIdentity::new(
        51,
        50,
        41,
        fs.uid,
        proof.record().executable_sha256(),
        "/fixture",
    )
    .unwrap();
    let mut runtime = OwnerRuntime {
        fs,
        proof: &proof,
        io: RenewalIo {
            process,
            bad: None,
            official: true,
            exists: true,
            reused: false,
            routes: false,
        },
        probe: None,
    };
    let record = runtime.record().unwrap();
    let attempt = crate::host::historical::UnfinishedRenewal {
        boot_id: "fixture-boot".into(),
        pid: 51,
        tick: 41,
    };
    let facts = runtime
        .historical_facts(&record, std::slice::from_ref(&attempt))
        .unwrap();
    assert!(facts.official_route && !facts.renewal_quiet);
    runtime.io.reused = true;
    assert!(
        runtime
            .historical_facts(&record, std::slice::from_ref(&attempt))
            .unwrap()
            .renewal_quiet
    );
    runtime.io.reused = false;
    runtime.io.exists = false;
    assert!(
        runtime
            .historical_facts(&record, std::slice::from_ref(&attempt))
            .unwrap()
            .renewal_quiet
    );
    runtime.io.official = false;
    assert!(
        !runtime
            .historical_facts(&record, &[])
            .unwrap()
            .official_route
    );
    use HistoricalObservation as Q;
    for (q, body) in [
        (Q::Service("ExecStart"), "/usr/bin/snap run certbot renew"),
        (Q::Service("FragmentPath"), "/tmp/foreign.service"),
        (Q::Timer("DropInPaths"), "/etc/systemd/system/foreign.conf"),
        (
            Q::Timer("TimersCalendar"),
            "{ OnCalendar=*-*-* 05:11:22 } { OnCalendar=*-*-* 06:11:22 }",
        ),
        (Q::Timer("ActiveState"), "inactive"),
        (
            Q::Snap,
            "Name Version Rev Tracking Publisher Notes\ncertbot 5.4.0 123 latest/stable other classic",
        ),
        (
            Q::Snap,
            "Name Version Rev Tracking Publisher Notes\ncertbot 5.3.9 123 latest/stable certbot-eff✓ classic",
        ),
        (
            Q::Changes,
            "ID Status Spawn Ready Summary\n1 Doing then - unfinished change",
        ),
    ] {
        runtime.io.bad = Some((q, body));
        assert!(runtime.historical_facts(&record, &[]).is_err(), "{q:?}");
    }
    runtime.io.bad = None;
    runtime.io.process.executable_sha256 = "f".repeat(64);
    assert!(runtime.historical_facts(&record, &[]).is_err());
}

#[test]
fn historical_firewall_loaded_commands_preserve_order_count_and_exact_shell_arguments() {
    let record = OwnershipRecord::decode(include_bytes!(
        "../../records/testdata/authority/https-activation-b.json"
    ))
    .unwrap();
    let unit = crate::host::historical::firewall_unit(&record).unwrap();
    let unit = std::str::from_utf8(&unit).unwrap();
    for key in ["ExecStart=", "ExecStop="] {
        let expected: Vec<_> = unit.lines().filter_map(|l| l.strip_prefix(key)).collect();
        assert_eq!(expected.len(), 2);
        let loaded:Vec<_>=expected.iter().map(|e|format!("{{ path=/bin/sh ; argv[]={} ; ignore_errors=no ; pid=0 ; code=(null) ; status=0 }}",e.strip_prefix("/bin/sh -ec '").unwrap().strip_suffix('\'').map(|e|format!("/bin/sh -ec {e}")).unwrap())).collect();
        let good = loaded.join(" ");
        assert!(historical::firewall_commands(&good, &expected));
        for bad in [
            loaded[0].clone(),
            format!("{} {}", loaded[1], loaded[0]),
            format!("{good} {}", loaded[0]),
            good.replace("8.8.8.8", "9.9.9.9"),
            good.replace("ignore_errors=no", "ignore_errors=yes"),
            good.replace("8443", "443"),
        ] {
            assert!(!historical::firewall_commands(&bad, &expected));
        }
    }
}

#[test]
fn historical_serving_unit_recognition_is_removal_only() {
    let root = Root::new();
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        include_bytes!("../../records/testdata/authority/https-activation-b.json"),
        0o600,
    );
    fs::set_permissions(
        root.0.join("var/lib/sbxr"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let archive = crate::release_acquisition::fixture_archive();
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let protected = ProtectedFs::open(&root.0).unwrap();
    let process = runtime_handoff::ProcessIdentity::new(
        51,
        50,
        41,
        protected.uid,
        proof.record().executable_sha256(),
        "/fixture",
    )
    .unwrap();
    let runtime = OwnerRuntime {
        fs: protected,
        proof: &proof,
        io: RenewalIo {
            process,
            bad: None,
            official: true,
            exists: false,
            reused: false,
            routes: true,
        },
        probe: None,
    };
    for (index, unit) in crate::host::historical::known_serving_units()
        .iter()
        .enumerate()
    {
        root.write(crate::host::subscription::UNIT, unit, 0o644);
        assert_eq!(
            runtime
                .serving_routes(&OwnerRuntime::<RenewalIo>::context())
                .is_ok(),
            index == 0
        );
        runtime
            .serving_routes_for_removal(&OwnerRuntime::<RenewalIo>::context())
            .unwrap();
    }
    root.write(crate::host::subscription::UNIT, b"foreign service", 0o644);
    assert!(
        runtime
            .serving_routes_for_removal(&OwnerRuntime::<RenewalIo>::context())
            .is_err()
    );
}
