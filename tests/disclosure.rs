use domain::Confirmation;
use records::{OwnershipRecord, ReleaseIdentity, SetupPhase, sha256_hex};
use sbxr::disclosure::*;
use sbxr::{client_identity, domain, records, subscription_artifact, subscription_serving};
use std::{cell::RefCell, rc::Rc};

const CONFIG: &[u8] = include_bytes!("testdata/server_configuration/standard.json");

#[derive(Clone)]
struct Fixture(Rc<RefCell<State>>);
struct State {
    record: Vec<u8>,
    config_reads: usize,
    reads: Vec<Material>,
    writes: usize,
    held: bool,
    staged: Option<Vec<u8>>,
    inspection: Option<Inspection>,
    files: [Vec<u8>; 3],
    proofs: [FileProof; 3],
    busy: bool,
    publication_failure: u8,
    drift_on_read: bool,
    cancel_on_read: Option<subscription_serving::Cancellation>,
}
struct Guard(Rc<RefCell<State>>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.borrow_mut().held = false;
    }
}
impl Fixture {
    fn new() -> Self {
        let release = ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap();
        let mut r = OwnershipRecord::new_standard(release, "8.8.8.8", &sha256_hex(CONFIG)).unwrap();
        while r.phase() != SetupPhase::Running {
            r = r.next_setup_checkpoint().unwrap();
        }
        Self(Rc::new(RefCell::new(State {
            record: r.encode().unwrap(),
            config_reads: 0,
            reads: Vec::new(),
            writes: 0,
            held: false,
            staged: None,
            inspection: None,
            files: [CONFIG.to_vec(), Vec::new(), Vec::new()],
            proofs: [
                FileProof {
                    mode: 0o640,
                    gid: 100,
                    ..proof()
                },
                proof(),
                proof(),
            ],
            busy: false,
            publication_failure: 0,
            drift_on_read: false,
            cancel_on_read: None,
        })))
    }
}
impl Host for Fixture {
    type Guard = Guard;
    fn acquire(&mut self) -> Result<Guard, Error> {
        let mut s = self.0.borrow_mut();
        if s.held || s.busy {
            return Err(Error::Refused);
        }
        s.held = true;
        Ok(Guard(self.0.clone()))
    }
    fn verify_guard(&mut self, _: &Guard) -> Result<(), Error> {
        if self.0.borrow().held {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }
    fn snapshot(&mut self, _: &Guard) -> Result<client_identity::Snapshot, Error> {
        Ok(client_identity::Snapshot {
            current: self.0.borrow().record.clone(),
            staged: self.0.borrow().staged.clone(),
        })
    }
    fn inspect(&mut self, _: &Guard, r: &OwnershipRecord) -> Result<Inspection, Error> {
        if let Some(i) = self.0.borrow().inspection.clone() {
            return Ok(i);
        }
        Ok(Inspection {
            release: r.release_identity(),
            configuration_gid: 100,
            running: RunningFacts {
                host: true,
                public_ipv4_matches: true,
                ownership: true,
                transaction_files_absent: true,
                apt_key: true,
                apt_source: true,
                package: true,
                hold: true,
                package_identity: true,
                configuration: true,
                state: true,
                validation: true,
                service_provenance: true,
                lock_provisioning: true,
                service_enabled: true,
                service_active: true,
                listener: true,
                fingerprint: "synthetic-running-v1".into(),
            },
            serving_surface_safe: true,
        })
    }
    fn read(&mut self, _: &Guard, material: Material) -> Result<ProtectedFile, Error> {
        let i = match material {
            Material::Configuration => 0,
            Material::SubscriptionToken => 1,
            Material::ServingState => 2,
        };
        let mut s = self.0.borrow_mut();
        s.reads.push(material);
        if i == 0 {
            s.config_reads += 1;
        }
        if s.drift_on_read {
            s.record.push(b' ');
        }
        if let Some(stop) = &s.cancel_on_read {
            stop.cancel();
        }
        Ok(ProtectedFile::new(s.files[i].clone(), s.proofs[i]))
    }

    fn publish(&mut self, _: &Guard, expected: &[u8], next: &OwnershipRecord) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record, expected);
        if s.publication_failure == 1 {
            return Err(Error::Publication);
        }
        s.record = next.encode().unwrap();
        s.writes += 1;
        if s.publication_failure == 2 {
            return Err(Error::Publication);
        }
        if s.publication_failure == 3 {
            s.staged = Some(s.record.clone());
        }
        Ok(())
    }
}

#[test]
fn only_explicit_confirmation_discloses_client_configuration_without_writes() {
    let f = Fixture::new();
    let mut session = Session::new(f.clone());
    let prepared = session.review(Action::ShowClientConfiguration).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        session.execute(prepared, Confirmation::Declined, Some(&mut output)),
        Ok(Outcome::Declined)
    );
    assert!(output.is_empty());
    assert_eq!(f.0.borrow().config_reads, 0);
    let prepared = session.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        session.execute(prepared, Confirmation::Approved, Some(&mut output)),
        Ok(Outcome::ClientConfigurationDisclosed)
    );
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("----- BEGIN SBXR CLIENT CONFIGURATION -----\n"));
    assert!(text.ends_with("----- END SBXR CLIENT CONFIGURATION -----\n"));
    assert!(text.contains("12345678-1234-4234-8234-123456789abc"));
    assert!(!text.contains("private_key"));
    assert!(!text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert_eq!(f.0.borrow().config_reads, 1);
    assert_eq!(f.0.borrow().writes, 0);
    assert!(!f.0.borrow().held);
}

fn proof() -> FileProof {
    FileProof {
        regular: true,
        uid: 0,
        gid: 0,
        mode: 0o600,
        links: 1,
        protected_ancestry: true,
    }
}
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
fn enable(f: &Fixture) {
    let mut s = f.0.borrow_mut();
    let mut r = OwnershipRecord::decode(&s.record)
        .unwrap()
        .begin_http_enablement(
            &"1".repeat(32),
            &subscription_artifact::SubscriptionCredential::parse(TOKEN).unwrap(),
            &"2".repeat(32),
            &"3".repeat(64),
        )
        .unwrap();
    for _ in 1..records::HTTP_ENABLEMENT_CHECKPOINTS.len() {
        r = r.advance_http_enablement().unwrap();
    }
    r = r.commit_http_enablement().unwrap();
    s.files[1] = format!("{TOKEN}\n").into_bytes();
    s.files[2] = r.serving_authority().unwrap().state_bytes().unwrap();
    s.record = r.encode().unwrap();
}
fn inspection(f: &Fixture) -> Inspection {
    let mut h = f.clone();
    let g = h.acquire().unwrap();
    let r = OwnershipRecord::decode(&f.0.borrow().record).unwrap();
    h.inspect(&g, &r).unwrap()
}

#[test]
fn status_and_review_never_read_secrets_and_a_new_review_expires_authority() {
    let f = Fixture::new();
    enable(&f);
    let mut session = Session::new(f.clone());
    let p = session.review(Action::ShowClientConfiguration).unwrap();
    let s = session.status().unwrap();
    assert!(s.client_configuration_available && s.mark_compromise_available);
    assert!(s.has_subscription && !s.compromised);
    assert_eq!(f.0.borrow().config_reads, 0);
    assert!(f.0.borrow().reads.is_empty());
    assert_eq!(
        session.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
        Err(Error::StaleReview)
    );
    let p = session.review(Action::ShowClientConfiguration).unwrap();
    let _ = session.review(Action::MarkSubscriptionCompromised).unwrap();
    assert_eq!(
        session.execute(p, Confirmation::Declined, None),
        Err(Error::StaleReview)
    );
    assert_eq!(f.0.borrow().writes, 0);
}

#[test]
fn tokens_are_bound_to_the_session_and_missing_output_refuses_before_secret_read() {
    let f = Fixture::new();
    let mut a = Session::new(f.clone());
    let mut b = Session::new(f.clone());
    let p = a.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        b.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
        Err(Error::StaleReview)
    );
    let p = a.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        a.execute(p, Confirmation::Approved, None),
        Err(Error::Refused)
    );
    assert_eq!(f.0.borrow().config_reads, 0);
    let p = a.review(Action::ShowClientConfiguration).unwrap();
    a.host_mut();
    assert_eq!(
        a.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
        Err(Error::StaleReview)
    );
    assert_eq!(f.0.borrow().writes, 0);
}

#[test]
fn every_running_proof_and_safe_serving_surface_is_required() {
    for i in 0..19 {
        let f = Fixture::new();
        enable(&f);
        let mut observed = inspection(&f);
        let fields = [
            &mut observed.running.host,
            &mut observed.running.public_ipv4_matches,
            &mut observed.running.ownership,
            &mut observed.running.transaction_files_absent,
            &mut observed.running.apt_key,
            &mut observed.running.apt_source,
            &mut observed.running.package,
            &mut observed.running.hold,
            &mut observed.running.package_identity,
            &mut observed.running.configuration,
            &mut observed.running.state,
            &mut observed.running.validation,
            &mut observed.running.service_provenance,
            &mut observed.running.lock_provisioning,
            &mut observed.running.service_enabled,
            &mut observed.running.service_active,
            &mut observed.running.listener,
            &mut observed.serving_surface_safe,
        ];
        if i < fields.len() {
            *fields.into_iter().nth(i).unwrap() = false;
        } else {
            observed.running.fingerprint.clear();
        }
        f.0.borrow_mut().inspection = Some(observed);
        let mut s = Session::new(f.clone());
        assert!(
            !s.status().unwrap().client_configuration_available,
            "proof {i}"
        );
        assert_eq!(
            s.review(Action::ShowClientConfiguration).err(),
            Some(Error::Refused)
        );
        assert_eq!(f.0.borrow().config_reads, 0);
        assert_eq!(f.0.borrow().writes, 0);
    }
}

#[test]
fn changed_running_release_or_record_facts_refuse_without_display() {
    for i in 0..6 {
        let f = Fixture::new();
        enable(&f);
        let mut s = Session::new(f.clone());
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        let mut observed = inspection(&f);
        match i {
            0 => observed.running.service_active = false,
            1 => observed.serving_surface_safe = false,
            2 => observed.running.fingerprint.push('x'),
            3 => {
                observed.release =
                    ReleaseIdentity::new("v3.1.119", &"c".repeat(40), &"d".repeat(64)).unwrap()
            }
            4 => observed.configuration_gid = 101,
            _ => f.0.borrow_mut().record.push(b' '),
        }
        f.0.borrow_mut().inspection = Some(observed);
        let mut out = Vec::new();
        assert_eq!(
            s.execute(p, Confirmation::Approved, Some(&mut out)),
            Err(Error::StaleReview)
        );
        assert!(out.is_empty());
        assert_eq!(f.0.borrow().config_reads, 0);
        assert_eq!(f.0.borrow().writes, 0);
    }
}

#[test]
fn exact_protected_configuration_and_supported_codec_are_required() {
    for i in 0..11 {
        let f = Fixture::new();
        let mut s = Session::new(f.clone());
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        let mut state = f.0.borrow_mut();
        match i {
            0 => state.proofs[0].regular = false,
            1 => state.proofs[0].uid = 1,
            2 => state.proofs[0].gid = 1,
            3 => state.proofs[0].mode = 0o644,
            4 => state.proofs[0].links = 2,
            5 => state.proofs[0].protected_ancestry = false,
            6 => state.files[0].push(b' '),
            7..=9 => {
                let mut v: serde_json::Value = serde_json::from_slice(CONFIG).unwrap();
                match i {
                    7 => v["unknown_secret"] = "not-supported".into(),
                    8 => v["inbounds"][0]["users"][0]["uuid"] = "bad".into(),
                    _ => v["outbounds"][0]["type"] = "block".into(),
                }
                state.files[0] = serde_json::to_vec(&v).unwrap();
                state.record = record_for(&state.files[0]).encode().unwrap();
            }
            _ => state.drift_on_read = true,
        }
        drop(state);
        // Re-review malformed-but-hash-bound configuration; review cannot read secrets.
        let p = if (7..=9).contains(&i) {
            s.review(Action::ShowClientConfiguration).unwrap()
        } else {
            p
        };
        let mut out = Vec::new();
        let e = s
            .execute(p, Confirmation::Approved, Some(&mut out))
            .unwrap_err();
        assert!(matches!(e, Error::Authority | Error::StaleReview));
        assert!(out.is_empty());
        assert_eq!(f.0.borrow().writes, 0);
    }
}

struct FailingOutput {
    remaining: usize,
    bytes: Vec<u8>,
}
impl std::io::Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("synthetic output secret marker"));
        }
        let n = bytes.len().min(self.remaining);
        self.bytes.extend_from_slice(&bytes[..n]);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn partial_or_failed_output_never_reports_disclosure_success_or_writes() {
    for remaining in [0, 1, 60, 100] {
        let f = Fixture::new();
        let mut s = Session::new(f.clone());
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        let mut output = FailingOutput {
            remaining,
            bytes: Vec::new(),
        };
        let e = s
            .execute(p, Confirmation::Approved, Some(&mut output))
            .unwrap_err();
        assert_eq!(e, Error::Output);
        assert!(!e.to_string().contains("secret marker"));
        assert_eq!(f.0.borrow().writes, 0);
        assert!(!f.0.borrow().held);
    }
}

#[test]
fn cancellation_before_or_during_material_read_and_lock_contention_refuse() {
    for i in 0..3 {
        let f = Fixture::new();
        let mut s = Session::new(f.clone());
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        match i {
            0 => s.cancellation().cancel(),
            1 => f.0.borrow_mut().cancel_on_read = Some(s.cancellation()),
            _ => f.0.borrow_mut().busy = true,
        }
        let mut out = Vec::new();
        let e = s
            .execute(p, Confirmation::Approved, Some(&mut out))
            .unwrap_err();
        assert_eq!(
            e,
            if i == 2 {
                Error::Refused
            } else {
                Error::Interrupted
            }
        );
        assert!(out.is_empty());
        assert_eq!(f.0.borrow().writes, 0);
    }
}

#[test]
fn view_details_rediscloses_current_link_without_configuration_or_write() {
    let f = Fixture::new();
    enable(&f);
    let before = f.0.borrow().record.clone();
    let mut s = Session::new(f.clone());
    let details = s.view_details().unwrap();
    let l = details.subscription_link.unwrap();
    assert_eq!(l.as_str(), format!("http://8.8.8.8:8443/s/{TOKEN}"));
    assert!(l.transport_warning().unwrap().contains("interception"));
    let mut out = Vec::new();
    write_link(&mut out, &l).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "This link is a reusable credential. Anyone with it can obtain your proxy connection details. Keep it private. It will remain in terminal scrollback.\nhttp://8.8.8.8:8443/s/{TOKEN}\n"
        )
    );
    assert!(!format!("{l:?} {l}").contains(TOKEN));
    assert_eq!(f.0.borrow().config_reads, 0);
    assert_eq!(f.0.borrow().writes, 0);
    assert_eq!(f.0.borrow().record, before);
    let mut failure = FailingOutput {
        remaining: 10,
        bytes: Vec::new(),
    };
    assert_eq!(write_link(&mut failure, &l), Err(Error::Output));
}

#[test]
fn link_redisclosure_and_confirmed_fallback_survive_serving_outage() {
    let f = Fixture::new();
    enable(&f);
    // Serving health is deliberately absent from safe surface and proxy facts.
    let mut s = Session::new(f.clone());
    assert!(s.view_details().unwrap().subscription_link.is_some());
    let p = s.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        s.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
        Ok(Outcome::ClientConfigurationDisclosed)
    );
    // Even a stopped proxy does not invalidate an exactly consistent bearer link.
    let mut observed = inspection(&f);
    observed.running.service_active = false;
    f.0.borrow_mut().inspection = Some(observed);
    assert!(s.view_details().unwrap().subscription_link.is_some());
    assert!(!s.status().unwrap().client_configuration_available);
}

#[test]
fn mismatched_unsafe_or_noncanonical_subscription_material_is_never_redisclosed() {
    for i in 0..17 {
        let f = Fixture::new();
        enable(&f);
        let mut state = f.0.borrow_mut();
        match i {
            0 => state.files[1].pop().map(|_| ()).unwrap(),
            1 => state.files[1].push(b'\n'),
            2 => state.files[1][43] = b'\r',
            3 => state.files[1][0] = b'A',
            4 => state.files[2][0] = b' ',
            5 => {
                let mut v: serde_json::Value = serde_json::from_slice(&state.files[2]).unwrap();
                v["serving"]["link_id"] = "9".repeat(32).into();
                state.files[2] = serde_json::to_vec(&v).unwrap();
            }
            6 => state.proofs[1].mode = 0o644,
            7 => state.proofs[1].links = 2,
            8 => state.proofs[1].regular = false,
            9 => state.proofs[2].uid = 1,
            10 => state.proofs[2].protected_ancestry = false,
            11 => state.proofs[2].mode = 0o644,
            12 => state.staged = Some(b"foreign-staged-authority".to_vec()),
            13 => state.drift_on_read = true,
            15 => state.proofs[1].mode = 0o640,
            16 => state.proofs[2].mode = 0o640,
            _ => {
                state.files[1][42] = b'R';
                let mut v: serde_json::Value = serde_json::from_slice(&state.record).unwrap();
                v["serving"]["credential_sha256"] = sha256_hex(&state.files[1][..43]).into();
                state.files[2] =
                    serde_json::to_vec(&serde_json::json!({"schema":1,"serving":v["serving"]}))
                        .unwrap();
                state.files[2].push(b'\n');
                state.record = serde_json::to_vec(&v).unwrap();
            }
        }
        drop(state);
        let mut s = Session::new(f.clone());
        assert!(s.view_details().is_err(), "case {i}");
        assert_eq!(f.0.borrow().config_reads, 0);
        assert_eq!(f.0.borrow().writes, 0);
    }
}

#[test]
fn confirmed_compromise_marking_preserves_all_material_and_uses_one_record_write() {
    let f = Fixture::new();
    enable(&f);
    let before = f.0.borrow().files.clone();
    let mut s = Session::new(f.clone());
    let p = s.review(Action::MarkSubscriptionCompromised).unwrap();
    assert_eq!(
        s.execute(p, Confirmation::Declined, None),
        Ok(Outcome::Declined)
    );
    assert_eq!(f.0.borrow().writes, 0);
    let p = s.review(Action::MarkSubscriptionCompromised).unwrap();
    assert_eq!(
        s.execute(p, Confirmation::Approved, None),
        Ok(Outcome::SubscriptionCompromised)
    );
    assert_eq!(f.0.borrow().writes, 1);
    assert_eq!(f.0.borrow().files, before);
    let r = OwnershipRecord::decode(&f.0.borrow().record).unwrap();
    assert!(r.subscription_compromised());
    assert!(r.pending_change().is_none());
    assert_eq!(f.0.borrow().config_reads, 0);
    let mut restarted = Session::new(f.clone());
    assert!(restarted.status().unwrap().compromised);
    assert!(!restarted.status().unwrap().mark_compromise_available);
    assert_eq!(
        restarted.review(Action::MarkSubscriptionCompromised).err(),
        Some(Error::Refused)
    );
    let details = restarted.view_details().unwrap();
    assert!(details.compromised);
    assert_eq!(
        details.subscription_link.unwrap().as_str(),
        format!("http://8.8.8.8:8443/s/{TOKEN}")
    );
    assert!(restarted.review(Action::ShowClientConfiguration).is_ok());
}

#[test]
fn uncertain_publication_is_never_retried_or_mistaken_for_success() {
    for failure in 1..=3 {
        let f = Fixture::new();
        enable(&f);
        let mut s = Session::new(f.clone());
        let p = s.review(Action::MarkSubscriptionCompromised).unwrap();
        f.0.borrow_mut().publication_failure = failure;
        assert_eq!(
            s.execute(p, Confirmation::Approved, None),
            Err(Error::Publication)
        );
        assert_eq!(f.0.borrow().writes, usize::from(failure != 1));
        assert_eq!(
            OwnershipRecord::decode(&f.0.borrow().record)
                .unwrap()
                .subscription_compromised(),
            failure != 1
        );
        assert!(!f.0.borrow().held);
    }
}

#[test]
fn pending_actions_and_staged_records_are_observed_without_promotion() {
    let f = Fixture::new();
    enable(&f);
    let before = f.0.borrow().record.clone();
    f.0.borrow_mut().staged = Some(before.clone());
    let mut s = Session::new(f.clone());
    assert!(!s.status().unwrap().client_configuration_available);
    assert!(s.review(Action::MarkSubscriptionCompromised).is_err());
    assert!(s.view_details().unwrap().subscription_link.is_some());
    assert_eq!(f.0.borrow().record, before);
    assert_eq!(f.0.borrow().staged.as_ref(), Some(&before));
    assert_eq!(f.0.borrow().writes, 0);
    f.0.borrow_mut().staged = None;
    let record = OwnershipRecord::decode(&before)
        .unwrap()
        .begin_http_link_rotation(
            &"5".repeat(32),
            &"6".repeat(32),
            &subscription_artifact::SubscriptionCredential::parse(&"A".repeat(43)).unwrap(),
        )
        .unwrap();
    f.0.borrow_mut().record = record.encode().unwrap();
    assert!(!s.status().unwrap().client_configuration_available);
    assert!(s.review(Action::MarkSubscriptionCompromised).is_err());
    // The candidate is never read: only still-authoritative source can appear.
    assert_eq!(
        s.view_details()
            .unwrap()
            .subscription_link
            .unwrap()
            .as_str(),
        format!("http://8.8.8.8:8443/s/{TOKEN}")
    );
    assert_eq!(f.0.borrow().writes, 0);
}

fn record_for(bytes: &[u8]) -> OwnershipRecord {
    let release = ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap();
    let mut r = OwnershipRecord::new_standard(release, "8.8.8.8", &sha256_hex(bytes)).unwrap();
    while r.phase() != SetupPhase::Running {
        r = r.next_setup_checkpoint().unwrap();
    }
    r
}

#[test]
fn standard_and_optional_vmess_client_disclosures_match_exact_go_bytes() {
    for (server, expected) in [
        (
            CONFIG,
            include_bytes!("testdata/disclosure/client-standard.json").as_slice(),
        ),
        (
            include_bytes!("testdata/server_configuration/vless-vmess.json").as_slice(),
            include_bytes!("testdata/disclosure/client-vless-vmess.json").as_slice(),
        ),
    ] {
        let f = Fixture::new();
        f.0.borrow_mut().files[0] = server.to_vec();
        f.0.borrow_mut().record = record_for(server).encode().unwrap();
        let mut s = Session::new(f.clone());
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            s.execute(p, Confirmation::Approved, Some(&mut out)),
            Ok(Outcome::ClientConfigurationDisclosed)
        );
        let mut framed = b"----- BEGIN SBXR CLIENT CONFIGURATION -----\n".to_vec();
        framed.extend_from_slice(expected);
        framed.extend_from_slice(b"----- END SBXR CLIENT CONFIGURATION -----\n");
        assert_eq!(out, framed);
        assert_eq!(f.0.borrow().writes, 0);
    }
}

#[test]
fn warnings_codes_and_diagnostics_do_not_contain_credentials() {
    for warning in [
        "contains a credential",
        "Anyone with a copy",
        "Terminal history or recording",
        "no client file",
        "Outside copies survive Complete removal",
    ] {
        assert!(
            Action::ShowClientConfiguration
                .plan()
                .join(" ")
                .contains(warning)
        );
    }
    assert!(
        Action::MarkSubscriptionCompromised
            .plan()
            .join(" ")
            .contains("remains active")
    );
    assert_eq!(
        Outcome::ClientConfigurationDisclosed.code(),
        "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
    );
    assert_eq!(
        Outcome::Declined.code(),
        "PROXY-INSTALLATION-ACTION-CANCELLED"
    );
    assert_eq!(
        Outcome::SubscriptionCompromised.code(),
        "PROXY-INSTALLATION-SUBSCRIPTION-COMPROMISED"
    );
    let f = Fixture::new();
    enable(&f);
    let mut s = Session::new(f.clone());
    let p = s.review(Action::ShowClientConfiguration).unwrap();
    let text = format!(
        "{p:?} {:?} {:?}",
        ProtectedFile::new(TOKEN.as_bytes().to_vec(), proof()),
        Error::Authority
    );
    let details = format!("{:?}", s.view_details().unwrap());
    for secret in [
        TOKEN,
        "12345678-1234-4234-8234-123456789abc",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(!text.contains(secret));
        assert!(!details.contains(secret));
    }
    // The cancellation handle and host extraction preserve typed orchestration.
    let stop = s.cancellation();
    stop.cancel();
    assert_eq!(s.status(), Err(Error::Interrupted));
    let _ = s.into_host();
}

#[test]
fn legacy_https_link_redisclosure_preserves_exact_transport_without_migration() {
    let f = Fixture::new();
    let r = OwnershipRecord::decode(include_bytes!(
        "../src/records/testdata/authority/https-active.json"
    ))
    .unwrap();
    f.0.borrow_mut().record = r.encode().unwrap();
    f.0.borrow_mut().files[1] = format!("{}\n", "A".repeat(43)).into_bytes();
    f.0.borrow_mut().files[2] = r.serving_authority().unwrap().state_bytes().unwrap();
    let mut s = Session::new(f.clone());
    let l = s.view_details().unwrap().subscription_link.unwrap();
    assert_eq!(
        l.as_str(),
        format!("https://8.8.8.8:8443/s/{}", "A".repeat(43))
    );
    assert!(l.transport_warning().is_none());
    assert_eq!(
        s.review(Action::MarkSubscriptionCompromised).err(),
        Some(Error::Refused)
    );
    assert_eq!(f.0.borrow().writes, 0);
    assert_eq!(f.0.borrow().config_reads, 0);
}

#[test]
fn failed_revocation_cleanup_preserves_compromise_until_successful_rotation() {
    let f = Fixture::new();
    enable(&f);
    let mut s = Session::new(f.clone());
    let p = s.review(Action::MarkSubscriptionCompromised).unwrap();
    s.execute(p, Confirmation::Approved, None).unwrap();
    let before = OwnershipRecord::decode(&f.0.borrow().record).unwrap();
    let candidate = subscription_artifact::SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    let pending = before
        .begin_http_link_rotation(&"5".repeat(32), &"6".repeat(32), &candidate)
        .unwrap();
    let cleaned = pending.cleanup_http_link_rotation().unwrap();
    f.0.borrow_mut().record = cleaned.encode().unwrap();
    let details = s.view_details().unwrap();
    assert!(details.compromised);
    assert_eq!(
        details.subscription_link.unwrap().as_str(),
        format!("http://8.8.8.8:8443/s/{TOKEN}")
    );
    let committed = pending
        .advance_http_link_rotation()
        .unwrap()
        .advance_http_link_rotation()
        .unwrap()
        .complete_http_link_rotation()
        .unwrap();
    assert!(!committed.subscription_compromised());
    assert_ne!(
        committed.serving_authority().unwrap(),
        before.serving_authority().unwrap()
    );
    // These pure authority transitions perform no host rotation in this test.
    assert_eq!(f.0.borrow().writes, 1);
}

struct FlushFailure;
impl std::io::Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("private output failure"))
    }
}
#[test]
fn buffered_output_flush_failure_is_unsuccessful_for_both_disclosure_paths() {
    let f = Fixture::new();
    enable(&f);
    let mut s = Session::new(f.clone());
    let p = s.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        s.execute(p, Confirmation::Approved, Some(&mut FlushFailure)),
        Err(Error::Output)
    );
    let link = s.view_details().unwrap().subscription_link.unwrap();
    assert_eq!(write_link(&mut FlushFailure, &link), Err(Error::Output));
    assert_eq!(f.0.borrow().writes, 0);
}

#[test]
fn client_configuration_uses_the_reviewed_sing_box_group_and_exact_0640_mode() {
    let f = Fixture::new();
    f.0.borrow_mut().proofs[0].mode = 0o640;
    f.0.borrow_mut().proofs[0].gid = 100;
    let mut s = Session::new(f.clone());
    let p = s.review(Action::ShowClientConfiguration).unwrap();
    assert_eq!(
        s.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
        Ok(Outcome::ClientConfigurationDisclosed)
    );
    for (mode, gid) in [(0o600, 100), (0o640, 0), (0o640, 101)] {
        f.0.borrow_mut().proofs[0].mode = mode;
        f.0.borrow_mut().proofs[0].gid = gid;
        let p = s.review(Action::ShowClientConfiguration).unwrap();
        assert_eq!(
            s.execute(p, Confirmation::Approved, Some(&mut Vec::new())),
            Err(Error::Authority)
        );
    }
}
