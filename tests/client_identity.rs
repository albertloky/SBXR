use sbxr::{
    client_identity::*,
    domain::Confirmation,
    identity_generation::{Entropy, IdentityError},
    records::{self, ChangeDirection, OwnershipRecord, SetupPhase, sha256_hex},
    server_configuration::{ServerConfiguration, ServerIdentity},
    subscription_artifact::SubscriptionCredential,
    subscription_serving::Cancellation,
};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR").expect("isolated TMPDIR required");
        let root = PathBuf::from(base).join(format!(
            "ci-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("only this disposable fixture");
    }
}
fn put(root: &Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    fs::File::open(root.join(name)).unwrap().sync_all().unwrap();
}
fn get(root: &Path, name: &str) -> Result<Vec<u8>, Error> {
    fs::read(root.join(name)).map_err(|_| Error::Effect)
}
fn absent(root: &Path, name: &str) -> Result<(), Error> {
    match fs::remove_file(root.join(name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Effect),
    }
}
fn source(vmess: bool) -> ServerConfiguration {
    let identity = ServerIdentity::from_private_key(
        "00112233-4455-4677-8899-aabbccddeeff",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "01234567",
    )
    .unwrap();
    let config = ServerConfiguration::standard(&identity).unwrap();
    if vmess {
        config.with_vmess_websocket("fixture.example.com").unwrap()
    } else {
        config
    }
}
fn initial(config: &ServerConfiguration, subscription: bool) -> OwnershipRecord {
    let release =
        records::ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap();
    let mut record =
        OwnershipRecord::new_standard(release, "8.8.8.8", &config.sha256_hex()).unwrap();
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    if subscription {
        let credential = SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
        record = record
            .begin_http_enablement(
                &"1".repeat(32),
                &credential,
                &"2".repeat(32),
                &"3".repeat(64),
            )
            .unwrap();
        for _ in 1..records::HTTP_ENABLEMENT_CHECKPOINTS.len() {
            record = record.advance_http_enablement().unwrap();
        }
        record = record.commit_http_enablement().unwrap();
    }
    record
}
#[derive(Default)]
struct EntropyCount {
    calls: usize,
    fail_at: Option<usize>,
}
impl Entropy for EntropyCount {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), IdentityError> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(IdentityError::EntropyUnavailable);
        }
        dst.fill(0x10 + self.calls as u8);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum PublicationFault {
    Before,
    Staged,
    Renamed,
}
struct Guard {
    directory: fs::File,
    inode: u64,
}
struct DiskHost {
    root: PathBuf,
    fail_effect: Option<(Effect, bool)>,
    fail_checkpoint: Option<(Checkpoint, PublicationFault)>,
    fail_complete: bool,
    ineffective_route: bool,
    subscription_route: bool,
    unsafe_quiescence: Option<usize>,
    stop_at: Option<Checkpoint>,
    cancel: Cancellation,
    changed_on_acquire: bool,
    session: Option<Child>,
    accepted: Option<TcpStream>,
    events: Vec<Effect>,
    executing_release: records::ReleaseIdentity,
}
impl DiskHost {
    fn create(root: &Root, vmess: bool, subscription: bool) -> Self {
        let config = source(vmess);
        let record = initial(&config, subscription);
        put(&root.0, "record", &record.encode().unwrap());
        put(&root.0, "config", config.as_bytes());
        put(&root.0, "running", config.sha256_hex().as_bytes());
        put(&root.0, "foreign", b"preserve unrelated bytes");
        if subscription {
            put(&root.0, "token", &[b'A'; 43]);
            put(&root.0, "artifact-current", b"synthetic original artifact");
        }
        Self::open(root)
    }
    fn open(root: &Root) -> Self {
        Self {
            root: root.0.clone(),
            fail_effect: None,
            fail_checkpoint: None,
            fail_complete: false,
            ineffective_route: false,
            subscription_route: true,
            unsafe_quiescence: None,
            stop_at: None,
            cancel: Cancellation::new(),
            changed_on_acquire: false,
            session: None,
            accepted: None,
            events: vec![],
            executing_release: OwnershipRecord::decode(&get(&root.0, "record").unwrap())
                .unwrap()
                .release_identity(),
        }
    }
    fn record(&self) -> OwnershipRecord {
        OwnershipRecord::decode(&get(&self.root, "record").unwrap()).unwrap()
    }
    fn cp(&self) -> Checkpoint {
        rotation(&self.record()).unwrap().checkpoint
    }
    fn exact_remove(&self, name: &str, hash: &str) -> Result<(), Error> {
        if self.root.join(name).exists() && sha256_hex(&get(&self.root, name)?) != hash {
            return Err(Error::Authority);
        }
        absent(&self.root, name)
    }
    fn do_effect(
        &mut self,
        e: Effect,
        r: &OwnershipRecord,
        m: Option<&Material>,
    ) -> Result<(), Error> {
        let rotation = rotation(r)?;
        match e {
            Effect::PrepareTarget => {
                let m = m.ok_or(Error::Effect)?;
                if sha256_hex(m.target_configuration()) != rotation.target_sha256 {
                    return Err(Error::Authority);
                }
                put(&self.root, "target", m.target_configuration());
                if r.serving_authority().is_some() {
                    put(&self.root, "artifact-target", m.target_artifact());
                }
            }
            Effect::PublishStartup => put(&self.root, "startup", STARTUP_DROP_IN.as_bytes()),
            Effect::Reload => {
                if !self.ineffective_route {
                    put(&self.root, "loaded", STARTUP_DROP_IN.as_bytes());
                }
            }
            Effect::StopSource => {
                assert_eq!(rotation.checkpoint, Checkpoint::Gated);
                absent(&self.root, "running")?;
                if let Some(mut child) = self.session.take() {
                    child.kill().map_err(|_| Error::Effect)?;
                    child.wait().map_err(|_| Error::Effect)?;
                }
                self.accepted.take();
            }
            Effect::PublishTarget => {
                assert_eq!(rotation.checkpoint.direction(), ChangeDirection::Forward);
                let target = get(&self.root, "target")?;
                if sha256_hex(&target) != rotation.target_sha256 {
                    return Err(Error::Authority);
                }
                put(&self.root, "config-next", &target);
                fs::rename(self.root.join("config-next"), self.root.join("config"))
                    .map_err(|_| Error::Effect)?;
                fs::File::open(&self.root).unwrap().sync_all().unwrap();
            }
            Effect::StartTarget => {
                assert_eq!(
                    sbxr::runtime_handoff::cutover_configuration(r).unwrap(),
                    Some(rotation.target_sha256.clone())
                );
                if sha256_hex(&get(&self.root, "config")?) != rotation.target_sha256 {
                    return Err(Error::Authority);
                }
                put(&self.root, "running", rotation.target_sha256.as_bytes());
            }
            Effect::RestoreSource => {
                assert_eq!(rotation.checkpoint.direction(), ChangeDirection::Cleanup);
                if sha256_hex(&get(&self.root, "config")?) != rotation.source_sha256 {
                    return Err(Error::Authority);
                }
                put(&self.root, "running", rotation.source_sha256.as_bytes());
            }
            Effect::FinishSubscription => {
                if let Some(sub) = r.serving_authority() {
                    let token = get(&self.root, "token")?;
                    if sha256_hex(&token) != sub.credential_sha256() {
                        return Err(Error::Authority);
                    }
                    if rotation.checkpoint.direction() == ChangeDirection::Forward {
                        let expected = rotation
                            .target_artifact_sha256
                            .as_ref()
                            .ok_or(Error::Authority)?;
                        let artifact = get(&self.root, "artifact-target")
                            .or_else(|_| get(&self.root, "artifact-current"))?;
                        if sha256_hex(&artifact) != *expected {
                            return Err(Error::Authority);
                        }
                        put(&self.root, "artifact-current", &artifact);
                    }
                    // Independent faults remain authoritative and suppress serving.
                    if !self.root.join("independent-fault").exists() {
                        put(&self.root, "serving", b"selected artifact only");
                    }
                }
            }
            Effect::RemoveTarget => {
                self.exact_remove("target", &rotation.target_sha256)?;
                if let Some(hash) = rotation.target_artifact_sha256 {
                    self.exact_remove("artifact-target", &hash)?;
                }
            }
            Effect::CleanupStartup => {
                self.exact_remove("startup", &sha256_hex(STARTUP_DROP_IN.as_bytes()))?;
                absent(&self.root, "loaded")?;
            }
        }
        Ok(())
    }
}
impl Drop for DiskHost {
    fn drop(&mut self) {
        if let Some(mut child) = self.session.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Host for DiskHost {
    type Guard = Guard;
    fn acquire(&mut self) -> Result<Guard, Error> {
        let directory = fs::File::open(&self.root).map_err(|_| Error::Effect)?;
        rustix::fs::flock(
            &directory,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| Error::Refused)?;
        if self.changed_on_acquire {
            put(&self.root, "stage", b"foreign interrupted publication");
        }
        let inode = directory.metadata().unwrap().ino();
        Ok(Guard { directory, inode })
    }
    fn verify_guard(&mut self, g: &Guard) -> Result<(), Error> {
        if g.directory.metadata().unwrap().ino() != g.inode
            || fs::metadata(&self.root).unwrap().ino() != g.inode
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn installed_release(&mut self, _: &Guard) -> Result<records::ReleaseIdentity, Error> {
        Ok(self.executing_release.clone())
    }
    fn snapshot(&mut self, _: &Guard) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            current: get(&self.root, "record")?,
            staged: match fs::read(self.root.join("stage")) {
                Ok(s) => Some(s),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(Error::Effect),
            },
        })
    }
    fn synchronize(&mut self, _: &Guard, expected: &[u8]) -> Result<(), Error> {
        if get(&self.root, "record")? != expected {
            return Err(Error::StaleReview);
        }
        fs::File::open(self.root.join("record"))
            .unwrap()
            .sync_all()
            .unwrap();
        fs::File::open(&self.root).unwrap().sync_all().unwrap();
        Ok(())
    }
    fn admit(&mut self, _: &Guard, r: &OwnershipRecord) -> Result<StartupAuthority, Error> {
        if r.pending_change().is_some()
            || self.root.join("target").exists()
            || self.root.join("artifact-target").exists()
            || get(&self.root, "running")? != r.configuration_sha256().as_bytes()
        {
            return Err(Error::Refused);
        }
        if sha256_hex(&get(&self.root, "config")?) != r.configuration_sha256() {
            return Err(Error::Authority);
        }
        Ok(StartupAuthority {
            directory_created: true,
        })
    }
    fn inspect(&mut self, _: &Guard, r: &OwnershipRecord) -> Result<(), Error> {
        let v = rotation(r)?;
        let hash = sha256_hex(&get(&self.root, "config")?);
        let allowed = if v.checkpoint == Checkpoint::Revoked {
            hash == v.source_sha256 || hash == v.target_sha256
        } else {
            hash == r.configuration_sha256()
        };
        if !allowed {
            return Err(Error::Authority);
        }
        if self.root.join("target").exists() {
            if sha256_hex(&get(&self.root, "target")?) != v.target_sha256 {
                return Err(Error::Authority);
            }
        } else if v.checkpoint.direction() == ChangeDirection::Forward
            && v.checkpoint != Checkpoint::TargetStarted
        {
            return Err(Error::Authority);
        }
        if let Some(hash) = v.target_artifact_sha256
            && self.root.join("artifact-target").exists()
            && sha256_hex(&get(&self.root, "artifact-target")?) != hash
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn configuration(&mut self, _: &Guard) -> Result<Vec<u8>, Error> {
        get(&self.root, "config")
    }
    fn publish(&mut self, _: &Guard, expected: &[u8], next: &OwnershipRecord) -> Result<(), Error> {
        if get(&self.root, "record")? != expected {
            return Err(Error::StaleReview);
        }
        let cp = rotation(next).ok().map(|r| r.checkpoint);
        let fault = self
            .fail_checkpoint
            .filter(|(c, _)| Some(*c) == cp)
            .map(|(_, f)| f);
        if let Some(PublicationFault::Before) = fault {
            return Err(Error::Publication);
        }
        put(&self.root, "stage", &next.encode().unwrap());
        if let Some(PublicationFault::Staged) = fault {
            return Err(Error::Publication);
        }
        fs::rename(self.root.join("stage"), self.root.join("record")).unwrap();
        if let Some(PublicationFault::Renamed) = fault {
            return Err(Error::Publication);
        }
        fs::File::open(&self.root).unwrap().sync_all().unwrap();
        if cp.is_none() && self.fail_complete {
            return Err(Error::Publication);
        }
        if cp == self.stop_at {
            self.cancel.cancel();
        }
        Ok(())
    }
    fn routes(&mut self, _: &Guard, _: &OwnershipRecord) -> Result<StartupRoutes, Error> {
        Ok(StartupRoutes {
            proxy: !self.ineffective_route
                && get(&self.root, "loaded").is_ok_and(|v| v == STARTUP_DROP_IN.as_bytes()),
            subscription: self.subscription_route,
        })
    }
    fn quiescence(&mut self, _: &Guard, _: &OwnershipRecord) -> Result<Quiescence, Error> {
        let mut p = [true; 9];
        if self.root.join("running").exists()
            || self
                .session
                .as_mut()
                .is_some_and(|p| p.try_wait().unwrap().is_none())
        {
            p[2] = false;
        }
        if self.accepted.is_some() {
            p[5] = false;
        }
        if let Some(i) = self.unsafe_quiescence {
            p[i] = false;
        }
        Ok(Quiescence {
            inactive: p[0],
            main_pid_zero: p[1],
            processes_absent: p[2],
            listener_absent: p[3],
            descendants_empty: p[4],
            subscription_requests_drained: p[5],
            subscription_descendants_empty: p[6],
            subscription_listener_absent: p[7],
            subscription_inactive: p[8],
        })
    }
    fn effect(
        &mut self,
        _: &Guard,
        e: Effect,
        r: &OwnershipRecord,
        m: Option<&Material>,
    ) -> Result<(), Error> {
        self.events.push(e);
        if self.fail_effect == Some((e, false)) {
            return Err(Error::Effect);
        }
        self.do_effect(e, r, m)?;
        if self.fail_effect == Some((e, true)) {
            return Err(Error::Effect);
        }
        Ok(())
    }
    fn verify_running(&mut self, _: &Guard, r: &OwnershipRecord) -> Result<(), Error> {
        if get(&self.root, "running")? != r.configuration_sha256().as_bytes()
            || sha256_hex(&get(&self.root, "config")?) != r.configuration_sha256()
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
fn execute_new(h: &mut DiskHost, entropy: &mut EntropyCount) -> Result<Outcome, Error> {
    let stop = h.cancel.clone();
    let p = review(h, entropy, &stop)?;
    execute(h, p, Confirmation::Approved, &stop)
}
fn finish_now(h: &mut DiskHost) -> Result<Outcome, Error> {
    let stop = h.cancel.clone();
    let p = review_finish(h, &stop)?;
    finish(h, p, Confirmation::Approved, &stop)
}
fn assert_preserved(root: &Root) {
    assert_eq!(
        get(&root.0, "foreign").unwrap(),
        b"preserve unrelated bytes"
    );
}

#[test]
fn rotation_has_the_go_checkpoint_contract() {
    assert_eq!(Checkpoint::Authorized.as_str(), "rotation authorized");
    assert_eq!(Checkpoint::Revoked.as_str(), "source revoked");
}
#[test]
fn vless_and_vmess_rotate_together_preserving_reality_and_subscription_credential() {
    for vmess in [false, true] {
        for sub in [false, true] {
            let root = Root::new();
            let mut h = DiskHost::create(&root, vmess, sub);
            let source = h.record();
            let before: Value = serde_json::from_slice(&get(&root.0, "config").unwrap()).unwrap();
            let mut entropy = EntropyCount::default();
            assert_eq!(execute_new(&mut h, &mut entropy), Ok(Outcome::Rotated));
            assert_eq!(entropy.calls, 2);
            let after: Value = serde_json::from_slice(&get(&root.0, "config").unwrap()).unwrap();
            assert_ne!(
                before["inbounds"][0]["users"][0]["uuid"],
                after["inbounds"][0]["users"][0]["uuid"]
            );
            let mut restored = after.clone();
            for inbound in restored["inbounds"].as_array_mut().unwrap() {
                inbound["users"][0]["uuid"] = before["inbounds"][0]["users"][0]["uuid"].clone();
            }
            assert_eq!(restored, before);
            if vmess {
                assert_eq!(
                    after["inbounds"][0]["users"][0]["uuid"],
                    after["inbounds"][1]["users"][0]["uuid"]
                );
            }
            assert_eq!(h.record().serving_authority(), source.serving_authority());
            assert!(h.record().pending_change().is_none());
            assert!(!root.0.join("target").exists());
            assert_preserved(&root);
            if sub {
                assert_eq!(get(&root.0, "token").unwrap(), vec![b'A'; 43]);
                let artifact =
                    String::from_utf8(get(&root.0, "artifact-current").unwrap()).unwrap();
                assert_eq!(artifact.lines().count(), if vmess { 2 } else { 1 });
            }
        }
    }
}
#[test]
fn every_checkpoint_survives_cancellation_and_reopens_with_the_committed_direction() {
    for cp in [
        Checkpoint::Authorized,
        Checkpoint::TargetPrepared,
        Checkpoint::IntegrationPublished,
        Checkpoint::Reloaded,
        Checkpoint::RouteVerified,
        Checkpoint::Gated,
        Checkpoint::Stopped,
        Checkpoint::Quiescent,
        Checkpoint::Revoked,
        Checkpoint::TargetPublished,
        Checkpoint::TargetStarted,
    ] {
        let root = Root::new();
        let mut h = DiskHost::create(&root, true, true);
        let old = get(&root.0, "config").unwrap();
        h.stop_at = Some(cp);
        let mut entropy = EntropyCount::default();
        assert_eq!(execute_new(&mut h, &mut entropy), Err(Error::Interrupted));
        assert_eq!(h.cp(), cp);
        let operation = rotation(&h.record()).unwrap();
        drop(h);
        let mut h = DiskHost::open(&root);
        assert_eq!(
            rotation(&h.record()).unwrap().operation_id,
            operation.operation_id
        );
        assert_eq!(
            finish_now(&mut h),
            Ok(if cp.direction() == ChangeDirection::Cleanup {
                Outcome::CleanedUp
            } else {
                Outcome::Finished
            })
        );
        assert_eq!(entropy.calls, 2);
        assert!(h.record().pending_change().is_none());
        if cp.direction() == ChangeDirection::Cleanup {
            assert_eq!(get(&root.0, "config").unwrap(), old);
        } else {
            assert_eq!(h.record().configuration_sha256(), operation.target_sha256);
            assert_ne!(get(&root.0, "config").unwrap(), old);
            assert!(!h.events.contains(&Effect::RestoreSource));
        }
        assert_preserved(&root);
    }
}
#[test]
fn failure_before_and_after_each_effect_keeps_the_replacement_and_never_regenerates() {
    for effect in [
        Effect::PrepareTarget,
        Effect::PublishStartup,
        Effect::Reload,
        Effect::StopSource,
        Effect::PublishTarget,
        Effect::StartTarget,
        Effect::FinishSubscription,
        Effect::RemoveTarget,
    ] {
        for after in [false, true] {
            let root = Root::new();
            let mut h = DiskHost::create(&root, false, true);
            h.fail_effect = Some((effect, after));
            let mut entropy = EntropyCount::default();
            assert_eq!(execute_new(&mut h, &mut entropy), Err(Error::Effect));
            let operation = rotation(&h.record()).unwrap();
            drop(h);
            let mut h = DiskHost::open(&root);
            let expected = if operation.checkpoint.direction() == ChangeDirection::Cleanup {
                Outcome::CleanedUp
            } else {
                Outcome::Finished
            };
            assert_eq!(finish_now(&mut h), Ok(expected), "{effect:?} after={after}");
            assert_eq!(entropy.calls, 2);
            assert_preserved(&root);
        }
    }
}
#[test]
fn publication_failure_never_continues_and_restart_observes_rename_before_direction() {
    for cp in [
        Checkpoint::Authorized,
        Checkpoint::Quiescent,
        Checkpoint::Revoked,
        Checkpoint::TargetPublished,
        Checkpoint::TargetStarted,
    ] {
        for fault in [
            PublicationFault::Before,
            PublicationFault::Staged,
            PublicationFault::Renamed,
        ] {
            let root = Root::new();
            let mut h = DiskHost::create(&root, false, false);
            h.fail_checkpoint = Some((cp, fault));
            let mut entropy = EntropyCount::default();
            assert_eq!(execute_new(&mut h, &mut entropy), Err(Error::Publication));
            drop(h);
            let mut h = DiskHost::open(&root);
            match fault {
                PublicationFault::Staged => {
                    assert_eq!(
                        review_finish(&mut h, &Cancellation::new()).unwrap_err(),
                        Error::Publication
                    );
                    assert!(root.0.join("stage").exists());
                }
                PublicationFault::Before if cp == Checkpoint::Authorized => {
                    assert!(h.record().pending_change().is_none());
                }
                _ => {
                    let r = rotation(&h.record()).unwrap();
                    assert_eq!(
                        finish_now(&mut h),
                        Ok(if r.checkpoint.direction() == ChangeDirection::Cleanup {
                            Outcome::CleanedUp
                        } else {
                            Outcome::Finished
                        })
                    );
                }
            }
            assert_eq!(entropy.calls, 2);
            assert_preserved(&root);
        }
    }
}
#[test]
fn no_revocation_without_every_fresh_shutdown_proof() {
    for bad in 0..9 {
        let root = Root::new();
        let mut h = DiskHost::create(&root, false, true);
        h.unsafe_quiescence = Some(bad);
        let mut entropy = EntropyCount::default();
        assert_eq!(execute_new(&mut h, &mut entropy), Err(Error::Refused));
        assert_eq!(h.cp(), Checkpoint::Stopped);
        assert!(!h.events.contains(&Effect::PublishTarget));
        assert_eq!(finish_now(&mut h), Ok(Outcome::CleanedUp));
    }
}
#[test]
fn stale_quiescence_on_restart_cannot_commit_revocation() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, false);
    h.stop_at = Some(Checkpoint::Quiescent);
    assert_eq!(
        execute_new(&mut h, &mut EntropyCount::default()),
        Err(Error::Interrupted)
    );
    drop(h);
    // Finish selects cleanup before revocation; even a forged runtime marker
    // cannot turn the saved observation into permission to publish the target.
    let mut h = DiskHost::open(&root);
    put(&root.0, "running", b"unknown process");
    assert_eq!(finish_now(&mut h), Ok(Outcome::CleanedUp));
    assert!(!h.events.contains(&Effect::PublishTarget));
}
#[test]
fn both_loaded_start_routes_must_be_proved_before_gate_or_revocation() {
    for proxy in [false, true] {
        let root = Root::new();
        let mut h = DiskHost::create(&root, false, true);
        if proxy {
            h.ineffective_route = true;
        } else {
            h.subscription_route = false;
        }
        assert_eq!(
            execute_new(&mut h, &mut EntropyCount::default()),
            Err(Error::Refused)
        );
        assert_eq!(h.cp(), Checkpoint::Reloaded);
        assert!(!h.events.contains(&Effect::StopSource));
        assert_eq!(finish_now(&mut h), Ok(Outcome::CleanedUp));
    }
}
#[test]
fn tampered_target_after_revocation_preserves_authority_and_refuses_source_restoration() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, true, true);
    h.stop_at = Some(Checkpoint::Revoked);
    assert_eq!(
        execute_new(&mut h, &mut EntropyCount::default()),
        Err(Error::Interrupted)
    );
    drop(h);
    put(&root.0, "target", b"foreign secret target");
    let before = get(&root.0, "record").unwrap();
    let mut h = DiskHost::open(&root);
    assert!(review_finish(&mut h, &Cancellation::new()).is_err());
    assert_eq!(get(&root.0, "record").unwrap(), before);
    assert_eq!(get(&root.0, "target").unwrap(), b"foreign secret target");
    assert!(h.events.is_empty());
}
#[test]
fn changed_review_cancellation_decline_entropy_failure_and_lock_contention_have_no_effects() {
    for case in 0..6 {
        let root = Root::new();
        let mut h = DiskHost::create(&root, false, false);
        let before = get(&root.0, "record").unwrap();
        let stop = Cancellation::new();
        let mut entropy = EntropyCount::default();
        if case == 4 {
            entropy.fail_at = Some(1);
            assert!(review(&mut h, &mut entropy, &stop).is_err());
        } else if case == 5 {
            let directory = fs::File::open(&root.0).unwrap();
            rustix::fs::flock(&directory, rustix::fs::FlockOperation::LockExclusive).unwrap();
            assert_eq!(
                review(&mut h, &mut entropy, &stop).unwrap_err(),
                Error::Refused
            );
        } else {
            let p = review(&mut h, &mut entropy, &stop).unwrap();
            match case {
                0 => assert_eq!(
                    execute(&mut h, p, Confirmation::Declined, &stop),
                    Ok(Outcome::Declined)
                ),
                1 => {
                    stop.cancel();
                    assert_eq!(
                        execute(&mut h, p, Confirmation::Approved, &stop),
                        Err(Error::Interrupted)
                    );
                }
                2 => {
                    h.changed_on_acquire = true;
                    assert_eq!(
                        execute(&mut h, p, Confirmation::Approved, &stop),
                        Err(Error::StaleReview)
                    );
                }
                _ => {
                    put(&root.0, "config", b"changed reviewed configuration");
                    assert!(execute(&mut h, p, Confirmation::Approved, &stop).is_err());
                }
            }
        }
        assert_eq!(get(&root.0, "record").unwrap(), before);
        assert!(h.events.is_empty());
        assert_preserved(&root);
    }
}
#[test]
fn independent_subscription_fault_is_preserved_and_stale_serving_is_never_started() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, true);
    let compromised = h.record().mark_subscription_compromised().unwrap();
    put(&root.0, "record", &compromised.encode().unwrap());
    put(
        &root.0,
        "independent-fault",
        b"preserve renewal or compromised evidence",
    );
    assert_eq!(
        execute_new(&mut h, &mut EntropyCount::default()),
        Ok(Outcome::Rotated)
    );
    assert_eq!(
        get(&root.0, "independent-fault").unwrap(),
        b"preserve renewal or compromised evidence"
    );
    assert!(!root.0.join("serving").exists());
    assert!(h.record().serving_authority().is_some());
    let after: Value = serde_json::from_slice(&h.record().encode().unwrap()).unwrap();
    assert_eq!(after["subscription_compromised"], true);
}
#[test]
fn real_synthetic_process_and_accepted_socket_are_closed_before_revocation() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, true);
    let child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    h.session = Some(child);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    accepted.write_all(b"synthetic session").unwrap();
    let mut greeting = [0; 17];
    peer.read_exact(&mut greeting).unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    h.accepted = Some(accepted);
    h.stop_at = Some(Checkpoint::Revoked);
    assert_eq!(
        execute_new(&mut h, &mut EntropyCount::default()),
        Err(Error::Interrupted)
    );
    assert!(h.session.is_none());
    assert!(h.accepted.is_none());
    assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
    assert_eq!(h.cp(), Checkpoint::Revoked);
}
#[test]
fn diagnostics_and_review_do_not_disclose_identity_or_private_key() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, true);
    let before = get(&root.0, "record").unwrap();
    let p = review(&mut h, &mut EntropyCount::default(), &Cancellation::new()).unwrap();
    let diagnostic = format!("{p:?} {}", Error::Authority);
    for secret in [
        "00112233-4455-4677-8899-aabbccddeeff",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "11111111-1111-4111-9111-111111111111",
    ] {
        assert!(!diagnostic.contains(secret));
    }
    assert_eq!(get(&root.0, "record").unwrap(), before);
    assert!(!root.0.join("target").exists());
    assert!(h.events.is_empty());
}
#[test]
fn strict_profile_rejects_mismatched_vmess_uuid_and_duplicate_keys_before_generation() {
    for duplicate in [false, true] {
        let root = Root::new();
        let mut h = DiskHost::create(&root, true, false);
        let bytes = get(&root.0, "config").unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["inbounds"][1]["users"][0]["uuid"] = "aabbccdd-eeff-4000-8000-001122334455".into();
        let changed = if duplicate {
            String::from_utf8(bytes)
                .unwrap()
                .replacen("\"log\":", "\"log\":{},\"log\":", 1)
                .into_bytes()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let mut record: Value = serde_json::from_slice(&get(&root.0, "record").unwrap()).unwrap();
        let hash = sha256_hex(&changed);
        record["configuration_sha256"] = hash.clone().into();
        for resource in record["permitted_resources"].as_array_mut().unwrap() {
            if resource
                .as_str()
                .unwrap()
                .starts_with("/etc/sing-box/config.json ")
            {
                *resource = format!("/etc/sing-box/config.json sha256:{hash}").into();
            }
        }
        put(
            &root.0,
            "record",
            &OwnershipRecord::decode(&serde_json::to_vec(&record).unwrap())
                .unwrap()
                .encode()
                .unwrap(),
        );
        put(&root.0, "config", &changed);
        put(&root.0, "running", hash.as_bytes());
        let mut entropy = EntropyCount::default();
        assert!(review(&mut h, &mut entropy, &Cancellation::new()).is_err());
        assert_eq!(entropy.calls, 0);
        assert!(h.events.is_empty());
    }
}

#[test]
fn checkpoint_direction_vectors_match_preserved_go_contract() {
    for (index, line) in include_str!("testdata/client_identity/checkpoints.tsv")
        .lines()
        .enumerate()
    {
        let (checkpoint, direction) = line.split_once('\t').unwrap();
        let expected = if index < 8 {
            ChangeDirection::Cleanup
        } else {
            ChangeDirection::Forward
        };
        assert_eq!(
            direction,
            if expected == ChangeDirection::Cleanup {
                "cleanup"
            } else {
                "forward"
            }
        );
        let root = Root::new();
        let mut h = DiskHost::create(&root, false, false);
        let mut entropy = EntropyCount::default();
        let p = review(&mut h, &mut entropy, &Cancellation::new()).unwrap();
        // Stop at each checkpoint independently; the fixture is external to the writer.
        let cps = [
            Checkpoint::Authorized,
            Checkpoint::TargetPrepared,
            Checkpoint::IntegrationPublished,
            Checkpoint::Reloaded,
            Checkpoint::RouteVerified,
            Checkpoint::Gated,
            Checkpoint::Stopped,
            Checkpoint::Quiescent,
            Checkpoint::Revoked,
            Checkpoint::TargetPublished,
            Checkpoint::TargetStarted,
        ];
        h.stop_at = Some(cps[index]);
        let stop = h.cancel.clone();
        assert_eq!(
            execute(&mut h, p, Confirmation::Approved, &stop),
            Err(Error::Interrupted)
        );
        let r = rotation(&h.record()).unwrap();
        assert_eq!(r.checkpoint.as_str(), checkpoint);
        assert_eq!(r.checkpoint.direction(), expected);
    }
}

#[test]
fn records_and_all_existing_start_selectors_close_the_gate_and_cannot_reverse_revocation() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, true);
    let original = h.record();
    let mut previous = original.clone();
    for cp in [
        Checkpoint::Authorized,
        Checkpoint::TargetPrepared,
        Checkpoint::IntegrationPublished,
        Checkpoint::Reloaded,
        Checkpoint::RouteVerified,
        Checkpoint::Gated,
        Checkpoint::Stopped,
        Checkpoint::Quiescent,
        Checkpoint::Revoked,
        Checkpoint::TargetPublished,
        Checkpoint::TargetStarted,
    ] {
        if cp == Checkpoint::Authorized {
            h.stop_at = Some(cp);
            assert_eq!(
                execute_new(&mut h, &mut EntropyCount::default()),
                Err(Error::Interrupted)
            );
        } else {
            let next = advance_record(&previous).unwrap();
            put(&root.0, "record", &next.encode().unwrap());
        }
        let current = h.record();
        assert!(permits_successor(&previous, &current));
        if previous.pending_change().is_some() {
            assert!(!permits_successor(&current, &previous));
        }
        let ordinary = (cp as usize) < Checkpoint::Gated as usize;
        let proxy = sbxr::runtime_handoff::cutover_configuration(&current);
        if ordinary {
            assert_eq!(proxy.unwrap(), None);
        } else {
            assert!(proxy.is_err() || proxy.unwrap().is_some());
        }
        assert_eq!(
            sbxr::runtime_handoff::select_http_authority(&current, false).is_ok(),
            ordinary
        );
        if cp == Checkpoint::Revoked {
            assert!(sbxr::runtime_handoff::select_http_authority(&current, true).is_err());
            assert!(sbxr::runtime_handoff::cutover_configuration(&current).is_err());
        }
        previous = current;
    }
    assert!(!permits_successor(&previous, &original));
}
#[test]
fn lost_completion_acknowledgement_preserves_the_finished_target_and_does_not_repeat() {
    let root = Root::new();
    let mut h = DiskHost::create(&root, false, true);
    h.fail_complete = true;
    assert_eq!(
        execute_new(&mut h, &mut EntropyCount::default()),
        Err(Error::Publication)
    );
    let target = h.record().configuration_sha256().to_owned();
    drop(h);
    let mut h = DiskHost::open(&root);
    assert!(h.record().pending_change().is_none());
    assert_eq!(sha256_hex(&get(&root.0, "config").unwrap()), target);
    assert!(review_finish(&mut h, &Cancellation::new()).is_err());
    assert!(h.events.is_empty());
}

#[test]
fn forward_recovery_refuses_changed_loaded_routes_without_restoring_the_source() {
    let root = Root::new();
    let mut host = DiskHost::create(&root, true, true);
    host.stop_at = Some(Checkpoint::Revoked);
    assert_eq!(
        execute_new(&mut host, &mut EntropyCount::default()),
        Err(Error::Interrupted)
    );
    let committed = get(&root.0, "record").unwrap();
    drop(host);
    put(&root.0, "loaded", b"foreign loaded startup condition");
    let mut host = DiskHost::open(&root);
    assert_eq!(finish_now(&mut host), Err(Error::Refused));
    assert_eq!(get(&root.0, "record").unwrap(), committed);
    assert!(host.events.is_empty());
    assert!(!root.0.join("running").exists());
}
#[test]
fn operation_id_entropy_failure_does_not_publish_or_prepare_the_generated_identity() {
    let root = Root::new();
    let mut host = DiskHost::create(&root, true, true);
    let initial = get(&root.0, "record").unwrap();
    let mut entropy = EntropyCount {
        calls: 0,
        fail_at: Some(2),
    };
    assert_eq!(
        review(&mut host, &mut entropy, &Cancellation::new()).unwrap_err(),
        Error::Authority
    );
    assert_eq!(entropy.calls, 2);
    assert_eq!(get(&root.0, "record").unwrap(), initial);
    assert!(!root.0.join("target").exists());
    assert!(host.events.is_empty());
}

#[test]
fn new_resource_provenance_uses_executing_release_and_preserves_existing_creators() {
    let root = Root::new();
    let mut host = DiskHost::create(&root, false, true);
    let source = host.record();
    let creator =
        records::ReleaseIdentity::new("v3.1.119", &"c".repeat(40), &"d".repeat(64)).unwrap();
    host.executing_release = creator.clone();
    host.stop_at = Some(Checkpoint::Authorized);
    assert_eq!(
        execute_new(&mut host, &mut EntropyCount::default()),
        Err(Error::Interrupted)
    );
    let next = host.record();
    let creators = next.creating_releases();
    assert_eq!(
        &creators[..source.permitted_resources().len()],
        source.creating_releases()
    );
    assert!(
        creators[source.permitted_resources().len()..]
            .iter()
            .all(|r| r == &creator)
    );
    assert!(permits_successor(&source, &next));
    assert_eq!(next.release_identity(), source.release_identity());
}
#[test]
fn changed_authenticated_release_invalidates_both_prepared_rotation_and_finish() {
    for finishing in [false, true] {
        let root = Root::new();
        let mut host = DiskHost::create(&root, false, false);
        let stop = Cancellation::new();
        let mut entropy = EntropyCount::default();
        let replacement =
            records::ReleaseIdentity::new("v3.1.119", &"c".repeat(40), &"d".repeat(64)).unwrap();
        if finishing {
            host.stop_at = Some(Checkpoint::Revoked);
            assert_eq!(
                execute_new(&mut host, &mut entropy),
                Err(Error::Interrupted)
            );
            let prepared = review_finish(&mut host, &stop).unwrap();
            let before = get(&root.0, "record").unwrap();
            host.executing_release = replacement;
            assert_eq!(
                finish(&mut host, prepared, Confirmation::Approved, &stop),
                Err(Error::StaleReview)
            );
            assert_eq!(get(&root.0, "record").unwrap(), before);
        } else {
            let prepared = review(&mut host, &mut entropy, &stop).unwrap();
            let before = get(&root.0, "record").unwrap();
            host.executing_release = replacement;
            assert_eq!(
                execute(&mut host, prepared, Confirmation::Approved, &stop),
                Err(Error::StaleReview)
            );
            assert_eq!(get(&root.0, "record").unwrap(), before);
            assert!(host.events.is_empty());
        }
    }
}
