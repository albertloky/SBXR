//! Sequential Client Identity rotation with injected, retained-lock effects.
//! No native adapter, secret display, system command or automatic direction choice.
use crate::{
    domain::Confirmation,
    identity_generation::{ClientUuid, Entropy, GenerationId, Identity},
    records::{
        ChangeDirection, OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase,
        sha256_hex,
    },
    server_configuration::ServerConfiguration,
    subscription_artifact::{ClientArtifact, ConnectionFacts},
    subscription_serving::Cancellation,
};
use serde_json::{Value, json};
use std::fmt;
use zeroize::Zeroizing;

pub const STARTUP_DROP_IN: &str =
    "[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n";
const STARTUP_PATH: &str = "/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf";
const STARTUP_DIRECTORY: &str = "/etc/systemd/system/sing-box.service.d";
const EFFECTS: &[&str] = &[
    "prepare target",
    "publish startup integration",
    "reload systemd",
    "verify startup route",
    "establish cutover gate",
    "stop source",
    "prove source quiescence",
    "revoke source",
    "publish target",
    "start target",
    "verify target",
    "clean staging",
];
const CHECKPOINTS: &[&str] = &[
    "rotation authorized",
    "target prepared",
    "startup integration published",
    "systemd reloaded",
    "startup route verified",
    "cutover gated",
    "source stopped",
    "source quiescent",
    "source revoked",
    "target published",
    "target started",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Checkpoint {
    Authorized,
    TargetPrepared,
    IntegrationPublished,
    Reloaded,
    RouteVerified,
    Gated,
    Stopped,
    Quiescent,
    Revoked,
    TargetPublished,
    TargetStarted,
}
impl Checkpoint {
    pub fn as_str(self) -> &'static str {
        CHECKPOINTS[self as usize]
    }
    fn from_index(i: usize) -> Result<Self, Error> {
        Ok(match i {
            0 => Self::Authorized,
            1 => Self::TargetPrepared,
            2 => Self::IntegrationPublished,
            3 => Self::Reloaded,
            4 => Self::RouteVerified,
            5 => Self::Gated,
            6 => Self::Stopped,
            7 => Self::Quiescent,
            8 => Self::Revoked,
            9 => Self::TargetPublished,
            10 => Self::TargetStarted,
            _ => return Err(Error::Authority),
        })
    }
    pub fn direction(self) -> ChangeDirection {
        if (self as usize) < 8 {
            ChangeDirection::Cleanup
        } else {
            ChangeDirection::Forward
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    StaleReview,
    Refused,
    Interrupted,
    Effect,
    Publication,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "Client Identity rotation incomplete; inspect exact durable authority before retrying.",
        )
    }
}
impl std::error::Error for Error {}
fn authority<T>(_: T) -> Error {
    Error::Authority
}
fn wire(record: &OwnershipRecord) -> Result<Value, Error> {
    serde_json::from_slice(&record.encode().map_err(authority)?).map_err(authority)
}
fn validated(value: &Value) -> Result<OwnershipRecord, Error> {
    OwnershipRecord::decode(&serde_json::to_vec(value).map_err(authority)?).map_err(authority)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupAuthority {
    pub directory_created: bool,
}
impl StartupAuthority {
    fn wire(self) -> Value {
        json!({"drop_in_sha256":sha256_hex(STARTUP_DROP_IN.as_bytes()),
            "directory_created":self.directory_created})
    }
    fn resources(self) -> Vec<String> {
        let mut out = vec![format!(
            "{STARTUP_PATH} root:root 0644 one-link sha256:{}",
            sha256_hex(STARTUP_DROP_IN.as_bytes())
        )];
        if self.directory_created {
            out.push(format!(
                "{STARTUP_DIRECTORY} root:root 0755 SBXR-created empty-after-drop-in-removal"
            ));
        }
        out
    }
}
/// Validated secret-free operation metadata; parsing grants no host capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub operation_id: String,
    pub checkpoint: Checkpoint,
    pub source_sha256: String,
    pub target_sha256: String,
    pub source_artifact_sha256: Option<String>,
    pub target_artifact_sha256: Option<String>,
}
pub fn rotation(record: &OwnershipRecord) -> Result<Rotation, Error> {
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
    {
        return Err(Error::Authority);
    }
    let value = wire(record)?;
    let r = value
        .get("client_identity_rotation")
        .ok_or(Error::Authority)?;
    let text = |key| r[key].as_str().map(str::to_owned).ok_or(Error::Authority);
    let cp = text("checkpoint")?;
    let index = CHECKPOINTS
        .iter()
        .position(|v| *v == cp)
        .ok_or(Error::Authority)?;
    Ok(Rotation {
        operation_id: text("operation_id")?,
        checkpoint: Checkpoint::from_index(index)?,
        source_sha256: text("source_configuration_sha256")?,
        target_sha256: text("target_configuration_sha256")?,
        source_artifact_sha256: r["subscription"]["source_artifact_sha256"]
            .as_str()
            .map(str::to_owned),
        target_artifact_sha256: r["subscription"]["target_artifact_sha256"]
            .as_str()
            .map(str::to_owned),
    })
}
fn operation_resources(target: &str, artifact: Option<&str>) -> Vec<String> {
    let mut out = vec![
        format!("/var/lib/sbxr/client-identity-target.json root:root 0600 one-link sha256:{target}"),
        "/var/lib/sbxr/client-identity-target.json.sbxr-next root-owned Client Identity target publication".into(),
        format!("/etc/sing-box/.config.json.sbxr-next root:sing-box 0640 one-link sha256:{target}"),
        format!("{STARTUP_PATH}.sbxr-next root-owned Client Identity startup publication"),
    ];
    if let Some(artifact) = artifact {
        out.extend([
            format!("/var/lib/sbxr/subscription-staging/client-artifact root:root 0600 one-link sha256:{artifact}"),
            "/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable Client Identity serving state".into(),
            "/var/lib/sbxr/subscription-staging/client-artifact.sbxr-next root-owned Client Identity artifact publication".into(),
            "/var/lib/sbxr/subscription-staging/serving.json.sbxr-next root-owned Client Identity state publication".into(),
            "/etc/systemd/system/sbxr-subscription.service.sbxr-next root-owned Client Identity serving startup publication".into(),
            "/etc/systemd/system/sbxr-subscription.service.sbxr-next.sbxr-next root-owned Client Identity serving startup publication".into(),
        ]);
    }
    out
}
fn release_wire(r: &ReleaseIdentity) -> Value {
    json!({"Repository":r.repository(),"Tag":r.tag(),"Commit":r.commit(),"IndexSHA256":r.index_sha256()})
}
fn append_resources(
    value: &mut Value,
    additions: Vec<String>,
    creating_release: &ReleaseIdentity,
) -> Result<(), Error> {
    let creator = release_wire(creating_release);
    for addition in additions {
        value["permitted_resources"]
            .as_array_mut()
            .ok_or(Error::Authority)?
            .push(addition.into());
        value["resource_creating_releases"]
            .as_array_mut()
            .ok_or(Error::Authority)?
            .push(creator.clone());
    }
    Ok(())
}
fn begin_record(
    record: &OwnershipRecord,
    operation_id: &str,
    material: &Material,
    startup: StartupAuthority,
    creating_release: &ReleaseIdentity,
) -> Result<OwnershipRecord, Error> {
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
        || record.pending_change().is_some()
        || record.configuration_sha256() != material.source_sha256
        || material.source_sha256 == material.target_sha256
    {
        return Err(Error::Authority);
    }
    let mut value = wire(record)?;
    if value.get("finishing_release_identity").is_some() {
        return Err(Error::Authority);
    }
    if record.schema() == 1 {
        value["schema"] = 2.into();
        value["permitted_resources"][0] =
            "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into();
        value["resource_creating_releases"] =
            vec![release_wire(&record.release_identity()); record.permitted_resources().len()]
                .into();
    }
    if let Some(existing) = value.get("proxy_startup") {
        if existing != &startup.wire() {
            return Err(Error::Authority);
        }
    } else {
        value["proxy_startup"] = startup.wire();
        append_resources(&mut value, startup.resources(), creating_release)?;
    }
    value["client_identity_rotation"] = json!({
        "operation_id":operation_id,"direction":"cleanup","effects":EFFECTS,
        "completed_effects":[],"source_configuration_sha256":material.source_sha256,
        "target_configuration_sha256":material.target_sha256,"checkpoint":Checkpoint::Authorized.as_str(),
    });
    if let Some(serving) = value.get("serving").cloned() {
        value["client_identity_rotation"]["subscription"] = json!({
            "source":serving,"target":serving,
            "source_artifact_sha256":material.source_artifact_sha256,
            "target_artifact_sha256":material.target_artifact_sha256,
        });
    }
    append_resources(
        &mut value,
        operation_resources(
            &material.target_sha256,
            record
                .serving_authority()
                .map(|_| material.target_artifact_sha256.as_str()),
        ),
        creating_release,
    )?;
    validated(&value)
}
/// One exact checkpoint at a time. Revocation and target selection cannot reverse.
pub fn advance_record(record: &OwnershipRecord) -> Result<OwnershipRecord, Error> {
    let r = rotation(record)?;
    let next = Checkpoint::from_index(r.checkpoint as usize + 1)?;
    let mut value = wire(record)?;
    value["client_identity_rotation"]["checkpoint"] = next.as_str().into();
    value["client_identity_rotation"]["completed_effects"] = json!(&EFFECTS[..next as usize]);
    value["client_identity_rotation"]["direction"] =
        if next.direction() == ChangeDirection::Forward {
            "forward"
        } else {
            "cleanup"
        }
        .into();
    if next == Checkpoint::TargetPublished {
        value["configuration_sha256"] = r.target_sha256.clone().into();
        let resources = value["permitted_resources"]
            .as_array_mut()
            .ok_or(Error::Authority)?;
        let slot = resources
            .iter_mut()
            .find(|s| {
                s.as_str()
                    .is_some_and(|s| s.starts_with("/etc/sing-box/config.json "))
            })
            .ok_or(Error::Authority)?;
        *slot = format!("/etc/sing-box/config.json sha256:{}", r.target_sha256).into();
    }
    validated(&value)
}
fn clear_record(record: &OwnershipRecord, retain_startup: bool) -> Result<OwnershipRecord, Error> {
    let r = rotation(record)?;
    if r.checkpoint.direction() == ChangeDirection::Forward
        && (r.checkpoint != Checkpoint::TargetStarted || !retain_startup)
    {
        return Err(Error::Authority);
    }
    let mut value = wire(record)?;
    let object = value.as_object_mut().ok_or(Error::Authority)?;
    object.remove("client_identity_rotation");
    let mut remove = operation_resources(&r.target_sha256, r.target_artifact_sha256.as_deref());
    if !retain_startup {
        let startup = object.remove("proxy_startup").ok_or(Error::Authority)?;
        let startup = StartupAuthority {
            directory_created: startup["directory_created"]
                .as_bool()
                .ok_or(Error::Authority)?,
        };
        remove.extend(startup.resources());
    }
    let creators = value["resource_creating_releases"]
        .as_array()
        .ok_or(Error::Authority)?
        .clone();
    let resources = value["permitted_resources"]
        .as_array()
        .ok_or(Error::Authority)?;
    let kept: Vec<_> = resources
        .iter()
        .zip(creators)
        .filter(|(r, _)| !remove.iter().any(|v| r.as_str() == Some(v)))
        .map(|(r, c)| (r.clone(), c))
        .collect();
    value["permitted_resources"] = kept
        .iter()
        .map(|(r, _)| r.clone())
        .collect::<Vec<_>>()
        .into();
    value["resource_creating_releases"] =
        kept.into_iter().map(|(_, c)| c).collect::<Vec<_>>().into();
    validated(&value)
}
fn initial_successor(
    source: &OwnershipRecord,
    next: &OwnershipRecord,
) -> Result<OwnershipRecord, Error> {
    let r = rotation(next)?;
    if r.checkpoint != Checkpoint::Authorized {
        return Err(Error::Authority);
    }
    let value = wire(next)?;
    let startup = StartupAuthority {
        directory_created: value["proxy_startup"]["directory_created"]
            .as_bool()
            .ok_or(Error::Authority)?,
    };
    let metadata = Material {
        target: Zeroizing::new(Vec::new()),
        artifact: Zeroizing::new(Vec::new()),
        source_sha256: r.source_sha256,
        target_sha256: r.target_sha256,
        source_artifact_sha256: r.source_artifact_sha256.unwrap_or_default(),
        target_artifact_sha256: r.target_artifact_sha256.unwrap_or_default(),
    };
    let creators = next.creating_releases();
    let creating_release = creators.last().ok_or(Error::Authority)?;
    begin_record(
        source,
        &r.operation_id,
        &metadata,
        startup,
        creating_release,
    )
}
/// Structural CAS validation only, never Owner confirmation or host proof.
/// Beginning still requires the non-cloneable PreparedRotation; clearing requires
/// fresh selected-runtime, subscription and exact-staging cleanup proofs.
pub fn permits_successor(source: &OwnershipRecord, next: &OwnershipRecord) -> bool {
    source == next
        || initial_successor(source, next).as_ref() == Ok(next)
        || advance_record(source).as_ref() == Ok(next)
        || clear_record(source, true).as_ref() == Ok(next)
        || clear_record(source, false).as_ref() == Ok(next)
}

/// Secret-bearing prepared material is zeroed on drop and omitted from Debug.
pub struct Material {
    target: Zeroizing<Vec<u8>>,
    artifact: Zeroizing<Vec<u8>>,
    source_sha256: String,
    target_sha256: String,
    source_artifact_sha256: String,
    target_artifact_sha256: String,
}
impl Material {
    pub fn target_configuration(&self) -> &[u8] {
        &self.target
    }
    pub fn target_artifact(&self) -> &[u8] {
        &self.artifact
    }
}
impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Material([REDACTED])")
    }
}
/// Shared strict profile check, including optional VMess. Unknown/duplicate
/// fields and UUID disagreement refuse before any generation or host effect.
fn configuration(bytes: &[u8]) -> Result<ServerConfiguration, Error> {
    ServerConfiguration::decode_supported(bytes).map_err(authority)
}

fn artifact(config: &ServerConfiguration, ipv4: &str) -> Result<ClientArtifact, Error> {
    let value: Value = serde_json::from_slice(config.as_bytes()).map_err(authority)?;
    let inbound = &value["inbounds"][0];
    let text = |v: &Value| v.as_str().ok_or(Error::Authority).map(str::to_owned);
    let identity = Identity::from_private_key(
        &text(&inbound["users"][0]["uuid"])?,
        &text(&inbound["tls"]["reality"]["private_key"])?,
        &text(&inbound["tls"]["reality"]["short_id"][0])?,
    )
    .map_err(authority)?;
    let tag = value["inbounds"][1]["tag"]
        .as_str()
        .and_then(|s| s.strip_prefix("vmess-ws@"));
    ConnectionFacts::new(
        ipv4,
        identity.uuid().as_str(),
        &text(&inbound["tls"]["server_name"])?,
        identity.public_key(),
        identity.short_id(),
        tag,
    )
    .map_err(authority)?
    .subscription_artifact()
    .map_err(authority)
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub current: Vec<u8>,
    pub staged: Option<Vec<u8>>,
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("staged", &self.staged.is_some())
            .finish_non_exhaustive()
    }
}
impl Snapshot {
    fn record(&self) -> Result<OwnershipRecord, Error> {
        let record = OwnershipRecord::decode(&self.current).map_err(authority)?;
        if self.staged.as_ref().is_some_and(|s| s != &self.current) {
            return Err(Error::Publication);
        }
        Ok(record)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    PrepareTarget,
    PublishStartup,
    Reload,
    StopSource,
    PublishTarget,
    StartTarget,
    RestoreSource,
    FinishSubscription,
    RemoveTarget,
    CleanupStartup,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupRoutes {
    pub proxy: bool,
    pub subscription: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quiescence {
    pub inactive: bool,
    pub main_pid_zero: bool,
    pub processes_absent: bool,
    pub listener_absent: bool,
    pub descendants_empty: bool,
    pub subscription_requests_drained: bool,
    pub subscription_descendants_empty: bool,
    pub subscription_listener_absent: bool,
    pub subscription_inactive: bool,
}
impl Quiescence {
    fn accepted(self, subscription: bool) -> bool {
        self.inactive
            && self.main_pid_zero
            && self.processes_absent
            && self.listener_absent
            && self.descendants_empty
            && (!subscription
                || self.subscription_requests_drained
                    && self.subscription_descendants_empty
                    && self.subscription_listener_absent
                    && self.subscription_inactive)
    }
}
/// All calls use the same retained whole-host mutation/package/managed-writer
/// exclusion. An implementation must verify that guard before and after effects.
/// Errors carry no command output, filenames, credentials or supplied text.
pub trait Host {
    fn native_host(&self) -> bool {
        false
    }
    type Guard;
    fn acquire(&mut self) -> Result<Self::Guard, Error>;
    fn verify_guard(&mut self, guard: &Self::Guard) -> Result<(), Error>;
    /// Authenticate the executing installed release independently of creator
    /// provenance. Review/Execute bind this identity and refuse a changed binary.
    fn installed_release(&mut self, guard: &Self::Guard) -> Result<ReleaseIdentity, Error>;
    fn snapshot(&mut self, guard: &Self::Guard) -> Result<Snapshot, Error>;
    /// Reestablish current file+directory durability; never promote staged data.
    fn synchronize(&mut self, guard: &Self::Guard, expected: &[u8]) -> Result<(), Error>;
    /// Authenticate exact installed release, prove Running/source bytes, idle
    /// target/token/staging and fresh package/Certbot/serving admission. Read only.
    fn admit(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<StartupAuthority, Error>;
    /// Verify exact installed release, provenance and recorded protected material;
    /// permit exact cleanup residue already removed, missing target at
    /// Authorized/TargetStarted, and target rename before
    /// its checkpoint only in Forward. Never repair foreign/partial residue.
    fn inspect(&mut self, guard: &Self::Guard, record: &OwnershipRecord) -> Result<(), Error>;
    fn configuration(&mut self, guard: &Self::Guard) -> Result<Vec<u8>, Error>;
    /// CAS no-follow record publication with file+directory fsync. Any uncertain
    /// write returns Publication and ends execution; a new review must reinspect.
    fn publish(
        &mut self,
        guard: &Self::Guard,
        expected: &[u8],
        next: &OwnershipRecord,
    ) -> Result<(), Error>;
    /// Verify effective loaded proxy ExecCondition and every subscription start
    /// route/sandbox. Content on disk alone is insufficient.
    fn routes(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<StartupRoutes, Error>;
    /// Include cgroup descendants, process/listener absence and accepted serving
    /// requests, not merely a successful stop or empty listening socket.
    fn quiescence(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<Quiescence, Error>;
    /// Idempotent, exact-authority effects only. PrepareTarget publishes supplied
    /// material with no-replace+fsync; PublishTarget never reconstructs/generates.
    /// StartTarget/RestoreSource use the exact one-use runtime gate/borrowed lock.
    /// FinishSubscription verifies the selected artifact and saved state, preserves
    /// independent credential/fault/renewal evidence, and stops stale serving.
    /// RemoveTarget/CleanupStartup remove only exact recorded owned material.
    fn effect(
        &mut self,
        guard: &Self::Guard,
        effect: Effect,
        record: &OwnershipRecord,
        material: Option<&Material>,
    ) -> Result<(), Error>;
    fn verify_running(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Declined,
    Rotated,
    Finished,
    CleanedUp,
}
/// Opaque, non-cloneable reviewed authority. Generation happens once here, never
/// in Execute, Finish or any retry. No host material is written during Review.
#[derive(Debug)]
pub struct PreparedRotation {
    snapshot: Snapshot,
    next: OwnershipRecord,
    material: Material,
    executing_release: ReleaseIdentity,
}
#[derive(Debug)]
pub struct PreparedFinish {
    snapshot: Snapshot,
    executing_release: ReleaseIdentity,
}
fn cancelled(stop: &Cancellation) -> Result<(), Error> {
    if stop.is_cancelled() {
        Err(Error::Interrupted)
    } else {
        Ok(())
    }
}
fn checked_snapshot<H: Host>(
    host: &mut H,
    guard: &H::Guard,
    expected: &Snapshot,
) -> Result<OwnershipRecord, Error> {
    host.verify_guard(guard)?;
    let fresh = host.snapshot(guard)?;
    if fresh != *expected {
        return Err(Error::StaleReview);
    }
    let record = fresh.record()?;
    host.synchronize(guard, &fresh.current)?;
    host.verify_guard(guard)?;
    Ok(record)
}
pub fn review<H: Host>(
    host: &mut H,
    entropy: &mut dyn Entropy,
    stop: &Cancellation,
) -> Result<PreparedRotation, Error> {
    cancelled(stop)?;
    let guard = host.acquire()?;
    let snapshot = host.snapshot(&guard)?;
    let record = checked_snapshot(host, &guard, &snapshot)?;
    if record.pending_change().is_some() {
        return Err(Error::Authority);
    }
    let executing_release = host.installed_release(&guard)?;
    let startup = host.admit(&guard, &record)?;
    let mut bytes = Zeroizing::new(host.configuration(&guard)?);
    if sha256_hex(&bytes) != record.configuration_sha256() {
        return Err(Error::Authority);
    }
    let source = configuration(&bytes)?;
    let uuid = ClientUuid::generate_with_entropy(entropy).map_err(authority)?;
    let target = source.with_client_uuid(uuid.as_str()).map_err(authority)?;
    let source_artifact = artifact(&source, record.public_ipv4())?;
    let target_artifact = artifact(&target, record.public_ipv4())?;
    let material = Material {
        source_sha256: sha256_hex(&bytes),
        target_sha256: target.sha256_hex(),
        source_artifact_sha256: sha256_hex(source_artifact.as_bytes()),
        target_artifact_sha256: sha256_hex(target_artifact.as_bytes()),
        target: Zeroizing::new(target.as_bytes().to_vec()),
        artifact: Zeroizing::new(target_artifact.as_bytes().to_vec()),
    };
    bytes.clear();
    if material.source_artifact_sha256 == material.target_artifact_sha256 {
        return Err(Error::Authority);
    }
    let operation = GenerationId::generate_with_entropy(entropy).map_err(authority)?;
    let next = begin_record(
        &record,
        operation.as_str(),
        &material,
        startup,
        &executing_release,
    )?;
    cancelled(stop)?;
    checked_snapshot(host, &guard, &snapshot)?;
    Ok(PreparedRotation {
        snapshot,
        next,
        material,
        executing_release,
    })
}
pub fn review_finish<H: Host>(host: &mut H, stop: &Cancellation) -> Result<PreparedFinish, Error> {
    cancelled(stop)?;
    let guard = host.acquire()?;
    let snapshot = host.snapshot(&guard)?;
    let record = checked_snapshot(host, &guard, &snapshot)?;
    rotation(&record)?;
    host.inspect(&guard, &record)?;
    let executing_release = host.installed_release(&guard)?;
    Ok(PreparedFinish {
        snapshot,
        executing_release,
    })
}
fn publish<H: Host>(
    host: &mut H,
    guard: &H::Guard,
    current: &mut Snapshot,
    next: OwnershipRecord,
    stop: &Cancellation,
) -> Result<OwnershipRecord, Error> {
    cancelled(stop)?;
    checked_snapshot(host, guard, current)?;
    host.publish(guard, &current.current, &next)?;
    let fresh = host.snapshot(guard)?;
    if fresh.current != next.encode().map_err(authority)? || fresh.staged.is_some() {
        return Err(Error::Publication);
    }
    host.synchronize(guard, &fresh.current)?;
    host.verify_guard(guard)?;
    *current = fresh;
    Ok(next)
}
fn run_effect<H: Host>(
    host: &mut H,
    guard: &H::Guard,
    current: &Snapshot,
    record: &OwnershipRecord,
    effect: Effect,
    material: Option<&Material>,
    stop: &Cancellation,
) -> Result<(), Error> {
    cancelled(stop)?;
    checked_snapshot(host, guard, current)?;
    host.inspect(guard, record)?;
    host.effect(guard, effect, record, material)?;
    host.verify_guard(guard)?;
    checked_snapshot(host, guard, current)?;
    cancelled(stop)
}
fn routes<H: Host>(host: &mut H, guard: &H::Guard, record: &OwnershipRecord) -> Result<(), Error> {
    let routes = host.routes(guard, record)?;
    if !routes.proxy || record.serving_authority().is_some() && !routes.subscription {
        return Err(Error::Refused);
    }
    Ok(())
}
pub fn execute<H: Host>(
    host: &mut H,
    prepared: PreparedRotation,
    confirmation: Confirmation,
    stop: &Cancellation,
) -> Result<Outcome, Error> {
    if confirmation != Confirmation::Approved {
        return Ok(Outcome::Declined);
    }
    cancelled(stop)?;
    let guard = host.acquire()?;
    let mut current = prepared.snapshot;
    let record = checked_snapshot(host, &guard, &current)?;
    if host.installed_release(&guard)? != prepared.executing_release {
        return Err(Error::StaleReview);
    }
    if host.admit(&guard, &record)?.wire() != wire(&prepared.next)?["proxy_startup"] {
        return Err(Error::StaleReview);
    }
    let record = publish(host, &guard, &mut current, prepared.next, stop)?;
    run_effect(
        host,
        &guard,
        &current,
        &record,
        Effect::PrepareTarget,
        Some(&prepared.material),
        stop,
    )?;
    let next = advance_record(&record)?;
    let record = publish(host, &guard, &mut current, next, stop)?;
    forward(host, &guard, current, record, stop)?;
    Ok(Outcome::Rotated)
}
pub fn finish<H: Host>(
    host: &mut H,
    prepared: PreparedFinish,
    confirmation: Confirmation,
    stop: &Cancellation,
) -> Result<Outcome, Error> {
    if confirmation != Confirmation::Approved {
        return Ok(Outcome::Declined);
    }
    cancelled(stop)?;
    let guard = host.acquire()?;
    let mut current = prepared.snapshot;
    let record = checked_snapshot(host, &guard, &current)?;
    if host.installed_release(&guard)? != prepared.executing_release {
        return Err(Error::StaleReview);
    }
    host.inspect(&guard, &record)?;
    let r = rotation(&record)?;
    if r.checkpoint.direction() == ChangeDirection::Forward {
        forward(host, &guard, current, record, stop)?;
        return Ok(Outcome::Finished);
    }
    let config = Zeroizing::new(host.configuration(&guard)?);
    if sha256_hex(&config) != r.source_sha256 {
        return Err(Error::Authority);
    }
    run_effect(
        host,
        &guard,
        &current,
        &record,
        Effect::RestoreSource,
        None,
        stop,
    )?;
    host.verify_running(&guard, &record)?;
    run_effect(
        host,
        &guard,
        &current,
        &record,
        Effect::FinishSubscription,
        None,
        stop,
    )?;
    run_effect(
        host,
        &guard,
        &current,
        &record,
        Effect::RemoveTarget,
        None,
        stop,
    )?;
    let retain = routes(host, &guard, &record).is_ok();
    if !retain {
        run_effect(
            host,
            &guard,
            &current,
            &record,
            Effect::CleanupStartup,
            None,
            stop,
        )?;
    }
    if sha256_hex(&host.configuration(&guard)?) != r.source_sha256 {
        return Err(Error::Authority);
    }
    let next = clear_record(&record, retain)?;
    publish(host, &guard, &mut current, next, stop)?;
    Ok(Outcome::CleanedUp)
}
fn forward<H: Host>(
    host: &mut H,
    guard: &H::Guard,
    mut current: Snapshot,
    mut record: OwnershipRecord,
    stop: &Cancellation,
) -> Result<(), Error> {
    loop {
        cancelled(stop)?;
        checked_snapshot(host, guard, &current)?;
        host.inspect(guard, &record)?;
        let cp = rotation(&record)?.checkpoint;
        if (cp as usize) >= Checkpoint::RouteVerified as usize {
            routes(host, guard, &record)?;
        }
        let effect = match cp {
            Checkpoint::TargetPrepared => Some(Effect::PublishStartup),
            Checkpoint::IntegrationPublished => Some(Effect::Reload),
            Checkpoint::Reloaded => {
                routes(host, guard, &record)?;
                None
            }
            Checkpoint::RouteVerified => None,
            Checkpoint::Gated => Some(Effect::StopSource),
            Checkpoint::Stopped | Checkpoint::Quiescent => {
                // Reprove after restart; a persisted empty cgroup is not a fresh
                // observation and cannot authorize revocation on its own.
                if !host
                    .quiescence(guard, &record)?
                    .accepted(record.serving_authority().is_some())
                {
                    return Err(Error::Refused);
                }
                None
            }
            Checkpoint::Revoked => Some(Effect::PublishTarget),
            Checkpoint::TargetPublished => Some(Effect::StartTarget),
            Checkpoint::TargetStarted => {
                host.verify_running(guard, &record)?;
                run_effect(
                    host,
                    guard,
                    &current,
                    &record,
                    Effect::FinishSubscription,
                    None,
                    stop,
                )?;
                run_effect(
                    host,
                    guard,
                    &current,
                    &record,
                    Effect::RemoveTarget,
                    None,
                    stop,
                )?;
                host.verify_running(guard, &record)?;
                let next = clear_record(&record, true)?;
                publish(host, guard, &mut current, next, stop)?;
                return Ok(());
            }
            Checkpoint::Authorized => return Err(Error::Authority),
        };
        if let Some(effect) = effect {
            run_effect(host, guard, &current, &record, effect, None, stop)?;
        }
        let next = advance_record(&record)?;
        record = publish(host, guard, &mut current, next, stop)?;
    }
}
