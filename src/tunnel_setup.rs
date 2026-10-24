//! Optional Standard + dedicated VMess setup over explicitly injected effects.
//! No native host, token-file access, Cloudflare API or network client is supplied.
use crate::{
    domain::Confirmation,
    host::{Operation, process::Cancellation},
    identity_generation::{Entropy, OsEntropy},
    records::{
        OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase, TunnelAuthority,
        sha256_hex,
    },
    runtime_handoff::ProcessIdentity,
    server_configuration::{ServerConfiguration, valid_cloudflared_version},
    subscription_artifact::{VMESS_WEBSOCKET_PATH, valid_vmess_hostname},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    rc::Rc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const CONNECTION_VERIFIED: &str = "PROXY-INSTALLATION-VMESS-CONNECTION-VERIFIED";
pub const CONNECTION_PENDING: &str = "PROXY-INSTALLATION-VMESS-CONNECTION-PENDING";
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(40);

/// Descriptor observations, supplied by the protected-file adapter, not by UI.
/// `stable` binds both the descriptor and final no-follow pathname to one inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFacts {
    pub uid: u32,
    pub mode: u32,
    pub links: u64,
    pub regular: bool,
    pub stable: bool,
    pub protected_parents: bool,
}
impl FileFacts {
    fn accepted(self, mode: u32) -> bool {
        self.uid == 0
            && self.mode == mode
            && self.links == 1
            && self.regular
            && self.stable
            && self.protected_parents
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prerequisites(TunnelAuthority);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    a: String,
    t: String,
    s: String,
}
impl Drop for Claims {
    fn drop(&mut self) {
        self.a.zeroize();
        self.s.zeroize();
    }
}
impl Prerequisites {
    /// Pure inspection of supplied bytes; never executes the supplied binary.
    /// Hash the original token bytes, including their optional final newline.
    pub fn inspect(
        token: &[u8],
        token_facts: FileFacts,
        binary: &[u8],
        binary_facts: FileFacts,
        version: &str,
    ) -> Result<Self, Error> {
        if !token_facts.accepted(0o600) || token.is_empty() || token.len() > 16_384 {
            return Err(Error::TokenFile);
        }
        let line = token.strip_suffix(b"\n").unwrap_or(token);
        if line.is_empty() || line.iter().any(u8::is_ascii_whitespace) {
            return Err(Error::TokenClaims);
        }
        let decoded = Zeroizing::new(STANDARD.decode(line).map_err(|_| Error::TokenClaims)?);
        let claims: Claims = serde_json::from_slice(&decoded).map_err(|_| Error::TokenClaims)?;
        if claims.a.is_empty() || claims.s.is_empty() {
            return Err(Error::TokenClaims);
        }
        if !binary_facts.accepted(0o755) || binary.is_empty() || binary.len() > 128 << 20 {
            return Err(Error::BinaryFile);
        }
        if !valid_cloudflared_version(version) {
            return Err(Error::BinaryVersion);
        }
        let authority = TunnelAuthority::new(&claims.t, &sha256_hex(token), &sha256_hex(binary))
            .map_err(|_| Error::TokenClaims)?;
        Ok(Self(authority))
    }
    pub fn authority(&self) -> &TunnelAuthority {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Standard(Operation),
    InstallConnector,
    StartConnector,
    RemoveConnector,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    StaleReview,
    TokenFile,
    TokenClaims,
    BinaryFile,
    BinaryVersion,
    PrerequisitesChanged,
    Interrupted,
    TimedOut,
    Publication,
    Effect(Effect),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authority => "Exact setup authority, idle state or owned resources could not be verified; preserve unknown state.",
            Self::StaleReview => "Setup facts changed or this review expired; review again before applying.",
            Self::TokenFile => "Keep the Owner token in the protected root-owned 0600 one-link token file; never enter it in the hostname field.",
            Self::TokenClaims => "The protected file is not an exact remotely managed dedicated tunnel token.",
            Self::BinaryFile => "The Owner-installed cloudflared binary must be root-owned 0755, regular, stable and one-link.",
            Self::BinaryVersion => "cloudflared 2025.4.0 or newer is required for --token-file.",
            Self::PrerequisitesChanged => "Restore the exact reviewed token and cloudflared binary; their replacement is not a setup repair.",
            Self::Interrupted => "Setup or connection check was cancelled; inspect durable authority before recovery.",
            Self::TimedOut => "The bounded operation timed out; inspect durable authority before recovery.",
            Self::Publication => "Record publication is incomplete or uncertain; re-read and synchronize exact authority before any further effect.",
            Self::Effect(Effect::InstallConnector) => "The dedicated connector could not be installed; inspect only sbxr-tunnel.service and follow the recorded recovery direction.",
            Self::Effect(Effect::StartConnector) => "The dedicated connector needs completion; restore reviewed prerequisites and choose Finish setup.",
            Self::Effect(Effect::RemoveConnector) => "Dedicated connector cleanup is incomplete; preserve foreign files and restore exact unit/link ownership.",
            Self::Effect(Effect::Standard(_)) => "A recorded Standard setup effect is incomplete; follow the durable recovery direction.",
        })
    }
}
impl std::error::Error for Error {}

/// One deadline is shared across all effects of a connection check. Adapters
/// must use `remaining` and cancellation while blocked, not just at call entry.
pub struct Budget<'a> {
    stop: &'a Cancellation,
    deadline: Instant,
}
impl<'a> Budget<'a> {
    pub fn new(stop: &'a Cancellation, timeout: Duration) -> Self {
        Self {
            stop,
            deadline: Instant::now() + timeout.min(CHECK_TIMEOUT),
        }
    }
    pub fn remaining(&self) -> Result<Duration, Error> {
        if self.stop.cancelled() {
            return Err(Error::Interrupted);
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Error::TimedOut)
    }
    pub fn cancellation(&self) -> &Cancellation {
        self.stop
    }
}
fn active(stop: &Cancellation) -> Result<(), Error> {
    if stop.cancelled() {
        Err(Error::Interrupted)
    } else {
        Ok(())
    }
}

/// Exact current/staged protected bytes; no implicit staged-record promotion.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub current: Option<Vec<u8>>,
    pub staged: Option<Vec<u8>>,
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tunnel snapshot (redacted)")
    }
}
impl Snapshot {
    fn record(&self) -> Result<OwnershipRecord, Error> {
        if self.staged.is_some() {
            return Err(Error::Publication);
        }
        OwnershipRecord::decode(self.current.as_deref().ok_or(Error::Authority)?)
            .map_err(|_| Error::Authority)
    }
    fn recovery_record(&self) -> Result<OwnershipRecord, Error> {
        let record = OwnershipRecord::decode(self.current.as_deref().ok_or(Error::Authority)?)
            .map_err(|_| Error::Authority)?;
        if let Some(bytes) = &self.staged {
            let next = OwnershipRecord::decode(bytes).map_err(|_| Error::Publication)?;
            if record.recovery_direction() != RecoveryDirection::Cleanup
                || next.recovery_direction() != RecoveryDirection::Cleanup
                || !record.permits_successor(&next)
            {
                return Err(Error::Publication);
            }
        }
        Ok(record)
    }
}
/// The fingerprint binds protected root identity, installed bytes, host/package
/// admission, services, fixed TCP443/10000 listeners and exact owned residue.
/// `ready` includes validated configuration, retained locks and stopped proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub fingerprint: String,
    pub empty: bool,
    pub ready: bool,
    pub stopped: bool,
    pub running: bool,
}

/// All operations retain the same Whole-Host Mutation Lock and package/writer
/// exclusion. A successful command alone is never an ownership observation.
pub trait Host {
    type Guard;
    type Probe: ProbeSession;
    fn acquire(&mut self, stop: &Cancellation) -> Result<Self::Guard, Error>;
    fn verify_guard(&mut self, guard: &Self::Guard) -> Result<(), Error>;
    fn installed_release(&mut self, guard: &Self::Guard) -> Result<ReleaseIdentity, Error>;
    /// Fresh globally routable IPv4 observation bound into the review fingerprint.
    fn public_ipv4(&mut self, guard: &Self::Guard) -> Result<String, Error>;
    fn snapshot(&mut self, guard: &Self::Guard) -> Result<Snapshot, Error>;
    /// Fresh protected no-follow token/binary reads, exact metadata, pinned inode
    /// and bounded version query. Preserve both prerequisites on all paths.
    fn prerequisites(
        &mut self,
        guard: &Self::Guard,
        stop: &Cancellation,
    ) -> Result<Prerequisites, Error>;
    /// Refuse foreign unit fragments, drop-ins, effective commands and links.
    /// Permit exact owned partial effects only when already recorded.
    fn inspect(
        &mut self,
        guard: &Self::Guard,
        record: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<Inspection, Error>;
    fn configuration(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<Vec<u8>, Error>;
    fn synchronize(&mut self, guard: &Self::Guard, expected: &[u8]) -> Result<(), Error>;
    /// Descriptor-relative exact CAS, no-replace publication and file/dir fsync.
    /// Any uncertain result stops orchestration with Error::Publication.
    fn publish(
        &mut self,
        guard: &Self::Guard,
        expected: Option<&[u8]>,
        next: &OwnershipRecord,
    ) -> Result<(), Error>;
    /// Idempotent effects limited to recorded resources. InstallConnector uses
    /// server_configuration::tunnel_unit and its exact link; StartConnector
    /// checks loaded effective unit and starts only sbxr-tunnel.service.
    /// Standard start must use the existing runtime_handoff retained-lock route.
    /// Removal verifies exact ownership and proves dedicated cgroup quiescence;
    /// it does not read/require/remove the Owner token, binary or account data.
    fn effect(
        &mut self,
        guard: &Self::Guard,
        effect: Effect,
        record: &OwnershipRecord,
        configuration: Option<&ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<(), Error>;
    fn remove_completed_cleanup(
        &mut self,
        guard: &Self::Guard,
        expected: &[u8],
    ) -> Result<(), Error>;
    /// Direct HTTP/1.1; no environment proxy or redirect, <=16KiB headers,
    /// normal trusted TLS/hostname verification for the public request.
    fn websocket(
        &mut self,
        guard: &Self::Guard,
        request: &WebSocketRequest,
        budget: &Budget<'_>,
    ) -> Result<WebSocketReply, ProbeProblem>;
    fn probe_port(&mut self, guard: &Self::Guard, budget: &Budget<'_>)
    -> Result<u16, ProbeProblem>;
    /// Execute only the authenticated pinned sing-box with the supplied config
    /// through stdin, suppressed output and no secret in argv/environment/files.
    /// A failed spawn must reap any partially started process before returning.
    fn spawn_probe(
        &mut self,
        guard: &Self::Guard,
        plan: &ProbePlan,
        budget: &Budget<'_>,
    ) -> Result<Self::Probe, ProbeProblem>;
}

pub struct PreparedAction {
    owner: Rc<()>,
    snapshot: Snapshot,
    inspection: Inspection,
    release: ReleaseIdentity,
    action: PreparedKind,
}
enum PreparedKind {
    Setup {
        record: Box<OwnershipRecord>,
        configuration: ServerConfiguration,
        prerequisites: Prerequisites,
    },
    Finish,
}
impl fmt::Debug for PreparedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prepared tunnel action (redacted)")
    }
}
impl PreparedAction {
    pub fn tunnel_id(&self) -> Result<String, Error> {
        match &self.action {
            PreparedKind::Setup { prerequisites, .. } => Ok(prerequisites.0.tunnel_id().into()),
            PreparedKind::Finish => self
                .snapshot
                .recovery_record()?
                .tunnel_authority()
                .map(|a| a.tunnel_id().into())
                .ok_or(Error::Authority),
        }
    }
    pub fn recovery_direction(&self) -> Option<RecoveryDirection> {
        match self.action {
            PreparedKind::Setup { .. } => None,
            PreparedKind::Finish => self
                .snapshot
                .recovery_record()
                .ok()
                .map(|r| r.recovery_direction()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupOutcome {
    Cancelled,
    CleanedUp,
    RunningConnectionPending,
}
pub struct TunnelInstallation<H: Host> {
    host: H,
    owner: Rc<()>,
}
impl<H: Host> TunnelInstallation<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            owner: Rc::new(()),
        }
    }
    pub fn host(&self) -> &H {
        &self.host
    }
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }
    pub fn into_host(self) -> H {
        self.host
    }
    pub fn review_setup(
        &mut self,
        hostname: &str,
        configuration: ServerConfiguration,
        stop: &Cancellation,
    ) -> Result<PreparedAction, Error> {
        self.owner = Rc::new(());
        active(stop)?;
        validate_configuration(&configuration, hostname)?;
        let guard = self.host.acquire(stop)?;
        let release = self.host.installed_release(&guard)?;
        let snapshot = self.host.snapshot(&guard)?;
        if snapshot.current.is_some() || snapshot.staged.is_some() {
            return Err(Error::Authority);
        }
        let inspection = self.host.inspect(&guard, None, stop)?;
        if !inspection.empty {
            return Err(Error::Authority);
        }
        let prerequisites = self.host.prerequisites(&guard, stop)?;
        // Public IPv4 is part of the authenticated configuration's host admission.
        // Host inspection binds its value through this separately supplied fact.
        let ipv4 = self.host.public_ipv4(&guard)?;
        let record = OwnershipRecord::new_tunnel_setup(
            release.clone(),
            &ipv4,
            &configuration.sha256_hex(),
            prerequisites.0.clone(),
        )
        .map_err(|_| Error::Authority)?;
        self.host.verify_guard(&guard)?;
        active(stop)?;
        Ok(PreparedAction {
            owner: Rc::clone(&self.owner),
            snapshot,
            inspection,
            release,
            action: PreparedKind::Setup {
                record: Box::new(record),
                configuration,
                prerequisites,
            },
        })
    }
    pub fn review_finish(&mut self, stop: &Cancellation) -> Result<PreparedAction, Error> {
        self.owner = Rc::new(());
        active(stop)?;
        let guard = self.host.acquire(stop)?;
        let release = self.host.installed_release(&guard)?;
        let snapshot = self.host.snapshot(&guard)?;
        let record = snapshot.recovery_record()?;
        setup_authority(&record, &release)?;
        if !matches!(
            record.recovery_direction(),
            RecoveryDirection::Cleanup | RecoveryDirection::FinishSetup
        ) {
            return Err(Error::Authority);
        }
        let inspection = self.host.inspect(&guard, Some(&record), stop)?;
        self.host.verify_guard(&guard)?;
        active(stop)?;
        Ok(PreparedAction {
            owner: Rc::clone(&self.owner),
            snapshot,
            inspection,
            release,
            action: PreparedKind::Finish,
        })
    }
    pub fn execute(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
        stop: &Cancellation,
    ) -> Result<SetupOutcome, Error> {
        let valid = Rc::ptr_eq(&self.owner, &prepared.owner);
        self.owner = Rc::new(());
        if !valid {
            return Err(Error::StaleReview);
        }
        if confirmation == Confirmation::Declined {
            return Ok(SetupOutcome::Cancelled);
        }
        active(stop)?;
        let guard = self.host.acquire(stop)?;
        if self.host.installed_release(&guard)? != prepared.release
            || self.host.snapshot(&guard)? != prepared.snapshot
        {
            return Err(Error::StaleReview);
        }
        let existing = prepared
            .snapshot
            .current
            .as_deref()
            .map(OwnershipRecord::decode)
            .transpose()
            .map_err(|_| Error::Authority)?;
        if self.host.inspect(&guard, existing.as_ref(), stop)? != prepared.inspection {
            return Err(Error::StaleReview);
        }
        self.host.verify_guard(&guard)?;
        active(stop)?;
        match prepared.action {
            PreparedKind::Setup {
                record,
                configuration,
                prerequisites,
            } => {
                if self.host.prerequisites(&guard, stop)? != prerequisites
                    || self.host.public_ipv4(&guard)? != record.public_ipv4()
                {
                    return Err(Error::PrerequisitesChanged);
                }
                self.publish(&guard, None, &record, stop)?;
                self.drive(&guard, *record, Some(configuration), stop)
            }
            PreparedKind::Finish => {
                let record = prepared.snapshot.recovery_record()?;
                setup_authority(&record, &prepared.release)?;
                if record.recovery_direction() == RecoveryDirection::Cleanup {
                    self.cleanup(&guard, record, stop)
                } else {
                    self.prerequisites_match(&guard, &record, stop)?;
                    let configuration = self.configuration(&guard, &record)?;
                    self.drive(&guard, record, Some(configuration), stop)
                }
            }
        }
    }
    fn prerequisites_match(
        &mut self,
        guard: &H::Guard,
        record: &OwnershipRecord,
        stop: &Cancellation,
    ) -> Result<(), Error> {
        if Some(self.host.prerequisites(guard, stop)?.0) != record.tunnel_authority() {
            return Err(Error::PrerequisitesChanged);
        }
        Ok(())
    }
    fn configuration(
        &mut self,
        guard: &H::Guard,
        record: &OwnershipRecord,
    ) -> Result<ServerConfiguration, Error> {
        let bytes = Zeroizing::new(self.host.configuration(guard, record)?);
        let config = ServerConfiguration::decode_supported(&bytes).map_err(|_| Error::Authority)?;
        if config.sha256_hex() != record.configuration_sha256() || config.is_standard_only() {
            return Err(Error::Authority);
        }
        config
            .connection_facts(record.public_ipv4())
            .map_err(|_| Error::Authority)?;
        Ok(config)
    }
    fn publish(
        &mut self,
        guard: &H::Guard,
        previous: Option<&OwnershipRecord>,
        next: &OwnershipRecord,
        stop: &Cancellation,
    ) -> Result<(), Error> {
        active(stop)?;
        self.host.verify_guard(guard)?;
        let expected = previous
            .map(OwnershipRecord::encode)
            .transpose()
            .map_err(|_| Error::Authority)?;
        self.host
            .publish(guard, expected.as_deref(), next)
            .map_err(|_| Error::Publication)?;
        self.host.verify_guard(guard)?;
        active(stop)
    }
    fn effect(
        &mut self,
        guard: &H::Guard,
        effect: Effect,
        record: &OwnershipRecord,
        config: Option<&ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<(), Error> {
        active(stop)?;
        self.host.verify_guard(guard)?;
        self.host.effect(guard, effect, record, config, stop)?;
        self.host.verify_guard(guard)?;
        active(stop)
    }
    fn drive(
        &mut self,
        guard: &H::Guard,
        mut record: OwnershipRecord,
        config: Option<ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<SetupOutcome, Error> {
        self.host
            .synchronize(guard, &record.encode().map_err(|_| Error::Authority)?)?;
        loop {
            active(stop)?;
            let next = record
                .next_setup_checkpoint()
                .map_err(|_| Error::Authority)?;
            if let Some(op) = setup_operation(next.phase()) {
                self.effect(guard, Effect::Standard(op), &record, config.as_ref(), stop)?;
            }
            if next.phase() == SetupPhase::ActivationCommitted {
                self.prerequisites_match(guard, &record, stop)?;
                self.effect(
                    guard,
                    Effect::InstallConnector,
                    &record,
                    config.as_ref(),
                    stop,
                )?;
                let inspection = self.host.inspect(guard, Some(&record), stop)?;
                if !inspection.ready || !inspection.stopped {
                    return Err(Error::Authority);
                }
            }
            if next.phase() == SetupPhase::Running {
                self.prerequisites_match(guard, &record, stop)?;
                self.effect(
                    guard,
                    Effect::InstallConnector,
                    &record,
                    config.as_ref(),
                    stop,
                )?;
                self.effect(
                    guard,
                    Effect::StartConnector,
                    &record,
                    config.as_ref(),
                    stop,
                )?;
                if !self.host.inspect(guard, Some(&record), stop)?.running {
                    return Err(Error::Authority);
                }
            }
            self.publish(guard, Some(&record), &next, stop)?;
            record = next;
            if record.phase() == SetupPhase::Running {
                return Ok(SetupOutcome::RunningConnectionPending);
            }
        }
    }
    fn cleanup(
        &mut self,
        guard: &H::Guard,
        mut record: OwnershipRecord,
        stop: &Cancellation,
    ) -> Result<SetupOutcome, Error> {
        if record.recovery_direction() != RecoveryDirection::Cleanup {
            return Err(Error::Authority);
        }
        if let Some(bytes) = self.host.snapshot(guard)?.staged {
            let next = OwnershipRecord::decode(&bytes).map_err(|_| Error::Publication)?;
            if !record.permits_successor(&next)
                || next.recovery_direction() != RecoveryDirection::Cleanup
            {
                return Err(Error::Publication);
            }
            self.publish(guard, Some(&record), &next, stop)?;
            record = next;
        }
        self.host
            .synchronize(guard, &record.encode().map_err(|_| Error::Authority)?)?;
        // Remove the dedicated connector before Standard cleanup. Replay is safe
        // after any checkpoint and needs neither token nor cloudflared binary.
        self.effect(guard, Effect::RemoveConnector, &record, None, stop)?;
        let steps = [
            Operation::StopDisableService,
            Operation::UnmaskService,
            Operation::RemovePackageArtifact,
            Operation::RemovePackage,
            Operation::RemoveConfigurationState,
            Operation::RemovePackageIdentity,
            Operation::RemoveAptSource,
            Operation::RemoveAptKey,
        ];
        while (record.cleanup_checkpoint() as usize) < steps.len() {
            self.effect(
                guard,
                Effect::Standard(steps[record.cleanup_checkpoint() as usize]),
                &record,
                None,
                stop,
            )?;
            let next = record
                .next_cleanup_checkpoint()
                .map_err(|_| Error::Authority)?;
            self.publish(guard, Some(&record), &next, stop)?;
            record = next;
        }
        if !self.host.inspect(guard, Some(&record), stop)?.empty {
            return Err(Error::Authority);
        }
        active(stop)?;
        self.host.verify_guard(guard)?;
        self.host
            .remove_completed_cleanup(guard, &record.encode().map_err(|_| Error::Authority)?)?;
        self.host.verify_guard(guard)?;
        active(stop)?;
        if !self.host.inspect(guard, None, stop)?.empty {
            return Err(Error::Authority);
        }
        Ok(SetupOutcome::CleanedUp)
    }
}

fn validate_configuration(config: &ServerConfiguration, hostname: &str) -> Result<(), Error> {
    if !valid_vmess_hostname(hostname) {
        return Err(Error::Authority);
    }
    let checked =
        ServerConfiguration::decode_supported(config.as_bytes()).map_err(|_| Error::Authority)?;
    let value: Value = serde_json::from_slice(checked.as_bytes()).map_err(|_| Error::Authority)?;
    if value["inbounds"][1]["tag"].as_str() != Some(format!("vmess-ws@{hostname}").as_str()) {
        return Err(Error::Authority);
    }
    Ok(())
}
fn setup_authority(record: &OwnershipRecord, release: &ReleaseIdentity) -> Result<(), Error> {
    if record.schema() != 1
        || record.tunnel_authority().is_none()
        || record.pending_change().is_some()
        || record.release_identity() != *release
        || record.lock_provisioning_sha256().is_none()
        || record.cleanup_checkpoint() > 8
        || record.recovery_direction() == RecoveryDirection::Removal
    {
        return Err(Error::Authority);
    }
    Ok(())
}
fn setup_operation(phase: SetupPhase) -> Option<Operation> {
    Some(match phase {
        SetupPhase::AptKeyInstalled => Operation::InstallAptKey,
        SetupPhase::AptSourceInstalled => Operation::InstallAptSource,
        SetupPhase::ServiceMasked => Operation::MaskService,
        SetupPhase::PackageInstalled => Operation::InstallPackage,
        SetupPhase::PackageHeld => Operation::HoldPackage,
        SetupPhase::StateDirectoryCreated => Operation::CreateStateDirectory,
        SetupPhase::ConfigurationInstalled => Operation::InstallConfiguration,
        SetupPhase::ConfigurationValidated => Operation::ValidateConfiguration,
        SetupPhase::ServiceUnmasked => Operation::UnmaskService,
        SetupPhase::ServiceEnabled => Operation::EnableService,
        SetupPhase::ServiceStarted => Operation::StartService,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStage {
    Authority,
    LocalWebSocket,
    PublicWebSocket,
    Traffic,
    ProbeCleanup,
    Complete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeProblem {
    Authority,
    Cancelled,
    TimedOut,
    Entropy,
    Dns,
    TlsCertificate,
    TlsHandshake,
    Network,
    Http(u16),
    InvalidUpgrade,
    InvalidConnection,
    InvalidAccept,
    Headers,
    Redirect,
    UntrustedTls,
    Port,
    Spawn,
    Listener,
    Traffic,
    Egress,
    Exited,
    Cleanup,
}
impl fmt::Display for ProbeProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Http(status) = self {
            return write!(f, "HTTP {status} (unexpected status)");
        }
        f.write_str(match self {
            Self::Authority => "Protected profile, installed bytes, exclusion or local runtime changed.",
            Self::Cancelled => "Connection check cancelled.",
            Self::TimedOut => "Connection check timed out.",
            Self::Entropy => "Probe key or credentials could not be generated.",
            Self::Dns => "DNS lookup failed.",
            Self::TlsCertificate => "TLS certificate verification failed; keep trust verification enabled.",
            Self::TlsHandshake => "TLS handshake failed.",
            Self::Network => "Network connection failed.",
            Self::InvalidUpgrade => "Invalid WebSocket Upgrade header.",
            Self::InvalidConnection => "Invalid WebSocket Connection header.",
            Self::InvalidAccept => "Invalid Sec-WebSocket-Accept header.",
            Self::Headers => "Response headers were duplicate, invalid or over the fixed limit.",
            Self::Redirect => "Redirects are not accepted as connection evidence.",
            Self::UntrustedTls => "Trusted public TLS was not proved.",
            Self::Port => "A temporary loopback probe port could not be allocated.",
            Self::Spawn => "The isolated sing-box probe could not start.",
            Self::Listener => "The authenticated loopback listener is not proved to belong exclusively to the isolated probe.",
            Self::Traffic => "Authenticated VMess-only HTTPS traffic failed after WebSocket upgrade; check the selected tunnel/origin and Client Identity.",
            Self::Egress => "HTTPS egress did not return the exact expected server IPv4; wrong origin, changed egress or check-service failure is not a pass.",
            Self::Exited => "The isolated sing-box probe stopped during the check.",
            Self::Cleanup => "The isolated probe could not be proved stopped and reaped.",
            Self::Http(_) => unreachable!(),
        })
    }
}
impl std::error::Error for ProbeProblem {}
fn probe_budget(budget: &Budget<'_>) -> Result<(), ProbeProblem> {
    budget.remaining().map(|_| ()).map_err(|e| {
        if e == Error::Interrupted {
            ProbeProblem::Cancelled
        } else {
            ProbeProblem::TimedOut
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionCheck {
    local_running: bool,
    stage: CheckStage,
    problem: Option<ProbeProblem>,
}
impl ConnectionCheck {
    pub fn verified(&self) -> bool {
        self.stage == CheckStage::Complete && self.problem.is_none()
    }
    pub fn code(&self) -> &'static str {
        if self.verified() {
            CONNECTION_VERIFIED
        } else {
            CONNECTION_PENDING
        }
    }
    pub fn local_running(&self) -> bool {
        self.local_running
    }
    pub fn stage(&self) -> CheckStage {
        self.stage
    }
    pub fn problem(&self) -> Option<ProbeProblem> {
        self.problem
    }
    pub fn message(&self) -> &'static str {
        if self.verified() {
            "VMess public connection verified from this server. Outside-client, Karing and deployment acceptance remain unverified."
        } else {
            "VMess public connection pending. Inspect the failed stage, correct only the dedicated connector or Cloudflare route, then check again; reinstalling is not needed."
        }
    }
    fn pending(local_running: bool, stage: CheckStage, problem: ProbeProblem) -> Self {
        Self {
            local_running,
            stage,
            problem: Some(problem),
        }
    }
}

/// Fixed direct targets; callers cannot supply a URL, insecure public scheme,
/// origin port, request path, credentials or an alternative egress service.
pub struct WebSocketRequest {
    hostname: Option<String>,
    key: String,
}
impl WebSocketRequest {
    fn new(hostname: Option<&str>, entropy: &mut dyn Entropy) -> Result<Self, ProbeProblem> {
        let mut nonce = [0; 16];
        entropy
            .fill(&mut nonce)
            .map_err(|_| ProbeProblem::Entropy)?;
        Ok(Self {
            hostname: hostname.map(str::to_owned),
            key: STANDARD.encode(nonce),
        })
    }
    pub fn url(&self) -> String {
        match &self.hostname {
            Some(h) => format!("https://{h}{VMESS_WEBSOCKET_PATH}"),
            None => format!("http://127.0.0.1:10000{VMESS_WEBSOCKET_PATH}"),
        }
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn trusted_tls_required(&self) -> bool {
        self.hostname.is_some()
    }
    pub fn max_header_bytes(&self) -> usize {
        16 << 10
    }
    pub fn follows_redirects(&self) -> bool {
        false
    }
    pub fn uses_environment_proxy(&self) -> bool {
        false
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    fn validate(&self, reply: WebSocketReply) -> Result<(), ProbeProblem> {
        if reply.redirected {
            return Err(ProbeProblem::Redirect);
        }
        if self.trusted_tls_required() && !reply.trusted_tls {
            return Err(ProbeProblem::UntrustedTls);
        }
        if reply.status != 101 {
            return Err(ProbeProblem::Http(reply.status));
        }
        if reply.headers.len() > 64
            || reply
                .headers
                .iter()
                .map(|(k, v)| k.len().saturating_add(v.len()).saturating_add(4))
                .sum::<usize>()
                > self.max_header_bytes()
        {
            return Err(ProbeProblem::Headers);
        }
        let header = |name: &str| -> Result<&str, ProbeProblem> {
            let mut found = reply
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name));
            let value = &found.next().ok_or(ProbeProblem::Headers)?.1;
            if found.next().is_some() || value.contains(['\r', '\n']) {
                return Err(ProbeProblem::Headers);
            }
            Ok(value)
        };
        if !header("upgrade")?.eq_ignore_ascii_case("websocket") {
            return Err(ProbeProblem::InvalidUpgrade);
        }
        if !header("connection")?
            .split(',')
            .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
        {
            return Err(ProbeProblem::InvalidConnection);
        }
        if header("sec-websocket-accept")? != websocket_accept(&self.key) {
            return Err(ProbeProblem::InvalidAccept);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct WebSocketReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub trusted_tls: bool,
    pub redirected: bool,
}

/// RFC6455's fixed SHA-1 challenge, used only for protocol upgrade validation.
/// This is not a signature or secret-authentication primitive.
pub fn websocket_accept(key: &str) -> String {
    let mut bytes = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").into_bytes();
    let bits = (bytes.len() as u64) * 8;
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bits.to_be_bytes());
    let mut hash = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for chunk in bytes.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (word, raw) in words.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes(raw.try_into().expect("four-byte chunk"));
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = hash;
        for (i, word) in words.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (state, value) in hash.iter_mut().zip([a, b, c, d, e]) {
            *state = state.wrapping_add(value);
        }
    }
    STANDARD.encode(
        hash.iter()
            .flat_map(|word| word.to_be_bytes())
            .collect::<Vec<_>>(),
    )
}

pub struct ProbePlan {
    bytes: Zeroizing<Vec<u8>>,
    port: u16,
    password: Zeroizing<String>,
}
impl fmt::Debug for ProbePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VMess-only probe plan (redacted)")
    }
}
impl ProbePlan {
    fn new(
        config: &ServerConfiguration,
        port: u16,
        entropy: &mut dyn Entropy,
    ) -> Result<Self, ProbeProblem> {
        if port == 0 {
            return Err(ProbeProblem::Port);
        }
        let value: Value =
            serde_json::from_slice(config.as_bytes()).map_err(|_| ProbeProblem::Authority)?;
        let inbound = &value["inbounds"][1];
        let hostname = inbound["tag"]
            .as_str()
            .and_then(|s| s.strip_prefix("vmess-ws@"))
            .filter(|s| valid_vmess_hostname(s))
            .ok_or(ProbeProblem::Authority)?;
        let mut secret = Zeroizing::new([0; 32]);
        entropy
            .fill(secret.as_mut())
            .map_err(|_| ProbeProblem::Entropy)?;
        let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_ref()));
        let bytes = serde_json::to_vec(&json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"http","tag":"probe-in","listen":"127.0.0.1","listen_port":port,"users":[{"username":"sbxr-probe","password":password.as_str()}]}],
            "outbounds":[{"type":"vmess","tag":"vmess-only","server":hostname,"server_port":443,"uuid":inbound["users"][0]["uuid"],"security":"auto","tls":{"enabled":true,"server_name":hostname},"transport":{"type":"ws","path":VMESS_WEBSOCKET_PATH,"headers":{"Host":hostname}}}],
            "route":{"final":"vmess-only"}
        })).map_err(|_| ProbeProblem::Authority)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            port,
            password,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    fn egress(&self) -> EgressRequest<'_> {
        EgressRequest {
            port: self.port,
            password: &self.password,
        }
    }
}
pub struct EgressRequest<'a> {
    port: u16,
    password: &'a str,
}
impl EgressRequest<'_> {
    pub fn url(&self) -> &'static str {
        "https://api.ipify.org"
    }
    pub fn proxy_address(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
    }
    pub fn username(&self) -> &'static str {
        "sbxr-probe"
    }
    pub fn password(&self) -> &str {
        self.password
    }
    pub fn max_body_bytes(&self) -> usize {
        128
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }
    pub fn follows_redirects(&self) -> bool {
        false
    }
    pub fn trusted_tls_required(&self) -> bool {
        true
    }
}
#[derive(Clone, Debug)]
pub struct ListenerProof {
    pub process: ProcessIdentity,
    pub listener_pid: u32,
    pub address: SocketAddrV4,
    pub exclusive: bool,
    pub process_alive: bool,
}
impl ListenerProof {
    fn validate(&self, port: u16) -> Result<(), ProbeProblem> {
        if !self.process_alive {
            return Err(ProbeProblem::Exited);
        }
        let p = &self.process;
        if ProcessIdentity::new(
            p.pid,
            p.parent_pid,
            p.start_ticks,
            p.uid,
            &p.executable_sha256,
            &p.cgroup,
        )
        .is_err()
            || p.parent_pid != std::process::id()
            || p.uid != rustix::process::geteuid().as_raw()
            || p.pid != self.listener_pid
            || !self.exclusive
            || self.address != SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        {
            return Err(ProbeProblem::Listener);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct EgressReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub trusted_tls: bool,
    pub authenticated_proxy: bool,
    pub redirected: bool,
}
pub trait ProbeSession {
    /// Bounded readiness and kernel-derived PID/start-time/executable/parent
    /// identity of the authenticated spawned child, with one loopback listener.
    fn listener(&mut self, budget: &Budget<'_>) -> Result<ListenerProof, ProbeProblem>;
    /// HTTPS through this authenticated HTTP loopback proxy only. No direct,
    /// VLESS, environment-proxy, redirect or TLS-verification fallback exists.
    fn egress(
        &mut self,
        request: &EgressRequest<'_>,
        budget: &Budget<'_>,
    ) -> Result<EgressReply, ProbeProblem>;
    /// Ignore cancelled request budgets for cleanup; use a separate bounded
    /// kill/process-group/wait path and prove all owned children reaped.
    /// Implementations must retain a Drop fallback for partially failed cleanup.
    fn stop_and_reap(&mut self) -> Result<(), ProbeProblem>;
}
struct Reap<P: ProbeSession> {
    probe: P,
    attempted: bool,
}
impl<P: ProbeSession> Reap<P> {
    fn finish(&mut self) -> Result<(), ProbeProblem> {
        self.attempted = true;
        self.probe.stop_and_reap()
    }
}
impl<P: ProbeSession> Drop for Reap<P> {
    fn drop(&mut self) {
        if !self.attempted {
            let _ = self.probe.stop_and_reap();
        }
    }
}

impl<H: Host> TunnelInstallation<H> {
    /// Complete the confirmed setup/recovery action, then independently acquire
    /// fresh authority for its server-originated check. The installation outcome
    /// is local/durable; only the separate ConnectionCheck can be verified.
    pub fn execute_and_check(
        &mut self,
        prepared: PreparedAction,
        confirmation: Confirmation,
        stop: &Cancellation,
    ) -> Result<(SetupOutcome, Option<ConnectionCheck>), Error> {
        let outcome = self.execute(prepared, confirmation, stop)?;
        let check = if outcome == SetupOutcome::RunningConnectionPending {
            Some(self.check_connection(stop))
        } else {
            None
        };
        Ok((outcome, check))
    }
    /// Fresh and repeatable; never writes a permanent readiness assertion.
    pub fn check_connection(&mut self, stop: &Cancellation) -> ConnectionCheck {
        self.check_connection_with_entropy(stop, CHECK_TIMEOUT, &mut OsEntropy)
    }
    pub fn check_connection_with_entropy(
        &mut self,
        stop: &Cancellation,
        timeout: Duration,
        entropy: &mut dyn Entropy,
    ) -> ConnectionCheck {
        self.owner = Rc::new(());
        let budget = Budget::new(stop, timeout);
        let mut stage = CheckStage::Authority;
        let mut local_running = false;
        let result = (|| -> Result<(), ProbeProblem> {
            probe_budget(&budget)?;
            let guard = self
                .host
                .acquire(stop)
                .map_err(|_| ProbeProblem::Authority)?;
            let snapshot = self
                .host
                .snapshot(&guard)
                .map_err(|_| ProbeProblem::Authority)?;
            let record = snapshot.record().map_err(|_| ProbeProblem::Authority)?;
            if record.phase() != SetupPhase::Running
                || record.recovery_direction() != RecoveryDirection::None
                || record.pending_change().is_some()
                || record.tunnel_authority().is_none()
                || record.release_identity()
                    != self
                        .host
                        .installed_release(&guard)
                        .map_err(|_| ProbeProblem::Authority)?
            {
                return Err(ProbeProblem::Authority);
            }
            if !self
                .host
                .inspect(&guard, Some(&record), stop)
                .map_err(|_| ProbeProblem::Authority)?
                .running
            {
                return Err(ProbeProblem::Authority);
            }
            let config = self
                .configuration(&guard, &record)
                .map_err(|_| ProbeProblem::Authority)?;
            let value: Value =
                serde_json::from_slice(config.as_bytes()).map_err(|_| ProbeProblem::Authority)?;
            let hostname = value["inbounds"][1]["tag"]
                .as_str()
                .and_then(|s| s.strip_prefix("vmess-ws@"))
                .ok_or(ProbeProblem::Authority)?;
            self.host
                .verify_guard(&guard)
                .map_err(|_| ProbeProblem::Authority)?;
            local_running = true;
            for (next, host) in [
                (CheckStage::LocalWebSocket, None),
                (CheckStage::PublicWebSocket, Some(hostname)),
            ] {
                stage = next;
                probe_budget(&budget)?;
                self.host
                    .verify_guard(&guard)
                    .map_err(|_| ProbeProblem::Authority)?;
                let request = WebSocketRequest::new(host, entropy)?;
                let reply = self.host.websocket(&guard, &request, &budget)?;
                probe_budget(&budget)?;
                request.validate(reply)?;
                self.host
                    .verify_guard(&guard)
                    .map_err(|_| ProbeProblem::Authority)?;
            }
            stage = CheckStage::Traffic;
            probe_budget(&budget)?;
            let port = self.host.probe_port(&guard, &budget)?;
            let plan = ProbePlan::new(&config, port, entropy)?;
            probe_budget(&budget)?;
            self.host
                .verify_guard(&guard)
                .map_err(|_| ProbeProblem::Authority)?;
            let mut session = Reap {
                probe: self.host.spawn_probe(&guard, &plan, &budget)?,
                attempted: false,
            };
            let traffic = (|| {
                probe_budget(&budget)?;
                self.host
                    .verify_guard(&guard)
                    .map_err(|_| ProbeProblem::Authority)?;
                let initial_listener = session.probe.listener(&budget)?;
                initial_listener.validate(port)?;
                probe_budget(&budget)?;
                let reply = session.probe.egress(&plan.egress(), &budget)?;
                probe_budget(&budget)?;
                if reply.redirected {
                    return Err(ProbeProblem::Redirect);
                }
                if !reply.trusted_tls {
                    return Err(ProbeProblem::UntrustedTls);
                }
                if !reply.authenticated_proxy {
                    return Err(ProbeProblem::Traffic);
                }
                if reply.status != 200 || reply.body.len() >= 128 {
                    return Err(ProbeProblem::Egress);
                }
                let text = std::str::from_utf8(&reply.body)
                    .map_err(|_| ProbeProblem::Egress)?
                    .trim();
                let ip: Ipv4Addr = text.parse().map_err(|_| ProbeProblem::Egress)?;
                if ip.to_string() != record.public_ipv4() {
                    return Err(ProbeProblem::Egress);
                }
                let final_listener = session.probe.listener(&budget)?;
                final_listener.validate(port)?;
                if initial_listener.process != final_listener.process {
                    return Err(ProbeProblem::Listener);
                }
                self.host
                    .verify_guard(&guard)
                    .map_err(|_| ProbeProblem::Authority)?;
                // Keep the source bytes bound throughout this fresh check.
                if self
                    .host
                    .snapshot(&guard)
                    .map_err(|_| ProbeProblem::Authority)?
                    != snapshot
                {
                    return Err(ProbeProblem::Authority);
                }
                Ok(())
            })();
            let cleanup = session.finish();
            if cleanup.is_err() {
                stage = CheckStage::ProbeCleanup;
                return Err(ProbeProblem::Cleanup);
            }
            traffic?;
            probe_budget(&budget)?;
            self.host
                .verify_guard(&guard)
                .map_err(|_| ProbeProblem::Authority)?;
            if self
                .host
                .snapshot(&guard)
                .map_err(|_| ProbeProblem::Authority)?
                != snapshot
                || !self
                    .host
                    .inspect(&guard, Some(&record), stop)
                    .map_err(|_| ProbeProblem::Authority)?
                    .running
            {
                return Err(ProbeProblem::Authority);
            }
            probe_budget(&budget)?;
            Ok(())
        })();
        match result {
            Ok(()) => ConnectionCheck {
                local_running,
                stage: CheckStage::Complete,
                problem: None,
            },
            Err(problem) => ConnectionCheck::pending(
                local_running && problem != ProbeProblem::Authority,
                stage,
                problem,
            ),
        }
    }
}
