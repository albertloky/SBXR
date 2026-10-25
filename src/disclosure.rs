//! Confirmed Client Configuration disclosure and read-only link redisclosure.
//! Effects are injected; this module grants no native filesystem or service access.
use crate::{
    client_identity::Snapshot,
    domain::Confirmation,
    records::{OwnershipRecord, RecoveryDirection, ReleaseIdentity, SetupPhase, sha256_hex},
    server_configuration::ServerConfiguration,
    subscription_artifact::{HTTP_TRANSPORT_WARNING, SubscriptionCredential},
    subscription_serving::Cancellation,
};
use std::{fmt, io::Write, rc::Rc};
use zeroize::Zeroizing;

pub const CLIENT_PLAN: &[&str] = &[
    "Warning: this Client Configuration contains a credential.",
    "Anyone with a copy can use the proxy while this Client Identity remains active.",
    "Terminal history or recording can retain the complete Client Configuration.",
    "SBXR creates no client file on this VPS.",
    "Outside copies survive Complete removal and must be deleted separately.",
];
pub const COMPROMISE_PLAN: &[&str] = &[
    "Record that the existing Subscription Link is compromised; its credential remains active.",
    "Rotate the Subscription Link separately to revoke it. Previously downloaded proxy credentials require separate Client Identity rotation.",
];
const LINK_WARNING: &str = "This link is a reusable credential. Anyone with it can obtain your proxy connection details. Keep it private. It will remain in terminal scrollback.\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Authority,
    StaleReview,
    Refused,
    Interrupted,
    Output,
    Publication,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Output => "Disclosure output failed; no successful display is established.",
            Self::Publication => "Compromise record publication is uncertain; inspect durable authority before retrying.",
            _ => "Disclosure authority cannot be verified; review the action again.",
        })
    }
}
impl std::error::Error for Error {}
fn authority<T>(_: T) -> Error {
    Error::Authority
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    ShowClientConfiguration,
    MarkSubscriptionCompromised,
}
impl Action {
    pub fn plan(self) -> &'static [&'static str] {
        match self {
            Self::ShowClientConfiguration => CLIENT_PLAN,
            Self::MarkSubscriptionCompromised => COMPROMISE_PLAN,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Declined,
    ClientConfigurationDisclosed,
    SubscriptionCompromised,
}
impl Outcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::Declined => "PROXY-INSTALLATION-ACTION-CANCELLED",
            Self::ClientConfigurationDisclosed => {
                "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
            }
            Self::SubscriptionCompromised => "PROXY-INSTALLATION-SUBSCRIPTION-COMPROMISED",
        }
    }
}

/// Fresh observed-and-accepted facts corresponding to Go RunningInspection.
/// Unknown observations must map to false. fingerprint binds the exact inspected
/// platform/address/resource/runtime facts, without including secret material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunningFacts {
    pub host: bool,
    pub public_ipv4_matches: bool,
    pub ownership: bool,
    pub transaction_files_absent: bool,
    pub apt_key: bool,
    pub apt_source: bool,
    pub package: bool,
    pub hold: bool,
    pub package_identity: bool,
    pub configuration: bool,
    pub state: bool,
    pub validation: bool,
    pub service_provenance: bool,
    pub lock_provisioning: bool,
    pub service_enabled: bool,
    pub service_active: bool,
    pub listener: bool,
    pub fingerprint: String,
}
impl RunningFacts {
    fn accepted(&self) -> bool {
        self.host
            && self.public_ipv4_matches
            && self.ownership
            && self.transaction_files_absent
            && self.apt_key
            && self.apt_source
            && self.package
            && self.hold
            && self.package_identity
            && self.configuration
            && self.state
            && self.validation
            && self.service_provenance
            && self.lock_provisioning
            && self.service_enabled
            && self.service_active
            && self.listener
            && !self.fingerprint.is_empty()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// Independently authenticated installed/executing identity; creator
    /// provenance alone is insufficient. Host also proves record compatibility.
    pub release: ReleaseIdentity,
    /// GID freshly resolved for the installed sing-box group, not the file's self-reported GID.
    pub configuration_gid: u32,
    pub running: RunningFacts,
    /// Owned, safely bounded serving files/writers even when serving is down.
    pub serving_surface_safe: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileProof {
    pub regular: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub protected_ancestry: bool,
}
impl FileProof {
    fn accepted(self, mode: u32, uid: u32, gid: u32) -> bool {
        self.regular
            && self.uid == uid
            && self.gid == gid
            && self.mode == mode
            && self.links == 1
            && self.protected_ancestry
    }
}
/// Metadata and bytes must come from the same no-follow descriptor and protected
/// ancestry. Parsing supplied bytes never establishes this host proof.
pub struct ProtectedFile {
    bytes: Zeroizing<Vec<u8>>,
    proof: FileProof,
}
impl ProtectedFile {
    pub fn new(bytes: Vec<u8>, proof: FileProof) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            proof,
        }
    }
    fn checked(&self, mode: u32, uid: u32, gid: u32) -> Result<&[u8], Error> {
        if self.proof.accepted(mode, uid, gid) {
            Ok(&self.bytes)
        } else {
            Err(Error::Authority)
        }
    }
}
impl fmt::Debug for ProtectedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected material (redacted)")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Material {
    Configuration,
    SubscriptionToken,
    ServingState,
}

/// All calls retain and verify one whole-host lock. Read methods never repair,
/// publish, promote staged bytes, clean files, or run runtime effects. Snapshot
/// reads require root:root 0600 one-link no-follow ownership files and protected
/// parents. Inspect authenticates installed bytes and ownership compatibility;
/// unhealthy runtime facts are observations, not successful proof or repair.
pub trait Host {
    /// Independently pinned namespace owner, never inferred from a supplied file.
    /// Native constructors require root:root; fixture roots use their real owner.
    fn owner_uid(&self) -> u32 {
        0
    }
    fn owner_gid(&self) -> u32 {
        0
    }
    type Guard;
    fn acquire(&mut self) -> Result<Self::Guard, Error>;
    fn verify_guard(&mut self, guard: &Self::Guard) -> Result<(), Error>;
    fn snapshot(&mut self, guard: &Self::Guard) -> Result<Snapshot, Error>;
    fn inspect(
        &mut self,
        guard: &Self::Guard,
        record: &OwnershipRecord,
    ) -> Result<Inspection, Error>;
    /// Bound reads to 1 MiB for configuration, 44 bytes for token, and
    /// MAX_RECORD_BYTES for serving state; verify the same opened descriptor.
    fn read(&mut self, guard: &Self::Guard, material: Material) -> Result<ProtectedFile, Error>;
    /// Exact CAS, no-follow publication with file+directory fsync. Any error
    /// after a possible write must return Publication; callers never auto-retry.
    fn publish(
        &mut self,
        guard: &Self::Guard,
        expected: &[u8],
        next: &OwnershipRecord,
    ) -> Result<(), Error>;
}

/// Only an explicit accessor or write_link reveals the authorized bearer URL.
pub struct SubscriptionLink(Zeroizing<String>);
impl SubscriptionLink {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn transport_warning(&self) -> Option<&'static str> {
        self.0
            .starts_with("http://")
            .then_some(HTTP_TRANSPORT_WARNING)
    }
}
impl fmt::Debug for SubscriptionLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subscription Link (redacted)")
    }
}
impl fmt::Display for SubscriptionLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
#[derive(Debug)]
pub struct Details {
    pub subscription_link: Option<SubscriptionLink>,
    pub compromised: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub client_configuration_available: bool,
    pub mark_compromise_available: bool,
    pub has_subscription: bool,
    pub compromised: bool,
}

/// Opaque, instance-bound, memory-only single-use authority. Never Clone/serde.
pub struct Prepared {
    owner: Rc<()>,
    action: Action,
    snapshot: Snapshot,
    inspection: Inspection,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prepared disclosure (redacted)")
    }
}
pub struct Session<H: Host> {
    host: H,
    owner: Rc<()>,
    stop: Cancellation,
}
impl<H: Host> Session<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            owner: Rc::new(()),
            stop: Cancellation::new(),
        }
    }
    pub fn cancellation(&self) -> Cancellation {
        self.stop.clone()
    }
    pub fn expire(&mut self) {
        self.owner = Rc::new(());
    }
    pub fn host_mut(&mut self) -> &mut H {
        self.expire();
        &mut self.host
    }
    pub fn into_host(self) -> H {
        self.host
    }
    fn cancelled(&self) -> Result<(), Error> {
        if self.stop.is_cancelled() {
            Err(Error::Interrupted)
        } else {
            Ok(())
        }
    }
    fn load(&mut self, guard: &H::Guard) -> Result<(Snapshot, OwnershipRecord, Inspection), Error> {
        self.cancelled()?;
        self.host.verify_guard(guard)?;
        let snapshot = self.host.snapshot(guard)?;
        let record = OwnershipRecord::decode(&snapshot.current).map_err(authority)?;
        if snapshot
            .staged
            .as_ref()
            .is_some_and(|s| s != &snapshot.current)
        {
            return Err(Error::Publication);
        }
        let inspection = self.host.inspect(guard, &record)?;
        self.host.verify_guard(guard)?;
        self.cancelled()?;
        Ok((snapshot, record, inspection))
    }
    fn summary(snapshot: &Snapshot, record: &OwnershipRecord, inspection: &Inspection) -> Summary {
        let ready = snapshot.staged.is_none()
            && record.phase() == SetupPhase::Running
            && record.recovery_direction() == RecoveryDirection::None
            && record.pending_change().is_none()
            && inspection.running.accepted()
            && (record.serving_authority().is_none() || inspection.serving_surface_safe);
        Summary {
            client_configuration_available: ready,
            mark_compromise_available: ready
                && !record.subscription_compromised()
                && record.serving_authority().is_some_and(|s| s.is_http()),
            has_subscription: record.serving_authority().is_some(),
            compromised: record.subscription_compromised(),
        }
    }
    pub fn status(&mut self) -> Result<Summary, Error> {
        self.expire();
        let guard = self.host.acquire()?;
        let (snapshot, record, inspection) = self.load(&guard)?;
        Ok(Self::summary(&snapshot, &record, &inspection))
    }
    pub fn review(&mut self, action: Action) -> Result<Prepared, Error> {
        self.expire();
        let guard = self.host.acquire()?;
        let (snapshot, record, inspection) = self.load(&guard)?;
        let summary = Self::summary(&snapshot, &record, &inspection);
        if !match action {
            Action::ShowClientConfiguration => summary.client_configuration_available,
            Action::MarkSubscriptionCompromised => summary.mark_compromise_available,
        } {
            return Err(Error::Refused);
        }
        Ok(Prepared {
            owner: self.owner.clone(),
            action,
            snapshot,
            inspection,
        })
    }
    /// The View details exception reads only the current authoritative token and
    /// state. A certificate/listener fault alone does not hide a consistent URL.
    pub fn view_details(&mut self) -> Result<Details, Error> {
        self.expire();
        let guard = self.host.acquire()?;
        let (snapshot, record, _) = self.load(&guard)?;
        let mut details = Details {
            subscription_link: None,
            compromised: record.subscription_compromised(),
        };
        let Some(serving) = record.serving_authority() else {
            return Ok(details);
        };
        let token = self.host.read(&guard, Material::SubscriptionToken)?;
        let token = token.checked(0o600, self.host.owner_uid(), self.host.owner_gid())?;
        if token.len() != 44
            || token[43] != b'\n'
            || sha256_hex(&token[..43]) != serving.credential_sha256()
        {
            return Err(Error::Authority);
        }
        let credential =
            SubscriptionCredential::parse(std::str::from_utf8(&token[..43]).map_err(authority)?)
                .map_err(authority)?;
        let state = self.host.read(&guard, Material::ServingState)?;
        if state.checked(0o600, self.host.owner_uid(), self.host.owner_gid())?
            != serving.state_bytes().map_err(authority)?
        {
            return Err(Error::Authority);
        }
        let scheme = if serving.is_http() { "http" } else { "https" };
        let link = SubscriptionLink(Zeroizing::new(format!(
            "{scheme}://{}:8443/s/{}",
            record.public_ipv4(),
            credential.as_str()
        )));
        let (fresh, _, _) = self.load(&guard)?;
        if fresh.current != snapshot.current || fresh.staged != snapshot.staged {
            return Err(Error::StaleReview);
        }
        details.subscription_link = Some(link);
        Ok(details)
    }
    pub fn execute(
        &mut self,
        prepared: Prepared,
        confirmation: Confirmation,
        output: Option<&mut dyn Write>,
    ) -> Result<Outcome, Error> {
        let valid = Rc::ptr_eq(&self.owner, &prepared.owner);
        self.expire();
        if !valid {
            return Err(Error::StaleReview);
        }
        if confirmation == Confirmation::Declined {
            return Ok(Outcome::Declined);
        }
        self.cancelled()?;
        if prepared.action == Action::ShowClientConfiguration && output.is_none() {
            return Err(Error::Refused);
        }
        let guard = self.host.acquire()?;
        let (snapshot, record, inspection) = self.revalidate(&guard, &prepared)?;
        match prepared.action {
            Action::ShowClientConfiguration => {
                if !Self::summary(&snapshot, &record, &inspection).client_configuration_available {
                    return Err(Error::Refused);
                }
                let file = self.host.read(&guard, Material::Configuration)?;
                let bytes =
                    file.checked(0o640, self.host.owner_uid(), inspection.configuration_gid)?;
                if sha256_hex(bytes) != record.configuration_sha256() {
                    return Err(Error::Authority);
                }
                let configuration =
                    ServerConfiguration::decode_supported(bytes).map_err(authority)?;
                let client = configuration
                    .connection_facts(record.public_ipv4())
                    .map_err(authority)?
                    .client_configuration()
                    .map_err(authority)?;
                self.revalidate(&guard, &prepared)?;
                let output = output.ok_or(Error::Refused)?;
                let mut framed = Zeroizing::new(Vec::new());
                framed.extend_from_slice(b"----- BEGIN SBXR CLIENT CONFIGURATION -----\n");
                framed.extend_from_slice(client.as_bytes());
                if !framed.ends_with(b"\n") {
                    framed.push(b'\n');
                }
                framed.extend_from_slice(b"----- END SBXR CLIENT CONFIGURATION -----\n");
                output.write_all(&framed).map_err(|_| Error::Output)?;
                output.flush().map_err(|_| Error::Output)?;
                Ok(Outcome::ClientConfigurationDisclosed)
            }
            Action::MarkSubscriptionCompromised => {
                if !Self::summary(&snapshot, &record, &inspection).mark_compromise_available {
                    return Err(Error::Refused);
                }
                let next = record.mark_subscription_compromised().map_err(authority)?;
                self.cancelled()?;
                self.host
                    .publish(&guard, &snapshot.current, &next)
                    .map_err(|_| Error::Publication)?;
                self.host
                    .verify_guard(&guard)
                    .map_err(|_| Error::Publication)?;
                let fresh = self.host.snapshot(&guard).map_err(|_| Error::Publication)?;
                if fresh.current != next.encode().map_err(authority)? || fresh.staged.is_some() {
                    return Err(Error::Publication);
                }
                Ok(Outcome::SubscriptionCompromised)
            }
        }
    }
    fn revalidate(
        &mut self,
        guard: &H::Guard,
        prepared: &Prepared,
    ) -> Result<(Snapshot, OwnershipRecord, Inspection), Error> {
        let (snapshot, record, inspection) = self.load(guard)?;
        if snapshot.current != prepared.snapshot.current
            || snapshot.staged != prepared.snapshot.staged
            || inspection != prepared.inspection
        {
            return Err(Error::StaleReview);
        }
        Ok((snapshot, record, inspection))
    }
}

/// Presentation failure is read-only failure, never a successful disclosure or
/// justification to repeat an earlier committed mutation.
pub fn write_link(output: &mut dyn Write, link: &SubscriptionLink) -> Result<(), Error> {
    output
        .write_all(LINK_WARNING.as_bytes())
        .map_err(|_| Error::Output)?;
    output
        .write_all(link.as_str().as_bytes())
        .map_err(|_| Error::Output)?;
    output.write_all(b"\n").map_err(|_| Error::Output)?;
    output.flush().map_err(|_| Error::Output)
}
