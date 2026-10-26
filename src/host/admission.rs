//! Read-only native admission: cryptographic delivery role plus a retained,
//! freshly checked protected installed/current process and loaded Rust statement.
//! Native effects also require platform/build admission, retained ownership and locks.
use super::{
    HostError,
    filesystem::{Evidence, ProtectedFs},
};
use crate::{
    artifact_trust::{AcquisitionTransport, SelectionBudget, TrustError},
    records::InstalledRecord,
    release_acquisition::{self, DeliveryRole, InstalledEvidence},
    release_identity::{self, Architecture},
    subscription_serving::Cancellation,
};
use rustix::fs::{Mode, OFlags};
use std::{
    fs::File,
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};
pub(super) const EXECUTABLE: &str = "usr/local/bin/sbxr";
pub(super) const LIMIT: usize = release_identity::MAX_EXECUTABLE_BYTES;
pub(super) fn refused(_: impl std::fmt::Debug) -> HostError {
    HostError::Foreign
}
fn acquisition_error(error: TrustError) -> HostError {
    if error == TrustError::Interrupted {
        HostError::Cancelled
    } else {
        HostError::Foreign
    }
}

pub(super) struct Snapshot {
    fs: ProtectedFs,
    record: InstalledRecord,
    record_bytes: Vec<u8>,
    record_named: Evidence,
    executable: Vec<u8>,
    named: Evidence,
    installed: File,
    current: File,
    stamp: Stamp,
    loaded: Vec<u8>,
    stop: Cancellation,
    candidate_input: Option<std::sync::Arc<super::entry_input::ProtectedCandidateInput>>,
}
#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn stamp(file: &File) -> Result<Stamp, HostError> {
    let m = file.metadata().map_err(refused)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        links: m.nlink(),
        size: m.size(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
fn read(file: &File, stop: &Cancellation) -> Result<Vec<u8>, HostError> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        if stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        let n = file
            .read_at(&mut chunk, bytes.len() as u64)
            .map_err(refused)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > LIMIT {
            return Err(HostError::OutputLimit);
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(bytes)
}
impl Snapshot {
    pub(in crate::host) fn record(&self) -> &InstalledRecord {
        &self.record
    }
    pub(in crate::host) fn root(&self) -> &Path {
        self.fs.path()
    }
    fn capture(
        fs: ProtectedFs,
        current: File,
        loaded: Vec<u8>,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        let record = super::linux::observation::read_installed(&fs)?.ok_or(HostError::Foreign)?;
        let (record_bytes, record_named) = fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        let (executable, named) = fs
            .raw(EXECUTABLE, Mode::from_raw_mode(0o755), LIMIT)?
            .ok_or(HostError::Foreign)?;
        let installed = fs.admission_executable()?;
        let original = stamp(&installed)?;
        let value = Self {
            fs,
            record,
            record_bytes,
            record_named,
            executable,
            named,
            installed,
            current,
            stamp: original,
            loaded,
            stop,
            candidate_input: None,
        };
        value.verify()?;
        Ok(value)
    }
    pub(super) fn verify(&self) -> Result<(), HostError> {
        let _phase = super::timing::span(super::timing::Phase::Snapshot);
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        if let Some(input) = &self.candidate_input {
            input.verify_record(&self.record, super::entry_input::now()?)?;
        }
        let s = &self.stamp;
        if s.uid != self.fs.uid
            || s.gid != self.fs.gid
            || s.links != 1
            || s.mode & 0o177777 != 0o100755
            || s.size as usize > LIMIT
            || stamp(&self.installed)? != *s
            || stamp(&self.current)? != *s
        {
            return Err(HostError::Foreign);
        }
        if super::linux::observation::read_installed(&self.fs)?.as_ref() != Some(&self.record)
            || !super::lifecycle::transactions_absent(&self.fs)?
        {
            return Err(HostError::Foreign);
        }
        let retained_record = self
            .fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        if retained_record.0 != self.record_bytes || retained_record.1 != self.record_named {
            return Err(HostError::Foreign);
        }
        let (bytes, evidence) = self
            .fs
            .raw(EXECUTABLE, Mode::from_raw_mode(0o755), LIMIT)?
            .ok_or(HostError::Foreign)?;
        if evidence != self.named
            || bytes != self.executable
            || read(&self.current, &self.stop)? != bytes
        {
            return Err(HostError::Foreign);
        }
        let arch = match self.record.architecture() {
            "amd64" => Architecture::Amd64,
            "arm64" => Architecture::Arm64,
            _ => return Err(HostError::Foreign),
        };
        if release_identity::inspect_linux_artifact(&bytes, arch)
            .map_err(refused)?
            .kind()
            != release_identity::ArtifactKind::Rust
            || self.loaded
                != release_identity::rust_artifact_metadata(
                    self.record.release_identity().commit(),
                    arch,
                )
                .map_err(refused)?
        {
            return Err(HostError::Foreign);
        }
        if stamp(&self.current)? != *s {
            return Err(HostError::Foreign);
        }
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        Ok(())
    }
}
fn require_delivery(
    proof: &dyn InstalledEvidence,
    expected: DeliveryRole,
) -> Result<(), HostError> {
    if proof.role() != expected {
        return Err(HostError::Foreign);
    }
    Ok(())
}
/// Cannot be constructed from a parsed record or structural build marker.
/// ```compile_fail
/// fn admit(p: sbxr::release_acquisition::AuthenticatedInstalled) -> sbxr::host::admission::NativeAdmission { p }
/// ```
pub struct NativeAdmission {
    snapshot: std::sync::Arc<Snapshot>,
    proof: Box<dyn InstalledEvidence>,
}
impl std::fmt::Debug for NativeAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bound native process admission")
    }
}
impl NativeAdmission {
    pub(super) fn snapshot(stop: Cancellation) -> Result<Snapshot, HostError> {
        super::linux::require_native_environment()?;
        if std::env::current_exe().map_err(refused)? != Path::new("/usr/local/bin/sbxr") {
            return Err(HostError::Foreign);
        }
        let loaded = crate::build_identity::compiled_statement()
            .ok_or(HostError::LiveUnavailable)?
            .to_vec();
        let fd = rustix::fs::open(
            "/proc/self/exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(refused)?;
        Snapshot::capture(ProtectedFs::native()?, File::from(fd), loaded, stop)
    }
    pub fn stable(
        transport: &mut impl AcquisitionTransport,
        budget: &SelectionBudget,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        budget.check().map_err(acquisition_error)?;
        let snapshot = Self::snapshot(stop)?;
        let proof = release_acquisition::AuthenticatedInstalled::acquire(
            transport,
            snapshot.record.clone(),
            &snapshot.executable,
            &read(&snapshot.current, &snapshot.stop)?,
            budget,
        )
        .map_err(acquisition_error)?;
        Self::bind(snapshot, Box::new(proof), DeliveryRole::Stable, budget)
    }
    pub fn candidate(
        ca_sha256: &str,
        budget: &SelectionBudget,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        Self::candidate_bound(ca_sha256, None, budget, stop)
    }
    pub(in crate::host) fn reviewed_candidate(
        input: &std::sync::Arc<super::entry_input::ProtectedCandidateInput>,
        budget: &SelectionBudget,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        input.authenticate(budget)?;
        Self::candidate_bound(input.ca_sha256(), Some(input), budget, stop)
    }
    fn candidate_bound(
        ca_sha256: &str,
        input: Option<&std::sync::Arc<super::entry_input::ProtectedCandidateInput>>,
        budget: &SelectionBudget,
        stop: Cancellation,
    ) -> Result<Self, HostError> {
        budget.check().map_err(acquisition_error)?;
        let mut snapshot = Self::snapshot(stop)?;
        if let Some(i) = input {
            i.verify_record(&snapshot.record, super::entry_input::now()?)?;
            snapshot.candidate_input = Some(std::sync::Arc::clone(i));
        }
        let mut transport = crate::release_https::CandidateGatewayTransport::from_retained_gateway(
            ca_sha256, budget,
        )
        .map_err(acquisition_error)?;
        let arch = match snapshot.record.architecture() {
            "amd64" => Architecture::Amd64,
            "arm64" => Architecture::Arm64,
            _ => return Err(HostError::Foreign),
        };
        let archive = release_acquisition::AuthenticatedCandidateArchive::acquire(
            &mut transport,
            &snapshot.record.release_identity(),
            arch,
            budget,
        )
        .map_err(acquisition_error)?;
        if let Some(i) = input {
            i.verify_manifest(archive.manifest_sha256(), super::entry_input::now()?)?;
        }
        let proof = archive
            .bind_current(
                &snapshot.executable,
                &read(&snapshot.current, &snapshot.stop)?,
                budget,
            )
            .map_err(acquisition_error)?;
        if let Some(i) = input {
            i.verify(super::entry_input::now()?)?;
        }
        Self::bind(snapshot, Box::new(proof), DeliveryRole::Candidate, budget)
    }
    fn bind(
        snapshot: Snapshot,
        proof: Box<dyn InstalledEvidence>,
        expected: DeliveryRole,
        budget: &SelectionBudget,
    ) -> Result<Self, HostError> {
        budget.check().map_err(acquisition_error)?;
        require_delivery(proof.as_ref(), expected)?;
        if proof.record() != &snapshot.record {
            return Err(HostError::Foreign);
        }
        let value = Self {
            snapshot: std::sync::Arc::new(snapshot),
            proof,
        };
        value.verify()?;
        budget.check().map_err(acquisition_error)?;
        Ok(value)
    }
    pub fn verify(&self) -> Result<(), HostError> {
        self.proof.verify_binding().map_err(refused)?;
        self.snapshot.verify()
    }
    pub fn role(&self) -> DeliveryRole {
        self.proof.role()
    }
    pub(in crate::host) fn snapshot_guard(&self) -> &Snapshot {
        &self.snapshot
    }
    pub(in crate::host) fn retain_snapshot(&self) -> std::sync::Arc<Snapshot> {
        std::sync::Arc::clone(&self.snapshot)
    }
    pub fn record(&self) -> &InstalledRecord {
        self.proof.record()
    }
}
impl release_acquisition::installed_seal::Sealed for NativeAdmission {}
impl InstalledEvidence for NativeAdmission {
    fn record(&self) -> &InstalledRecord {
        self.record()
    }
    fn index(&self) -> &release_identity::ReleaseIndex {
        self.proof.index()
    }
    fn role(&self) -> DeliveryRole {
        self.role()
    }
    fn verify_binding(&self) -> Result<(), TrustError> {
        self.verify().map_err(|e| {
            if e == HostError::Cancelled {
                TrustError::Interrupted
            } else {
                TrustError::Refused
            }
        })
    }
}
#[cfg(test)]
#[path = "admission_tests.rs"]
pub(super) mod tests;

/// Existing journeys keep their own opaque authority and effects. This retained
/// process guard invalidates a reviewed journey before any stale execution.
pub(in crate::host) struct BoundJourney<'a> {
    snapshot: &'a Snapshot,
    inner: Box<dyn crate::proxyinstallation::Interface + 'a>,
}
impl<'a> BoundJourney<'a> {
    pub(in crate::host) fn new(
        snapshot: &'a Snapshot,
        inner: Box<dyn crate::proxyinstallation::Interface + 'a>,
    ) -> Self {
        Self { snapshot, inner }
    }
    fn refusal() -> crate::proxyinstallation::Review {
        use crate::{domain::*, proxyinstallation::*};
        Review {
            mode: ExecutionMode::NativeUnavailable,
            details: vec!["Native process admission is stale or unavailable.".into()],
            status: Status::ProblemDetected,
            legal_actions: vec![Action::ViewDetails],
            plan: vec![],
            refusal: Some("Preserve authority and recheck the exact installed process."),
            prepared: None,
        }
    }
    fn result() -> crate::domain::Result {
        use crate::domain::*;
        Result {
            outcome: Outcome::Refused,
            status: Status::ProblemDetected,
            proxy_traffic: Availability::CannotBeVerified,
            message: "Native process admission changed. Reinspect before effects.",
        }
    }
}
impl crate::proxyinstallation::Interface for BoundJourney<'_> {
    fn supports_tunnel(&self) -> bool {
        self.snapshot.verify().is_ok() && self.inner.supports_tunnel()
    }
    fn review(&self, a: crate::domain::Action) -> crate::proxyinstallation::Review {
        if self.snapshot.verify().is_err() {
            return Self::refusal();
        }
        self.inner.review(a)
    }
    fn review_tunnel_setup(&self, hostname: &str) -> crate::proxyinstallation::Review {
        if self.snapshot.verify().is_err() {
            return Self::refusal();
        }
        self.inner.review_tunnel_setup(hostname)
    }
    fn execute(
        &mut self,
        p: crate::proxyinstallation::PreparedAction,
        c: crate::domain::Confirmation,
    ) -> crate::domain::Result {
        if self.snapshot.verify().is_err() {
            return Self::result();
        }
        self.inner.execute(p, c)
    }
    fn execute_output(
        &mut self,
        p: crate::proxyinstallation::PreparedAction,
        c: crate::domain::Confirmation,
        out: &mut dyn std::io::Write,
    ) -> std::io::Result<crate::domain::Result> {
        if self.snapshot.verify().is_err() {
            return Ok(Self::result());
        }
        self.inner.execute_output(p, c, out)
    }
    fn write_details(&mut self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.snapshot.verify().is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Native process admission refused",
            ));
        }
        self.inner.write_details(out)
    }
    fn subscription_status(&self) -> &'static str {
        if self.snapshot.verify().is_err() {
            "Problem detected"
        } else {
            self.inner.subscription_status()
        }
    }
    fn take_subscription_link(
        &mut self,
    ) -> Option<crate::subscription_artifact::HttpSubscriptionLink> {
        if self.snapshot.verify().is_err() {
            None
        } else {
            self.inner.take_subscription_link()
        }
    }
}
