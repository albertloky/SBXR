//! Concrete native Owner sources behind authenticated installed/current admission.
//! Local implementation and tests do not establish packaged live qualification.
use super::{HostError, filesystem::ProtectedFs};
use crate::{
    proxyinstallation::{
        ClientIdentityInstallation, ExecutionMode, HttpInstallation, Interface, Journey,
        OwnerInstallation, OwnerSources,
    },
    records::{RecoveryDirection, SetupPhase},
};
/// The executing bytes must already be authenticated by NativeObserver. This
/// adapter never creates an installed proof from local metadata alone.
type CachedPackage = std::sync::Arc<(Vec<u8>, Vec<u8>)>;
type NativeRemovalHost<'a> = super::linux::StandardRemovalHost<
    super::system::SystemRunner<super::system::NativeTransport>,
    super::linux::TunnelRemovalRuntime<
        super::owner_runtime::OwnerRuntime<'a, super::owner_runtime::NativeIo>,
        super::tunnel_native::NativeConnectorIo,
    >,
>;
pub struct NativeOwnerSources<'a> {
    proof: &'a super::admission::NativeAdmission,
    stop: crate::subscription_serving::Cancellation,
    package: std::cell::RefCell<Option<CachedPackage>>,
    probe: std::cell::RefCell<Option<crate::package_acquisition::ProbeImage>>,
}
impl<'a> NativeOwnerSources<'a> {
    pub fn authenticated_unreleased(
        proof: &'a super::admission::NativeAdmission,
    ) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        proof.verify()?;
        super::owner_runtime::OwnerRuntime::native_unreleased(proof)?;
        Ok(Self {
            proof,
            stop: crate::subscription_serving::Cancellation::new(),
            package: std::cell::RefCell::new(None),
            probe: std::cell::RefCell::new(None),
        })
    }
    pub fn with_cancellation(mut self, stop: crate::subscription_serving::Cancellation) -> Self {
        self.stop = stop;
        self
    }
    fn runtime(
        &self,
    ) -> Result<super::owner_runtime::OwnerRuntime<'a, super::owner_runtime::NativeIo>, HostError>
    {
        Ok(
            super::owner_runtime::OwnerRuntime::native_unreleased(self.proof)?
                .with_cancellation(self.stop.clone()),
        )
    }
    fn ensure_package(&self) -> Result<(), HostError> {
        use crate::{
            artifact_trust::SelectionBudget,
            package_acquisition::{self, PackageHttps},
        };
        if self.package.borrow().is_none() {
            let _phase = super::timing::span(super::timing::Phase::Package);
            let package = package_acquisition::acquire(
                &mut PackageHttps::new().map_err(|_| HostError::Foreign)?,
                &SelectionBudget::new().with_cancellation(self.stop.clone()),
            )
            .map_err(|_| HostError::Foreign)?;
            *self.package.borrow_mut() = Some(std::sync::Arc::new(package.into_parts()));
        }
        Ok(())
    }
    fn probe_image(&self) -> Result<crate::package_acquisition::ProbeImage, HostError> {
        self.ensure_package()?;
        if self.probe.borrow().is_none() {
            let _phase = super::timing::span(super::timing::Phase::Probe);
            let cache = self.package.borrow();
            let (key, deb) = cache.as_ref().ok_or(HostError::Foreign)?.as_ref();
            let budget =
                crate::artifact_trust::SelectionBudget::new().with_cancellation(self.stop.clone());
            let package = crate::package_acquisition::VerifiedPackage::verify(
                key.clone(),
                deb.clone(),
                &budget,
            )
            .map_err(|_| HostError::Foreign)?;
            *self.probe.borrow_mut() = Some(
                package
                    .probe_image(&budget)
                    .map_err(|_| HostError::Foreign)?,
            );
        }
        self.probe.borrow().clone().ok_or(HostError::Foreign)
    }
    fn tunnel_module(&self) -> Result<Box<dyn Interface + 'a>, HostError> {
        use super::linux::{LinuxHost, SetupMaterial, TunnelStandard};
        let fs = ProtectedFs::native()?;
        let record = super::linux::observation::read_ownership(&fs)?;
        if fs.metadata("var/lib/.sbxr-removal.json")?.is_some() {
            return Err(HostError::Foreign);
        }
        let (host, probe) = if let Some(r) = record {
            if r.tunnel_authority().is_none() {
                return Err(HostError::Foreign);
            }
            if r.recovery_direction() == RecoveryDirection::Cleanup {
                (
                    self.offline_host(SetupMaterial::tunnel_cleanup(&r)?, r.public_ipv4())?,
                    None,
                )
            } else {
                let probe = self.probe_image()?;
                let cache = self.package.borrow();
                let (key, deb) = cache.as_ref().ok_or(HostError::Foreign)?.as_ref();
                let (config, _) = fs
                    .raw(
                        "etc/sing-box/config.json",
                        rustix::fs::Mode::from_raw_mode(0o640),
                        1 << 20,
                    )?
                    .ok_or(HostError::Foreign)?;
                if crate::records::sha256_hex(&config) != r.configuration_sha256() {
                    return Err(HostError::Foreign);
                }
                let material = SetupMaterial::recovered_tunnel(key.clone(), deb.clone(), &config)?;
                let runner = super::system::SystemRunner::native(
                    super::system::NativeTransport::new()?,
                    &material.configuration_sha256(),
                )?;
                let network = super::network::NetworkAdmission::native(
                    &super::process::Cancellation::from(self.stop.clone()),
                    false,
                )?;
                (
                    LinuxHost::native_authenticated_unreleased(
                        runner, material, network, self.proof,
                    )?
                    .with_cancellation(self.stop.clone().into()),
                    Some(probe),
                )
            }
        } else {
            (self.standard_host()?, Some(self.probe_image()?))
        };
        let runtime = self.runtime()?;
        let bridge = TunnelStandard::new(host, runtime, probe)?;
        let tunnel =
            super::tunnel_native::ProtectedTunnelHost::native_unreleased(self.proof, bridge)?;
        Ok(Box::new(
            crate::proxyinstallation::TunnelOwnerInstallation::new(
                tunnel,
                ExecutionMode::native_unreleased(),
            )
            .with_cancellation(self.stop.clone().into()),
        ))
    }
    fn standard_host(
        &self,
    ) -> Result<
        super::linux::LinuxHost<super::system::SystemRunner<super::system::NativeTransport>>,
        HostError,
    > {
        use crate::identity_generation::OsEntropy;
        let fs = ProtectedFs::native()?;
        let record = super::linux::observation::read_ownership(&fs)?;
        if fs.metadata("var/lib/.sbxr-removal.json")?.is_some() {
            return Err(HostError::Foreign);
        }
        if let Some(record) = record
            .as_ref()
            .filter(|r| r.recovery_direction() == RecoveryDirection::Cleanup)
        {
            return self.offline_host(
                super::linux::SetupMaterial::for_cleanup(record)?,
                record.public_ipv4(),
            );
        }
        let require_bind = !record.as_ref().is_some_and(|r| {
            matches!(
                r.recovery_direction(),
                RecoveryDirection::None | RecoveryDirection::FinishSetup
            )
        });
        let network = super::network::NetworkAdmission::native(
            &super::process::Cancellation::from(self.stop.clone()),
            require_bind,
        )?;
        self.ensure_package()?;
        let cache = self.package.borrow();
        let (key, deb) = cache.as_ref().ok_or(HostError::Foreign)?.as_ref();
        let material = if let Some(r) = record {
            let (config, _) = fs
                .raw(
                    "etc/sing-box/config.json",
                    rustix::fs::Mode::from_raw_mode(0o640),
                    1 << 20,
                )?
                .ok_or(HostError::LiveUnavailable)?;
            if crate::records::sha256_hex(&config) != r.configuration_sha256() {
                return Err(HostError::Foreign);
            }
            super::linux::SetupMaterial::recovered_standard(key.clone(), deb.clone(), &config)?
        } else {
            super::linux::SetupMaterial::generated_standard(
                key.clone(),
                deb.clone(),
                &mut OsEntropy,
            )?
        };
        let runner = super::system::SystemRunner::native(
            super::system::NativeTransport::new()?,
            &material.configuration_sha256(),
        )?;
        super::linux::LinuxHost::native_authenticated_unreleased(
            runner, material, network, self.proof,
        )
        .map(|host| host.with_cancellation(self.stop.clone().into()))
    }
    fn offline_host(
        &self,
        material: super::linux::SetupMaterial,
        public_ipv4: &str,
    ) -> Result<
        super::linux::LinuxHost<super::system::SystemRunner<super::system::NativeTransport>>,
        HostError,
    > {
        let runner = super::system::SystemRunner::native(
            super::system::NativeTransport::new()?,
            &material.configuration_sha256(),
        )?;
        super::linux::LinuxHost::native_offline_authenticated_unreleased(
            runner,
            material,
            public_ipv4,
            self.proof,
        )
        .map(|host| host.with_cancellation(self.stop.clone().into()))
    }
    fn removal_host(&self) -> Result<NativeRemovalHost<'a>, HostError> {
        let fs = ProtectedFs::native()?;
        let current = super::linux::observation::read_ownership(&fs)?;
        let finalizer = fs
            .raw(
                "var/lib/.sbxr-removal.json",
                rustix::fs::Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .map(|(b, _)| {
                crate::records::OwnershipRecord::decode(&b).map_err(|_| HostError::Foreign)
            })
            .transpose()?;
        if current.is_some() && finalizer.is_some() {
            return Err(HostError::Foreign);
        }
        let record = current.as_ref().or(finalizer.as_ref());
        let material = super::linux::SetupMaterial::for_removal(record)?;
        Ok(super::linux::StandardRemovalHost::new(
            self.offline_host(material, record.map(|r| r.public_ipv4()).unwrap_or(""))?,
        )?
        .with_auxiliary(super::linux::TunnelRemovalRuntime::new(
            self.runtime()?,
            super::tunnel_native::Connector::native_unreleased()?,
        )))
    }
    pub fn frontend(self) -> OwnerInstallation<'a, Self> {
        OwnerInstallation::new(self)
    }
}
impl<'a> OwnerSources<'a> for NativeOwnerSources<'a> {
    fn journeys(&self) -> Result<Vec<Journey>, HostError> {
        let _phase = super::timing::span(super::timing::Phase::Journeys);
        self.proof.verify()?;
        super::linux::require_native_environment()?;
        if self.stop.is_cancelled() {
            return Err(HostError::Cancelled);
        }
        let fs = ProtectedFs::native()?;
        let lifecycle = super::lifecycle::LifecycleHost::native_unreleased()?.inspect()?;
        if lifecycle.busy
            || lifecycle.transaction
            || lifecycle.installed.as_ref() != Some(self.proof.record())
        {
            return Err(HostError::Foreign);
        }
        if super::linux::observation::read_installed(&fs)?.as_ref() != Some(self.proof.record()) {
            return Err(HostError::Foreign);
        }
        let r = super::linux::observation::read_ownership(&fs)?;
        if let Some((bytes, _)) = fs.raw(
            "var/lib/.sbxr-removal.json",
            rustix::fs::Mode::from_raw_mode(0o600),
            crate::records::MAX_RECORD_BYTES,
        )? {
            if r.is_some() {
                return Err(HostError::Foreign);
            }
            let record =
                crate::records::OwnershipRecord::decode(&bytes).map_err(|_| HostError::Foreign)?;
            if crate::removal::finishing_release(&record).map_err(|_| HostError::Foreign)?
                != self.proof.record().release_identity()
                || crate::removal::checkpoint(&record).map_err(|_| HostError::Foreign)?
                    != crate::removal::checkpoint_limit(&record).map_err(|_| HostError::Foreign)?
            {
                return Err(HostError::Foreign);
            }
            return Ok(vec![Journey::Removal]);
        }
        let Some(r) = r else {
            return Ok(vec![Journey::Standard, Journey::Tunnel, Journey::Removal]);
        };
        if r.release_identity() != self.proof.record().release_identity() {
            return Err(HostError::Foreign);
        }
        if r.recovery_direction() == RecoveryDirection::Removal {
            return Ok(vec![Journey::Removal]);
        }
        if r.phase() != SetupPhase::Running {
            return Ok(if r.tunnel_authority().is_some() {
                vec![Journey::Tunnel, Journey::Removal]
            } else {
                vec![Journey::Standard, Journey::Removal]
            });
        }
        if r.serving_authority().is_some_and(|s| !s.is_http()) {
            // Read-only historical disclosure grants no HTTPS mutation/migration.
            return Ok(vec![Journey::Disclosure]);
        }
        if crate::client_identity::rotation(&r).is_ok() {
            return Ok(vec![Journey::Identity, Journey::Removal]);
        }
        if r.http_operation()
            .map_err(|_| HostError::LiveUnavailable)?
            .is_some()
        {
            return Ok(vec![Journey::Http, Journey::Disclosure, Journey::Removal]);
        }
        let mut journeys = vec![
            Journey::Http,
            Journey::Identity,
            Journey::Disclosure,
            Journey::Removal,
        ];
        if r.tunnel_authority().is_some() {
            journeys.insert(0, Journey::Tunnel);
        }
        Ok(journeys)
    }
    fn open(&self, journey: Journey) -> Result<Box<dyn Interface + 'a>, HostError> {
        use super::timing::Phase;
        let _phase = super::timing::span(match journey {
            Journey::Standard => Phase::Standard,
            Journey::Tunnel => Phase::Tunnel,
            Journey::Removal => Phase::Removal,
            Journey::Http => Phase::Http,
            Journey::Identity => Phase::Identity,
            Journey::Disclosure => Phase::Disclosure,
        });
        if !self.journeys()?.contains(&journey) {
            return Err(HostError::Foreign);
        }
        let inner: Result<Box<dyn Interface + 'a>, HostError> = match journey {
            Journey::Tunnel => self.tunnel_module(),
            Journey::Http => Ok(Box::new(
                HttpInstallation::native_unreleased(self.proof)?
                    .with_native_cancellation(self.stop.clone()),
            )),
            Journey::Identity => Ok(Box::new(
                ClientIdentityInstallation::new(
                    super::identity::ProtectedIdentityHost::native_unreleased(self.proof)?
                        .with_native_cancellation(self.stop.clone()),
                )
                .with_cancellation(self.stop.clone()),
            )),
            Journey::Standard => Ok(Box::new(
                crate::proxyinstallation::StandardInstallation::new(
                    self.standard_host()?,
                    self.proof.record().release_identity(),
                )?,
            )),
            Journey::Removal => Ok(Box::new(
                crate::proxyinstallation::RemovalInstallation::new(self.removal_host()?),
            )),
            Journey::Disclosure => Ok(Box::new(
                crate::proxyinstallation::DisclosureInstallation::new(
                    super::disclosure::ProtectedDisclosureHost::native_unreleased(self.proof)?
                        .with_cancellation(self.stop.clone()),
                    ExecutionMode::native_unreleased(),
                ),
            )),
        };
        let inner = inner?;
        Ok(Box::new(super::admission::BoundJourney::new(
            self.proof.snapshot_guard(),
            inner,
        )))
    }
    fn mode(&self) -> ExecutionMode {
        ExecutionMode::native_unreleased()
    }
}

/// Concrete zero-argument native composition. The existing qualification boundary
/// runs before transport construction, file inspection, entropy or host effects.
/// No unsupported/development host is silently redirected to the simulator.
pub fn run_public_unreleased(
    input: &mut impl std::os::fd::AsFd,
    output: &mut (impl std::io::Write + std::os::fd::AsFd),
) -> Result<(), PublicEntryError> {
    super::require_live_adapter()?;
    let _trace = super::timing::enable();
    let _entry = super::timing::span(super::timing::Phase::Entry);
    let selected = {
        let _phase = super::timing::span(super::timing::Phase::Select);
        let root = ProtectedFs::native()?;
        super::entry_input::select(&root, super::entry_input::now()?)?
    };
    match selected {
        super::entry_input::EntryInput::Stable => run_public_selected(input, output, None),
        super::entry_input::EntryInput::Candidate(reviewed) => {
            run_public_selected(input, output, Some(&reviewed))
        }
    }
}
fn run_public_selected(
    input: &mut impl std::os::fd::AsFd,
    output: &mut (impl std::io::Write + std::os::fd::AsFd),
    reviewed: Option<&std::sync::Arc<super::entry_input::ProtectedCandidateInput>>,
) -> Result<(), PublicEntryError> {
    super::require_live_adapter()?;
    let commit = crate::build_identity::compiled_commit().ok_or(HostError::LiveUnavailable)?;
    let stop = crate::subscription_serving::Cancellation::new();
    let _signals = super::runtime::shutdown::Signals::native(stop.clone())
        .map_err(|_| HostError::Cancelled)?;
    let mut input = super::input::InterruptibleInput::new(input, stop.clone())?;
    let mut output = super::input::InterruptibleOutput::native(output, stop.clone())?;
    let observer = super::linux::NativeObserver::open()?;
    let budget = match reviewed {
        Some(i) => crate::artifact_trust::SelectionBudget::until(i.selection_deadline()),
        None => crate::artifact_trust::SelectionBudget::new(),
    }
    .with_cancellation(stop.clone());
    let _authentication = super::timing::span(super::timing::Phase::Authenticate);
    let proof = match reviewed {
        None => {
            let mut authentication =
                crate::release_https::HttpsTransport::new().map_err(|_| HostError::Foreign)?;
            observer.authenticate_current(&mut authentication, &budget, stop.clone())?
        }
        Some(input) => {
            super::admission::NativeAdmission::reviewed_candidate(input, &budget, stop.clone())?
        }
    };
    drop(_authentication);
    if proof.record().release_identity().commit() != commit {
        return Err(HostError::Foreign.into());
    }
    let mut owner = NativeOwnerSources::authenticated_unreleased(&proof)?
        .with_cancellation(stop.clone())
        .frontend();
    // Admission has authenticated the selected role. Keep Check on the same
    // pinned delivery route; public roots cannot authenticate the private CA.
    // Lifecycle still uses acquire_latest's stable proof and refuses candidates.
    let candidate_transport = reviewed
        .map(|input| {
            crate::release_https::CandidateGatewayTransport::from_retained_gateway(
                input.ca_sha256(),
                &budget,
            )
        })
        .transpose()
        .map_err(|_| HostError::Foreign)?;
    let transport = crate::release_https::LifecycleTransport::new(candidate_transport)
        .map_err(|_| HostError::Foreign)?;
    let mut lifecycle = crate::software_lifecycle::Installed::new(
        super::lifecycle::LifecycleHost::native_unreleased()?,
        transport,
    )
    .with_cancellation(stop.clone());
    let terminal =
        crate::terminal::run_with_lifecycle(&mut input, &mut output, &mut owner, &mut lifecycle);
    if stop.is_cancelled() {
        return Err(HostError::Cancelled.into());
    }
    terminal?;
    drop(owner);
    use crate::software_lifecycle::Interface as _;
    if let Some(finisher) = lifecycle.take_finisher() {
        match finisher.exec_native_unreleased() {
            Ok(never) => match never {},
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub enum PublicEntryError {
    Host(HostError),
    Terminal(std::io::Error),
}
impl std::fmt::Debug for PublicEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Native public entry refused or terminal failed (redacted)")
    }
}
impl From<HostError> for PublicEntryError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}
impl From<std::io::Error> for PublicEntryError {
    fn from(value: std::io::Error) -> Self {
        Self::Terminal(value)
    }
}
impl std::fmt::Display for PublicEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(e) => e.fmt(f),
            Self::Terminal(_) => f.write_str(
                "Terminal session failed; preserve the current authority and review again.",
            ),
        }
    }
}
impl std::error::Error for PublicEntryError {}
