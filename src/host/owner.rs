//! Concrete installed native Owner sources. Public entry remains closed while
//! Standard input/recovery, auxiliary cleanup and disclosure owners are incomplete.
use super::{HostError, filesystem::ProtectedFs};
use crate::{
    proxyinstallation::{
        ClientIdentityInstallation, ExecutionMode, HttpInstallation, Interface, Journey,
        OwnerInstallation, OwnerSources,
    },
    records::{RecoveryDirection, SetupPhase},
    release_acquisition::AuthenticatedInstalled,
};
/// The executing bytes must already be authenticated by NativeObserver. This
/// adapter never creates an installed proof from local metadata alone.
type CachedPackage = std::sync::Arc<(Vec<u8>, Vec<u8>)>;
pub struct NativeOwnerSources<'a> {
    proof: &'a AuthenticatedInstalled,
    package: std::cell::RefCell<Option<CachedPackage>>,
}
impl<'a> NativeOwnerSources<'a> {
    pub fn authenticated_unreleased(proof: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        super::owner_runtime::OwnerRuntime::native_unreleased(proof)?;
        Ok(Self {
            proof,
            package: std::cell::RefCell::new(None),
        })
    }
    fn standard_host(
        &self,
    ) -> Result<
        super::linux::LinuxHost<super::system::SystemRunner<super::system::NativeTransport>>,
        HostError,
    > {
        use crate::{
            artifact_trust::SelectionBudget,
            identity_generation::OsEntropy,
            package_acquisition::{self, PackageHttps},
        };
        let fs = ProtectedFs::native()?;
        let record = super::linux::observation::read_ownership(&fs)?;
        let require_bind = !record.as_ref().is_some_and(|r| {
            matches!(
                r.recovery_direction(),
                RecoveryDirection::None | RecoveryDirection::FinishSetup
            )
        });
        let network = super::network::NetworkAdmission::native(
            &super::process::Cancellation::new(),
            require_bind,
        )?;
        if self.package.borrow().is_none() {
            let package = package_acquisition::acquire(
                &mut PackageHttps::new().map_err(|_| HostError::Foreign)?,
                &SelectionBudget::new(),
            )
            .map_err(|_| HostError::Foreign)?;
            *self.package.borrow_mut() = Some(std::sync::Arc::new(package.into_parts()));
        }
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
    }
    pub fn frontend(self) -> OwnerInstallation<'a, Self> {
        OwnerInstallation::new(self)
    }
}
impl<'a> OwnerSources<'a> for NativeOwnerSources<'a> {
    fn journeys(&self) -> Result<Vec<Journey>, HostError> {
        super::linux::require_native_environment()?;
        let fs = ProtectedFs::native()?;
        if super::linux::observation::read_installed(&fs)?.as_ref() != Some(self.proof.record()) {
            return Err(HostError::Foreign);
        }
        let r = super::linux::observation::read_ownership(&fs)?;
        let Some(r) = r else {
            return Ok(vec![Journey::Standard, Journey::Removal]);
        };
        if r.release_identity() != self.proof.record().release_identity() {
            return Err(HostError::Foreign);
        }
        if r.recovery_direction() == RecoveryDirection::Removal {
            return Ok(vec![Journey::Removal]);
        }
        if r.phase() != SetupPhase::Running {
            return Ok(vec![Journey::Standard, Journey::Removal]);
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
        Ok(vec![
            Journey::Http,
            Journey::Identity,
            Journey::Disclosure,
            Journey::Removal,
        ])
    }
    fn open(&self, journey: Journey) -> Result<Box<dyn Interface + 'a>, HostError> {
        match journey {
            Journey::Http => Ok(Box::new(HttpInstallation::native_unreleased(self.proof)?)),
            Journey::Identity => Ok(Box::new(ClientIdentityInstallation::new(
                super::identity::ProtectedIdentityHost::native_unreleased(self.proof)?,
            ))),
            Journey::Standard => Ok(Box::new(
                crate::proxyinstallation::StandardInstallation::new(
                    self.standard_host()?,
                    self.proof.record().release_identity(),
                )?,
            )),
            // Offline removal must not acquire a package or probe external
            // destinations. Its native input builder remains a separate owner.
            Journey::Removal => Err(HostError::LiveUnavailable),
            Journey::Disclosure => Ok(Box::new(
                crate::proxyinstallation::DisclosureInstallation::new(
                    super::disclosure::ProtectedDisclosureHost::native_unreleased(self.proof)?,
                    ExecutionMode::NativeUnavailable,
                ),
            )),
        }
    }
    fn mode(&self) -> ExecutionMode {
        ExecutionMode::NativeUnavailable
    }
}
