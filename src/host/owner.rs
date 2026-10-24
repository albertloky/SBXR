//! Concrete installed native Owner sources. Public entry remains closed while
//! native recovery, auxiliary cleanup and exact-candidate qualification are incomplete.
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
    }
    fn removal_host(
        &self,
    ) -> Result<
        super::linux::StandardRemovalHost<
            super::system::SystemRunner<super::system::NativeTransport>,
            super::owner_runtime::OwnerRuntime<'a, super::owner_runtime::NativeIo>,
        >,
        HostError,
    > {
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
        .with_auxiliary(super::owner_runtime::OwnerRuntime::native_unreleased(
            self.proof,
        )?))
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
            Journey::Removal => Ok(Box::new(
                crate::proxyinstallation::RemovalInstallation::new(self.removal_host()?),
            )),
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
