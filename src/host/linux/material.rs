use super::*;
/// Supplied, pinned, bounded installation bytes; no download or key generation.
/// The constructor validates actual upstream key/package hashes and package size.
pub struct SetupMaterial {
    pub(super) key: Vec<u8>,
    pub(super) package: Vec<u8>,
    pub(super) configuration: Option<ServerConfiguration>,
    pub(super) configuration_digest: String,
    pub(super) offline: bool,
    pub(super) key_sha256: String,
    pub(super) package_sha256: String,
}
impl SetupMaterial {
    pub fn configuration_sha256(&self) -> String {
        self.configuration_digest.clone()
    }

    /// Journal-bound cleanup has no package/configuration bytes and cannot be
    /// used to install or activate a service. Existing residues are hash-checked.
    pub fn for_cleanup(record: &OwnershipRecord) -> Result<Self, HostError> {
        if record.schema() != 1
            || record.tunnel_authority().is_some()
            || record.recovery_direction() != crate::records::RecoveryDirection::Cleanup
        {
            return Err(HostError::Foreign);
        }
        Self::offline_bound(Some(record))
    }
    pub(in crate::host) fn tunnel_cleanup(record: &OwnershipRecord) -> Result<Self, HostError> {
        if record.schema() != 1
            || record.tunnel_authority().is_none()
            || record.recovery_direction() != crate::records::RecoveryDirection::Cleanup
        {
            return Err(HostError::Foreign);
        }
        Self::offline_bound(Some(record))
    }
    pub fn recovered_tunnel(
        key: Vec<u8>,
        package: Vec<u8>,
        configuration: &[u8],
    ) -> Result<Self, HostError> {
        let config =
            ServerConfiguration::decode_supported(configuration).map_err(|_| HostError::Foreign)?;
        if config.is_standard_only() {
            return Err(HostError::Foreign);
        }
        Self::verified_profile(key, package, config, true)
    }
    /// Complete removal needs only public pins and committed local authority.
    /// It never downloads a package or regenerates an absent Client Identity.
    pub fn for_removal(record: Option<&OwnershipRecord>) -> Result<Self, HostError> {
        Self::offline_bound(record)
    }
    fn offline_bound(record: Option<&OwnershipRecord>) -> Result<Self, HostError> {
        let digest = record
            .map(OwnershipRecord::configuration_sha256)
            .unwrap_or("");
        if !digest.is_empty()
            && (digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        {
            return Err(HostError::Foreign);
        }
        Ok(Self {
            key: Vec::new(),
            package: Vec::new(),
            configuration: None,
            configuration_digest: if digest.is_empty() {
                "0".repeat(64)
            } else {
                digest.into()
            },
            key_sha256: PINNED_SING_BOX.signing_key_sha256.into(),
            package_sha256: PINNED_SING_BOX.sha256.into(),
            offline: true,
        })
    }
    pub(super) fn configuration_bytes(&self) -> Result<&[u8], HostError> {
        self.configuration
            .as_ref()
            .map(ServerConfiguration::as_bytes)
            .ok_or(HostError::Foreign)
    }
    /// Acquired pinned material is consumed without exposing host mutation
    /// authority. Identity generation still follows verified-input admission.
    pub fn from_acquired_package(
        package: crate::package_acquisition::VerifiedPackage,
        entropy: &mut dyn crate::identity_generation::Entropy,
    ) -> Result<Self, HostError> {
        let (key, deb) = package.into_parts();
        Self::generated_standard(key, deb, entropy)
    }
    /// Recovery keeps the existing exact configuration and Client Identity.
    pub fn recover_acquired_package(
        package: crate::package_acquisition::VerifiedPackage,
        configuration: &[u8],
    ) -> Result<Self, HostError> {
        let (key, deb) = package.into_parts();
        Self::recovered_standard(key, deb, configuration)
    }

    /// Invalid pinned inputs fail before allocating any new Client Identity.
    pub fn generated_standard(
        key: Vec<u8>,
        package: Vec<u8>,
        entropy: &mut dyn crate::identity_generation::Entropy,
    ) -> Result<Self, HostError> {
        if key.len() > 1 << 20
            || sha256_hex(&key) != PINNED_SING_BOX.signing_key_sha256
            || package.len() as u64 != PINNED_SING_BOX.size
            || sha256_hex(&package) != PINNED_SING_BOX.sha256
        {
            return Err(HostError::Foreign);
        }
        let identity = crate::identity_generation::Identity::generate_with_entropy(entropy)
            .map_err(|_| HostError::Io)?;
        let identity = identity.server_identity().map_err(|_| HostError::Unsafe)?;
        let configuration =
            ServerConfiguration::standard(&identity).map_err(|_| HostError::Unsafe)?;
        Self::verified(key, package, configuration)
    }
    /// Recovery reuses the bound configuration; it never regenerates credentials.
    pub fn recovered_standard(
        key: Vec<u8>,
        package: Vec<u8>,
        configuration: &[u8],
    ) -> Result<Self, HostError> {
        Self::verified(
            key,
            package,
            ServerConfiguration::decode_standard(configuration).map_err(|_| HostError::Foreign)?,
        )
    }
    pub fn verified(
        key: Vec<u8>,
        package: Vec<u8>,
        configuration: ServerConfiguration,
    ) -> Result<Self, HostError> {
        Self::verified_profile(key, package, configuration, false)
    }
    fn verified_profile(
        key: Vec<u8>,
        package: Vec<u8>,
        configuration: ServerConfiguration,
        tunnel: bool,
    ) -> Result<Self, HostError> {
        if configuration.as_bytes().len() > 1 << 20
            || configuration.is_standard_only() == tunnel
            || key.len() > 1 << 20
            || sha256_hex(&key) != PINNED_SING_BOX.signing_key_sha256
            || package.len() as u64 != PINNED_SING_BOX.size
            || sha256_hex(&package) != PINNED_SING_BOX.sha256
        {
            return Err(HostError::Foreign);
        }
        Ok(Self {
            key,
            package,
            configuration_digest: configuration.sha256_hex(),
            configuration: Some(configuration),
            offline: false,
            key_sha256: PINNED_SING_BOX.signing_key_sha256.into(),
            package_sha256: PINNED_SING_BOX.sha256.into(),
        })
    }
}
impl fmt::Debug for SetupMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Setup material (redacted)")
    }
}
