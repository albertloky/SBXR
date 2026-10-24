use super::*;
/// Supplied, pinned, bounded installation bytes; no download or key generation.
/// The constructor validates actual upstream key/package hashes and package size.
pub struct SetupMaterial {
    pub(super) key: Vec<u8>,
    pub(super) package: Vec<u8>,
    pub(super) configuration: ServerConfiguration,
    pub(super) key_sha256: String,
    pub(super) package_sha256: String,
}
impl SetupMaterial {
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
        if configuration.as_bytes().len() > 1 << 20
            || !configuration.is_standard_only()
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
            configuration,
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
