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
