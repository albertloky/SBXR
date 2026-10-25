//! The package's public conffile is a distinct pre-configuration setup state.
use super::*;
use crate::records::RecoveryDirection;
impl<R: CommandRunner> LinuxHost<R> {
    pub(super) fn package_default(
        &self,
        record: Option<&OwnershipRecord>,
        facts: &Facts,
        fingerprint: &mut String,
    ) -> Result<bool, HostError> {
        // Ordinary private/absent files keep the existing reader and authority.
        if self
            .fs
            .raw(CONFIG, Mode::from_raw_mode(0o640), 1 << 20)
            .is_ok()
        {
            return Ok(false);
        }
        let record = record.ok_or(HostError::Foreign)?;
        if observation::read_ownership(&self.fs)?.as_ref() != Some(record)
            || record.lock_provisioning_sha256() != Some(sha256_hex(UNIT).as_str())
            || record.schema() != 1
            || record.configuration_sha256() != self.configuration_sha256()
            || record.public_ipv4() != self.public_ipv4()
            || record.recovery_direction() != RecoveryDirection::Cleanup
            || record.cleanup_checkpoint() > 4
            || !matches!(
                record.phase(),
                SetupPhase::ServiceMasked
                    | SetupPhase::PackageInstalled
                    | SetupPhase::PackageHeld
                    | SetupPhase::StateDirectoryCreated
            )
        {
            return Err(HostError::Foreign);
        }
        // A staged successor can already prove private publication completed.
        // Reading the old canonical checkpoint must not reverse that evidence.
        if let Some((bytes, proof)) = self.fs.raw(
            &format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
            Mode::from_raw_mode(0o600),
            crate::records::MAX_RECORD_BYTES,
        )? {
            let staged = OwnershipRecord::decode(&bytes).map_err(|_| HostError::Foreign)?;
            if !record.permits_successor(&staged)
                || staged.cleanup_checkpoint() > 4
                || !matches!(
                    staged.phase(),
                    SetupPhase::ServiceMasked
                        | SetupPhase::PackageInstalled
                        | SetupPhase::PackageHeld
                        | SetupPhase::StateDirectoryCreated
                )
            {
                return Err(HostError::Foreign);
            }
            fingerprint.push_str(&format!("package-default-journal-stage:{proof:?};"));
        }
        let (body, proof) = self
            .fs
            .raw(CONFIG, Mode::from_raw_mode(0o644), 635)?
            .ok_or(HostError::Foreign)?;
        if body != crate::package_acquisition::DEFAULT_CONFIGURATION || proof.gid != self.fs.gid {
            return Err(HostError::Foreign);
        }
        if facts.package {
            let owner = self.runner.query(Query::ConfigurationOwner, &self.stop)?;
            if !facts.provenance
                || !facts.identity
                || owner.code() != 0
                || owner.text()? != "sing-box: /etc/sing-box/config.json"
            {
                return Err(HostError::Foreign);
            }
            fingerprint.push_str(&format!(
                "configuration-owner:{}:{};",
                owner.code(),
                sha256_hex(owner.bytes())
            ));
        } else if !(3..=4).contains(&record.cleanup_checkpoint()) {
            // Purge may have completed before its journal checkpoint was synced.
            // Only that exact cleanup interval can retain the known public residue.
            return Err(HostError::Foreign);
        }
        fingerprint.push_str(&format!("package-default:{proof:?};"));
        Ok(true)
    }
}
