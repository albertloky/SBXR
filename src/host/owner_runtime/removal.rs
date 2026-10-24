//! Local-only current HTTP removal observations. No Internet or token acquisition.
use super::*;
use crate::host::{
    linux::{AuxiliaryFacts, AuxiliaryRuntime},
    subscription::{HttpRuntime, SystemEffect},
};
impl<I: OwnerIo> AuxiliaryRuntime for OwnerRuntime<'_, I> {
    fn observe(&self, record: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError> {
        use command::{Property as P, Unit as U};
        let current = self.io.current().map_err(refused)?;
        if current.uid != self.fs.uid
            || current.executable_sha256 != self.proof.record().executable_sha256()
        {
            return Err(HostError::Foreign);
        }
        if crate::removal::finishing_release(record).ok().as_ref()
            != Some(&self.proof.record().release_identity())
            && record.release_identity() != self.proof.record().release_identity()
        {
            return Err(HostError::Foreign);
        }
        let checkpoint = crate::removal::checkpoint(record).unwrap_or(0);
        match self.fs.raw(
            "var/lib/sbxr/installed.json",
            Mode::from_raw_mode(0o600),
            4096,
        )? {
            Some((bytes, proof))
                if crate::records::InstalledRecord::decode(&bytes).map_err(refused)?
                    == *self.proof.record()
                    && proof.gid == self.fs.gid => {}
            None if checkpoint >= 10 => {}
            _ => return Err(HostError::Foreign),
        }
        match self.fs.raw(
            "usr/local/bin/sbxr",
            Mode::from_raw_mode(0o755),
            crate::release_identity::MAX_EXECUTABLE_BYTES,
        )? {
            Some((bytes, proof))
                if sha256_hex(&bytes) == self.proof.record().executable_sha256()
                    && proof.gid == self.fs.gid => {}
            None if checkpoint >= 9 => {}
            _ => return Err(HostError::Foreign),
        }
        if self.record()? != *record {
            return Err(HostError::Foreign);
        }
        let c = Self::context();
        let active = self.property(U::Subscription, P::ActiveState, &c)? == "active";
        if self.fs.metadata(crate::host::subscription::UNIT)?.is_some() {
            self.serving_routes(&c)?;
        } else if active {
            return Err(HostError::Foreign);
        }
        let mut image = String::new();
        if active {
            let pid = self
                .property(U::Subscription, P::MainPid, &c)?
                .parse::<u32>()
                .map_err(refused)?;
            let process = self.io.process(pid)?;
            image = format!("{process:?}");
            if process.uid != self.fs.uid
                || process.executable_sha256 != self.proof.record().executable_sha256()
                || process.cgroup != U::Subscription.cgroup()
                || self.property(U::Subscription, P::ControlPid, &c)? != "0"
                || self.io.process(pid)? != process
            {
                return Err(HostError::Foreign);
            }
        }
        if self
            .fs
            .metadata(crate::host::subscription::FIREWALL)?
            .is_some()
        {
            self.firewall_effective(record, &c)?;
        }
        Ok(AuxiliaryFacts {
            fingerprint: sha256_hex(image.as_bytes()),
            serving_running: active,
            quiescent: !active
                && self.quiescence(U::Subscription, &c)?
                && self.io.port_available(8443, &c)?,
            firewall_rules: self.text(Observation::Firewall, &c)?,
        })
    }
    fn disable(
        &mut self,
        firewall: bool,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
    ) -> Result<(), HostError> {
        HttpRuntime::effect(
            self,
            if firewall {
                SystemEffect::DisableFirewall
            } else {
                SystemEffect::DisableServing
            },
            record,
            owner,
            &Self::context(),
        )
    }
}
