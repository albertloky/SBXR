use super::*;
pub(in crate::host) struct HistoricalExclusion {
    locks: super::super::filesystem::HistoricalFileLocks,
}
impl HistoricalExclusion {
    pub fn permit_removed_renewal(&mut self) {
        self.locks.permit_removed_renewal();
    }
    pub fn verify(&self) -> Result<(), HostError> {
        self.locks.verify()
    }
}
impl HistoricalHttps {
    pub(in crate::host) fn exclusion(
        &mut self,
        owner: &Arc<HostLock>,
        record: &OwnershipRecord,
    ) -> Result<HistoricalExclusion, HostError> {
        self.plan(record)?;
        let value = record_value(record)?;
        let renewal = value.get("renewal").is_some()
            || value.get("https_retirement").is_some()
            || value
                .get("subscription_enablement")
                .and_then(|e| e.get("renewal"))
                .is_some();
        let absent = renewal::MANAGED
            .into_iter()
            .take(3)
            .all(|(path, _, _)| self.fs.metadata(path).is_ok_and(|v| v.is_none()));
        self.scoped(owner, |this| {
            Ok(HistoricalExclusion {
                locks: this.fs.historical_exclusion(renewal, absent)?,
            })
        })
    }
}
