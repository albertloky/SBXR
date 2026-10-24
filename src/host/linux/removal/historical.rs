use super::*;
use crate::host::{
    historical::{Asset, HistoricalHttps},
    locks::HostLock,
};
#[derive(Clone, Debug)]
pub struct HistoricalRuntimeFacts {
    pub fingerprint: String,
    pub renewal_quiet: bool,
    pub official_route: bool,
}
impl<R: CommandRunner, B: AuxiliaryRuntime> StandardRemovalHost<R, B> {
    pub(super) fn historical_host(&self) -> Result<HistoricalHttps, HostError> {
        if self.inner.native_mode {
            HistoricalHttps::native_unreleased()
        } else {
            HistoricalHttps::injected(self.inner.fs.path())
        }
    }
    pub(super) fn inspect_historical(&self, record: &OwnershipRecord) -> Result<String, HostError> {
        let host = self.historical_host()?;
        let plan = host.plan(record)?;
        if !crate::host::historical::has_authority(record) {
            return Ok(plan.fingerprint());
        }
        host.renewal_hooks_safe()?;
        let unfinished = host.unfinished(record)?;
        let facts = self.auxiliary.historical(record, &unfinished)?;
        if !facts.renewal_quiet {
            return Err(HostError::Busy);
        }
        Ok(format!("{}:{}", plan.fingerprint(), facts.fingerprint))
    }
    pub(super) fn historical_effect_present(
        &self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<bool, HostError> {
        let plan = self.historical_host()?.plan(record)?;
        Ok(match effect {
            RemovalEffect::RenewalIntegration => !plan.renewal.is_empty(),
            RemovalEffect::RetiredHttps => !plan.retired.is_empty(),
            _ => return Err(HostError::Foreign),
        })
    }
    fn historical_remove(
        &self,
        host: &mut HistoricalHttps,
        owner: &Arc<HostLock>,
        assets: &[Asset],
        _boundary: u8,
    ) -> Result<(), HostError> {
        for (index, asset) in assets.iter().enumerate() {
            self.guard()?;
            host.remove_assets(owner, std::slice::from_ref(asset))?;
            self.historical_boundary(usize::from(_boundary) + index)?;
        }
        Ok(())
    }
    fn historical_boundary(&self, _point: usize) -> Result<(), HostError> {
        #[cfg(test)]
        if self.fault.is_some_and(|p| usize::from(p) == _point) {
            return Err(HostError::Injected);
        }
        Ok(())
    }
    pub(super) fn apply_historical(
        &mut self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<(), HostError> {
        self.guard()?;
        self.historical
            .as_ref()
            .ok_or(HostError::Unsafe)?
            .verify()?;
        let owner = self.inner.lock.as_ref().ok_or(HostError::Unsafe)?.clone();
        let mut host = self.historical_host()?;
        let plan = host.plan(record)?;
        if effect == RemovalEffect::RenewalIntegration {
            let (entry, mut rest): (Vec<_>, Vec<_>) = plan
                .renewal
                .into_iter()
                .partition(|a| matches!(a,Asset::File{path,..} if path.starts_with("etc/")));
            rest.sort_by_key(|a| {
                if matches!(a,Asset::File{path,..} if path=="var/lib/sbxr/renewal-attempts.json") {
                    0
                } else {
                    1
                }
            });
            self.historical_remove(&mut host, &owner, &entry, 120)?;
            self.inner.runner.reload_units(&self.inner.stop)?;
            let facts = self
                .auxiliary
                .historical(record, &host.unfinished(record)?)?;
            if !facts.official_route || !facts.renewal_quiet {
                return Err(HostError::Foreign);
            }
            self.historical
                .as_mut()
                .ok_or(HostError::Unsafe)?
                .permit_removed_renewal();
            self.historical_remove(&mut host, &owner, &rest, 130)?;
        } else if effect == RemovalEffect::RetiredHttps {
            if self
                .inner
                .fs
                .metadata(crate::host::subscription::FIREWALL)?
                .is_some()
            {
                return Err(HostError::Foreign);
            }
            let facts = self.auxiliary.historical(record, &[])?;
            if !facts.official_route || !facts.renewal_quiet {
                return Err(HostError::Foreign);
            }
            self.historical
                .as_mut()
                .ok_or(HostError::Unsafe)?
                .permit_removed_renewal();
            self.historical_remove(&mut host, &owner, &plan.retired, 140)?;
            self.inner.runner.reload_units(&self.inner.stop)?;
        } else {
            return Err(HostError::LiveUnavailable);
        }
        Ok(())
    }
    pub(super) fn remove_historical_serving(
        &mut self,
        record: &OwnershipRecord,
    ) -> Result<(), HostError> {
        if !crate::host::historical::has_authority(record) {
            return Ok(());
        }
        self.historical
            .as_ref()
            .ok_or(HostError::Unsafe)?
            .verify()?;
        let owner = self.inner.lock.as_ref().ok_or(HostError::Unsafe)?.clone();
        let mut host = self.historical_host()?;
        let plan = host.plan(record)?;
        self.historical_remove(&mut host, &owner, &plan.serving, 170)
    }
    pub(super) fn remove_historical_resources(
        &mut self,
        record: &OwnershipRecord,
    ) -> Result<(), HostError> {
        if !crate::host::historical::has_authority(record) {
            return Ok(());
        }
        self.historical
            .as_ref()
            .ok_or(HostError::Unsafe)?
            .verify()?;
        let owner = self.inner.lock.as_ref().ok_or(HostError::Unsafe)?.clone();
        let mut host = self.historical_host()?;
        let plan = host.plan(record)?;
        self.historical_remove(&mut host, &owner, &plan.serving, 170)?;
        self.historical_remove(&mut host, &owner, &plan.resources, 200)
    }
}
