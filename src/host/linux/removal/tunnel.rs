//! Dedicated connector cleanup composed with the existing HTTP runtime.
use super::*;
use crate::host::tunnel_native::{Connector, ConnectorIo};
use crate::records::TunnelAuthority;
#[derive(Clone, Debug)]
pub struct TunnelRemovalFacts {
    pub fingerprint: String,
    pub empty: bool,
}
pub struct TunnelRemovalRuntime<B, I> {
    http: B,
    connector: Connector<I>,
}
impl<B: AuxiliaryRuntime, I: ConnectorIo> TunnelRemovalRuntime<B, I> {
    pub fn new(http: B, connector: Connector<I>) -> Self {
        Self { http, connector }
    }
}
impl<B: AuxiliaryRuntime, I: ConnectorIo> AuxiliaryRuntime for TunnelRemovalRuntime<B, I> {
    fn observe(&self, record: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError> {
        self.http.observe(record)
    }
    fn disable(
        &mut self,
        firewall: bool,
        record: &OwnershipRecord,
        owner: &Arc<super::super::super::locks::HostLock>,
    ) -> Result<(), HostError> {
        self.http.disable(firewall, record, owner)
    }
    fn historical(
        &self,
        r: &OwnershipRecord,
        a: &[crate::host::historical::UnfinishedRenewal],
    ) -> Result<super::HistoricalRuntimeFacts, HostError> {
        self.http.historical(r, a)
    }
    fn inspect_tunnel(
        &self,
        authority: &TunnelAuthority,
        stop: &Cancellation,
    ) -> Result<TunnelRemovalFacts, HostError> {
        let facts = self
            .connector
            .inspect_removal(authority, stop)
            .map_err(|_| HostError::Foreign)?;
        Ok(TunnelRemovalFacts {
            fingerprint: facts.fingerprint,
            empty: facts.empty,
        })
    }
    fn remove_tunnel(
        &mut self,
        authority: &TunnelAuthority,
        owner: &Arc<super::super::super::locks::HostLock>,
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        self.connector
            .remove(owner, authority, stop)
            .map_err(|_| HostError::Foreign)
    }
}
impl<R: CommandRunner, B: AuxiliaryRuntime> StandardRemovalHost<R, B> {
    pub(super) fn tunnel_state(
        &self,
        record: &OwnershipRecord,
    ) -> Result<TunnelRemovalFacts, HostError> {
        if let Some(authority) = record.tunnel_authority() {
            self.auxiliary.inspect_tunnel(&authority, &self.inner.stop)
        } else {
            for path in [
                "etc/systemd/system/sbxr-tunnel.service",
                "etc/systemd/system/sbxr-tunnel.service.sbxr-next",
                "etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service",
            ] {
                if self.inner.fs.metadata(path)?.is_some() {
                    return Err(HostError::Foreign);
                }
            }
            Ok(TunnelRemovalFacts {
                fingerprint: "no dedicated tunnel authority".into(),
                empty: true,
            })
        }
    }
}
