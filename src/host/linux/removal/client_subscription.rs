//! Hash-bound temporary artifacts from interrupted Client Identity rotation.
use super::*;
use crate::host::{identity as ci, subscription as http};
impl<R: CommandRunner, B: AuxiliaryRuntime> StandardRemovalHost<R, B> {
    pub(super) fn identity_subscription(
        &self,
        record: &OwnershipRecord,
        remove: bool,
    ) -> Result<bool, HostError> {
        let value: serde_json::Value =
            serde_json::from_slice(&record.encode().map_err(|_| HostError::Foreign)?)
                .map_err(|_| HostError::Foreign)?;
        let subscription = value
            .get("client_identity_rotation")
            .and_then(|r| r.get("subscription"));
        let upgrade = format!("{}.sbxr-next", http::UNIT);
        let Some(subscription) = subscription else {
            for path in [
                ci::ARTIFACT.to_owned(),
                format!("{}.sbxr-next", ci::ARTIFACT),
                format!("{upgrade}.sbxr-next"),
            ] {
                if self.inner.fs.metadata(&path)?.is_some() {
                    return Err(HostError::Foreign);
                }
            }
            return Ok(false);
        };
        let hash = subscription["target_artifact_sha256"]
            .as_str()
            .ok_or(HostError::Foreign)?;
        let bodies = self.publication_bodies(ci::ARTIFACT, Mode::from_raw_mode(0o600))?;
        if bodies
            .iter()
            .any(|body| body.len() > 4096 || sha256_hex(body) != hash)
        {
            return Err(HostError::Foreign);
        }
        let target = crate::host::historical::authority(&subscription["target"])?;
        let states = [target.state_bytes().map_err(|_| HostError::Foreign)?];
        let state = self.auxiliary_file(http::CANDIDATE_STATE, &states, 0o600, false)?;
        let unit = [crate::runtime_handoff::SERVING_UNIT.as_bytes().to_vec()];
        let startup = self.auxiliary_file(&upgrade, &unit, 0o644, false)?;
        if remove {
            self.clear_publication(ci::ARTIFACT, Mode::from_raw_mode(0o600), &bodies)?;
            #[cfg(test)]
            if self.fault == Some(100) {
                return Err(HostError::Injected);
            }
            self.auxiliary_file(http::CANDIDATE_STATE, &states, 0o600, true)?;
            #[cfg(test)]
            if self.fault == Some(101) {
                return Err(HostError::Injected);
            }
            self.auxiliary_file(&upgrade, &unit, 0o644, true)?;
            #[cfg(test)]
            if self.fault == Some(102) {
                return Err(HostError::Injected);
            }
        }
        Ok(!bodies.is_empty() || state || startup)
    }
}
