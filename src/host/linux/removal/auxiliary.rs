//! Current HTTP and Client Identity removal over the same protected paths used
//! by their writers. No certificate/tunnel/account acquisition is part of removal.
use super::*;
use crate::{
    host::{identity as ci, locks::HostLock, subscription as http},
    records::ServingAuthority,
};
use std::sync::Arc;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxiliaryFacts {
    /// Stable service/process identity, excluding mutable traffic counters.
    pub fingerprint: String,
    pub serving_running: bool,
    pub quiescent: bool,
    pub firewall_rules: String,
}
pub trait AuxiliaryRuntime {
    /// Local systemd/process/listener/firewall facts; no public-IP/DNS/TLS probe.
    fn observe(&self, record: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError>;
    fn disable(
        &mut self,
        firewall: bool,
        record: &OwnershipRecord,
        owner: &Arc<HostLock>,
    ) -> Result<(), HostError>;
}
pub struct NoAuxiliaryRuntime;
impl AuxiliaryRuntime for NoAuxiliaryRuntime {
    fn observe(&self, _: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError> {
        Err(HostError::LiveUnavailable)
    }
    fn disable(
        &mut self,
        _: bool,
        _: &OwnershipRecord,
        _: &Arc<HostLock>,
    ) -> Result<(), HostError> {
        Err(HostError::LiveUnavailable)
    }
}
fn wire(record: &OwnershipRecord) -> Result<serde_json::Value, HostError> {
    serde_json::from_slice(&record.encode().map_err(|_| HostError::Foreign)?)
        .map_err(|_| HostError::Foreign)
}
fn authorities(
    value: &serde_json::Value,
    result: &mut Vec<ServingAuthority>,
) -> Result<(), HostError> {
    match value {
        serde_json::Value::Object(object) => {
            if (object.contains_key("certificate_generation")
                || object.get("resources").is_some_and(|r| r["http"] == true))
                && let (Some(id), Some(hash)) =
                    (object.get("link_id"), object.get("credential_sha256"))
            {
                if object.get("http") != Some(&serde_json::Value::Bool(true))
                    && !object.get("resources").is_some_and(|r| r["http"] == true)
                {
                    return Err(HostError::LiveUnavailable);
                }
                let a = ServingAuthority::http_digest(
                    id.as_str().ok_or(HostError::Foreign)?,
                    hash.as_str().ok_or(HostError::Foreign)?,
                )
                .map_err(|_| HostError::Foreign)?;
                if !result.contains(&a) {
                    result.push(a);
                }
            }
            for v in object.values() {
                authorities(v, result)?;
            }
        }
        serde_json::Value::Array(values) => {
            for v in values {
                authorities(v, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}
impl<R: CommandRunner, B: AuxiliaryRuntime> StandardRemovalHost<R, B> {
    pub(super) fn current_auxiliary(&self, record: &OwnershipRecord) -> Result<bool, HostError> {
        let v = wire(record)?;
        for key in [
            "tunnel",
            "renewal",
            "certificate_activation",
            "https_retirement",
            "subscription_transport_migration",
        ] {
            if v.get(key).is_some() {
                return Err(HostError::LiveUnavailable);
            }
        }
        if v.get("client_identity_rotation")
            .is_some_and(|r| r.get("subscription").is_some())
        {
            return Err(HostError::LiveUnavailable);
        }
        for resource in [
            v.get("subscription_resources"),
            v.get("subscription_enablement")
                .and_then(|e| e.get("resources")),
        ]
        .into_iter()
        .flatten()
        {
            if resource["http"] != true
                || resource["firewall_sha256"]
                    != sha256_hex(&http::http_firewall_unit(record.public_ipv4())?)
            {
                return Err(HostError::Foreign);
            }
        }
        let mut a = Vec::new();
        authorities(&v, &mut a)?;
        if v.get("subscription_resources")
            .is_some_and(|r| r["http"] != true)
        {
            return Err(HostError::LiveUnavailable);
        }
        if let Some(startup) = v.get("proxy_startup")
            && startup["drop_in_sha256"]
                != sha256_hex(crate::client_identity::STARTUP_DROP_IN.as_bytes())
        {
            return Err(HostError::Foreign);
        }
        Ok(!a.is_empty())
    }
    fn publication_bodies(&self, path: &str, mode: Mode) -> Result<Vec<Vec<u8>>, HostError> {
        for selected in [path.to_owned(), format!("{path}.sbxr-next")] {
            if self
                .inner
                .fs
                .metadata(&selected)?
                .is_some_and(|m| m.gid != self.inner.fs.gid)
            {
                return Err(HostError::Foreign);
            }
        }
        let canonical = self.inner.fs.publication_bytes(path, mode)?;
        let stage = match self
            .inner
            .fs
            .raw(&format!("{path}.sbxr-next"), mode, 1 << 20)
        {
            Ok(value) => value.map(|(b, _)| b),
            Err(_) if canonical.is_some() && self.inner.fs.raw(path, mode, 1 << 20).is_err() => {
                canonical.clone()
            }
            Err(e) => return Err(e),
        };
        Ok(canonical.into_iter().chain(stage).collect())
    }
    fn clear_publication(
        &self,
        path: &str,
        mode: Mode,
        allowed: &[Vec<u8>],
    ) -> Result<(), HostError> {
        if self.inner.fs.raw(path, mode, 1 << 20).is_err() {
            let body = self
                .inner
                .fs
                .publication_bytes(path, mode)?
                .ok_or(HostError::Foreign)?;
            if !allowed.contains(&body) {
                return Err(HostError::Foreign);
            }
            return self.inner.fs.clear_subscription(path, &body, mode);
        }
        for p in [format!("{path}.sbxr-next"), path.to_owned()] {
            if let Some((body, _)) = self.inner.fs.raw(&p, mode, 1 << 20)? {
                if !allowed.contains(&body) {
                    return Err(HostError::Foreign);
                }
                self.inner.fs.remove_bytes(&p, &body, mode)?;
            }
        }
        Ok(())
    }
    fn auxiliary_file(
        &self,
        path: &str,
        allowed: &[Vec<u8>],
        mode: rustix::fs::RawMode,
        remove: bool,
    ) -> Result<bool, HostError> {
        let mode = Mode::from_raw_mode(mode);
        let bodies = self.publication_bodies(path, mode)?;
        if bodies.iter().any(|b| !allowed.contains(b)) {
            return Err(HostError::Foreign);
        }
        if remove {
            self.clear_publication(path, mode, &bodies)?;
        }
        Ok(!bodies.is_empty())
    }
    fn token(
        &self,
        path: &str,
        allowed: &[ServingAuthority],
        remove: bool,
    ) -> Result<bool, HostError> {
        let mode = Mode::from_raw_mode(0o600);
        let bodies = self.publication_bodies(path, mode)?;
        for body in &bodies {
            if body.len() != 44
                || body[43] != b'\n'
                || !allowed
                    .iter()
                    .any(|a| sha256_hex(&body[..43]) == a.credential_sha256())
                || crate::subscription_artifact::SubscriptionCredential::parse(
                    std::str::from_utf8(&body[..43]).map_err(|_| HostError::Foreign)?,
                )
                .is_err()
            {
                return Err(HostError::Foreign);
            }
        }
        if remove {
            self.clear_publication(path, mode, &bodies)?;
        }
        Ok(!bodies.is_empty())
    }
    fn auxiliary_link(
        &self,
        path: &'static str,
        relative: &'static str,
        absolute: &'static str,
        remove: bool,
    ) -> Result<bool, HostError> {
        if self.inner.fs.metadata(path)?.is_none() {
            return Ok(false);
        }
        let mut resource = Resource {
            path,
            kind: Kind::Link(relative),
        };
        if self.inner.fs.observe(resource).is_err() {
            resource.kind = Kind::Link(absolute);
        }
        self.inner.fs.observe(resource)?.ok_or(HostError::Foreign)?;
        if remove {
            self.inner.fs.remove(resource)?;
        }
        Ok(true)
    }
    fn startup(&self, record: &OwnershipRecord, remove: bool) -> Result<bool, HostError> {
        let v = wire(record)?;
        let startup = v.get("proxy_startup");
        if self
            .inner
            .fs
            .metadata(ci::STARTUP_DIR)?
            .is_some_and(|m| m.gid != self.inner.fs.gid)
        {
            return Err(HostError::Foreign);
        }
        let directory = self
            .inner
            .fs
            .directory_entries(ci::STARTUP_DIR, Mode::from_raw_mode(0o755))?;
        if directory.as_ref().is_some_and(|entries| {
            entries.iter().any(|s| {
                s != "sbxr-client-identity.conf" && s != "sbxr-client-identity.conf.sbxr-next"
            })
        }) {
            return Err(HostError::Foreign);
        }
        let present = self.auxiliary_file(
            ci::STARTUP,
            &[crate::client_identity::STARTUP_DROP_IN.as_bytes().to_vec()],
            0o644,
            false,
        )?;
        if startup.is_none() && (present || directory.is_some()) {
            return Err(HostError::Foreign);
        }
        if remove {
            self.auxiliary_file(
                ci::STARTUP,
                &[crate::client_identity::STARTUP_DROP_IN.as_bytes().to_vec()],
                0o644,
                true,
            )?;
            if startup.is_some_and(|s| s["directory_created"] == true) {
                self.inner.fs.remove(Resource {
                    path: ci::STARTUP_DIR,
                    kind: Kind::Directory(Mode::from_raw_mode(0o755)),
                })?;
            }
        }
        Ok(present
            || directory.is_some() && startup.is_some_and(|s| s["directory_created"] == true))
    }
    pub(super) fn configuration_digests(
        &self,
        record: &OwnershipRecord,
    ) -> Result<Vec<String>, HostError> {
        let mut hashes = vec![record.configuration_sha256().to_owned()];
        if let Some(rotation) = wire(record)?.get("client_identity_rotation") {
            for key in ["source_configuration_sha256", "target_configuration_sha256"] {
                hashes.push(rotation[key].as_str().ok_or(HostError::Foreign)?.to_owned());
            }
        }
        Ok(hashes)
    }
    fn identity_target(&self, record: &OwnershipRecord, remove: bool) -> Result<bool, HostError> {
        let v = wire(record)?;
        let rotation = v.get("client_identity_rotation");
        let mut present = false;
        for (path, mode) in [(ci::TARGET, 0o600), (ci::CONFIG_STAGE, 0o640)] {
            if let Some(body) = self
                .inner
                .fs
                .publication_or_stage_bytes(path, Mode::from_raw_mode(mode))?
            {
                let hash = rotation
                    .and_then(|r| r["target_configuration_sha256"].as_str())
                    .ok_or(HostError::Foreign)?;
                if sha256_hex(&body) != hash {
                    return Err(HostError::Foreign);
                }
                let gid = if mode == 0o640 {
                    let facts = Facts::removal(&self.inner.runner, &self.inner.stop)?;
                    if !facts.identity {
                        return Err(HostError::Foreign);
                    }
                    facts.gid.ok_or(HostError::Foreign)?
                } else {
                    self.inner.fs.gid
                };
                for selected in [path.to_owned(), format!("{path}.sbxr-next")] {
                    if self
                        .inner
                        .fs
                        .metadata(&selected)?
                        .is_some_and(|m| m.gid != gid)
                    {
                        return Err(HostError::Foreign);
                    }
                }
                if remove {
                    self.inner
                        .fs
                        .clear_subscription(path, &body, Mode::from_raw_mode(mode))?;
                }
                present = true;
            }
        }
        Ok(present)
    }
    fn http_material(
        &self,
        record: &OwnershipRecord,
        remove: bool,
        firewall: bool,
    ) -> Result<bool, HostError> {
        let mut allowed = Vec::new();
        authorities(&wire(record)?, &mut allowed)?;
        let states: Vec<Vec<u8>> = allowed
            .iter()
            .map(|a| a.state_bytes().map_err(|_| HostError::Foreign))
            .collect::<Result<_, _>>()?;
        let mut present = false;
        if firewall {
            let value = wire(record)?;
            if value.get("subscription_resources").is_none()
                && value
                    .get("subscription_enablement")
                    .and_then(|e| e.get("resources"))
                    .is_none()
            {
                for p in [http::FIREWALL, http::FIREWALL_LINK] {
                    if self.inner.fs.metadata(p)?.is_some()
                        || self.inner.fs.metadata(&format!("{p}.sbxr-next"))?.is_some()
                    {
                        return Err(HostError::Foreign);
                    }
                }
                return Ok(false);
            }
            present |= self.auxiliary_file(
                http::FIREWALL,
                &[http::http_firewall_unit(record.public_ipv4())?],
                0o644,
                remove,
            )?;
            present |= self.auxiliary_link(
                http::FIREWALL_LINK,
                "../sbxr-subscription-firewall.service",
                "/etc/systemd/system/sbxr-subscription-firewall.service",
                remove,
            )?;
        } else {
            for p in [http::TOKEN, http::CANDIDATE_TOKEN] {
                present |= self.token(p, &allowed, remove)?;
            }
            for p in [http::STATE, http::CANDIDATE_STATE] {
                present |= self.auxiliary_file(p, &states, 0o600, remove)?;
            }
            present |= self.auxiliary_file(
                http::UNIT,
                &[crate::runtime_handoff::SERVING_UNIT.as_bytes().to_vec()],
                0o644,
                remove,
            )?;
            present |= self.auxiliary_link(
                http::LINK,
                "../sbxr-subscription.service",
                "/etc/systemd/system/sbxr-subscription.service",
                remove,
            )?;
            if self
                .inner
                .fs
                .metadata(http::STAGING)?
                .is_some_and(|m| m.gid != self.inner.fs.gid)
            {
                return Err(HostError::Foreign);
            }
            if let Some(entries) = self
                .inner
                .fs
                .directory_entries(http::STAGING, Mode::from_raw_mode(0o700))?
            {
                if entries.iter().any(|p| {
                    ![
                        "credential",
                        "credential.sbxr-next",
                        "serving.json",
                        "serving.json.sbxr-next",
                    ]
                    .contains(&p.as_str())
                }) {
                    return Err(HostError::Foreign);
                }
                present = true;
                if remove {
                    self.inner.fs.remove(Resource {
                        path: http::STAGING,
                        kind: Kind::Directory(Mode::from_raw_mode(0o700)),
                    })?;
                }
            }
        }
        Ok(present)
    }
    pub(super) fn inspect_auxiliary(&self, record: &OwnershipRecord) -> Result<String, HostError> {
        let http = self.current_auxiliary(record)?;
        let startup = self.startup(record, false)?;
        let target = self.identity_target(record, false)?;
        if !http {
            for p in [
                http::TOKEN,
                http::STATE,
                http::STAGING,
                http::UNIT,
                http::LINK,
                http::FIREWALL,
                http::FIREWALL_LINK,
            ] {
                if self.inner.fs.metadata(p)?.is_some()
                    || self.inner.fs.metadata(&format!("{p}.sbxr-next"))?.is_some()
                {
                    return Err(HostError::Foreign);
                }
            }
            return Ok(format!("startup:{startup};target:{target}"));
        }
        let material = self.http_material(record, false, false)?;
        let firewall = self.http_material(record, false, true)?;
        let facts = self.auxiliary.observe(record)?;
        let absent_rules = crate::host::subscription::material::firewall(
            &facts.firewall_rules,
            record.public_ipv4(),
            false,
        );
        let own_rules = crate::host::subscription::material::firewall(
            &facts.firewall_rules,
            record.public_ipv4(),
            true,
        );
        if !absent_rules && !own_rules
            || facts.serving_running && self.inner.fs.metadata(http::UNIT)?.is_none()
            || !facts.serving_running && !facts.quiescent
            || own_rules && self.inner.fs.metadata(http::FIREWALL)?.is_none()
        {
            return Err(HostError::Foreign);
        }
        Ok(sha256_hex(
            format!(
                "{startup}:{target}:{material}:{firewall}:{}:{}:{}:{}",
                facts.fingerprint,
                facts.serving_running,
                facts.quiescent,
                crate::host::subscription::material::normalized_rules(&facts.firewall_rules)
            )
            .as_bytes(),
        ))
    }
    pub(super) fn auxiliary_effect(
        &self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<bool, HostError> {
        self.inspect_auxiliary(record)?;
        Ok(match effect {
            RemovalEffect::ProxyStartup => self.startup(record, false)?,
            RemovalEffect::ClientIdentityTarget => self.identity_target(record, false)?,
            RemovalEffect::ServingRuntime
            | RemovalEffect::PreparedSubscription
            | RemovalEffect::SubscriptionRotation
            | RemovalEffect::SubscriptionRepair => self.http_material(record, false, false)?,
            RemovalEffect::SubscriptionResources => self.http_material(record, false, true)?,
            _ => return Err(HostError::LiveUnavailable),
        })
    }
    pub(super) fn apply_auxiliary(
        &mut self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<(), HostError> {
        self.inspect_auxiliary(record)?;
        match effect {
            RemovalEffect::ProxyStartup => {
                let f = Facts::removal(&self.inner.runner, &self.inner.stop)?;
                if f.active || f.process || f.listener.contains("sing-box") {
                    return Err(HostError::Unsafe);
                }
                self.startup(record, true)?;
                self.inner.runner.reload_units(&self.inner.stop)
            }
            RemovalEffect::ClientIdentityTarget => {
                self.identity_target(record, true)?;
                Ok(())
            }
            RemovalEffect::ServingRuntime
            | RemovalEffect::PreparedSubscription
            | RemovalEffect::SubscriptionRotation
            | RemovalEffect::SubscriptionRepair
            | RemovalEffect::SubscriptionResources => {
                let firewall = effect == RemovalEffect::SubscriptionResources;
                let owner = self.inner.lock.as_ref().ok_or(HostError::Unsafe)?.clone();
                let path = if firewall { http::FIREWALL } else { http::UNIT };
                if self.inner.fs.metadata(path)?.is_some() {
                    self.auxiliary.disable(firewall, record, &owner)?;
                }
                let facts = self.auxiliary.observe(record)?;
                if !firewall && (facts.serving_running || !facts.quiescent) {
                    return Err(HostError::Unsafe);
                }
                if firewall
                    && !crate::host::subscription::material::firewall(
                        &facts.firewall_rules,
                        record.public_ipv4(),
                        false,
                    )
                {
                    return Err(HostError::Unsafe);
                }
                self.http_material(record, true, firewall)?;
                self.inner.runner.reload_units(&self.inner.stop)?;
                if effect == RemovalEffect::PreparedSubscription {
                    self.apply_auxiliary(RemovalEffect::SubscriptionResources, record)?;
                }
                Ok(())
            }
            _ => Err(HostError::LiveUnavailable),
        }
    }
}
