//! Retained HTTPS assets and recovery only. No issuance, ACME or migration writer.
mod assets;
mod certificates;
pub(in crate::host) use assets::Asset;
mod exclusion;
mod hooks;
mod renewal;
use super::{HostError, filesystem::ProtectedFs, locks::HostLock};
use crate::records::{OwnershipRecord, ServingAuthority, sha256_hex};
pub use certificates::{CertificateTrust, SelectedCertificate};
pub(in crate::host) use exclusion::HistoricalExclusion;
pub use renewal::UnfinishedRenewal;
use rustix::fs::Mode;
use std::{path::Path, sync::Arc};
pub(in crate::host) const ARCHIVE: &str = "etc/letsencrypt/archive/sbxr-subscription";
pub(in crate::host) const LIVE: &str = "etc/letsencrypt/live/sbxr-subscription";
pub(in crate::host) const RENEWAL_CONFIG: &str = "etc/letsencrypt/renewal/sbxr-subscription.conf";
pub(in crate::host) const RETIRED: &str = "var/lib/sbxr/subscription-https-retired";
const NAMES: [&str; 4] = ["cert", "chain", "fullchain", "privkey"];
pub(in crate::host) fn record_value(
    record: &OwnershipRecord,
) -> Result<serde_json::Value, HostError> {
    serde_json::from_slice(&record.encode().map_err(|_| HostError::Foreign)?)
        .map_err(|_| HostError::Foreign)
}
pub(in crate::host) fn authority(value: &serde_json::Value) -> Result<ServingAuthority, HostError> {
    let text = |key| value[key].as_str().ok_or(HostError::Foreign);
    let id = text("link_id")?;
    let digest = text("credential_sha256")?;
    if value["http"] == true {
        return ServingAuthority::http_digest(id, digest).map_err(|_| HostError::Foreign);
    }
    let generation = value["certificate_generation"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(HostError::Foreign)?;
    let mut hashes: [String; 4] = Default::default();
    for (i, hash) in hashes.iter_mut().enumerate() {
        *hash = value["certificate_sha256"][i]
            .as_str()
            .ok_or(HostError::Foreign)?
            .into();
    }
    ServingAuthority::https_digest(id, digest, generation, hashes).map_err(|_| HostError::Foreign)
}
pub struct HistoricalHttps {
    fs: ProtectedFs,
    #[cfg(test)]
    publication_fault: Option<u8>,
}
impl HistoricalHttps {
    pub fn injected(root: &Path) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        Ok(Self {
            fs: ProtectedFs::open(root)?,
            #[cfg(test)]
            publication_fault: None,
        })
    }
    pub fn native_unreleased() -> Result<Self, HostError> {
        Ok(Self {
            fs: ProtectedFs::native()?,
            #[cfg(test)]
            publication_fault: None,
        })
    }
    fn bytes(
        &self,
        path: &str,
        mode: rustix::fs::RawMode,
        hash: Option<&str>,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let result = self.fs.raw(path, Mode::from_raw_mode(mode), 1 << 20)?;
        if result.as_ref().is_some_and(|(body, p)| {
            p.gid != self.fs.gid || hash.is_some_and(|h| sha256_hex(body) != h)
        }) {
            return Err(HostError::Foreign);
        }
        Ok(result.map(|(body, _)| body))
    }
    fn scoped<T>(
        &mut self,
        owner: &Arc<HostLock>,
        f: impl FnOnce(&mut Self) -> Result<T, HostError>,
    ) -> Result<T, HostError> {
        if owner.root() != self.fs.path() {
            return Err(HostError::Foreign);
        }
        owner.verify()?;
        if self.fs.path() == Path::new("/") {
            self.fs.authorize_native_writes(Some(owner.clone()))?;
        }
        let result = f(self);
        self.fs.authorize_native_writes(None)?;
        result
    }
}

pub(in crate::host) fn has_authority(record: &OwnershipRecord) -> bool {
    record_value(record).is_ok_and(|v| {
        v.get("renewal").is_some()
            || v.get("https_retirement").is_some()
            || v.get("certificate_activation").is_some()
            || v.get("serving").is_some_and(|s| s["http"] != true)
            || v.get("subscription_enablement")
                .is_some_and(|s| s.get("resources").is_none_or(|r| r["http"] != true))
    })
}
pub(in crate::host) fn known_serving_units() -> Vec<Vec<u8>> {
    let current = crate::runtime_handoff::SERVING_UNIT;
    let previous = current
        .replacen("TemporaryFileSystem=/run/systemd:ro,mode=000\n", "", 1)
        .replacen(" /run/dbus\n", " /run/systemd /run/dbus\n", 1);
    let legacy=previous.replace(" AF_UNIX","").replace(" -/var/lib/sbxr/client-identity-target.json -/var/lib/sbxr/client-identity-target.json.sbxr-next","");
    vec![
        current.as_bytes().to_vec(),
        previous.into_bytes(),
        legacy.into_bytes(),
    ]
}
pub(in crate::host) fn firewall_unit(record: &OwnershipRecord) -> Result<Vec<u8>, HostError> {
    let v = record_value(record)?;
    let r = v
        .get("subscription_resources")
        .or_else(|| {
            v.get("subscription_enablement")
                .and_then(|e| e.get("resources"))
        })
        .ok_or(HostError::Foreign)?;
    if r["http"] == true {
        return crate::host::subscription::http_firewall_unit(record.public_ipv4());
    }
    let ip = record.public_ipv4();
    let rule = |port| {
        format!("-d {ip}/32 -p tcp --dport {port} -m comment --comment sbxr-subscription -j ACCEPT")
    };
    let cmd = "/usr/sbin/iptables -w";
    Ok(format!("[Unit]\nDescription=SBXR Subscription Firewall\nBefore=sbxr-subscription.service snap.certbot.renew.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -ec '{cmd} -C INPUT {} || {cmd} -I INPUT 1 {}'\nExecStart=/bin/sh -ec '{cmd} -C INPUT {} || {cmd} -I INPUT 1 {}'\nExecStop=/bin/sh -ec 'while {cmd} -C INPUT {}; do {cmd} -D INPUT {}; done'\nExecStop=/bin/sh -ec 'while {cmd} -C INPUT {}; do {cmd} -D INPUT {}; done'\n\n[Install]\nWantedBy=multi-user.target\n",rule(80),rule(80),rule(8443),rule(8443),rule(8443),rule(8443),rule(80),rule(80)).into_bytes())
}

pub(in crate::host) fn firewall_rules(record: &OwnershipRecord, body: &str, present: bool) -> bool {
    let Ok(v) = record_value(record) else {
        return false;
    };
    let resources = v.get("subscription_resources").or_else(|| {
        v.get("subscription_enablement")
            .and_then(|e| e.get("resources"))
    });
    if resources.is_none_or(|r| r["http"] == true) {
        return crate::host::subscription::material::firewall(body, record.public_ipv4(), present);
    }
    if body.len() > 1 << 20
        || !body.contains("*filter\n")
        || !body.lines().any(|l| l.starts_with(":INPUT "))
        || !body.lines().any(|l| l == "COMMIT")
    {
        return false;
    }
    let owned: Vec<_> = body
        .lines()
        .filter(|l| l.contains("sbxr-subscription"))
        .collect();
    if !present {
        return owned.is_empty();
    }
    let rules:[String;2]=[80,8443].map(|port|format!("-A INPUT -d {}/32 -p tcp -m tcp --dport {port} -m comment --comment sbxr-subscription -j ACCEPT",record.public_ipv4()));
    !owned.is_empty() && owned.iter().all(|l| rules.iter().any(|r| r == l))
}

#[cfg(test)]
#[path = "historical/tests.rs"]
mod tests;
