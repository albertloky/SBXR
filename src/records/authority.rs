//! Secret-free Ownership Record components. No key, token, CA or host writer.
use super::{RecordError, lower_hex, sha256_hex};
use crate::subscription_artifact::SubscriptionCredential;
use serde::{Deserialize, Serialize};
use std::{fmt, net::Ipv4Addr};
pub(super) fn nonzero_hex(value: &str, len: usize) -> bool {
    lower_hex(value, len) && value.bytes().any(|b| b != b'0')
}
pub(super) fn canonical_ipv4(value: &str) -> bool {
    value
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.to_string() == value)
}
pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireServing {
    #[serde(default, skip_serializing_if = "is_false")]
    pub http: bool,
    pub link_id: String,
    pub credential_sha256: String,
    pub certificate_generation: u32,
    pub certificate_sha256: [String; 4],
}
impl WireServing {
    pub fn valid(&self) -> bool {
        nonzero_hex(&self.link_id, 32)
            && nonzero_hex(&self.credential_sha256, 64)
            && if self.http {
                self.certificate_generation == 0
                    && self.certificate_sha256.iter().all(String::is_empty)
            } else {
                (1..=1_000_000).contains(&self.certificate_generation)
                    && self.certificate_sha256.iter().all(|v| nonzero_hex(v, 64))
            }
    }
    pub fn compatible_target(&self, target: &Self) -> bool {
        self.valid()
            && target.valid()
            && self.http == target.http
            && self.link_id == target.link_id
            && self.credential_sha256 == target.credential_sha256
            && (self == target || target.certificate_generation > self.certificate_generation)
    }
    pub fn resources(&self) -> Vec<String> {
        let mut out=vec!["/etc/systemd/system/sbxr-subscription.service root:root 0644 one-link fixed-serving-v1".into(),"/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service root-owned symlink ../sbxr-subscription.service".into(),"/var/lib/sbxr/subscription-token root:root 0600 one-link credential".into(),"/var/lib/sbxr/subscription-serving.json root:root 0600 immutable serving state".into(),"/var/lib/sbxr/subscription-staging root:root 0700 empty-directory".into()];
        if self.http {
            return out;
        }
        out.extend([
            "/etc/letsencrypt/archive/sbxr-subscription root:root 0700 directory".into(),
            "/etc/letsencrypt/live/sbxr-subscription root:root 0700 directory".into(),
        ]);
        for (i, name) in ["cert", "chain", "fullchain", "privkey"].iter().enumerate() {
            let file = format!("{name}{}.pem", self.certificate_generation);
            let mode = if *name == "privkey" { "0600" } else { "0644" };
            out.push(format!(
                "/etc/letsencrypt/archive/sbxr-subscription/{file} root:root {mode} one-link {}",
                self.certificate_sha256[i]
            ));
            out.push(format!("/etc/letsencrypt/live/sbxr-subscription/{name}.pem root:root symlink ../../archive/sbxr-subscription/{file}"));
        }
        out
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ServingAuthority(pub(super) WireServing);
impl ServingAuthority {
    pub fn http(link_id: &str, credential: &SubscriptionCredential) -> Result<Self, RecordError> {
        let digest = credential
            .sha256()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        Self::http_digest(link_id, &digest)
    }
    pub fn http_digest(link_id: &str, digest: &str) -> Result<Self, RecordError> {
        let wire = WireServing {
            http: true,
            link_id: link_id.into(),
            credential_sha256: digest.into(),
            certificate_generation: 0,
            certificate_sha256: Default::default(),
        };
        if !wire.valid() {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn is_http(&self) -> bool {
        self.0.http
    }
    pub fn link_id(&self) -> &str {
        &self.0.link_id
    }
    pub fn credential_sha256(&self) -> &str {
        &self.0.credential_sha256
    }
    /// The validated wire hash is not a bearer credential.
    pub fn credential_digest(&self) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.0.credential_sha256[i * 2..i * 2 + 2], 16)
                .expect("validated lowercase digest")
        }
        out
    }
    pub fn certificate_generation(&self) -> u32 {
        self.0.certificate_generation
    }
    pub fn resources(&self) -> Vec<String> {
        self.0.resources()
    }
}
impl fmt::Debug for ServingAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Serving authority (redacted)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireSubscriptionResources {
    #[serde(default, skip_serializing_if = "is_false")]
    pub http: bool,
    pub public_ipv4: String,
    pub firewall_sha256: String,
    pub snapd_created: bool,
    pub certbot_created: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recorder_directory_created: bool,
}
impl WireSubscriptionResources {
    pub fn valid(&self) -> bool {
        canonical_ipv4(&self.public_ipv4)
            && lower_hex(&self.firewall_sha256, 64)
            && !(self.http
                && (self.snapd_created || self.certbot_created || self.recorder_directory_created))
    }
    pub fn resources(&self) -> Vec<String> {
        let mut out = vec![format!(
            "/etc/systemd/system/sbxr-subscription-firewall.service root:root 0644 one-link sha256:{}",
            self.firewall_sha256
        )];
        if self.http {
            out.push(format!(
                "iptables filter INPUT {}/32 tcp/8443 comment=sbxr-subscription exact-owned",
                self.public_ipv4
            ));
            return out;
        }
        out.extend([
            format!(
                "iptables filter INPUT {}/32 tcp/80 comment=sbxr-subscription exact-owned",
                self.public_ipv4
            ),
            format!(
                "iptables filter INPUT {}/32 tcp/8443 comment=sbxr-subscription exact-owned",
                self.public_ipv4
            ),
            format!(
                "snapd dependency {}",
                if self.snapd_created {
                    "created"
                } else {
                    "reused"
                }
            ),
            format!(
                "official Certbot snap dependency {}",
                if self.certbot_created {
                    "created"
                } else {
                    "reused"
                }
            ),
        ]);
        if self.recorder_directory_created {
            out.push("/etc/systemd/system/snap.certbot.renew.service.d root:root 0755 SBXR-created empty-after-drop-in-removal".into())
        }
        out
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SubscriptionResources(pub(super) WireSubscriptionResources);
impl SubscriptionResources {
    pub fn http(ipv4: &str, firewall_sha256: &str) -> Result<Self, RecordError> {
        let wire = WireSubscriptionResources {
            http: true,
            public_ipv4: ipv4.into(),
            firewall_sha256: firewall_sha256.into(),
            snapd_created: false,
            certbot_created: false,
            recorder_directory_created: false,
        };
        if !wire.valid() {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn firewall_sha256(&self) -> &str {
        &self.0.firewall_sha256
    }
    pub fn resources(&self) -> Vec<String> {
        self.0.resources()
    }
}
impl fmt::Debug for SubscriptionResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subscription resource authority")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRenewal {
    pub recorder_id: String,
    pub lineage: String,
    pub public_ipv4: String,
    pub invocation: String,
}
impl WireRenewal {
    pub fn valid(&self) -> bool {
        nonzero_hex(&self.recorder_id, 32)
            && self.lineage == "sbxr-subscription"
            && canonical_ipv4(&self.public_ipv4)
            && self.invocation == "snap-certbot-renew-v1"
    }
    pub fn resources(&self) -> Vec<String> {
        ["/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf root:root 0644 one-link recorder-v1","/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription root:root 0700 one-link deploy-writer-v1","/etc/letsencrypt/renewal-hooks/post/sbxr-subscription root:root 0700 one-link post-writer-v1","/var/lib/sbxr/renewal-attempts.json root:root 0600 one-link bounded-evidence-v1","/var/lib/sbxr/renewal-admission.lock root:root 0600 one-link admission-v1","/var/lib/sbxr/renewal-writer.lock root:root 0600 one-link writer-v1"].into_iter().map(str::to_owned).collect()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireStartup {
    pub drop_in_sha256: String,
    pub directory_created: bool,
}
impl WireStartup {
    pub fn valid(&self) -> bool {
        nonzero_hex(&self.drop_in_sha256, 64)
    }
    pub fn resources(&self) -> Vec<String> {
        let mut out = vec![format!(
            "/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:{}",
            self.drop_in_sha256
        )];
        if self.directory_created {
            out.push("/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal".into())
        }
        out
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireTunnel {
    pub tunnel_id: String,
    pub token_sha256: String,
    pub binary_sha256: String,
}
impl WireTunnel {
    pub fn valid(&self) -> bool {
        let b = self.tunnel_id.as_bytes();
        b.len() == 36
            && b.iter().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    *c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(c)
                }
            })
            && lower_hex(&self.token_sha256, 64)
            && lower_hex(&self.binary_sha256, 64)
    }
    pub fn resources(&self) -> Vec<String> {
        vec![format!("/etc/systemd/system/sbxr-tunnel.service root:root 0644 one-link sha256:{}",tunnel_unit_sha256()),"/etc/systemd/system/sbxr-tunnel.service.sbxr-next root-owned synchronized no-replace publication".into(),"/etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service root-owned symlink ../sbxr-tunnel.service".into()]
    }
}
pub fn tunnel_unit_sha256() -> String {
    sha256_hex(include_bytes!("tunnel-authority.service"))
}
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelAuthority(pub(super) WireTunnel);
impl TunnelAuthority {
    pub fn new(
        tunnel_id: &str,
        token_sha256: &str,
        binary_sha256: &str,
    ) -> Result<Self, RecordError> {
        let wire = WireTunnel {
            tunnel_id: tunnel_id.into(),
            token_sha256: token_sha256.into(),
            binary_sha256: binary_sha256.into(),
        };
        if !wire.valid() {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn binary_sha256(&self) -> &str {
        &self.0.binary_sha256
    }
    pub fn tunnel_id(&self) -> &str {
        &self.0.tunnel_id
    }
    pub fn resources(&self) -> Vec<String> {
        self.0.resources()
    }
}
impl fmt::Debug for TunnelAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tunnel authority (redacted)")
    }
}
