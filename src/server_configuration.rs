//! Pure production-format rendering. No key generation, file access or commands.
//!
//! Rendering grants no installation, disclosure or removal authority. The host
//! must still validate the pinned package and fresh protected prerequisite files.

use crate::{configuration::STANDARD, subscription_artifact::valid_vmess_hostname};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigurationError;
impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server configuration refused")
    }
}
impl std::error::Error for ConfigurationError {}

/// Supplied server-side identity. Public-key derivation and randomness belong to
/// a future cryptographic adapter; no caller-supplied public key is trusted here.
pub struct ServerIdentity {
    uuid: String,
    private_key: String,
    short_id: String,
}
impl ServerIdentity {
    /// Matches Go's v4 UUID, four-byte hex short ID and X25519 private-key input
    /// syntax. Like Go RawURLEncoding, CR/LF and nonzero unused bits are accepted.
    pub fn from_private_key(
        uuid: &str,
        private_key: &str,
        short_id: &str,
    ) -> Result<Self, ConfigurationError> {
        let mut key = private_key.bytes().filter(|b| !matches!(b, b'\r' | b'\n'));
        if !valid_client_uuid(uuid)
            || short_id.len() != 8
            || !short_id.bytes().all(|b| b.is_ascii_hexdigit())
            || key.clone().count() != 43
            || !key.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(ConfigurationError);
        }
        Ok(Self {
            uuid: uuid.into(),
            private_key: private_key.into(),
            short_id: short_id.into(),
        })
    }
}

/// Secret-bearing server bytes. Only the explicit accessor discloses them.
pub struct ServerConfiguration(Vec<u8>);
impl ServerConfiguration {
    /// Decode the exact Standard shape without changing its hash subject. Unknown
    /// or duplicate fields, extra inbounds and unsupported configurations refuse.
    pub fn decode_standard(bytes: &[u8]) -> Result<Self, ConfigurationError> {
        let value =
            crate::artifact_trust::json_object(bytes, 1 << 20).map_err(|_| ConfigurationError)?;
        let inbound = &value["inbounds"][0];
        let identity = ServerIdentity::from_private_key(
            inbound["users"][0]["uuid"]
                .as_str()
                .ok_or(ConfigurationError)?,
            inbound["tls"]["reality"]["private_key"]
                .as_str()
                .ok_or(ConfigurationError)?,
            inbound["tls"]["reality"]["short_id"][0]
                .as_str()
                .ok_or(ConfigurationError)?,
        )?;
        let expected = Self::standard(&identity)?;
        let parsed: Value =
            serde_json::from_slice(expected.as_bytes()).map_err(|_| ConfigurationError)?;
        if value != parsed {
            return Err(ConfigurationError);
        }
        Ok(Self(bytes.to_vec()))
    }
    pub fn connection_facts(
        &self,
        public_ipv4: &str,
    ) -> Result<crate::subscription_artifact::ConnectionFacts, ConfigurationError> {
        let checked = Self::decode_standard(self.as_bytes())?;
        let value: Value =
            serde_json::from_slice(checked.as_bytes()).map_err(|_| ConfigurationError)?;
        let inbound = &value["inbounds"][0];
        let identity = crate::identity_generation::Identity::from_private_key(
            inbound["users"][0]["uuid"]
                .as_str()
                .ok_or(ConfigurationError)?,
            inbound["tls"]["reality"]["private_key"]
                .as_str()
                .ok_or(ConfigurationError)?,
            inbound["tls"]["reality"]["short_id"][0]
                .as_str()
                .ok_or(ConfigurationError)?,
        )
        .map_err(|_| ConfigurationError)?;
        crate::subscription_artifact::ConnectionFacts::new(
            public_ipv4,
            identity.uuid().as_str(),
            STANDARD.server_name,
            identity.public_key(),
            identity.short_id(),
            None,
        )
        .map_err(|_| ConfigurationError)
    }

    pub fn standard(identity: &ServerIdentity) -> Result<Self, ConfigurationError> {
        Self::new(identity, STANDARD.handshake_address, STANDARD.server_name)
    }

    /// The low-level Go encoder accepts any SplitHostPort host and nonempty SNI.
    /// Production setup must use `standard` and independently prove compatibility.
    pub fn new(
        identity: &ServerIdentity,
        destination_address: &str,
        server_name: &str,
    ) -> Result<Self, ConfigurationError> {
        let (host, port) = split_destination(destination_address)?;
        if server_name.is_empty() {
            return Err(ConfigurationError);
        }
        Self::encode(json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": 443,
                "users": [{"uuid": identity.uuid, "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": true, "server_name": server_name,
                    "reality": {
                        "enabled": true, "handshake": {"server": host, "server_port": port},
                        "private_key": identity.private_key, "short_id": [identity.short_id]
                    }
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
    }

    pub fn with_vmess_websocket(&self, hostname: &str) -> Result<Self, ConfigurationError> {
        if !valid_vmess_hostname(hostname) {
            return Err(ConfigurationError);
        }
        let mut value: Value = serde_json::from_slice(&self.0).map_err(|_| ConfigurationError)?;
        let inbounds = value["inbounds"].as_array_mut().ok_or(ConfigurationError)?;
        if inbounds.len() != 1 {
            return Err(ConfigurationError);
        }
        let uuid = inbounds[0]["users"][0]["uuid"]
            .as_str()
            .ok_or(ConfigurationError)?;
        inbounds.push(json!({
            "type": "vmess", "tag": format!("vmess-ws@{hostname}"),
            "listen": "127.0.0.1", "listen_port": 10000,
            "users": [{"uuid": uuid}],
            "transport": {"type": "ws", "path": "/sbxr-vmess"}
        }));
        Self::encode(value)
    }

    /// Pure UUID-only replacement for a separately prepared identity. This does
    /// not generate credentials, end old sessions or authorize a rotation.
    pub fn with_client_uuid(&self, uuid: &str) -> Result<Self, ConfigurationError> {
        if !valid_client_uuid(uuid) {
            return Err(ConfigurationError);
        }
        let mut value: Value = serde_json::from_slice(&self.0).map_err(|_| ConfigurationError)?;
        for inbound in value["inbounds"].as_array_mut().ok_or(ConfigurationError)? {
            inbound["users"][0]["uuid"] = uuid.into();
        }
        Self::encode(value)
    }

    pub(crate) fn is_standard_only(&self) -> bool {
        let Ok(value) = serde_json::from_slice::<Value>(&self.0) else {
            return false;
        };
        value["inbounds"]
            .as_array()
            .is_some_and(|inbounds| inbounds.len() == 1)
            && value["inbounds"][0]["tls"]["server_name"] == STANDARD.server_name
            && value["inbounds"][0]["tls"]["reality"]["handshake"]["server"] == "google.com"
            && value["inbounds"][0]["tls"]["reality"]["handshake"]["server_port"] == 443
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn sha256_hex(&self) -> String {
        digest(&self.0)
    }

    fn encode(value: Value) -> Result<Self, ConfigurationError> {
        // Go map keys sort lexically and encoding/json HTML-escapes these chars.
        let text = serde_json::to_string(&value).map_err(|_| ConfigurationError)?;
        let mut escaped = String::with_capacity(text.len() + 1);
        for c in text.chars() {
            match c {
                '<' => escaped.push_str("\\u003c"),
                '>' => escaped.push_str("\\u003e"),
                '&' => escaped.push_str("\\u0026"),
                '\u{2028}' => escaped.push_str("\\u2028"),
                '\u{2029}' => escaped.push_str("\\u2029"),
                _ => escaped.push(c),
            }
        }
        escaped.push('\n');
        Ok(Self(escaped.into_bytes()))
    }
}

macro_rules! redacted {
    ($kind:ty, $text:literal) => {
        impl fmt::Debug for $kind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
        impl fmt::Display for $kind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
    };
}
redacted!(ServerIdentity, "Server identity (redacted)");
redacted!(ServerConfiguration, "Server configuration (redacted)");

/// Immutable package identity copied from Go's hostSetupSpec, never downloaded here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedPackage {
    pub repository: &'static str,
    pub signing_key_url: &'static str,
    pub signing_key_sha256: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub architecture: &'static str,
    pub size: u64,
    pub sha256: &'static str,
    pub artifact_path: &'static str,
    pub service_unit_path: &'static str,
}
pub const PINNED_SING_BOX: PinnedPackage = PinnedPackage {
    repository: "https://deb.sagernet.org/",
    signing_key_url: "https://sing-box.app/gpg.key",
    signing_key_sha256: "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
    name: "sing-box",
    version: "1.14.3",
    architecture: "amd64",
    size: 32_297_878,
    sha256: "ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e",
    artifact_path: "/var/lib/sbxr/sing-box_1.14.3_amd64.deb",
    service_unit_path: "/usr/lib/systemd/system/sing-box.service",
};

pub const TUNNEL_BINARY_PATH: &str = "/usr/bin/cloudflared";
pub const TUNNEL_TOKEN_PATH: &str = "/etc/cloudflared/sbxr.token";
pub const TUNNEL_UNIT_PATH: &str = "/etc/systemd/system/sbxr-tunnel.service";
pub const TUNNEL_WANTS_PATH: &str =
    "/etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service";
pub const TUNNEL_WANTS_TARGET: &str = "../sbxr-tunnel.service";

/// Fixed unit only. The Owner's root:root 0600 one-link token and 0755 one-link
/// official binary remain protected prerequisites, never owned cleanup resources.
pub fn tunnel_unit() -> &'static str {
    include_str!("records/tunnel-authority.service")
}

/// Nonsecret syntax-checked prerequisite fingerprints. Constructing this value
/// does not inspect files or grant authority; the host must bind fresh evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelBinding {
    tunnel_id: String,
    token_sha256: String,
    binary_sha256: String,
}
impl TunnelBinding {
    pub fn from_parts(
        tunnel_id: &str,
        token_sha256: &str,
        binary_sha256: &str,
    ) -> Result<Self, ConfigurationError> {
        if !valid_tunnel_id(tunnel_id)
            || !valid_digest(token_sha256)
            || !valid_digest(binary_sha256)
        {
            return Err(ConfigurationError);
        }
        Ok(Self {
            tunnel_id: tunnel_id.into(),
            token_sha256: token_sha256.into(),
            binary_sha256: binary_sha256.into(),
        })
    }
    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }
    pub fn token_sha256(&self) -> &str {
        &self.token_sha256
    }
    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }
    pub fn resources(&self) -> Vec<String> {
        vec![
            format!(
                "{TUNNEL_UNIT_PATH} root:root 0644 one-link sha256:{}",
                digest(tunnel_unit().as_bytes())
            ),
            format!("{TUNNEL_UNIT_PATH}.sbxr-next root-owned synchronized no-replace publication"),
            format!("{TUNNEL_WANTS_PATH} root-owned symlink {TUNNEL_WANTS_TARGET}"),
        ]
    }
}

/// Matches Go's trimmed version-output shape and minimum --token-file support.
/// This checks a supplied string, not the binary's provenance or execution result.
pub fn valid_cloudflared_version(output: &str) -> bool {
    let Some(rest) = output.trim().strip_prefix("cloudflared version ") else {
        return false;
    };
    let version = rest.split(' ').next().unwrap_or("");
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3
        || parts[0].len() != 4
        || !(1..=2).contains(&parts[1].len())
        || parts[2].is_empty()
        || !parts
            .iter()
            .all(|part| part.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let year = parts[0].parse::<u16>().unwrap_or(0);
    let month = parts[1].parse::<u8>().unwrap_or(0);
    (1..=12).contains(&month) && (year > 2025 || year == 2025 && month >= 4)
}

fn valid_client_uuid(value: &str) -> bool {
    valid_tunnel_id(value)
        && value.as_bytes()[14] == b'4'
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}
fn valid_tunnel_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                lower_hex(b)
            }
        })
}
fn lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn split_destination(value: &str) -> Result<(&str, u16), ConfigurationError> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or(ConfigurationError)?;
        (host, suffix.strip_prefix(':').ok_or(ConfigurationError)?)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or(ConfigurationError)?;
        if host.contains(':') {
            return Err(ConfigurationError);
        }
        (host, port)
    };
    if host.contains(['[', ']']) || port.contains(['[', ']', ':']) {
        return Err(ConfigurationError);
    }
    let port = port.parse::<u16>().map_err(|_| ConfigurationError)?;
    if port == 0 {
        return Err(ConfigurationError);
    }
    Ok((host, port))
}
