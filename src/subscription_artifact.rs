//! Pure client codecs; no credential generation, serving, authority or disclosure approval.
//! Go reference: internal/proxyinstallation/adapter/singbox/{subscription,singbox,vmess}.go.
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, net::Ipv4Addr};

pub const MAX_SUBSCRIPTION_BYTES: usize = 4096;
pub const VMESS_WEBSOCKET_PATH: &str = "/sbxr-vmess";
pub const HTTP_TRANSPORT_WARNING: &str = "HTTP exposes the Subscription Link credential and downloaded proxy credentials to network interception and permits response tampering. Token authentication does not protect the transport.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactError;
impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("subscription artifact refused")
    }
}
impl std::error::Error for ArtifactError {}

/// Validated Client Access Values, never a REALITY private key.
/// IPv4 admission here is syntactic; host/public-address policy belongs to the caller.
pub struct ConnectionFacts {
    public_ipv4: Ipv4Addr,
    uuid: String,
    server_name: String,
    public_key: String,
    short_id: String,
    vmess_hostname: Option<String>,
}

impl ConnectionFacts {
    pub fn new(
        public_ipv4: &str,
        uuid: &str,
        server_name: &str,
        public_key: &str,
        short_id: &str,
        vmess_hostname: Option<&str>,
    ) -> Result<Self, ArtifactError> {
        let public_ipv4 = canonical_ipv4(public_ipv4)?;
        let vmess_hostname = vmess_hostname.filter(|hostname| !hostname.is_empty());
        if !valid_uuid(uuid)
            || !valid_server_name(server_name)
            || public_key.len() > MAX_SUBSCRIPTION_BYTES
            || !valid_base64url_32(public_key, true)
            || short_id.len() != 8
            || !short_id.bytes().all(lower_hex)
            || vmess_hostname.is_some_and(|hostname| !valid_vmess_hostname(hostname))
        {
            return Err(ArtifactError);
        }
        Ok(Self {
            public_ipv4,
            uuid: uuid.into(),
            server_name: server_name.into(),
            public_key: public_key.into(),
            short_id: short_id.into(),
            vmess_hostname: vmess_hostname.map(str::to_owned),
        })
    }

    /// Exact ordered VLESS URI followed by the optional VMess v2 URI, each with LF.
    pub fn subscription_artifact(&self) -> Result<ClientArtifact, ArtifactError> {
        let ip = self.public_ipv4.to_string();
        let mut artifact = format!(
            "vless://{}@{ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni={}&fp=chrome&pbk={}&sid={}&type=tcp#{}\n",
            self.uuid,
            percent_escape(&self.server_name),
            percent_escape(&self.public_key),
            percent_escape(&self.short_id),
            percent_escape(&format!("SBXR Proxy ({ip})")),
        );
        if let Some(hostname) = &self.vmess_hostname {
            let label = format!("SBXR VMess ({hostname})");
            // Go json.Marshal(map[string]string) sorts keys lexicographically.
            let node = BTreeMap::from([
                ("v", "2"),
                ("ps", label.as_str()),
                ("add", hostname.as_str()),
                ("port", "443"),
                ("id", self.uuid.as_str()),
                ("aid", "0"),
                ("scy", "auto"),
                ("net", "ws"),
                ("type", "none"),
                ("host", hostname.as_str()),
                ("path", VMESS_WEBSOCKET_PATH),
                ("tls", "tls"),
                ("sni", hostname.as_str()),
            ]);
            let bytes = serde_json::to_vec(&node).map_err(|_| ArtifactError)?;
            artifact.push_str("vmess://");
            artifact.push_str(&base64_standard(&bytes));
            artifact.push('\n');
        }
        if artifact.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(ArtifactError);
        }
        Ok(ClientArtifact(artifact.into_bytes()))
    }

    /// Official outside-client JSON. VLESS stays the first/default outbound.
    /// This does not validate a server configuration or approve credential disclosure.
    pub fn client_configuration(&self) -> Result<ClientArtifact, ArtifactError> {
        #[derive(Serialize)]
        struct Configuration {
            log: serde_json::Value,
            inbounds: Vec<serde_json::Value>,
            outbounds: Vec<serde_json::Value>,
        }
        let mut outbounds = vec![json!({
            "type": "vless", "tag": "vless-out", "server": self.public_ipv4.to_string(),
            "server_port": 443, "uuid": self.uuid, "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true, "server_name": self.server_name,
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {"enabled": true, "public_key": self.public_key, "short_id": self.short_id},
            },
        })];
        if let Some(hostname) = &self.vmess_hostname {
            outbounds.push(json!({
                "type": "vmess", "tag": "vmess-ws-out", "server": hostname,
                "server_port": 443, "uuid": self.uuid, "security": "auto",
                "tls": {"enabled": true, "server_name": hostname},
                "transport": {"type": "ws", "path": VMESS_WEBSOCKET_PATH, "headers": {"Host": hostname}},
            }));
        }
        let config = Configuration {
            log: json!({"level": "warn", "timestamp": true}),
            inbounds: vec![
                json!({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}),
            ],
            outbounds,
        };
        let mut bytes = serde_json::to_vec(&config).map_err(|_| ArtifactError)?;
        bytes.push(b'\n');
        Ok(ClientArtifact(bytes))
    }
}

/// Secret-bearing encoded bytes, exposed only through an explicit accessor.
pub struct ClientArtifact(Vec<u8>);
impl ClientArtifact {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A supplied canonical 43-character token. This type generates no randomness.
pub struct SubscriptionCredential(String);
impl SubscriptionCredential {
    pub fn parse(value: &str) -> Result<Self, ArtifactError> {
        if value.len() != 43 || !valid_base64url_32(value, false) {
            return Err(ArtifactError);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Go hashes the encoded token text, not its decoded 32 bytes.
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

/// Exact HTTP capability URL. Validation proves syntax only, never serving readiness.
pub struct HttpSubscriptionLink(String);
impl HttpSubscriptionLink {
    pub fn new(ipv4: &str, credential: &SubscriptionCredential) -> Result<Self, ArtifactError> {
        let ip = canonical_ipv4(ipv4)?;
        Ok(Self(format!("http://{ip}:8443/s/{}", credential.as_str())))
    }
    pub fn parse(value: &str) -> Result<Self, ArtifactError> {
        let (ip, token) = value
            .strip_prefix("http://")
            .and_then(|rest| rest.split_once(":8443/s/"))
            .ok_or(ArtifactError)?;
        Self::new(ip, &SubscriptionCredential::parse(token)?)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn transport_warning(&self) -> &'static str {
        HTTP_TRANSPORT_WARNING
    }
}

macro_rules! redacted {
    ($type:ty, $text:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
    };
}
redacted!(ConnectionFacts, "Client Access Values (redacted)");
redacted!(ClientArtifact, "Client artifact (redacted)");
redacted!(SubscriptionCredential, "Subscription credential (redacted)");
redacted!(HttpSubscriptionLink, "Subscription Link (redacted)");

fn canonical_ipv4(value: &str) -> Result<Ipv4Addr, ArtifactError> {
    let ip: Ipv4Addr = value.parse().map_err(|_| ArtifactError)?;
    if ip.to_string() != value {
        return Err(ArtifactError);
    }
    Ok(ip)
}

fn lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn valid_uuid(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, byte)| match i {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'4',
            19 => matches!(*byte, b'8' | b'9' | b'a' | b'b'),
            _ => lower_hex(*byte),
        })
}

fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// Canonical DNS hostname, never a URL or an IP; matches Go ValidVMessHostname.
pub fn valid_vmess_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.parse::<Ipv4Addr>().is_err()
        && value.split('.').all(|label| {
            let valid_end = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            !label.is_empty()
                && label.len() <= 63
                && valid_end(label.as_bytes()[0])
                && valid_end(label.as_bytes()[label.len() - 1])
                && label.bytes().all(|b| valid_end(b) || b == b'-')
        })
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn valid_base64url_32(value: &str, ignore_crlf: bool) -> bool {
    let mut count = 0;
    let mut last = 0;
    for byte in value.bytes() {
        // Go's Strict decoder still ignores CR/LF; retain these bytes for escaping.
        if ignore_crlf && matches!(byte, b'\r' | b'\n') {
            continue;
        }
        let Some(bits) = base64url_value(byte) else {
            return false;
        };
        count += 1;
        if count > 43 {
            return false;
        }
        last = bits;
    }
    count == 43 && last & 3 == 0
}

fn percent_escape(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}

// Encoding only, not a cryptographic primitive. Go-generated fixtures cover padding.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(a >> 2) as usize] as char);
        encoded.push(ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

#[cfg(test)]
mod tests {
    #[test]
    fn standard_base64_uses_rfc4648_padding_and_alphabet() {
        for (bytes, encoded) in [
            (b"".as_slice(), ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[251, 255], "+/8="),
        ] {
            assert_eq!(super::base64_standard(bytes), encoded);
        }
    }
}
