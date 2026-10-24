//! Ephemeral identity generation and Go-compatible validation. No persistence,
//! network access, installation effects or credential-disclosure authorization.

use crate::{server_configuration::ServerIdentity, subscription_artifact::SubscriptionCredential};
use base64::{Engine, alphabet, engine::general_purpose};
use std::fmt;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    EntropyUnavailable,
    InvalidIdentity,
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EntropyUnavailable => "secure identity entropy unavailable",
            Self::InvalidIdentity => "identity validation refused",
        })
    }
}
impl std::error::Error for IdentityError {}

/// Implementations must fill the entire destination from a cryptographically
/// secure source or return an error. Deterministic sources are for tests only.
/// Partial output on error is discarded and never retried or returned.
pub trait Entropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityError>;
}

/// Uses the operating system's secure random source through getrandom, with no
/// fallback to timestamps, process identifiers or a deterministic generator.
pub struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityError> {
        getrandom::fill(destination).map_err(|_| IdentityError::EntropyUnavailable)
    }
}

/// A lowercase v4 Client Identity UUID, also shared by optional VMess.
pub struct ClientUuid(Zeroizing<String>);
impl ClientUuid {
    pub fn generate() -> Result<Self, IdentityError> {
        Self::generate_with_entropy(&mut OsEntropy)
    }

    pub fn generate_with_entropy(entropy: &mut dyn Entropy) -> Result<Self, IdentityError> {
        let mut bytes = random_bytes::<16>(entropy)?;
        bytes[6] = bytes[6] & 0x0f | 0x40;
        bytes[8] = bytes[8] & 0x3f | 0x80;
        let text = Zeroizing::new(hex(&*bytes));
        Ok(Self(Zeroizing::new(format!(
            "{}-{}-{}-{}-{}",
            &text[..8],
            &text[8..12],
            &text[12..16],
            &text[16..20],
            &text[20..]
        ))))
    }

    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        if value.len() != 36
            || !value.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            || value.as_bytes()[14] != b'4'
            || !matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
        {
            return Err(IdentityError::InvalidIdentity);
        }
        Ok(Self(Zeroizing::new(value.into())))
    }

    /// Explicit credential disclosure to an authorized caller.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated server/client key material. Construction derives the X25519 public
/// key using dalek; a supplied public key must match in constant time.
pub struct Identity {
    uuid: ClientUuid,
    private_key: Zeroizing<String>,
    public_key: String,
    short_id: String,
}
impl Identity {
    pub fn generate() -> Result<Self, IdentityError> {
        Self::generate_with_entropy(&mut OsEntropy)
    }

    /// Uses separate draws in Go's order: UUID (16), short ID (4), key (32).
    pub fn generate_with_entropy(entropy: &mut dyn Entropy) -> Result<Self, IdentityError> {
        let uuid = ClientUuid::generate_with_entropy(entropy)?;
        let short_id = random_bytes::<4>(entropy)?;
        let private_bytes = random_bytes::<32>(entropy)?;
        let private = StaticSecret::from(*private_bytes);
        Ok(Self {
            uuid,
            private_key: Zeroizing::new(
                general_purpose::URL_SAFE_NO_PAD.encode(private.as_bytes()),
            ),
            public_key: general_purpose::URL_SAFE_NO_PAD
                .encode(PublicKey::from(&private).as_bytes()),
            short_id: hex(&*short_id),
        })
    }

    /// Derives the public key for an existing Go-format private key. Every
    /// 32-byte X25519 private input is legal, including fixed zero test inputs.
    pub fn from_private_key(
        uuid: &str,
        private_key: &str,
        short_id: &str,
    ) -> Result<Self, IdentityError> {
        let uuid = ClientUuid::parse(uuid)?;
        if short_id.len() != 8 || !short_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IdentityError::InvalidIdentity);
        }
        let private_bytes = decode_key(private_key)?;
        let private = StaticSecret::from(*private_bytes);
        Ok(Self {
            uuid,
            private_key: Zeroizing::new(private_key.into()),
            public_key: general_purpose::URL_SAFE_NO_PAD
                .encode(PublicKey::from(&private).as_bytes()),
            short_id: short_id.into(),
        })
    }

    /// Matches Go ValidIdentity, including CR/LF, noncanonical unused base64
    /// bits and uppercase short-ID hex. Accepted input spelling is retained.
    pub fn from_parts(
        uuid: &str,
        private_key: &str,
        public_key: &str,
        short_id: &str,
    ) -> Result<Self, IdentityError> {
        let mut identity = Self::from_private_key(uuid, private_key, short_id)?;
        let supplied = decode_key(public_key)?;
        let derived = decode_key(&identity.public_key)?;
        if !bool::from(derived.ct_eq(&*supplied)) {
            return Err(IdentityError::InvalidIdentity);
        }
        identity.public_key = public_key.into();
        Ok(identity)
    }

    pub fn uuid(&self) -> &ClientUuid {
        &self.uuid
    }
    /// Explicit Infrastructure Secret access; never include this in a client artifact.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    /// Pure adaptation to the existing renderer; grants no installation authority.
    pub fn server_identity(&self) -> Result<ServerIdentity, IdentityError> {
        ServerIdentity::from_private_key(self.uuid.as_str(), &self.private_key, &self.short_id)
            .map_err(|_| IdentityError::InvalidIdentity)
    }
}

/// A nonsecret 128-bit random generation, operation or recorder identifier.
/// It is never derived from a Client Identity or Subscription Link Credential.
pub struct GenerationId(String);
impl GenerationId {
    pub fn generate() -> Result<Self, IdentityError> {
        Self::generate_with_entropy(&mut OsEntropy)
    }
    pub fn generate_with_entropy(entropy: &mut dyn Entropy) -> Result<Self, IdentityError> {
        Ok(Self(hex(&*random_bytes::<16>(entropy)?)))
    }
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdentityError::InvalidIdentity);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independent 256-bit Subscription Link Credential and 128-bit Link ID.
/// Recorder/rotation operation IDs use a further GenerationId draw. Nothing is
/// persisted; the existing credential's digest hashes its encoded token text.
pub struct SubscriptionGeneration {
    credential: SubscriptionCredential,
    link_id: GenerationId,
}
impl SubscriptionGeneration {
    pub fn generate() -> Result<Self, IdentityError> {
        Self::generate_with_entropy(&mut OsEntropy)
    }
    pub fn generate_with_entropy(entropy: &mut dyn Entropy) -> Result<Self, IdentityError> {
        let bytes = random_bytes::<32>(entropy)?;
        let link_id = GenerationId::generate_with_entropy(entropy)?;
        let encoded = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice()));
        let credential =
            SubscriptionCredential::parse(&encoded).map_err(|_| IdentityError::InvalidIdentity)?;
        Ok(Self {
            credential,
            link_id,
        })
    }
    pub fn credential(&self) -> &SubscriptionCredential {
        &self.credential
    }
    pub fn link_id(&self) -> &GenerationId {
        &self.link_id
    }
}

fn random_bytes<const N: usize>(
    entropy: &mut dyn Entropy,
) -> Result<Zeroizing<[u8; N]>, IdentityError> {
    let mut bytes = Zeroizing::new([0; N]);
    entropy
        .fill(&mut *bytes)
        .map_err(|_| IdentityError::EntropyUnavailable)?;
    Ok(bytes)
}

fn decode_key(value: &str) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut encoded = Zeroizing::new([0; 43]);
    let mut length = 0;
    for byte in value.bytes().filter(|b| !matches!(b, b'\r' | b'\n')) {
        *encoded
            .get_mut(length)
            .ok_or(IdentityError::InvalidIdentity)? = byte;
        length += 1;
    }
    if length != 43 {
        return Err(IdentityError::InvalidIdentity);
    }
    let decoder = general_purpose::GeneralPurpose::new(
        &alphabet::URL_SAFE,
        general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let mut decoded = Zeroizing::new([0; 32]);
    if decoder
        .decode_slice(encoded.as_slice(), &mut *decoded)
        .map_err(|_| IdentityError::InvalidIdentity)?
        != 32
    {
        return Err(IdentityError::InvalidIdentity);
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
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
redacted!(ClientUuid, "Client UUID (redacted)");
redacted!(Identity, "Identity (redacted)");
redacted!(GenerationId, "Generation ID (redacted)");
redacted!(SubscriptionGeneration, "Subscription generation (redacted)");
