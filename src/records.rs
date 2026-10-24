//! Strict, secret-free historical authority codecs and current HTTP transitions.
//! Decoding grants no host effect, migration or release-verification authority.
mod authority;
mod http;
mod identity;
pub use http::HttpOperation;
mod operations;
mod ownership;
mod resources;
mod retirement;
mod transitions;
mod validation;
pub use authority::{ServingAuthority, SubscriptionResources, TunnelAuthority, tunnel_unit_sha256};
pub use identity::{InstalledRecord, ReleaseIdentity};
pub use ownership::{OwnershipRecord, RecoveryDirection, SetupPhase};
use sha2::{Digest, Sha256};
use std::fmt;
pub use transitions::{ChangeDirection, HTTP_ENABLEMENT_CHECKPOINTS, PendingChange};

pub(crate) fn ownership_public_ipv4(value: &str) -> bool {
    ownership::public_ipv4(value)
}

pub const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordError;
impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid or unsupported record authority")
    }
}
impl std::error::Error for RecordError {}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RecordError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError);
    }
    // Typed Serde structs reject duplicate keys (including escaped aliases),
    // unknown fields, nulls, wrong types, and a second trailing document.
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = object(&mut decoder).map_err(|_| RecordError)?;
    decoder.end().map_err(|_| RecordError)?;
    Ok(value)
}

fn object<'de, D, T>(decoder: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

fn optional_object<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    object(decoder).map(Some)
}
fn optional_objects<'de, D, T>(decoder: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Entry<T>(T);
    impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Entry<T> {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            object(decoder).map(Self)
        }
    }
    let values = <Vec<Entry<T>> as serde::Deserialize>::deserialize(decoder)?;
    Ok(Some(values.into_iter().map(|v| v.0).collect()))
}
fn true_only<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<bool, D::Error> {
    let value = <bool as serde::Deserialize>::deserialize(decoder)?;
    if !value {
        return Err(serde::de::Error::custom("true required"));
    }
    Ok(true)
}

fn encode<T: serde::Serialize>(record: &T) -> Result<Vec<u8>, RecordError> {
    let mut bytes = serde_json::to_vec(record).map_err(|_| RecordError)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "authority_tests.rs"]
mod authority_tests;

#[cfg(test)]
pub(crate) fn historical_fixture(value: serde_json::Value) -> OwnershipRecord {
    let mut wire: ownership::WireOwnershipRecord =
        serde_json::from_value(value).expect("typed historical fixture");
    wire.permitted_resources = resources::resources(&wire);
    if wire.schema == 2 {
        wire.resource_creating_releases = Some(vec![
            wire.release_identity.clone();
            wire.permitted_resources.len()
        ]);
    }
    OwnershipRecord::validated(wire).expect("valid historical fixture")
}
