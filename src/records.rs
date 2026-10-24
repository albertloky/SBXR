//! Strict, secret-free codecs for Standard setup schema-1 authority.
//! Schema 2, tunnel, subscriptions and removal remain unsupported and refuse.
mod identity;
mod ownership;
pub use identity::{InstalledRecord, ReleaseIdentity};
pub use ownership::{OwnershipRecord, RecoveryDirection, SetupPhase};
use sha2::{Digest, Sha256};
use std::fmt;

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
