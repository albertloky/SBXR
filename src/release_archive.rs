//! Bounded, single-member gzip/ustar decoding. Never extracts or executes files.
use crate::{
    artifact_trust::{SelectionBudget, TrustError},
    release_identity::MAX_EXECUTABLE_BYTES,
};
use std::io::Read;
type Result<T> = std::result::Result<T, TrustError>;

pub fn unpack(archive: &[u8], budget: &SelectionBudget) -> Result<Vec<u8>> {
    unpack_limit(archive, budget, MAX_EXECUTABLE_BYTES)
}
fn unpack_limit(archive: &[u8], budget: &SelectionBudget, limit: usize) -> Result<Vec<u8>> {
    budget.check()?;
    if archive.is_empty() || archive.len() > MAX_EXECUTABLE_BYTES {
        return Err(TrustError::Refused);
    }
    let mut decoder = flate2::bufread::GzDecoder::new(archive);
    let mut tar = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        budget.check()?;
        let n = decoder.read(&mut chunk).map_err(|_| TrustError::Refused)?;
        budget.check()?;
        if n == 0 {
            break;
        }
        if tar.len() + n > limit + 2048 {
            return Err(TrustError::Refused);
        }
        tar.extend_from_slice(&chunk[..n]);
    }
    if !decoder.into_inner().is_empty() {
        return Err(TrustError::Refused);
    }
    let header = tar.get(..512).ok_or(TrustError::Refused)?;
    let checksum = octal(&header[148..156])?;
    let computed: usize = header
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                usize::from(*b)
            }
        })
        .sum();
    let size = octal(&header[124..136])?;
    if checksum != computed
        || text(&header[..100])? != "sbxr"
        || header[156] != b'0'
        || !text(&header[157..257])?.is_empty()
        || octal(&header[100..108])? != 0o755
        || octal(&header[108..116])? != 0
        || octal(&header[116..124])? != 0
        || !matches!(text(&header[265..297])?, "" | "root")
        || !matches!(text(&header[297..329])?, "" | "root")
        || !text(&header[345..500])?.is_empty()
        || &header[257..265] != b"ustar\x0000"
        || size == 0
        || size > limit
        || tar.len() != (512 + size).div_ceil(512) * 512 + 1024
        || tar[512 + size..].iter().any(|b| *b != 0)
    {
        return Err(TrustError::Refused);
    }
    budget.check()?;
    Ok(tar[512..512 + size].to_vec())
}
fn octal(bytes: &[u8]) -> Result<usize> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| TrustError::Refused)?
        .trim_matches(['\0', ' ']);
    if value.is_empty() || !value.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(TrustError::Refused);
    }
    usize::from_str_radix(value, 8).map_err(|_| TrustError::Refused)
}
fn text(bytes: &[u8]) -> Result<&str> {
    let n = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if bytes[n..].iter().any(|b| *b != 0) {
        return Err(TrustError::Refused);
    }
    std::str::from_utf8(&bytes[..n]).map_err(|_| TrustError::Refused)
}
#[cfg(test)]
#[path = "release_archive_tests.rs"]
pub(crate) mod tests;
