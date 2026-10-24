//! Read the exact pinned DEB's executable without extracting or executing it.
use super::*;
const MAX_DATA: usize = 128 << 20;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeImage {
    sha256: String,
    size: usize,
}
impl ProbeImage {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn verify_bytes(&self, bytes: &[u8], budget: &SelectionBudget) -> Result<()> {
        if bytes.len() != self.size || hash(bytes, budget)? != self.sha256 {
            return Err(TrustError::Refused);
        }
        budget.check()
    }
    #[cfg(test)]
    pub(crate) fn fixture(bytes: &[u8]) -> Self {
        Self {
            sha256: crate::records::sha256_hex(bytes),
            size: bytes.len(),
        }
    }
}
impl VerifiedPackage {
    /// The private VerifiedPackage fields were admitted by full key/DEB pins.
    /// A caller cannot mint this proof from an installed hash or version string.
    pub fn probe_image(&self, budget: &SelectionBudget) -> Result<ProbeImage> {
        let mut offset = 8usize;
        let mut data = None;
        for _ in 0..4 {
            budget.check()?;
            let header = self
                .deb
                .get(offset..offset + 60)
                .ok_or(TrustError::Refused)?;
            let name = std::str::from_utf8(&header[..16])
                .map_err(|_| TrustError::Refused)?
                .trim();
            let size = number(&header[48..58], 10)?;
            offset = offset.checked_add(60).ok_or(TrustError::Refused)?;
            let end = offset.checked_add(size).ok_or(TrustError::Refused)?;
            if name == "data.tar.gz" {
                data = Some(self.deb.get(offset..end).ok_or(TrustError::Refused)?);
            }
            offset = end.checked_add(size % 2).ok_or(TrustError::Refused)?;
        }
        inspect_image(data.ok_or(TrustError::Refused)?, budget)
    }
}
fn exact(reader: &mut impl Read, bytes: &mut [u8], budget: &SelectionBudget) -> Result<()> {
    for chunk in bytes.chunks_mut(8192) {
        budget.check()?;
        reader.read_exact(chunk).map_err(|_| TrustError::Refused)?;
    }
    budget.check()
}
fn inspect_image(compressed: &[u8], budget: &SelectionBudget) -> Result<ProbeImage> {
    let mut decoder = flate2::bufread::GzDecoder::new(compressed);
    let mut total = 0usize;
    let mut image = None;
    let mut buffer = [0u8; 8192];
    for _ in 0..256 {
        let mut header = [0u8; 512];
        exact(&mut decoder, &mut header, budget)?;
        total = total.checked_add(512).ok_or(TrustError::Refused)?;
        if header.iter().all(|b| *b == 0) {
            let mut terminator = [0u8; 512];
            exact(&mut decoder, &mut terminator, budget)?;
            if terminator.iter().any(|b| *b != 0) {
                return Err(TrustError::Refused);
            }
            loop {
                budget.check()?;
                let n = decoder.read(&mut buffer).map_err(|_| TrustError::Refused)?;
                if n == 0 {
                    break;
                }
                total = total.checked_add(n).ok_or(TrustError::Refused)?;
                if total > MAX_DATA || buffer[..n].iter().any(|b| *b != 0) {
                    return Err(TrustError::Refused);
                }
            }
            if !decoder.into_inner().is_empty() {
                return Err(TrustError::Refused);
            }
            return image.ok_or(TrustError::Refused);
        }
        let checksum: usize = header
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
        let name = tar_text(&header[..100])?;
        if number(&header[148..156], 8)? != checksum
            || !matches!(&header[257..265], b"ustar\0\x30\x30" | b"ustar  \0")
            || header[345..500].iter().any(|b| *b != 0)
            || !matches!(header[156], b'0' | 0 | b'5')
        {
            return Err(TrustError::Refused);
        }
        let size = number(&header[124..136], 8)?;
        if header[156] == b'5' && size != 0 {
            return Err(TrustError::Refused);
        }
        total = total
            .checked_add(size)
            .and_then(|n| n.checked_add((512 - size % 512) % 512))
            .ok_or(TrustError::Refused)?;
        if total > MAX_DATA {
            return Err(TrustError::Refused);
        }
        let selected = name == "./usr/bin/sing-box";
        if selected
            && (image.is_some()
                || !matches!(header[156], b'0' | 0)
                || number(&header[100..108], 8)? != 0o755
                || number(&header[108..116], 8)? != 0
                || number(&header[116..124], 8)? != 0
                || size == 0)
        {
            return Err(TrustError::Refused);
        }
        let mut digest = Sha256::new();
        let mut remaining = size;
        while remaining > 0 {
            let count = remaining.min(buffer.len());
            exact(&mut decoder, &mut buffer[..count], budget)?;
            if selected {
                digest.update(&buffer[..count]);
            }
            remaining -= count;
        }
        if selected {
            image = Some(ProbeImage {
                sha256: format!("{:x}", digest.finalize()),
                size,
            });
        }
        let padding = (512 - size % 512) % 512;
        exact(&mut decoder, &mut buffer[..padding], budget)?;
        if buffer[..padding].iter().any(|b| *b != 0) {
            return Err(TrustError::Refused);
        }
    }
    Err(TrustError::Refused)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_digest_is_bound_to_the_entire_pinned_package_and_exact_member() {
        let package = VerifiedPackage::verify(
            include_bytes!("../../tests/testdata/package_acquisition/sagernet.asc").to_vec(),
            include_bytes!("../../tests/testdata/package_acquisition/sing-box_1.14.3_amd64.deb")
                .to_vec(),
            &SelectionBudget::new(),
        )
        .unwrap();
        let image = package.probe_image(&SelectionBudget::new()).unwrap();
        // Independent Python hashlib/tarfile observation of the authenticated DEB.
        assert_eq!(
            image.sha256(),
            "33de1654134de582a3d23786fdba32e5461bfe3eefe3e11ddeef2a9635a9e91c"
        );
        assert_eq!(image.size(), 91_990_368);
        assert!(
            image
                .verify_bytes(
                    b"version 1.14.3 is not executable proof",
                    &SelectionBudget::new()
                )
                .is_err()
        );
        let cancelled = SelectionBudget::new();
        cancelled.cancel();
        assert!(package.probe_image(&cancelled).is_err());
        let mut changed = package.deb().to_vec();
        changed[100] ^= 1;
        assert!(
            VerifiedPackage::verify(package.key().to_vec(), changed, &SelectionBudget::new())
                .is_err()
        );
    }
}
