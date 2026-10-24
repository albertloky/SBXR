use super::*;
use std::io::Write;
pub(crate) fn tar(payload: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..4].copy_from_slice(b"sbxr");
    for (a, b, n) in [
        (100, 108, 0o755),
        (108, 116, 0),
        (116, 124, 0),
        (124, 136, payload.len()),
        (136, 148, 0),
        (329, 337, 0),
        (337, 345, 0),
    ] {
        let text = format!("{n:0width$o}", width = b - a - 1);
        header[a..b - 1].copy_from_slice(text.as_bytes());
    }
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..265].copy_from_slice(b"ustar\x0000");
    let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
    let sum = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(sum.as_bytes());
    let mut tar = header.to_vec();
    tar.extend_from_slice(payload);
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    tar
}
pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(bytes).unwrap();
    gzip.finish().unwrap()
}
pub(crate) fn archive(bytes: &[u8]) -> Vec<u8> {
    gzip(&tar(bytes))
}
#[test]
fn single_member_crc_bounds_and_cancellation() {
    let expected = b"inert synthetic executable";
    assert_eq!(
        unpack(&archive(expected), &SelectionBudget::new()).unwrap(),
        expected
    );
    let cancelled = SelectionBudget::new();
    cancelled.cancel();
    assert!(unpack(&archive(expected), &cancelled).is_err());
    let mut corrupt = archive(expected);
    let n = corrupt.len();
    corrupt[n - 8] ^= 1;
    assert!(unpack(&corrupt, &SelectionBudget::new()).is_err());
    let mut concat = archive(expected);
    concat.extend_from_slice(&archive(expected));
    assert!(unpack(&concat, &SelectionBudget::new()).is_err());
    assert!(unpack_limit(&archive(&[0; 4096]), &SelectionBudget::new(), 1024).is_err());
}
#[test]
fn paths_links_metadata_and_extra_tar_members_cannot_extract() {
    for (offset, byte) in [
        (0, b'/'),
        (156, b'2'),
        (108, b'1'),
        (116, b'1'),
        (104, b'6'),
        (345, b'x'),
    ] {
        let mut tar = tar(b"inert");
        tar[offset] = byte;
        tar[148..156].fill(b' ');
        let sum: usize = tar[..512].iter().map(|b| usize::from(*b)).sum();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(unpack(&gzip(&tar), &SelectionBudget::new()).is_err());
    }
    let mut extra = tar(b"inert");
    extra.extend_from_slice(&[0; 512]);
    assert!(unpack(&gzip(&extra), &SelectionBudget::new()).is_err());
}

#[test]
fn independently_generated_go_ustar_gzip_is_accepted() {
    assert_eq!(
        unpack(
            include_bytes!("release_acquisition/testdata/go-single-member.tar.gz"),
            &SelectionBudget::new()
        )
        .unwrap(),
        b"inert Go archive fixture\n"
    );
}
