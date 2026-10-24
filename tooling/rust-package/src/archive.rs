use crate::{PackageError, Result};
use sbxr::release_identity::{
    Architecture, ArtifactKind, MAX_EXECUTABLE_BYTES, inspect_linux_artifact, stamp_executable,
};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn gzip(input: &[u8], decompress: bool, limit: usize) -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/bin/gzip");
    command.env_clear().env("LC_ALL", "C").args(["-n", "-c"]);
    if decompress {
        command.arg("-d");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PackageError("gzip"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input));
        let mut output = Vec::new();
        let read = stdout.take(limit as u64 + 1).read_to_end(&mut output);
        if read.is_err() || output.len() > limit {
            let _ = child.kill();
        }
        let status = child.wait();
        let written = writer.join();
        if read.is_err()
            || output.len() > limit
            || !matches!(written, Ok(Ok(())))
            || !status.is_ok_and(|status| status.success())
        {
            return Err(PackageError("gzip"));
        }
        Ok(output)
    })
}
fn octal(field: &mut [u8], value: usize) {
    let text = format!("{value:0width$o}", width = field.len() - 1);
    field[..text.len()].copy_from_slice(text.as_bytes());
}
fn tar_header(size: usize) -> [u8; 512] {
    let mut header = [0; 512];
    header[..4].copy_from_slice(b"sbxr");
    for (start, end, value) in [
        (100, 108, 0o755),
        (108, 116, 0),
        (116, 124, 0),
        (124, 136, size),
        (136, 148, 0),
        (329, 337, 0),
        (337, 345, 0),
    ] {
        octal(&mut header[start..end], value);
    }
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: usize = header.iter().map(|b| usize::from(*b)).sum();
    octal(&mut header[148..155], checksum);
    header[155] = b' ';
    header
}
/// Requires an already-built, unstamped Rust ELF with retained build metadata.
/// The commit claim does not prove that a clean checkout produced these bytes.
pub fn package_executable(
    payload: &[u8],
    tag: &str,
    commit: &str,
    sequence: u64,
    architecture: Architecture,
) -> Result<Vec<u8>> {
    let executable = stamp_executable(payload, tag, commit, sequence, architecture)
        .map_err(|_| PackageError("identity"))?;
    let inspected = inspect_linux_artifact(&executable, architecture)
        .map_err(|_| PackageError("executable"))?;
    if inspected.kind() != ArtifactKind::Rust {
        return Err(PackageError("rust-executable"));
    }
    let mut tar = tar_header(executable.len()).to_vec();
    tar.extend_from_slice(&executable);
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    gzip(&tar, false, MAX_EXECUTABLE_BYTES)
}
/// Canonical ustar; no disk extraction, links, extensions or extra members.
pub fn unpack_archive(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 10
        || body.len() > MAX_EXECUTABLE_BYTES
        || body[..8] != [0x1f, 0x8b, 8, 0, 0, 0, 0, 0]
    {
        return Err(PackageError("archive-size"));
    }
    let tar = gzip(body, true, MAX_EXECUTABLE_BYTES + 2048)?;
    let size = tar
        .get(124..135)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|s| usize::from_str_radix(s, 8).ok())
        .ok_or(PackageError("tar"))?;
    if size == 0
        || size > MAX_EXECUTABLE_BYTES
        || tar.get(..512) != Some(tar_header(size).as_slice())
        || tar.len() != (512 + size).div_ceil(512) * 512 + 1024
        || tar[512 + size..].iter().any(|b| *b != 0)
    {
        return Err(PackageError("tar"));
    }
    Ok(tar[512..512 + size].to_vec())
}
