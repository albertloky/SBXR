use crate::{PackageError, Result};
use rustix::fs::{Mode, OFlags, open, openat};
use sbxr::release_identity::{MAX_EXECUTABLE_BYTES, MAX_INDEX_BYTES};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
}
fn read_file(mut file: File, limit: usize) -> Result<(Vec<u8>, Metadata)> {
    let before = file.metadata().map_err(|_| PackageError("read"))?;
    if !before.is_file() || before.len() == 0 || before.len() > limit as u64 {
        return Err(PackageError("input-file"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PackageError("read"))?;
    let after = file.metadata().map_err(|_| PackageError("read"))?;
    if bytes.len() as u64 != before.len() || !unchanged(&before, &after) {
        return Err(PackageError("input-changed"));
    }
    Ok((bytes, after))
}
pub fn read_input(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| PackageError("input-file"))?,
    );
    let (bytes, identity) = read_file(file, limit)?;
    if !unchanged(
        &identity,
        &fs::symlink_metadata(path).map_err(|_| PackageError("input-changed"))?,
    ) {
        return Err(PackageError("input-changed"));
    }
    Ok(bytes)
}
pub(crate) fn asset_files(directory: &Path, names: &[&str]) -> Result<BTreeMap<String, Vec<u8>>> {
    let root = File::from(
        open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| PackageError("directory"))?,
    );
    let root_identity = root.metadata().map_err(|_| PackageError("directory"))?;
    let mut actual: Vec<_> = fs::read_dir(directory)
        .map_err(|_| PackageError("asset-set"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()
        .map_err(|_| PackageError("asset-set"))?;
    actual.sort();
    let mut expected: Vec<_> = names.iter().map(std::ffi::OsString::from).collect();
    expected.sort();
    if actual != expected {
        return Err(PackageError("asset-set"));
    }
    let open_asset = |name: &str| {
        openat(
            &root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| PackageError("input-file"))
    };
    let mut bodies = BTreeMap::new();
    let mut identities = Vec::new();
    for name in names {
        let limit = if *name == "install.sh" || *name == "release-index.json" {
            MAX_INDEX_BYTES
        } else {
            MAX_EXECUTABLE_BYTES
        };
        let (body, identity) = read_file(open_asset(name)?, limit)?;
        bodies.insert((*name).to_string(), body);
        identities.push((*name, identity));
    }
    for (name, identity) in identities {
        let current = open_asset(name)?
            .metadata()
            .map_err(|_| PackageError("input-changed"))?;
        if !unchanged(&identity, &current) {
            return Err(PackageError("input-changed"));
        }
    }
    if !unchanged(
        &root_identity,
        &root.metadata().map_err(|_| PackageError("directory"))?,
    ) || !unchanged(
        &root_identity,
        &fs::symlink_metadata(directory).map_err(|_| PackageError("directory"))?,
    ) {
        return Err(PackageError("asset-set-changed"));
    }
    Ok(bodies)
}
pub fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    write_mode(path, bytes, 0o600)
}
pub fn write_script_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    write_mode(path, bytes, 0o700)
}
fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| PackageError("output"))?;
    // Failed partial outputs stay for inspection; an existing output is never replaced.
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| PackageError("output-write"))
}
