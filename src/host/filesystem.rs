mod restoration;
mod runtime;
use super::HostError;
use crate::records::sha256_hex;
pub(super) use runtime::PROXY_GATE;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    io::Errno,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    File(&'static [u8], Mode),
    Directory(Mode),
    OwnedDirectory(Mode, u32, u32),
    Link(&'static str),
}
#[derive(Clone, Copy)]
pub(super) struct Resource {
    pub path: &'static str,
    pub kind: Kind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    identity: String,
    digest: Option<String>,
    pub(super) gid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub kind: FileType,
    pub uid: u32,
    pub gid: u32,
}
pub(super) struct ProtectedFs {
    root: OwnedFd,
    path: PathBuf,
    pub uid: u32,
    pub gid: u32,
    native_write_lock: Option<std::sync::Arc<super::locks::HostLock>>,
}
fn failure(_: impl std::fmt::Debug) -> HostError {
    HostError::Io
}
impl ProtectedFs {
    pub fn open(path: &Path) -> Result<Self, HostError> {
        let uid = std::fs::symlink_metadata(path).map_err(failure)?.uid();
        let root = crate::durable::open_directory(path, uid).map_err(|_| HostError::Unsafe)?;
        let gid = fs::fstat(&root).map_err(failure)?.st_gid;
        Ok(Self {
            root,
            path: path.into(),
            uid,
            gid,
            native_write_lock: None,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn native() -> Result<Self, HostError> {
        super::linux::require_native_platform()?;
        let root = fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let stat = fs::fstat(&root).map_err(failure)?;
        if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
            return Err(HostError::Unsafe);
        }
        Ok(Self {
            root,
            path: PathBuf::from("/"),
            uid: 0,
            gid: stat.st_gid,
            native_write_lock: None,
        })
    }
    pub(super) fn authorize_native_writes(
        &mut self,
        lock: Option<std::sync::Arc<super::locks::HostLock>>,
    ) -> Result<(), HostError> {
        if let Some(guard) = &lock {
            super::linux::require_native_environment()?;
            if self.path != Path::new("/") || guard.root() != self.path {
                return Err(HostError::Unsafe);
            }
            guard.verify()?;
        }
        self.native_write_lock = lock;
        Ok(())
    }
    fn write_allowed(&self) -> Result<(), HostError> {
        if self.path == Path::new("/") {
            super::linux::require_native_environment()?;
            self.native_write_lock
                .as_ref()
                .ok_or(HostError::LiveUnavailable)?
                .verify()?;
        }
        self.check_root()
    }
    fn check_root(&self) -> Result<(), HostError> {
        let current = if self.path == Path::new("/") {
            super::linux::require_native_platform()?;
            fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(failure)?
        } else {
            crate::durable::open_directory(&self.path, self.uid).map_err(|_| HostError::Unsafe)?
        };
        let a = fs::fstat(&self.root).map_err(failure)?;
        let b = fs::fstat(current).map_err(failure)?;
        if a.st_dev != b.st_dev
            || a.st_ino != b.st_ino
            || b.st_uid != self.uid
            || b.st_mode & 0o022 != 0
        {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    pub fn empty(&self) -> Result<bool, HostError> {
        self.check_root()?;
        let entries = fs::Dir::read_from(&self.root).map_err(failure)?;
        for entry in entries {
            let entry = entry.map_err(failure)?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn parent(&self, path: &str, create: bool) -> Result<Option<(OwnedFd, String)>, HostError> {
        self.check_root()?;
        let parts = Path::new(path)
            .components()
            .map(|part| match part {
                Component::Normal(name) => name.to_str().ok_or(HostError::Unsafe),
                _ => Err(HostError::Unsafe),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (name, parents) = parts.split_last().ok_or(HostError::Unsafe)?;
        let mut dir = fs::openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        for part in parents {
            if create {
                match fs::mkdirat(&dir, *part, Mode::from_raw_mode(0o755)) {
                    Ok(()) => fs::fsync(&dir).map_err(failure)?,
                    Err(Errno::EXIST) => (),
                    Err(error) => return Err(failure(error)),
                }
            }
            dir = match fs::openat(
                &dir,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if !create => return Ok(None),
                Err(error) => return Err(failure(error)),
            };
            let stat = fs::fstat(&dir).map_err(failure)?;
            if stat.st_uid != self.uid || stat.st_mode & 0o022 != 0 {
                return Err(HostError::Unsafe);
            }
        }
        Ok(Some((dir, (*name).into())))
    }
    pub fn raw(
        &self,
        path: &str,
        mode: Mode,
        limit: usize,
    ) -> Result<Option<(Vec<u8>, Evidence)>, HostError> {
        let Some((dir, name)) = self.parent(path, false)? else {
            return Ok(None);
        };
        let stat = match fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(v) => v,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(failure(error)),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != self.uid
            || stat.st_nlink != 1
            || Mode::from_raw_mode(stat.st_mode) & Mode::from_raw_mode(0o7777) != mode
            || stat.st_size < 0
            || stat.st_size as usize > limit
        {
            return Err(HostError::Foreign);
        }
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        let opened = fs::fstat(&fd).map_err(failure)?;
        if stat.st_dev != opened.st_dev || stat.st_ino != opened.st_ino {
            return Err(HostError::Unsafe);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        let after = fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        if bytes.len() > limit
            || after.st_dev != stat.st_dev
            || after.st_ino != stat.st_ino
            || after.st_uid != stat.st_uid
            || after.st_mode != stat.st_mode
            || after.st_gid != stat.st_gid
            || after.st_nlink != 1
            || after.st_size as usize != bytes.len()
        {
            return Err(HostError::Unsafe);
        }
        let evidence = Evidence {
            identity: format!(
                "{}:{}:{}:{}:{}:{}",
                stat.st_dev, stat.st_ino, stat.st_uid, stat.st_gid, stat.st_mode, stat.st_nlink
            ),
            digest: Some(sha256_hex(&bytes)),
            gid: stat.st_gid,
        };
        Ok(Some((bytes, evidence)))
    }
    pub fn observe(&self, resource: Resource) -> Result<Option<Evidence>, HostError> {
        if let Kind::File(body, mode) = resource.kind {
            return self
                .raw(resource.path, mode, 1 << 20)?
                .map(|(actual, evidence)| {
                    if actual == body {
                        Ok(evidence)
                    } else {
                        Err(HostError::Foreign)
                    }
                })
                .transpose();
        }
        let Some((dir, name)) = self.parent(resource.path, false)? else {
            return Ok(None);
        };
        let stat = match fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(v) => v,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(failure(error)),
        };
        let expected_uid = match resource.kind {
            Kind::OwnedDirectory(_, uid, _) => uid,
            _ => self.uid,
        };
        if stat.st_uid != expected_uid {
            return Err(HostError::Foreign);
        }
        match resource.kind {
            Kind::OwnedDirectory(mode, _, gid)
                if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                    && Mode::from_raw_mode(stat.st_mode) & Mode::from_raw_mode(0o7777) == mode
                    && stat.st_gid == gid => {}
            Kind::Directory(mode)
                if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                    && Mode::from_raw_mode(stat.st_mode) & Mode::from_raw_mode(0o7777) == mode => {}
            Kind::Link(target)
                if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink
                    && stat.st_nlink == 1 =>
            {
                if fs::readlinkat(&dir, name.as_str(), Vec::new())
                    .map_err(failure)?
                    .to_bytes()
                    != target.as_bytes()
                {
                    return Err(HostError::Foreign);
                }
            }
            _ => return Err(HostError::Foreign),
        }
        Ok(Some(Evidence {
            identity: format!(
                "{}:{}:{}:{}:{}:{}",
                stat.st_dev, stat.st_ino, stat.st_uid, stat.st_gid, stat.st_mode, stat.st_nlink
            ),
            digest: None,
            gid: stat.st_gid,
        }))
    }
    pub fn install(&self, resource: Resource) -> Result<(), HostError> {
        self.write_allowed()?;
        if self.observe(resource)?.is_some() {
            return Ok(());
        }
        let (dir, name) = self.parent(resource.path, true)?.ok_or(HostError::Unsafe)?;
        match resource.kind {
            Kind::File(body, mode) => {
                let fd = fs::openat(
                    &dir,
                    name.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    mode,
                )
                .map_err(failure)?;
                fs::fchmod(&fd, mode).map_err(failure)?;
                let mut file = File::from(fd);
                file.write_all(body).map_err(failure)?;
                file.sync_all().map_err(failure)?;
            }
            Kind::OwnedDirectory(mode, uid, gid) => {
                fs::mkdirat(&dir, name.as_str(), mode).map_err(failure)?;
                let fd = fs::openat(
                    &dir,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(failure)?;
                fs::fchown(
                    &fd,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )
                .map_err(failure)?;
                fs::fchmod(&fd, mode).map_err(failure)?;
                fs::fsync(fd).map_err(failure)?;
            }
            Kind::Directory(mode) => {
                fs::mkdirat(&dir, name.as_str(), mode).map_err(failure)?;
                let created = fs::openat(
                    &dir,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(failure)?;
                fs::fchmod(&created, mode).map_err(failure)?;
                fs::fsync(created).map_err(failure)?;
            }
            Kind::Link(target) => fs::symlinkat(target, &dir, name.as_str()).map_err(failure)?,
        }
        fs::fsync(dir).map_err(failure)?;
        self.observe(resource)?.ok_or(HostError::Unsafe)?;
        Ok(())
    }
    pub fn remove(&self, resource: Resource) -> Result<(), HostError> {
        self.write_allowed()?;
        if self.observe(resource)?.is_none() {
            return Ok(());
        }
        let (dir, name) = self
            .parent(resource.path, false)?
            .ok_or(HostError::Unsafe)?;
        fs::unlinkat(
            &dir,
            name.as_str(),
            if matches!(
                resource.kind,
                Kind::Directory(_) | Kind::OwnedDirectory(_, _, _)
            ) {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )
        .map_err(failure)?;
        fs::fsync(dir).map_err(failure)?;
        if self.observe(resource)?.is_some() {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    pub(super) fn metadata(&self, path: &str) -> Result<Option<Metadata>, HostError> {
        let Some((dir, name)) = self.parent(path, false)? else {
            return Ok(None);
        };
        let stat = match fs::statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        Ok(Some(Metadata {
            kind: FileType::from_raw_mode(stat.st_mode),
            uid: stat.st_uid,
            gid: stat.st_gid,
        }))
    }
    pub(super) fn publish_bytes(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        self.publish_bytes_group(path, body, mode, self.gid)
    }
    pub(super) fn publish_bytes_group(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
        gid: u32,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let stage = format!("{path}.sbxr-next");
        if let Some((existing, evidence)) = self.raw(path, mode, 1 << 26)? {
            if existing != body || evidence.gid != gid {
                return Err(HostError::Foreign);
            }
            if self.metadata(&stage)?.is_some() {
                return Err(HostError::Foreign);
            }
            return Ok(());
        }
        if let Some((existing, evidence)) = self.raw(&stage, mode, 1 << 26)? {
            if existing != body || evidence.gid != gid {
                return Err(HostError::Foreign);
            }
        } else {
            self.install_bytes_group(&stage, body, mode, gid)?;
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let stage_name = format!("{name}.sbxr-next");
        fs::renameat_with(
            &dir,
            stage_name.as_str(),
            &dir,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(failure)?;
        fs::fsync(&dir).map_err(failure)?;
        if self
            .raw(path, mode, 1 << 26)?
            .is_none_or(|(bytes, evidence)| bytes != body || evidence.gid != gid)
        {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
    pub(super) fn sync_bytes(&self, path: &str, body: &[u8], mode: Mode) -> Result<(), HostError> {
        let (bytes, proof) = self.raw(path, mode, 1 << 20)?.ok_or(HostError::Foreign)?;
        if bytes != body {
            return Err(HostError::Foreign);
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        if self
            .raw(path, mode, 1 << 20)?
            .is_none_or(|(_, p)| p != proof)
        {
            return Err(HostError::Unsafe);
        }
        fs::fsync(fd).map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
    pub(super) fn move_bytes(
        &self,
        source: &str,
        target: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let (bytes, proof) = self.raw(source, mode, 1 << 20)?.ok_or(HostError::Foreign)?;
        if bytes != body || self.metadata(target)?.is_some() {
            return Err(HostError::Foreign);
        }
        let (from, name) = self.parent(source, false)?.ok_or(HostError::Unsafe)?;
        let (to, target_name) = self.parent(target, false)?.ok_or(HostError::Unsafe)?;
        if self
            .raw(source, mode, 1 << 20)?
            .is_none_or(|(_, p)| p != proof)
        {
            return Err(HostError::Unsafe);
        }
        fs::renameat_with(
            &from,
            name.as_str(),
            &to,
            target_name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(failure)?;
        fs::fsync(from).map_err(failure)?;
        fs::fsync(to).map_err(failure)?;
        self.sync_bytes(target, body, mode)
    }
    pub(super) fn directory_entries(
        &self,
        path: &str,
        mode: Mode,
    ) -> Result<Option<Vec<String>>, HostError> {
        self.directory_entries_owned(path, mode, self.uid)
    }
    pub(super) fn directory_entries_owned(
        &self,
        path: &str,
        mode: Mode,
        uid: u32,
    ) -> Result<Option<Vec<String>>, HostError> {
        let Some((parent, name)) = self.parent(path, false)? else {
            return Ok(None);
        };
        let fd = match fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        let stat = fs::fstat(&fd).map_err(failure)?;
        if stat.st_uid != uid
            || Mode::from_raw_mode(stat.st_mode) & Mode::from_raw_mode(0o7777) != mode
        {
            return Err(HostError::Foreign);
        }
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(&fd).map_err(failure)? {
            let entry = entry.map_err(failure)?;
            let name = entry.file_name().to_str().map_err(failure)?;
            if !matches!(name, "." | "..") {
                names.push(name.into());
            }
        }
        let current =
            fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(failure)?;
        if stat.st_dev != current.st_dev
            || stat.st_ino != current.st_ino
            || stat.st_uid != current.st_uid
            || stat.st_mode != current.st_mode
        {
            return Err(HostError::Unsafe);
        }
        names.sort();
        Ok(Some(names))
    }
    pub(super) fn remove_bytes(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let Some((existing, evidence)) = self.raw(path, mode, 1 << 26)? else {
            return Ok(());
        };
        if existing != body {
            return Err(HostError::Foreign);
        }
        let (dir, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        if self
            .raw(path, mode, 1 << 26)?
            .is_none_or(|(_, fresh)| fresh != evidence)
        {
            return Err(HostError::Unsafe);
        }
        fs::unlinkat(&dir, name.as_str(), AtFlags::empty()).map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
    pub fn install_bytes(&self, path: &str, body: &[u8], mode: Mode) -> Result<(), HostError> {
        self.install_bytes_group(path, body, mode, self.gid)
    }
    fn install_bytes_group(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
        gid: u32,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        if self.raw(path, mode, 1 << 20)?.is_some() {
            return Err(HostError::Foreign);
        }
        let (dir, name) = self.parent(path, true)?.ok_or(HostError::Unsafe)?;
        let fd = fs::openat(
            &dir,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map_err(failure)?;
        fs::fchown(&fd, None, Some(rustix::process::Gid::from_raw(gid))).map_err(failure)?;
        fs::fchmod(&fd, mode).map_err(failure)?;
        let mut file = File::from(fd);
        file.write_all(body).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
}
