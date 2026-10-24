use super::HostError;
use crate::records::sha256_hex;
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
}
pub(super) struct FixtureFs {
    root: OwnedFd,
    path: PathBuf,
    pub uid: u32,
}
fn failure(_: impl std::fmt::Debug) -> HostError {
    HostError::Io
}
impl FixtureFs {
    pub fn open(path: &Path) -> Result<Self, HostError> {
        let uid = std::fs::symlink_metadata(path).map_err(failure)?.uid();
        let root = crate::durable::open_directory(path, uid).map_err(|_| HostError::Unsafe)?;
        Ok(Self {
            root,
            path: path.into(),
            uid,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn check_root(&self) -> Result<(), HostError> {
        let current =
            crate::durable::open_directory(&self.path, self.uid).map_err(|_| HostError::Unsafe)?;
        let a = fs::fstat(&self.root).map_err(failure)?;
        let b = fs::fstat(current).map_err(failure)?;
        if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
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
            || after.st_nlink != 1
            || after.st_size as usize != bytes.len()
        {
            return Err(HostError::Unsafe);
        }
        let evidence = Evidence {
            identity: format!("{}:{}", stat.st_dev, stat.st_ino),
            digest: Some(sha256_hex(&bytes)),
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
        if stat.st_uid != self.uid {
            return Err(HostError::Foreign);
        }
        match resource.kind {
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
            identity: format!("{}:{}", stat.st_dev, stat.st_ino),
            digest: None,
        }))
    }
    pub fn install(&self, resource: Resource) -> Result<(), HostError> {
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
        if self.observe(resource)?.is_none() {
            return Ok(());
        }
        let (dir, name) = self
            .parent(resource.path, false)?
            .ok_or(HostError::Unsafe)?;
        fs::unlinkat(
            &dir,
            name.as_str(),
            if matches!(resource.kind, Kind::Directory(_)) {
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
    pub fn install_bytes(&self, path: &str, body: &[u8], mode: Mode) -> Result<(), HostError> {
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
        fs::fchmod(&fd, mode).map_err(failure)?;
        let mut file = File::from(fd);
        file.write_all(body).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        fs::fsync(dir).map_err(failure)
    }
}
