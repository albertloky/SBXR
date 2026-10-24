use super::*;
/// Missing independent network/lock proofs remain unknown. No guessed public IP,
/// external TLS probe, listener bind or lock mutation is hidden in this observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadOnlyObservation {
    pub ubuntu_2404: bool,
    pub architecture: &'static str,
    pub package_present: bool,
    pub clock_synchronized: bool,
    pub service_enabled: bool,
    pub service_active: bool,
    pub process_present: bool,
    pub listener_present: bool,
    pub production_admitted: bool,
    pub ownership_present: bool,
    pub installed_pair_coherent: bool,
}
pub struct NativeObserver {
    fs: ProtectedFs,
    runner: NativeReadOnly,
}
impl NativeObserver {
    pub fn open() -> Result<Self, HostError> {
        require_native_platform()?;
        let fs = ProtectedFs::native()?;
        if !ubuntu(&fs)? {
            return Err(HostError::UnsupportedHost);
        }
        Ok(Self {
            fs,
            runner: NativeReadOnly,
        })
    }
    pub fn inspect(&self, stop: &Cancellation) -> Result<ReadOnlyObservation, HostError> {
        let facts = Facts::query(&self.runner, stop)?;
        if !ubuntu(&self.fs)? {
            return Err(HostError::UnsupportedHost);
        }
        Ok(ReadOnlyObservation {
            ubuntu_2404: true,
            architecture: "amd64",
            package_present: facts.package,
            clock_synchronized: facts.clock,
            service_enabled: facts.enabled,
            service_active: facts.active,
            process_present: facts.process,
            listener_present: !facts.listener.is_empty(),
            production_admitted: false,
            ownership_present: self.read_ownership()?.is_some(),
            installed_pair_coherent: self.read_installed()?.is_some(),
        })
    }
}
impl NativeObserver {
    /// Binds the actual kernel-reported running executable and protected installed
    /// file to exact authenticated release/index/archive bytes. No effects follow.
    pub fn authenticate_current(
        &self,
        transport: &mut impl crate::artifact_trust::AcquisitionTransport,
        budget: &crate::artifact_trust::SelectionBudget,
    ) -> Result<crate::release_acquisition::AuthenticatedInstalled, HostError> {
        require_native_environment()?;
        if std::env::current_exe().map_err(|_| HostError::Unsafe)?
            != Path::new("/usr/local/bin/sbxr")
        {
            return Err(HostError::Foreign);
        }
        let record = self.read_installed()?.ok_or(HostError::Foreign)?;
        let (installed, _) = self
            .fs
            .raw(
                "usr/local/bin/sbxr",
                Mode::from_raw_mode(0o755),
                crate::release_identity::MAX_EXECUTABLE_BYTES,
            )?
            .ok_or(HostError::Foreign)?;
        let descriptor = rustix::fs::open(
            "/proc/self/exe",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| HostError::Unsafe)?;
        let mut file = std::fs::File::from(descriptor);
        use std::os::unix::fs::MetadataExt;
        let before = file.metadata().map_err(|_| HostError::Unsafe)?;
        if !before.is_file()
            || before.uid() != 0
            || before.gid() != 0
            || before.nlink() != 1
            || before.mode() & 0o7777 != 0o755
        {
            return Err(HostError::Foreign);
        }
        // Read access may update atime. Stable ownership/inode/content metadata
        // must not change; atime is not an authority or content-change proof.
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.mode(),
                m.uid(),
                m.gid(),
                m.nlink(),
                m.size(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        let stable = identity(&before);
        let mut current = Vec::new();
        use std::io::Read;
        let mut chunk = [0; 8192];
        loop {
            budget.check().map_err(|_| HostError::Cancelled)?;
            let n = file.read(&mut chunk).map_err(|_| HostError::Io)?;
            if n == 0 {
                break;
            }
            if current.len() + n > crate::release_identity::MAX_EXECUTABLE_BYTES {
                return Err(HostError::OutputLimit);
            }
            current.extend_from_slice(&chunk[..n]);
        }
        let after = identity(&file.metadata().map_err(|_| HostError::Unsafe)?);
        if stable != after {
            return Err(HostError::Unsafe);
        }
        let admitted = crate::release_acquisition::AuthenticatedInstalled::acquire(
            transport, record, &installed, &current, budget,
        )
        .map_err(|_| HostError::Foreign)?;
        if self.read_installed()?.as_ref() != Some(admitted.record()) {
            return Err(HostError::Foreign);
        }
        Ok(admitted)
    }
    /// Reads validated authority without rewriting/promoting it or granting effects.
    pub fn read_ownership(&self) -> Result<Option<OwnershipRecord>, HostError> {
        read_ownership(&self.fs)
    }
    /// Coherence is not executable/release authentication. Software Lifecycle must
    /// separately prove the exact signed Rust/Go release identity.
    pub fn read_installed(&self) -> Result<Option<InstalledRecord>, HostError> {
        read_installed(&self.fs)
    }
    pub fn read_configuration(
        &self,
        expected_sha256: &str,
        stop: &Cancellation,
    ) -> Result<ProtectedConfiguration, HostError> {
        read_configuration(&self.fs, &self.runner, expected_sha256, stop)
    }
}
pub(super) fn read_ownership(fs: &ProtectedFs) -> Result<Option<OwnershipRecord>, HostError> {
    if fs.metadata("var/lib/sbxr")?.is_none() {
        return Ok(None);
    }
    fs.observe(Resource {
        path: "var/lib/sbxr",
        kind: Kind::Directory(Mode::from_raw_mode(0o700)),
    })?
    .ok_or(HostError::Unsafe)?;
    fs.raw(
        "var/lib/sbxr/proxy-ownership.json",
        Mode::from_raw_mode(0o600),
        crate::records::MAX_RECORD_BYTES,
    )?
    .map(|(bytes, _)| OwnershipRecord::decode(&bytes).map_err(|_| HostError::Foreign))
    .transpose()
}
pub(in crate::host) fn read_installed(
    fs: &ProtectedFs,
) -> Result<Option<InstalledRecord>, HostError> {
    let record = fs.raw(
        "var/lib/sbxr/installed.json",
        Mode::from_raw_mode(0o600),
        4096,
    )?;
    let executable = fs.raw(
        "usr/local/bin/sbxr",
        Mode::from_raw_mode(0o755),
        crate::release_identity::MAX_EXECUTABLE_BYTES,
    )?;
    match (record, executable) {
        (None, None) => Ok(None),
        (Some((record, _)), Some((executable, _))) => {
            let record = InstalledRecord::decode(&record).map_err(|_| HostError::Foreign)?;
            crate::release_identity::verify_installed_pair(&record, &executable)
                .map_err(|_| HostError::Foreign)?;
            crate::release_identity::inspect_linux_artifact(
                &executable,
                crate::release_identity::Architecture::Amd64,
            )
            .map_err(|_| HostError::Foreign)?;
            Ok(Some(record))
        }
        _ => Err(HostError::Foreign),
    }
}
pub struct ProtectedConfiguration(zeroize::Zeroizing<Vec<u8>>);
impl ProtectedConfiguration {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.0)
    }
}
impl fmt::Debug for ProtectedConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected configuration (redacted)")
    }
}
pub(super) fn read_configuration(
    fs: &ProtectedFs,
    runner: &impl CommandRunner,
    expected: &str,
    stop: &Cancellation,
) -> Result<ProtectedConfiguration, HostError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HostError::Unsafe);
    }
    let group = runner.query(Query::Group, stop)?;
    let fields: Vec<_> = group.text()?.split(':').collect();
    if group.code() != 0 || fields.len() != 4 || fields[0] != "sing-box" {
        return Err(HostError::Unsafe);
    }
    let gid = fields[2].parse::<u32>().map_err(|_| HostError::Unsafe)?;
    let (bytes, evidence) = fs
        .raw(CONFIG, Mode::from_raw_mode(0o640), 1 << 20)?
        .ok_or(HostError::Unsafe)?;
    if evidence.gid != gid || sha256_hex(&bytes) != expected {
        return Err(HostError::Foreign);
    }
    Ok(ProtectedConfiguration(zeroize::Zeroizing::new(bytes)))
}

pub(super) fn ubuntu(fs: &ProtectedFs) -> Result<bool, HostError> {
    // Ubuntu's standard os-release symlink is resolved only to its fixed protected
    // usr/lib target; arbitrary symlinks and escapes are refused.
    let path = if fs
        .metadata("etc/os-release")?
        .is_some_and(|s| s.kind == FileType::Symlink)
    {
        if fs
            .observe(Resource {
                path: "etc/os-release",
                kind: Kind::Link("../usr/lib/os-release"),
            })?
            .is_none()
        {
            return Err(HostError::Unsafe);
        }
        "usr/lib/os-release"
    } else {
        "etc/os-release"
    };
    let Some((bytes, _)) = fs.raw(path, Mode::from_raw_mode(0o644), 4096)? else {
        return Err(HostError::Unsafe);
    };
    let body = std::str::from_utf8(&bytes).map_err(|_| HostError::Unsafe)?;
    let (mut id, mut version) = (None, None);
    for line in body.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"');
            match key {
                "ID" => {
                    if id.replace(value).is_some() {
                        return Err(HostError::Unsafe);
                    }
                }
                "VERSION_ID" => {
                    if version.replace(value).is_some() {
                        return Err(HostError::Unsafe);
                    }
                }
                _ => (),
            }
        }
    }
    Ok(id == Some("ubuntu") && version == Some("24.04"))
}

pub(super) struct Facts {
    pub(super) package: bool,
    pub(super) held: bool,
    pub(super) held_package: bool,
    pub(super) identity: bool,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    pub(super) enabled: bool,
    pub(super) active: bool,
    pub(super) masked: bool,
    pub(super) process: bool,
    pub(super) listener: String,
    pub(super) provenance: bool,
    pub(super) clock: bool,
    pub(super) fingerprint: String,
}
fn presence(out: &CommandOutput, absent: i32) -> Result<bool, HostError> {
    match out.code() {
        0 if !out.text()?.is_empty() => Ok(true),
        n if n == absent && out.text()?.is_empty() => Ok(false),
        _ => Err(HostError::Unsafe),
    }
}
impl Facts {
    pub(super) fn query(
        runner: &impl CommandRunner,
        stop: &Cancellation,
    ) -> Result<Self, HostError> {
        Self::query_inner(runner, stop, true)
    }
    pub(super) fn removal(
        runner: &impl CommandRunner,
        stop: &Cancellation,
    ) -> Result<Self, HostError> {
        Self::query_inner(runner, stop, false)
    }
    fn query_inner(
        runner: &impl CommandRunner,
        stop: &Cancellation,
        clock: bool,
    ) -> Result<Self, HostError> {
        let values = QUERIES
            .iter()
            .map(|q| {
                if *q == Query::Clock && !clock {
                    CommandOutput::completed(0, b"yes".to_vec())
                } else {
                    runner.query(*q, stop)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut fingerprint = String::new();
        for (q, value) in QUERIES.iter().zip(&values) {
            fingerprint.push_str(&format!(
                "{q:?}:{}:{};",
                value.code(),
                sha256_hex(value.bytes())
            ))
        }
        let package = presence(&values[0], 1)?;
        let mut held_package = false;
        if package {
            let parts: Vec<_> = values[0].text()?.split_whitespace().collect();
            if parts.len() != 3
                || parts[0] != "1.14.3"
                || parts[1] != "amd64"
                || !matches!(
                    parts[2],
                    "ii" | "hi"
                        | "rc"
                        | "iU"
                        | "iF"
                        | "iH"
                        | "it"
                        | "iW"
                        | "hU"
                        | "hF"
                        | "hH"
                        | "ht"
                        | "hW"
                )
            {
                return Err(HostError::Foreign);
            }
            held_package = parts[2] == "hi";
        }
        if values[1].code() != 0 {
            return Err(HostError::Unsafe);
        }
        let held = values[1]
            .text()?
            .split_whitespace()
            .any(|v| v == "sing-box");
        let user = presence(&values[2], 2)?;
        let group = presence(&values[3], 2)?;
        let (mut uid, mut user_gid, mut gid) = (None, None, None);
        if user {
            let u: Vec<_> = values[2].text()?.split(':').collect();
            if u.len() != 7 || u[0] != "sing-box" {
                return Err(HostError::Unsafe);
            }
            uid = Some(u[2].parse::<u32>().map_err(|_| HostError::Unsafe)?);
            user_gid = Some(u[3].parse::<u32>().map_err(|_| HostError::Unsafe)?);
        }
        if group {
            let g: Vec<_> = values[3].text()?.split(':').collect();
            if g.len() != 4 || g[0] != "sing-box" {
                return Err(HostError::Unsafe);
            }
            gid = Some(g[2].parse::<u32>().map_err(|_| HostError::Unsafe)?);
        }
        if user && group && user_gid != gid {
            return Err(HostError::Unsafe);
        }
        let process = presence(&values[4], 1)?;
        if process
            && !values[4]
                .text()?
                .split_whitespace()
                .all(|v| v.parse::<u32>().is_ok_and(|pid| pid > 0))
        {
            return Err(HostError::Unsafe);
        }
        let enabled = values[5].text()?;
        let active = values[6].text()?;
        if !matches!(enabled, "enabled" | "disabled" | "masked" | "not-found")
            || !matches!(active, "active" | "inactive" | "failed")
            || values[5].code()
                != match enabled {
                    "enabled" => 0,
                    "not-found" => 4,
                    _ => 1,
                }
            || values[6].code() != if active == "active" { 0 } else { 3 }
        {
            return Err(HostError::Unsafe);
        }
        if !matches!(values[9].code(), 0 | 1)
            || values[7].code() != 0
            || !matches!(values[7].text()?, "loaded" | "masked" | "not-found")
            || values[8].code() != 0
            || values[10].code() != 0
        {
            return Err(HostError::Unsafe);
        }
        Ok(Self {
            package,
            held,
            held_package,
            identity: user && group,
            uid,
            gid,
            enabled: enabled == "enabled",
            active: active == "active",
            masked: enabled == "masked",
            process,
            listener: values[8].text()?.into(),
            provenance: values[9].code() == 0 && values[9].text()?.starts_with("sing-box:"),
            clock: values[10].text()? == "yes",
            fingerprint,
        })
    }
}
