//! Concrete removal with exact current and retained HTTPS/renewal ownership.
//! All native execution remains behind the closed production entry.
mod auxiliary;
mod client_subscription;
mod historical;
mod tunnel;
use super::*;
use crate::{
    durable::{OWNERSHIP_FILE, OwnershipStore, STAGED_FILE},
    removal::{
        self, AuthorityLocation, AuthoritySnapshot, EffectState, FinalizationError, LifecycleFacts,
        RemovalEffect, RemovalFacts, RemovalHost,
    },
};
pub use auxiliary::{AuxiliaryFacts, AuxiliaryRuntime, NoAuxiliaryRuntime};
pub use historical::HistoricalRuntimeFacts;
pub use tunnel::{TunnelRemovalFacts, TunnelRemovalRuntime};
const CURRENT: &str = "var/lib/sbxr/proxy-ownership.json";
const FINAL: &str = "var/lib/.sbxr-removal.json";
pub struct StandardRemovalHost<R, B = NoAuxiliaryRuntime> {
    auxiliary: B,
    pub(super) inner: LinuxHost<R>,
    store: Option<OwnershipStore>,
    historical: Option<crate::host::historical::HistoricalExclusion>,
    package_locks: Option<super::super::locks::PackageLocks<'static>>,
    installed: InstalledRecord,
    executable: Vec<u8>,
    #[cfg(test)]
    fault: Option<u8>,
}
impl<R: CommandRunner> StandardRemovalHost<R, NoAuxiliaryRuntime> {
    pub fn new(inner: LinuxHost<R>) -> Result<Self, HostError> {
        let installed = inner
            .authenticated
            .clone()
            .ok_or(HostError::LiveUnavailable)?;
        let executable = inner
            .fs
            .raw(
                "usr/local/bin/sbxr",
                Mode::from_raw_mode(0o755),
                crate::release_identity::MAX_EXECUTABLE_BYTES,
            )?
            .ok_or(HostError::Foreign)?
            .0;
        if sha256_hex(&executable) != installed.executable_sha256() {
            return Err(HostError::Foreign);
        }
        let store = Some(
            OwnershipStore::open(&inner.fs.path().join("var/lib/sbxr"), inner.fs.uid)
                .map_err(|_| HostError::Unsafe)?,
        );
        Ok(Self {
            auxiliary: NoAuxiliaryRuntime,
            inner,
            store,
            historical: None,
            package_locks: None,
            installed,
            executable,
            #[cfg(test)]
            fault: None,
        })
    }
    pub fn with_auxiliary<B: AuxiliaryRuntime>(self, auxiliary: B) -> StandardRemovalHost<R, B> {
        StandardRemovalHost {
            auxiliary,
            inner: self.inner,
            store: self.store,
            historical: self.historical,
            package_locks: self.package_locks,
            installed: self.installed,
            executable: self.executable,
            #[cfg(test)]
            fault: self.fault,
        }
    }
}
impl<R: CommandRunner, B: AuxiliaryRuntime> StandardRemovalHost<R, B> {
    /// Compose dedicated connector removal with the already selected HTTP runtime.
    pub fn with_tunnel<I: crate::host::tunnel_native::ConnectorIo>(
        self,
        connector: crate::host::tunnel_native::Connector<I>,
    ) -> StandardRemovalHost<R, TunnelRemovalRuntime<B, I>> {
        StandardRemovalHost {
            auxiliary: TunnelRemovalRuntime::new(self.auxiliary, connector),
            inner: self.inner,
            store: self.store,
            historical: self.historical,
            package_locks: self.package_locks,
            installed: self.installed,
            executable: self.executable,
            #[cfg(test)]
            fault: self.fault,
        }
    }
    #[cfg(test)]
    pub(super) fn interrupt_auxiliary_removal(&mut self, point: u8) {
        self.fault = Some(100 + point);
    }
    #[cfg(test)]
    pub(super) fn interrupt_finalization(&mut self, point: u8) {
        self.fault = Some(point)
    }
    fn supported(&self, record: &OwnershipRecord) -> Result<(), HostError> {
        self.current_auxiliary(record)?;
        let value: serde_json::Value =
            serde_json::from_slice(&record.encode().map_err(|_| HostError::Foreign)?)
                .map_err(|_| HostError::Foreign)?;
        if value["proxy_package_identity"] == "" {
            if record.release_identity() != self.installed.release_identity() || !self.absent()? {
                return Err(HostError::Foreign);
            }
            return Ok(());
        }
        if record.lock_provisioning_sha256() != Some(sha256_hex(UNIT).as_str()) {
            return Err(HostError::LiveUnavailable);
        }
        if record.release_identity() != self.installed.release_identity()
            || record.configuration_sha256() != self.inner.configuration_sha256()
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn bytes(&self, path: &str) -> Result<Option<Vec<u8>>, HostError> {
        Ok(self
            .inner
            .fs
            .raw(
                path,
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .map(|(b, _)| b))
    }
    fn stage() -> String {
        format!("var/lib/sbxr/{STAGED_FILE}")
    }
    fn absent(&self) -> Result<bool, HostError> {
        let facts = Facts::removal(&self.inner.runner, &self.inner.stop)?;
        if facts.package
            || facts.held
            || facts.uid.is_some()
            || facts.gid.is_some()
            || facts.active
            || facts.enabled
            || facts.process
            || !facts.listener.is_empty()
        {
            return Ok(false);
        }
        for path in [
            KEY,
            SOURCE,
            CONFIG,
            ARTIFACT,
            LOCK_UNIT,
            LOCK_LINK,
            "etc/systemd/system/sing-box.service",
            "etc/sing-box",
            "var/lib/sing-box",
            "usr/lib/systemd/system/sing-box.service",
            crate::host::identity::STARTUP,
            crate::host::identity::TARGET,
            crate::host::identity::CONFIG_STAGE,
            crate::host::subscription::TOKEN,
            crate::host::subscription::STATE,
            crate::host::subscription::STAGING,
            crate::host::subscription::UNIT,
            crate::host::subscription::LINK,
            crate::host::subscription::FIREWALL,
            crate::host::subscription::FIREWALL_LINK,
            "etc/systemd/system/sbxr-tunnel.service",
            "etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service",
            "etc/systemd/system/sbxr-subscription.service.sbxr-next.sbxr-next",
        ] {
            if self.inner.fs.metadata(path)?.is_some()
                || self
                    .inner
                    .fs
                    .metadata(&format!("{path}.sbxr-next"))?
                    .is_some()
            {
                return Ok(false);
            }
        }
        for path in [
            crate::host::historical::ARCHIVE,
            crate::host::historical::LIVE,
            crate::host::historical::RENEWAL_CONFIG,
            crate::host::historical::RETIRED,
            "var/lib/sbxr/renewal-attempts.json",
            "var/lib/sbxr/.renewal-attempts.json.next",
            "var/lib/sbxr/renewal-admission.lock",
            "var/lib/sbxr/renewal-writer.lock",
            "etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf",
            "etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription",
            "etc/letsencrypt/renewal-hooks/post/sbxr-subscription",
        ] {
            if self.inner.fs.metadata(path)?.is_some() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn owned_proxy(&self, record: &OwnershipRecord) -> Result<String, HostError> {
        let facts = Facts::removal(&self.inner.runner, &self.inner.stop)?;
        self.inner.runner.removal_identity_safe(&self.inner.stop)?;
        let mut fingerprint = facts.fingerprint.clone();
        for (path, digest, mode) in [
            (KEY, self.inner.material.key_sha256.clone(), 0o644),
            (SOURCE, sha256_hex(APT_SOURCE), 0o644),
            (
                CONFIG,
                self.inner.material.configuration_digest.clone(),
                0o640,
            ),
            (ARTIFACT, self.inner.material.package_sha256.clone(), 0o600),
            (LOCK_UNIT, sha256_hex(UNIT), 0o644),
        ] {
            for selected in [path.to_string(), format!("{path}.sbxr-next")] {
                if let Some((bytes, evidence)) =
                    self.inner
                        .fs
                        .raw(&selected, Mode::from_raw_mode(mode), 1 << 26)?
                {
                    if (if path == CONFIG {
                        !self
                            .configuration_digests(record)?
                            .contains(&sha256_hex(&bytes))
                    } else {
                        sha256_hex(&bytes) != digest || evidence.gid != self.inner.fs.gid
                    }) || path == CONFIG && (!facts.identity || Some(evidence.gid) != facts.gid)
                    {
                        return Err(HostError::Foreign);
                    }
                    fingerprint.push_str(&format!("{selected}:{evidence:?}"));
                }
            }
        }
        if let Some(meta) = self.inner.fs.metadata("var/lib/sing-box")? {
            if !facts.identity || Some(meta.uid) != facts.uid || Some(meta.gid) != facts.gid {
                return Err(HostError::Foreign);
            }
            self.inner.fs.observe(Resource {
                path: "var/lib/sing-box",
                kind: Kind::OwnedDirectory(Mode::from_raw_mode(0o755), meta.uid, meta.gid),
            })?;
            if self
                .inner
                .fs
                .directory_entries_owned("var/lib/sing-box", Mode::from_raw_mode(0o755), meta.uid)?
                .is_some_and(|v| !v.is_empty())
            {
                return Err(HostError::Foreign);
            }
        }
        self.inner.fs.observe(Resource {
            path: "etc/sing-box",
            kind: Kind::Directory(Mode::from_raw_mode(0o755)),
        })?;
        if self
            .inner
            .fs
            .directory_entries("etc/sing-box", Mode::from_raw_mode(0o755))?
            .is_some_and(|names| {
                names.iter().any(|s| {
                    s != "config.json"
                        && s != "config.json.sbxr-next"
                        && s != ".config.json.sbxr-next"
                })
            })
        {
            return Err(HostError::Foreign);
        }
        self.inner.fs.observe(Resource {
            path: LOCK_LINK,
            kind: Kind::Link("../sbxr-mutation-lock.service"),
        })?;
        self.inner.fs.observe(Resource {
            path: "etc/systemd/system/sing-box.service",
            kind: Kind::Link("/dev/null"),
        })?;
        if let Some((_, proof)) = self.inner.fs.raw(
            "usr/lib/systemd/system/sing-box.service",
            Mode::from_raw_mode(0o644),
            1 << 20,
        )? {
            if !facts.package || !facts.provenance {
                return Err(HostError::Foreign);
            }
            fingerprint.push_str(&format!("{proof:?}"));
        }
        Ok(fingerprint)
    }
    fn remove_bound_configuration(&self, record: &OwnershipRecord) -> Result<(), HostError> {
        let digests = self.configuration_digests(record)?;
        for path in [CONFIG.to_owned(), format!("{CONFIG}.sbxr-next")] {
            if let Some((bytes, _)) =
                self.inner
                    .fs
                    .raw(&path, Mode::from_raw_mode(0o640), 1 << 20)?
            {
                if !digests.contains(&sha256_hex(&bytes)) {
                    return Err(HostError::Foreign);
                }
                self.inner
                    .fs
                    .remove_bytes(&path, &bytes, Mode::from_raw_mode(0o640))?;
            }
        }
        Ok(())
    }
    fn guard(&self) -> Result<(), HostError> {
        self.inner
            .lock
            .as_ref()
            .ok_or(HostError::Unsafe)?
            .verify()?;
        if let Some(h) = &self.historical {
            h.verify()?;
        }
        Ok(())
    }
}
impl<R: CommandRunner, B: AuxiliaryRuntime> RemovalHost for StandardRemovalHost<R, B> {
    fn is_native_system(&self) -> bool {
        self.inner.native_mode
    }
    fn effects_available(&self) -> bool {
        self.inner.effects_available() && self.inner.authenticated.is_some()
    }
    fn executing_release(&self) -> Result<ReleaseIdentity, HostError> {
        Ok(self.installed.release_identity())
    }
    fn read_authority(&self) -> Result<AuthoritySnapshot, HostError> {
        if self
            .inner
            .fs
            .metadata("var/lib/sbxr/proxy-ownership.json.sbxr-next")?
            .is_some()
        {
            return Err(HostError::Foreign);
        }
        Ok(AuthoritySnapshot {
            current: self.bytes(CURRENT)?,
            staged: self.bytes(&Self::stage())?,
            finalizer: self.bytes(FINAL)?,
        })
    }
    fn inspect_removal(
        &self,
        record: Option<&OwnershipRecord>,
        release: &ReleaseIdentity,
    ) -> Result<RemovalFacts, HostError> {
        if release != &self.installed.release_identity() {
            return Err(HostError::Foreign);
        }
        let mut proof = self.inspect_lifecycle(release)?;
        if let Some(lock) = &self.inner.lock {
            lock.verify()?;
        }
        if let Some(packages) = &self.package_locks {
            packages.verify()?;
        }
        let names = self
            .inner
            .fs
            .directory_entries("var/lib/sbxr", Mode::from_raw_mode(0o700))?
            .unwrap_or_default();
        if names.iter().any(|n| {
            ![
                OWNERSHIP_FILE,
                STAGED_FILE,
                "installed.json",
                "sing-box_1.14.3_amd64.deb",
                "sing-box_1.14.3_amd64.deb.sbxr-next",
                "subscription-token",
                "subscription-token.sbxr-next",
                "subscription-serving.json",
                "subscription-serving.json.sbxr-next",
                "subscription-staging",
                "client-identity-target.json",
                "client-identity-target.json.sbxr-next",
                "renewal-attempts.json",
                "renewal-admission.lock",
                "renewal-writer.lock",
                "subscription-https-retired",
            ]
            .contains(&n.as_str())
        }) {
            return Err(HostError::Foreign);
        }
        let fingerprint = if let Some(record) = record {
            self.supported(record)?;
            format!(
                "{}:{}",
                self.owned_proxy(record)?,
                self.inspect_auxiliary(record)?
            )
        } else {
            if !self.absent()? {
                return Err(HostError::Foreign);
            }
            "absent".into()
        };
        proof.valid = true;
        let digest =
            sha256_hex(format!("{fingerprint}:{proof:?}:{:?}", self.read_authority()?).as_bytes());
        let mut fingerprint = [0; 32];
        for (i, chunk) in digest.as_bytes().chunks_exact(2).enumerate() {
            fingerprint[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).map_err(|_| HostError::Unsafe)?,
                16,
            )
            .map_err(|_| HostError::Unsafe)?;
        }
        Ok(RemovalFacts {
            fingerprint,
            accepted: true,
        })
    }
    fn inspect_lifecycle(&self, release: &ReleaseIdentity) -> Result<LifecycleFacts, HostError> {
        if release != &self.installed.release_identity() {
            return Err(HostError::Foreign);
        }
        let executable = self.inner.fs.raw(
            "usr/local/bin/sbxr",
            Mode::from_raw_mode(0o755),
            crate::release_identity::MAX_EXECUTABLE_BYTES,
        )?;
        if executable
            .as_ref()
            .is_some_and(|(b, _)| b != &self.executable)
        {
            return Err(HostError::Foreign);
        }
        let installed = self.bytes("var/lib/sbxr/installed.json")?;
        if let Some(bytes) = &installed
            && InstalledRecord::decode(bytes).map_err(|_| HostError::Foreign)? != self.installed
        {
            return Err(HostError::Foreign);
        }
        let names = self
            .inner
            .fs
            .directory_entries("var/lib/sbxr", Mode::from_raw_mode(0o700))?
            .unwrap_or_default();
        let empty = names
            .iter()
            .all(|s| [OWNERSHIP_FILE, STAGED_FILE, "installed.json"].contains(&s.as_str()));
        Ok(LifecycleFacts {
            release: release.clone(),
            valid: true,
            executable_present: executable.is_some(),
            installed_record_present: installed.is_some(),
            state_directory_empty: empty,
        })
    }
    fn begin_change(&mut self, record: Option<&OwnershipRecord>) -> Result<(), HostError> {
        if let Some(record) = record {
            self.supported(record)?;
        }
        SetupHost::begin_change(&mut self.inner)?;
        match self
            .inner
            .lock
            .as_ref()
            .ok_or(HostError::Unsafe)?
            .retain_packages()
        {
            Ok(packages) => {
                self.package_locks = Some(packages);
                if let Some(record) = record
                    && crate::host::historical::has_authority(record)
                {
                    let result = self.historical_host().and_then(|mut host| {
                        host.exclusion(self.inner.lock.as_ref().ok_or(HostError::Unsafe)?, record)
                    });
                    match result {
                        Ok(guard) => self.historical = Some(guard),
                        Err(e) => {
                            self.package_locks = None;
                            SetupHost::end_change(&mut self.inner);
                            return Err(e);
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                SetupHost::end_change(&mut self.inner);
                Err(e)
            }
        }
    }
    fn release_package_locks(&mut self) {
        self.package_locks = None;
    } // Fixed effects probe/drop package guards before APT itself locks.
    fn end_change(&mut self) {
        self.historical = None;
        self.package_locks = None;
        SetupHost::end_change(&mut self.inner)
    }
    fn publish(
        &mut self,
        expected: Option<&[u8]>,
        target: &OwnershipRecord,
    ) -> Result<(), HostError> {
        self.guard()?;
        self.store
            .as_mut()
            .ok_or(HostError::Unsafe)?
            .publish(expected, target)
            .map_err(|_| HostError::Io)
    }
    fn synchronize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), HostError> {
        self.guard()?;
        match location {
            AuthorityLocation::Current => self
                .store
                .as_ref()
                .ok_or(HostError::Unsafe)?
                .synchronize(expected)
                .map_err(|_| HostError::Io),
            AuthorityLocation::Finalizer => {
                self.inner
                    .fs
                    .sync_bytes(FINAL, expected, Mode::from_raw_mode(0o600))
            }
        }
    }
    fn inspect_effect(
        &self,
        effect: RemovalEffect,
        record: &OwnershipRecord,
    ) -> Result<EffectState, HostError> {
        self.supported(record)?;
        self.owned_proxy(record)?;
        self.inspect_auxiliary(record)?;
        use RemovalEffect::*;
        let present = match effect {
            Executable => self.inner.fs.metadata("usr/local/bin/sbxr")?.is_some(),
            InstalledRecord => self
                .inner
                .fs
                .metadata("var/lib/sbxr/installed.json")?
                .is_some(),
            StopDisableProxy => {
                let f = Facts::removal(&self.inner.runner, &self.inner.stop)?;
                f.enabled
                    || f.masked
                    || f.active
                    || f.process
                    || self.inner.fs.metadata(LOCK_UNIT)?.is_some()
                    || self.inner.fs.metadata(LOCK_LINK)?.is_some()
            }
            PackageHold => Facts::removal(&self.inner.runner, &self.inner.stop)?.held,
            Package => Facts::removal(&self.inner.runner, &self.inner.stop)?.package,
            PackageIdentity => {
                let f = Facts::removal(&self.inner.runner, &self.inner.stop)?;
                f.uid.is_some() || f.gid.is_some()
            }
            PackageArtifact => {
                self.inner.fs.metadata(ARTIFACT)?.is_some()
                    || self
                        .inner
                        .fs
                        .metadata(&format!("{ARTIFACT}.sbxr-next"))?
                        .is_some()
            }
            ConfigurationState => {
                self.inner.fs.metadata("etc/sing-box")?.is_some()
                    || self.inner.fs.metadata("var/lib/sing-box")?.is_some()
            }
            AptSource => {
                self.inner.fs.metadata(SOURCE)?.is_some()
                    || self
                        .inner
                        .fs
                        .metadata(&format!("{SOURCE}.sbxr-next"))?
                        .is_some()
            }
            AptKey => {
                self.inner.fs.metadata(KEY)?.is_some()
                    || self
                        .inner
                        .fs
                        .metadata(&format!("{KEY}.sbxr-next"))?
                        .is_some()
            }
            _ => self.auxiliary_effect(effect, record)?,
        };
        self.inspect_lifecycle(&self.installed.release_identity())?;
        Ok(if present {
            EffectState::ExactOwned
        } else {
            EffectState::Absent
        })
    }
    fn apply(&mut self, effect: RemovalEffect, record: &OwnershipRecord) -> Result<(), HostError> {
        self.guard()?;
        self.supported(record)?;
        self.inspect_effect(effect, record)?;
        use RemovalEffect::*;
        match effect {
            Executable => self.inner.fs.remove_bytes(
                "usr/local/bin/sbxr",
                &self.executable,
                Mode::from_raw_mode(0o755),
            ),
            InstalledRecord => {
                if let Some(bytes) = self.bytes("var/lib/sbxr/installed.json")? {
                    self.inner.fs.remove_bytes(
                        "var/lib/sbxr/installed.json",
                        &bytes,
                        Mode::from_raw_mode(0o600),
                    )
                } else {
                    Ok(())
                }
            }
            StopDisableProxy => {
                self.inner
                    .runner
                    .effect(Operation::StopDisableService, &self.inner.stop)?;
                let f = Facts::removal(&self.inner.runner, &self.inner.stop)?;
                if f.active || f.enabled || f.process || f.listener.contains("sing-box") {
                    return Err(HostError::Unsafe);
                }
                if f.masked
                    || self
                        .inner
                        .fs
                        .metadata("etc/systemd/system/sing-box.service")?
                        .is_some()
                {
                    self.inner.fs.observe(Resource {
                        path: "etc/systemd/system/sing-box.service",
                        kind: Kind::Link("/dev/null"),
                    })?;
                    self.inner
                        .runner
                        .effect(Operation::UnmaskService, &self.inner.stop)?;
                    self.inner.fs.remove(Resource {
                        path: "etc/systemd/system/sing-box.service",
                        kind: Kind::Link("/dev/null"),
                    })?;
                }
                self.inner.fs.remove(Resource {
                    path: LOCK_LINK,
                    kind: Kind::Link("../sbxr-mutation-lock.service"),
                })?;
                self.inner.remove(LOCK_UNIT, UNIT, 0o644)?;
                self.inner.runner.reload_units(&self.inner.stop)
            }
            PackageHold | Package | PackageIdentity => self.inner.runner.effect(
                effect.host_operation().ok_or(HostError::Unsafe)?,
                &self.inner.stop,
            ),
            PackageArtifact => {
                self.inner
                    .remove_hashed(ARTIFACT, &self.inner.material.package_sha256, 0o600)
            }
            ConfigurationState => {
                self.remove_bound_configuration(record)?;
                self.inner.fs.remove(Resource {
                    path: "etc/sing-box",
                    kind: Kind::Directory(Mode::from_raw_mode(0o755)),
                })?;
                if let Some(m) = self.inner.fs.metadata("var/lib/sing-box")? {
                    self.inner.fs.remove(Resource {
                        path: "var/lib/sing-box",
                        kind: Kind::OwnedDirectory(Mode::from_raw_mode(0o755), m.uid, m.gid),
                    })?;
                }
                Ok(())
            }
            AptSource => self.inner.remove(SOURCE, APT_SOURCE, 0o644),
            AptKey => self
                .inner
                .remove_hashed(KEY, &self.inner.material.key_sha256, 0o644),
            _ => self.apply_auxiliary(effect, record),
        }
    }
    fn proxy_absent(&self, record: &OwnershipRecord) -> Result<bool, HostError> {
        self.supported(record)?;
        self.inspect_auxiliary(record)?;
        self.absent()
    }
    fn finalize(
        &mut self,
        location: AuthorityLocation,
        expected: &[u8],
    ) -> Result<(), FinalizationError> {
        let perform = || -> Result<(), HostError> {
            self.guard()?;
            let r = OwnershipRecord::decode(expected).map_err(|_| HostError::Foreign)?;
            if removal::checkpoint(&r).ok() != removal::checkpoint_limit(&r).ok() {
                return Err(HostError::Foreign);
            }
            Ok(())
        };
        perform().map_err(|_| FinalizationError::Interrupted)?;
        if location == AuthorityLocation::Current {
            if let Some(stage) = self
                .bytes(&Self::stage())
                .map_err(|_| FinalizationError::Interrupted)?
            {
                if stage != expected {
                    return Err(FinalizationError::Interrupted);
                }
                self.inner
                    .fs
                    .remove_bytes(&Self::stage(), expected, Mode::from_raw_mode(0o600))
                    .map_err(|_| FinalizationError::Interrupted)?;
            }
            self.inner
                .fs
                .move_bytes(CURRENT, FINAL, expected, Mode::from_raw_mode(0o600))
                .map_err(|_| FinalizationError::Interrupted)?;
        } else {
            self.inner
                .fs
                .sync_bytes(FINAL, expected, Mode::from_raw_mode(0o600))
                .map_err(|_| FinalizationError::Interrupted)?;
        }
        #[cfg(test)]
        if self.fault == Some(1) {
            self.fault = None;
            return Err(FinalizationError::Interrupted);
        }
        self.store = None;
        self.inner
            .fs
            .remove(Resource {
                path: "var/lib/sbxr",
                kind: Kind::Directory(Mode::from_raw_mode(0o700)),
            })
            .map_err(|_| FinalizationError::Interrupted)?;
        #[cfg(test)]
        if self.fault == Some(2) {
            self.fault = None;
            return Err(FinalizationError::Interrupted);
        }
        self.inner
            .fs
            .remove_bytes(FINAL, expected, Mode::from_raw_mode(0o600))
            .map_err(|_| FinalizationError::SynchronizationUnknown)?;
        #[cfg(test)]
        if self.fault == Some(3) {
            self.fault = None;
            return Err(FinalizationError::SynchronizationUnknown);
        }
        Ok(())
    }
    fn cancelled(&self) -> bool {
        self.inner.stop.cancelled()
    }
}
