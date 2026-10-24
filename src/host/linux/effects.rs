use super::*;
impl<R: CommandRunner> SetupHost for LinuxHost<R> {
    fn root(&self) -> &Path {
        self.fs.path()
    }
    fn uid(&self) -> u32 {
        self.fs.uid
    }
    fn public_ipv4(&self) -> &str {
        &self.admission.public_ipv4
    }
    fn configuration_sha256(&self) -> String {
        self.material.configuration_sha256()
    }
    fn setup_inputs_available(&self) -> bool {
        !self.material.offline
    }
    fn is_native_system(&self) -> bool {
        self.native_mode
    }
    fn is_injected_system(&self) -> bool {
        !self.native_mode
    }
    fn effects_available(&self) -> bool {
        if self.native_mode {
            false
        } else {
            self.runner.injected_effects()
        }
    }
    fn begin_change(&mut self) -> Result<(), HostError> {
        if !self.effects_available() {
            return Err(HostError::LiveUnavailable);
        }
        if self.lock.is_some() {
            return Err(HostError::Busy);
        }
        let lock = Arc::new(super::super::locks::HostLock::acquire(
            self.root(),
            self.uid(),
        )?);
        if self.native_mode {
            self.fs.authorize_native_writes(Some(lock.clone()))?;
        }
        self.runner.change_lock(Some(lock.clone()));
        self.lock = Some(lock);
        Ok(())
    }
    fn end_change(&mut self) {
        self.runner.change_lock(None);
        let _ = self.fs.authorize_native_writes(None);
        self.lock = None;
    }
    fn interrupted(&self, phase: SetupPhase) -> bool {
        self.interruption == Some(phase)
    }
    fn inspect_setup(&self, release: &ReleaseIdentity) -> Result<SetupObservation, HostError> {
        if self.stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let bound = observation::read_ownership(&self.fs)?;
        if self.material.offline
            && bound.as_ref().is_some_and(|r| {
                r.recovery_direction() != crate::records::RecoveryDirection::Cleanup
                    || r.configuration_sha256() != self.configuration_sha256()
                    || r.release_identity() != *release
                    || r.public_ipv4() != self.public_ipv4()
            })
        {
            return Err(HostError::Foreign);
        }
        let facts = self.facts()?;
        self.admission(&facts)?;
        let (installed, record_proof) = self
            .fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Unsafe)?;
        let installed = InstalledRecord::decode(&installed).map_err(|_| HostError::Unsafe)?;
        let (executable, exec_proof) = self
            .fs
            .raw(
                "usr/local/bin/sbxr",
                Mode::from_raw_mode(0o755),
                crate::release_identity::MAX_EXECUTABLE_BYTES,
            )?
            .ok_or(HostError::Unsafe)?;
        if installed.release_identity() != *release
            || installed.architecture() != "amd64"
            || installed.executable_sha256() != sha256_hex(&executable)
        {
            return Err(HostError::Foreign);
        }
        crate::release_identity::verify_installed_pair(&installed, &executable)
            .map_err(|_| HostError::Foreign)?;
        crate::release_identity::inspect_linux_artifact(
            &executable,
            crate::release_identity::Architecture::Amd64,
        )
        .map_err(|_| HostError::Foreign)?;
        let mut fingerprint = format!(
            "{}:{record_proof:?}:{exec_proof:?}:{:?}",
            facts.fingerprint, self.admission
        );
        let key = self.hashed_file(KEY, &self.material.key_sha256, 0o644, &mut fingerprint)?;
        let source = self.file(SOURCE, APT_SOURCE, 0o644, &mut fingerprint)?;
        let configuration = self.hashed_file(
            CONFIG,
            &self.material.configuration_digest,
            0o640,
            &mut fingerprint,
        )?;
        let artifact = self.hashed_file(
            ARTIFACT,
            &self.material.package_sha256,
            0o600,
            &mut fingerprint,
        )?;
        let lock = self.file(LOCK_UNIT, UNIT, 0o644, &mut fingerprint)?;
        let link = self.fs.observe(Resource {
            path: LOCK_LINK,
            kind: Kind::Link("../sbxr-mutation-lock.service"),
        })?;
        let mask = self.fs.observe(Resource {
            path: "etc/systemd/system/sing-box.service",
            kind: Kind::Link("/dev/null"),
        })?;
        fingerprint.push_str(&format!("{link:?}:{mask:?}"));
        let config_dir = self.fs.observe(Resource {
            path: "etc/sing-box",
            kind: Kind::Directory(Mode::from_raw_mode(0o755)),
        })?;
        let state_metadata = self.fs.metadata("var/lib/sing-box")?;
        if (configuration || state_metadata.is_some()) && !facts.identity {
            return Err(HostError::Foreign);
        }
        let state_dir = self.fs.observe(Resource {
            path: "var/lib/sing-box",
            kind: Kind::OwnedDirectory(
                Mode::from_raw_mode(0o755),
                facts.uid.unwrap_or(self.fs.uid),
                facts.gid.unwrap_or(self.fs.gid),
            ),
        })?;
        fingerprint.push_str(&format!("{config_dir:?}:{state_dir:?}"));
        // Actual Linux UID/GID proofs belong to the observed package account. In the
        // injected root those identities must map exactly to its caller-owned files.
        if facts.identity {
            let user = self.runner.query(Query::User, &self.stop)?;
            let group = self.runner.query(Query::Group, &self.stop)?;
            let uid = user
                .text()?
                .split(':')
                .nth(2)
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or(HostError::Unsafe)?;
            let gid = group
                .text()?
                .split(':')
                .nth(2)
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or(HostError::Unsafe)?;
            if state_dir.is_some()
                && self
                    .fs
                    .metadata("var/lib/sing-box")?
                    .is_none_or(|s| s.uid != uid || s.gid != gid)
                || configuration && self.fs.metadata(CONFIG)?.is_none_or(|s| s.gid != gid)
            {
                return Err(HostError::Foreign);
            }
        }
        let mut staged = false;
        for (path, digest, mode) in [
            (KEY, self.material.key_sha256.clone(), 0o644),
            (SOURCE, sha256_hex(APT_SOURCE), 0o644),
            (CONFIG, self.material.configuration_digest.clone(), 0o640),
            (ARTIFACT, self.material.package_sha256.clone(), 0o600),
            (LOCK_UNIT, sha256_hex(UNIT), 0o644),
        ] {
            let stage_path = format!("{path}.sbxr-next");
            let present = self.hashed_file(&stage_path, &digest, mode, &mut fingerprint)?;
            if path == CONFIG
                && present
                && (!facts.identity
                    || self
                        .fs
                        .metadata(&stage_path)?
                        .is_none_or(|m| Some(m.gid) != facts.gid))
            {
                return Err(HostError::Foreign);
            }
            staged |= present;
        }
        let package_unit = self.fs.raw(
            "usr/lib/systemd/system/sing-box.service",
            Mode::from_raw_mode(0o644),
            1 << 20,
        )?;
        fingerprint.push_str(&format!("{:?}", package_unit.as_ref().map(|(_, p)| p)));
        let validated = if configuration && facts.package && !self.material.offline {
            let validation = self
                .runner
                .query(Query::ValidateConfiguration, &self.stop)?;
            fingerprint.push_str(&format!(
                "validate:{}:{}",
                validation.code(),
                sha256_hex(validation.bytes())
            ));
            validation.code() == 0
        } else {
            false
        };
        let ready = key
            && source
            && configuration
            && lock
            && link.is_some()
            && facts.package
            && facts.held_package
            && facts.held
            && facts.identity
            && facts.provenance
            && package_unit.is_some()
            && config_dir.is_some()
            && state_dir.is_some()
            && validated
            && !facts.masked
            && mask.is_none()
            && !artifact
            && !staged;
        let listener_owned = facts.listener.contains("sing-box")
            && [
                format!("{}:443", self.admission.public_ipv4),
                "*:443".into(),
                "[::]:443".into(),
            ]
            .iter()
            .any(|s| facts.listener.contains(s));
        let empty = !key
            && !source
            && !configuration
            && !artifact
            && !lock
            && link.is_none()
            && mask.is_none()
            && config_dir.is_none()
            && state_dir.is_none()
            && package_unit.is_none()
            && !facts.package
            && !facts.held
            && facts.uid.is_none()
            && facts.gid.is_none()
            && !facts.enabled
            && !facts.active
            && !facts.process
            && facts.listener.is_empty()
            && !staged;
        if self.material.offline && bound.is_none() && !empty {
            return Err(HostError::Foreign);
        }
        if empty && !self.material.offline && !self.admission.tcp443_available {
            return Err(HostError::Unsafe);
        }
        Ok(SetupObservation {
            fingerprint: sha256_hex(fingerprint.as_bytes()),
            empty,
            ready,
            running: ready && facts.enabled && facts.active && facts.process && listener_owned,
            enabled: facts.enabled,
            stopped: !facts.active
                && !facts.enabled
                && !facts.process
                && !facts.listener.contains("sing-box"),
        })
    }
    fn apply_setup(
        &mut self,
        operation: Operation,
        authority: &OwnershipRecord,
    ) -> Result<(), HostError> {
        if !self.effects_available()
            || self.lock.as_ref().is_none_or(|lock| lock.verify().is_err())
            || authority.schema() != 1
            || authority.tunnel_authority().is_some()
            || authority.configuration_sha256() != self.configuration_sha256()
            || authority.public_ipv4() != self.public_ipv4()
        {
            return Err(HostError::LiveUnavailable);
        }
        let before = self.inspect_setup(&authority.release_identity())?;
        if operation == Operation::EnableService {
            let facts = self.facts()?;
            // A succeeded enable effect may precede an interrupted checkpoint.
            // Retry it idempotently without permitting an active source process.
            if !before.ready_to_activate()
                || facts.active
                || facts.process
                || facts.listener.contains("sing-box")
            {
                return Err(HostError::Unsafe);
            }
        }
        if operation == Operation::StartService
            && (!before.ready_to_activate() || !before.service_enabled())
        {
            return Err(HostError::Unsafe);
        }
        let cleanup = matches!(
            operation,
            Operation::StopDisableService
                | Operation::UnmaskService
                | Operation::RemovePackageArtifact
                | Operation::RemovePackage
                | Operation::RemovePackageHold
                | Operation::RemoveConfigurationState
                | Operation::RemovePackageIdentity
                | Operation::RemoveAptSource
                | Operation::RemoveAptKey
        );
        if self.material.offline
            && (!cleanup
                || authority.recovery_direction() != crate::records::RecoveryDirection::Cleanup)
        {
            return Err(HostError::Foreign);
        }
        if !self.material.offline
            && (sha256_hex(&self.material.key) != self.material.key_sha256
                || sha256_hex(&self.material.package) != self.material.package_sha256)
        {
            return Err(HostError::Foreign);
        }
        use Operation::*;
        match operation {
            InstallAptKey => self.install(KEY, &self.material.key, 0o644),
            InstallAptSource => self.install(SOURCE, APT_SOURCE, 0o644),
            InstallConfiguration => {
                let facts = self.facts()?;
                let gid = facts.gid.ok_or(HostError::Unsafe)?;
                if !facts.identity {
                    return Err(HostError::Unsafe);
                }
                self.fs.publish_bytes_group(
                    CONFIG,
                    self.material.configuration_bytes()?,
                    Mode::from_raw_mode(0o640),
                    gid,
                )
            }
            CreateStateDirectory => {
                let facts = self.facts()?;
                self.fs.install(Resource {
                    path: "var/lib/sing-box",
                    kind: Kind::OwnedDirectory(
                        Mode::from_raw_mode(0o755),
                        facts.uid.ok_or(HostError::Unsafe)?,
                        facts.gid.ok_or(HostError::Unsafe)?,
                    ),
                })
            }
            MaskService => {
                self.runner.effect(operation, &self.stop)?;
                self.fs.install(Resource {
                    path: "etc/systemd/system/sing-box.service",
                    kind: Kind::Link("/dev/null"),
                })?;
                self.install(LOCK_UNIT, UNIT, 0o644)?;
                self.fs.install(Resource {
                    path: LOCK_LINK,
                    kind: Kind::Link("../sbxr-mutation-lock.service"),
                })?;
                self.runner.reload_units(&self.stop)
            }
            InstallPackage => {
                let before = self.facts()?;
                if !before.masked || before.active {
                    return Err(HostError::Unsafe);
                }
                self.install(ARTIFACT, &self.material.package, 0o600)?;
                self.runner.effect(operation, &self.stop)?;
                let after = self.facts()?;
                if !after.package || !after.masked || after.active {
                    return Err(HostError::Unsafe);
                }
                self.remove(ARTIFACT, &self.material.package, 0o600)
            }
            ValidateConfiguration => {
                if self
                    .runner
                    .query(Query::ValidateConfiguration, &self.stop)?
                    .code()
                    != 0
                {
                    return Err(HostError::Unsafe);
                }
                Ok(())
            }
            StopDisableService => {
                let _ = self.runner.effect(operation, &self.stop);
                let after = self.facts()?;
                if after.enabled
                    || after.active
                    || after.process
                    || after.listener.contains("sing-box")
                {
                    return Err(HostError::Unsafe);
                }
                self.fs.remove(Resource {
                    path: LOCK_LINK,
                    kind: Kind::Link("../sbxr-mutation-lock.service"),
                })?;
                self.remove(LOCK_UNIT, UNIT, 0o644)?;
                self.runner.reload_units(&self.stop)
            }
            UnmaskService => {
                self.runner.effect(operation, &self.stop)?;
                self.fs.remove(Resource {
                    path: "etc/systemd/system/sing-box.service",
                    kind: Kind::Link("/dev/null"),
                })
            }
            RemovePackageArtifact => {
                self.remove_hashed(ARTIFACT, &self.material.package_sha256, 0o600)
            }
            RemoveConfigurationState => {
                self.remove_hashed(CONFIG, &self.material.configuration_digest, 0o640)?;
                self.fs.remove(Resource {
                    path: "etc/sing-box",
                    kind: Kind::Directory(Mode::from_raw_mode(0o755)),
                })?;
                if let Some(metadata) = self.fs.metadata("var/lib/sing-box")? {
                    self.fs.remove(Resource {
                        path: "var/lib/sing-box",
                        kind: Kind::OwnedDirectory(
                            Mode::from_raw_mode(0o755),
                            metadata.uid,
                            metadata.gid,
                        ),
                    })?;
                }
                Ok(())
            }
            RemoveAptSource => self.remove(SOURCE, APT_SOURCE, 0o644),
            RemoveAptKey => self.remove_hashed(KEY, &self.material.key_sha256, 0o644),
            HoldPackage
            | EnableService
            | StartService
            | RemovePackage
            | RemovePackageHold
            | RemovePackageIdentity => self.runner.effect(operation, &self.stop),
        }
    }
}
