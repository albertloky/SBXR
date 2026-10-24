use super::*;
impl<B: IdentityRuntime> ProtectedIdentityHost<'_, B> {
    pub(super) fn apply(
        &mut self,
        g: &IdentityGuard,
        effect: ci::Effect,
        record: &OwnershipRecord,
        material: Option<&ci::Material>,
    ) -> Result<(), ci::Error> {
        self.inspect_record(record)?;
        let rotation = ci::rotation(record)?;
        match effect {
            ci::Effect::PrepareTarget => {
                let target = material.ok_or(ci::Error::Authority)?;
                if sha256_hex(target.target_configuration()) != rotation.target_sha256 {
                    return Err(ci::Error::Authority);
                }
                self.fs
                    .publish_subscription(
                        TARGET,
                        target.target_configuration(),
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(refused)?;
                if let Some(hash) = rotation.target_artifact_sha256 {
                    if sha256_hex(target.target_artifact()) != hash {
                        return Err(ci::Error::Authority);
                    }
                    self.fs
                        .install(Resource {
                            path: super::super::subscription::STAGING,
                            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
                        })
                        .map_err(refused)?;
                    self.fs
                        .publish_subscription(
                            ARTIFACT,
                            target.target_artifact(),
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(refused)?;
                    let serving = record.serving_authority().ok_or(ci::Error::Authority)?;
                    self.fs
                        .publish_subscription(
                            super::super::subscription::CANDIDATE_STATE,
                            &serving.state_bytes().map_err(refused)?,
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(refused)?;
                }
            }
            ci::Effect::PublishStartup => {
                self.fs
                    .install(Resource {
                        path: STARTUP_DIR,
                        kind: Kind::Directory(Mode::from_raw_mode(0o755)),
                    })
                    .map_err(refused)?;
                self.fs
                    .publish_subscription(
                        STARTUP,
                        ci::STARTUP_DROP_IN.as_bytes(),
                        Mode::from_raw_mode(0o644),
                    )
                    .map_err(refused)?;
            }
            ci::Effect::Reload => self
                .backend
                .reload_identity(&Self::context())
                .map_err(refused)?,
            ci::Effect::StopSource => {
                let gate = self.gate(g)?;
                self.backend
                    .stop_identity_source(record, &g.owner, &Self::context())
                    .map_err(refused)?;
                gate.finish().map_err(refused)?;
            }
            ci::Effect::PublishTarget => {
                let (target, _) = self
                    .fs
                    .raw(TARGET, Mode::from_raw_mode(0o600), 1 << 20)
                    .map_err(refused)?
                    .ok_or(ci::Error::Authority)?;
                if sha256_hex(&target) != rotation.target_sha256 {
                    return Err(ci::Error::Authority);
                }
                let (_, proof) = self
                    .fs
                    .raw(CONFIG, Mode::from_raw_mode(0o640), 1 << 20)
                    .map_err(refused)?
                    .ok_or(ci::Error::Authority)?;
                if self.fs.metadata(CONFIG_STAGE).map_err(refused)?.is_none() {
                    self.fs
                        .install_configuration_candidate(&target, proof.gid)
                        .map_err(refused)?;
                }
                self.fs
                    .replace_subscription(
                        CONFIG,
                        CONFIG_STAGE,
                        &target,
                        Mode::from_raw_mode(0o640),
                        &rotation.source_sha256,
                        false,
                    )
                    .map_err(refused)?;
            }
            ci::Effect::StartTarget => {
                let gate = self.gate(g)?;
                self.backend
                    .start_identity_proxy(record, &g.owner, Some(&gate), &Self::context())
                    .map_err(refused)?;
                gate.finish().map_err(refused)?;
            }
            ci::Effect::RestoreSource => {
                if self.backend.verify_identity_running(record).is_err() {
                    if matches!(runtime_handoff::cutover_configuration(record), Ok(Some(_))) {
                        let gate = self.gate(g)?;
                        self.backend
                            .start_identity_proxy(record, &g.owner, Some(&gate), &Self::context())
                            .map_err(refused)?;
                        gate.finish().map_err(refused)?;
                    } else {
                        self.backend
                            .start_identity_proxy(record, &g.owner, None, &Self::context())
                            .map_err(refused)?;
                    }
                }
            }
            ci::Effect::FinishSubscription => {
                if let Some(serving) = record.serving_authority() {
                    if !serving.is_http() {
                        return Err(ci::Error::Authority);
                    }
                    let configuration =
                        crate::server_configuration::ServerConfiguration::decode_supported(
                            &self.read_configuration()?,
                        )
                        .map_err(refused)?;
                    let artifact = configuration
                        .connection_facts(record.public_ipv4())
                        .map_err(refused)?
                        .subscription_artifact()
                        .map_err(refused)?;
                    let expected = if rotation.checkpoint.direction()
                        == crate::records::ChangeDirection::Forward
                    {
                        rotation.target_artifact_sha256.as_ref()
                    } else {
                        rotation.source_artifact_sha256.as_ref()
                    };
                    if expected.is_none_or(|hash| sha256_hex(artifact.as_bytes()) != *hash) {
                        return Err(ci::Error::Authority);
                    }
                    self.fs
                        .sync_bytes(
                            super::super::subscription::STATE,
                            &serving.state_bytes().map_err(refused)?,
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(refused)?;
                    self.backend
                        .finish_identity_subscription(record, &g.owner, &Self::context())
                        .map_err(refused)?;
                }
            }
            ci::Effect::RemoveTarget => {
                for path in [TARGET, CONFIG_STAGE] {
                    if let Some(body) = self
                        .fs
                        .publication_or_stage_bytes(
                            path,
                            Mode::from_raw_mode(if path == TARGET { 0o600 } else { 0o640 }),
                        )
                        .map_err(refused)?
                    {
                        if sha256_hex(&body) != rotation.target_sha256 {
                            return Err(ci::Error::Authority);
                        }
                        self.fs
                            .clear_subscription(
                                path,
                                &body,
                                Mode::from_raw_mode(if path == TARGET { 0o600 } else { 0o640 }),
                            )
                            .map_err(refused)?;
                    }
                }
                if let Some(hash) = rotation.target_artifact_sha256 {
                    if let Some(body) = self
                        .fs
                        .publication_or_stage_bytes(ARTIFACT, Mode::from_raw_mode(0o600))
                        .map_err(refused)?
                    {
                        if sha256_hex(&body) != hash {
                            return Err(ci::Error::Authority);
                        }
                        self.fs
                            .clear_subscription(ARTIFACT, &body, Mode::from_raw_mode(0o600))
                            .map_err(refused)?;
                    }
                    let serving = record.serving_authority().ok_or(ci::Error::Authority)?;
                    self.fs
                        .clear_subscription(
                            super::super::subscription::CANDIDATE_STATE,
                            &serving.state_bytes().map_err(refused)?,
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(refused)?;
                    if self
                        .fs
                        .directory_entries(
                            super::super::subscription::STAGING,
                            Mode::from_raw_mode(0o700),
                        )
                        .map_err(refused)?
                        .is_none_or(|names| !names.is_empty())
                    {
                        return Err(ci::Error::Authority);
                    }
                }
            }
            ci::Effect::CleanupStartup => {
                self.fs
                    .clear_subscription(
                        STARTUP,
                        ci::STARTUP_DROP_IN.as_bytes(),
                        Mode::from_raw_mode(0o644),
                    )
                    .map_err(refused)?;
                let wire: serde_json::Value =
                    serde_json::from_slice(&record.encode().map_err(refused)?).map_err(refused)?;
                if wire["proxy_startup"]["directory_created"] == true {
                    self.fs
                        .remove(Resource {
                            path: STARTUP_DIR,
                            kind: Kind::Directory(Mode::from_raw_mode(0o755)),
                        })
                        .map_err(refused)?;
                }
                self.backend
                    .reload_identity(&Self::context())
                    .map_err(refused)?;
            }
        }
        Ok(())
    }
}
