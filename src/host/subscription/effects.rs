use super::*;
impl<B: HttpRuntime> ProtectedHttpHost<'_, B> {
    fn credential_body(
        credential: &SubscriptionCredential,
        target: &ServingAuthority,
    ) -> Result<Vec<u8>, HostError> {
        if sha256_hex(credential.as_str().as_bytes()) != target.credential_sha256() {
            return Err(HostError::Foreign);
        }
        Ok(format!("{}\n", credential.as_str()).into_bytes())
    }
    fn target_credential(
        &self,
        target: &ServingAuthority,
    ) -> Result<SubscriptionCredential, HostError> {
        if let Some(credential) = self.credential_at(CANDIDATE_TOKEN, target)? {
            return Ok(credential);
        }
        self.current_credential(target)
    }
    fn stage(&self) -> Result<(), HostError> {
        self.fs.install(Resource {
            path: STAGING,
            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
        })?;
        if !self.staging_empty()? {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn candidates_clear(&self, target: &ServingAuthority) -> Result<(), HostError> {
        if let Some(credential) = self.credential_at(CANDIDATE_TOKEN, target)? {
            self.fs.clear_subscription(
                CANDIDATE_TOKEN,
                &Self::credential_body(&credential, target)?,
                Mode::from_raw_mode(0o600),
            )?;
        } else if self
            .fs
            .metadata(&format!("{CANDIDATE_TOKEN}.sbxr-next"))?
            .is_some()
        {
            let c = self
                .credential_at(&format!("{CANDIDATE_TOKEN}.sbxr-next"), target)?
                .ok_or(HostError::Foreign)?;
            self.fs.clear_subscription(
                CANDIDATE_TOKEN,
                &Self::credential_body(&c, target)?,
                Mode::from_raw_mode(0o600),
            )?;
        }
        self.fs.clear_subscription(
            CANDIDATE_STATE,
            &target.state_bytes().map_err(|_| HostError::Foreign)?,
            Mode::from_raw_mode(0o600),
        )?;
        Ok(())
    }
    fn verify(
        &self,
        record: &OwnershipRecord,
        target: &ServingAuthority,
        context: &StartContext,
    ) -> Result<(), HostError> {
        self.complete_material(target, record)?;
        if !self.staging_empty()? {
            return Err(HostError::Foreign);
        }
        let facts = self.backend.facts()?;
        if !facts.proxy_running
            || facts.public_ipv4 != record.public_ipv4()
            || !facts.serving_running
            || !material::firewall(&facts.firewall_rules, record.public_ipv4(), true)
        {
            return Err(HostError::Foreign);
        }
        let credential = self.current_credential(target)?;
        self.backend.probe(record, target, &credential, context)
    }
    pub(super) fn apply(
        &mut self,
        effect: HttpEffect,
        record: &OwnershipRecord,
        credential: Option<&SubscriptionCredential>,
        context: &StartContext,
    ) -> Result<(), HostError> {
        self.owner()?;
        self.authority(record)?;
        self.known_paths()?;
        if self
            .fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .map(|(b, _)| b)
            != Some(record.encode().map_err(|_| HostError::Foreign)?)
        {
            return Err(HostError::Foreign);
        }
        if self.fault == Some(HttpFault::Before(effect)) {
            return Err(HostError::Injected);
        }
        let op = record.http_operation().map_err(|_| HostError::Foreign)?;
        let target = Self::target(record)?;
        match effect {
            HttpEffect::Enable(checkpoint) => {
                if !matches!(op,Some(HttpOperation::Enablement{checkpoint:c,..}) if c==checkpoint) {
                    return Err(HostError::Foreign);
                }
                match checkpoint {
                    1 => {
                        let facts = self.backend.facts()?;
                        if !material::firewall(&facts.firewall_rules, record.public_ipv4(), false) {
                            return Err(HostError::Foreign);
                        }
                        self.fs.publish_subscription(
                            FIREWALL,
                            &http_firewall_unit(record.public_ipv4())?,
                            Mode::from_raw_mode(0o644),
                        )?;
                    }
                    2 | 22 => self.system(SystemEffect::Reload, record, context)?,
                    3 => {
                        self.install_link(FIREWALL_LINK, "../sbxr-subscription-firewall.service")?;
                        self.system(SystemEffect::EnableFirewall, record, context)?;
                        if !material::firewall(
                            &self.backend.facts()?.firewall_rules,
                            record.public_ipv4(),
                            true,
                        ) {
                            return Err(HostError::Foreign);
                        }
                    }
                    8 => self.stage()?,
                    9 | 11 => {
                        let body =
                            Self::credential_body(credential.ok_or(HostError::Foreign)?, &target)?;
                        self.fs.publish_subscription(
                            if checkpoint == 9 {
                                CANDIDATE_TOKEN
                            } else {
                                TOKEN
                            },
                            &body,
                            Mode::from_raw_mode(0o600),
                        )?;
                    }
                    10 | 12 => self.fs.publish_subscription(
                        if checkpoint == 10 {
                            CANDIDATE_STATE
                        } else {
                            STATE
                        },
                        &target.state_bytes().map_err(|_| HostError::Foreign)?,
                        Mode::from_raw_mode(0o600),
                    )?,
                    13 => self.fs.publish_subscription(
                        UNIT,
                        crate::runtime_handoff::SERVING_UNIT.as_bytes(),
                        Mode::from_raw_mode(0o644),
                    )?,
                    14 => {
                        let c = self.current_credential(&target)?;
                        self.fs.clear_subscription(
                            CANDIDATE_TOKEN,
                            &Self::credential_body(&c, &target)?,
                            Mode::from_raw_mode(0o600),
                        )?;
                    }
                    15 => {
                        self.fs.clear_subscription(
                            CANDIDATE_STATE,
                            &target.state_bytes().map_err(|_| HostError::Foreign)?,
                            Mode::from_raw_mode(0o600),
                        )?;
                        if !self.staging_empty()? {
                            return Err(HostError::Foreign);
                        }
                    }
                    23 => {
                        self.complete_material(&target, record)?;
                        self.install_link(LINK, "../sbxr-subscription.service")?;
                        self.system(SystemEffect::ActivateServing, record, context)?;
                    }
                    _ => return Err(HostError::Foreign),
                }
            }
            HttpEffect::PrepareRotation => {
                let Some(HttpOperation::Rotation {
                    source, checkpoint, ..
                }) = op
                else {
                    return Err(HostError::Foreign);
                };
                if checkpoint != "target authorized" {
                    return Err(HostError::Foreign);
                }
                self.complete_material(&source, record)?;
                self.stage()?;
                let body = Self::credential_body(credential.ok_or(HostError::Foreign)?, &target)?;
                self.fs
                    .publish_subscription(CANDIDATE_TOKEN, &body, Mode::from_raw_mode(0o600))?;
                self.fs.publish_subscription(
                    CANDIDATE_STATE,
                    &target.state_bytes().map_err(|_| HostError::Foreign)?,
                    Mode::from_raw_mode(0o600),
                )?;
            }
            HttpEffect::StopSource => {
                let Some(HttpOperation::Rotation {
                    source, checkpoint, ..
                }) = op
                else {
                    return Err(HostError::Foreign);
                };
                if checkpoint != "stop authorized" {
                    return Err(HostError::Foreign);
                }
                self.complete_material(&source, record)?;
                self.target_credential(&target)?;
                if self
                    .fs
                    .publication_bytes(CANDIDATE_STATE, Mode::from_raw_mode(0o600))?
                    != Some(target.state_bytes().map_err(|_| HostError::Foreign)?)
                {
                    return Err(HostError::Foreign);
                }
                self.system(SystemEffect::StopServing, record, context)?;
                let f = self.backend.facts()?;
                if !f.quiescent || f.serving_running {
                    return Err(HostError::Foreign);
                }
            }
            HttpEffect::PublishTarget => {
                let Some(HttpOperation::Rotation {
                    source,
                    checkpoint,
                    direction,
                    ..
                }) = op
                else {
                    return Err(HostError::Foreign);
                };
                if checkpoint != "committed"
                    || direction != crate::records::ChangeDirection::Forward
                {
                    return Err(HostError::Foreign);
                }
                let c = self.target_credential(&target)?;
                self.fs.replace_subscription(
                    TOKEN,
                    CANDIDATE_TOKEN,
                    &Self::credential_body(&c, &target)?,
                    Mode::from_raw_mode(0o600),
                    source.credential_sha256(),
                    true,
                )?;
                self.fs.replace_subscription(
                    STATE,
                    CANDIDATE_STATE,
                    &target.state_bytes().map_err(|_| HostError::Foreign)?,
                    Mode::from_raw_mode(0o600),
                    &sha256_hex(&source.state_bytes().map_err(|_| HostError::Foreign)?),
                    false,
                )?;
                if !self.staging_empty()? {
                    return Err(HostError::Foreign);
                }
            }
            HttpEffect::RestoreSource => {
                let Some(HttpOperation::Rotation {
                    source,
                    direction: crate::records::ChangeDirection::Cleanup,
                    ..
                }) = op
                else {
                    return Err(HostError::Foreign);
                };
                self.complete_material(&source, record)?;
                self.candidates_clear(&target)?;
                self.system(SystemEffect::ActivateServing, record, context)?;
                self.verify(record, &source, context)?;
            }
            HttpEffect::Activate => {
                self.complete_material(&target, record)?;
                self.system(SystemEffect::ActivateServing, record, context)?;
            }
            HttpEffect::Verify => self.verify(record, &target, context)?,
            HttpEffect::FinishRepairState => {
                if !matches!(op,Some(HttpOperation::Repair{checkpoint,..}) if checkpoint=="accepted")
                {
                    return Err(HostError::Foreign);
                }
                self.verify(record, &target, context)?;
                self.fs.sync_bytes(
                    STATE,
                    &target.state_bytes().map_err(|_| HostError::Foreign)?,
                    Mode::from_raw_mode(0o600),
                )?;
            }
            HttpEffect::CleanupEnable => self.cleanup_enable(record, &target, context)?,
        }
        self.owner()?;
        if self.fault == Some(HttpFault::After(effect)) {
            return Err(HostError::Injected);
        }
        Ok(())
    }
    fn cleanup_enable(
        &mut self,
        record: &OwnershipRecord,
        target: &ServingAuthority,
        context: &StartContext,
    ) -> Result<(), HostError> {
        if !matches!(
            record.http_operation(),
            Ok(Some(HttpOperation::Enablement { .. }))
        ) {
            return Err(HostError::Foreign);
        }
        let mut token = None;
        for path in [TOKEN, CANDIDATE_TOKEN] {
            for p in [path.to_owned(), format!("{path}.sbxr-next")] {
                if self.fs.metadata(&p)?.is_some() {
                    let c = if self.fs.raw(path, Mode::from_raw_mode(0o600), 4096).is_err() {
                        self.credential_at(path, target)?
                    } else {
                        self.credential_at(&p, target)?
                    }
                    .ok_or(HostError::Foreign)?;
                    token = Some(Self::credential_body(&c, target)?);
                }
            }
        }
        let state = target.state_bytes().map_err(|_| HostError::Foreign)?;
        let unit = crate::runtime_handoff::SERVING_UNIT.as_bytes();
        let firewall = http_firewall_unit(record.public_ipv4())?;
        for (path, body, mode) in [
            (TOKEN, token.as_deref().unwrap_or(&[]), 0o600),
            (CANDIDATE_TOKEN, token.as_deref().unwrap_or(&[]), 0o600),
            (STATE, state.as_slice(), 0o600),
            (CANDIDATE_STATE, state.as_slice(), 0o600),
            (UNIT, unit, 0o644),
            (FIREWALL, firewall.as_slice(), 0o644),
        ] {
            if let Some(current) = self.fs.publication_bytes(path, Mode::from_raw_mode(mode))?
                && current != body
            {
                return Err(HostError::Foreign);
            }
            let staged = format!("{path}.sbxr-next");
            if self.fs.metadata(&staged)?.is_some()
                && self
                    .fs
                    .raw(path, Mode::from_raw_mode(mode), 1 << 20)
                    .is_ok()
                && self
                    .fs
                    .raw(&staged, Mode::from_raw_mode(mode), 1 << 20)?
                    .is_none_or(|(b, _)| b != body)
            {
                return Err(HostError::Foreign);
            }
        }
        let facts = self.backend.facts()?;
        if !material::firewall(&facts.firewall_rules, record.public_ipv4(), true)
            && !material::firewall(&facts.firewall_rules, record.public_ipv4(), false)
        {
            return Err(HostError::Foreign);
        }
        if self.fs.metadata(UNIT)?.is_some() {
            self.system(SystemEffect::DisableServing, record, context)?;
        }
        let f = self.backend.facts()?;
        if !f.quiescent || f.serving_running {
            return Err(HostError::Foreign);
        }
        for (path, body, mode) in [
            (TOKEN, token.as_deref().unwrap_or(&[]), 0o600),
            (CANDIDATE_TOKEN, token.as_deref().unwrap_or(&[]), 0o600),
            (STATE, state.as_slice(), 0o600),
            (CANDIDATE_STATE, state.as_slice(), 0o600),
            (UNIT, unit, 0o644),
        ] {
            self.fs
                .clear_subscription(path, body, Mode::from_raw_mode(mode))?;
        }
        self.remove_link(LINK, "../sbxr-subscription.service")?;
        self.fs.remove(Resource {
            path: STAGING,
            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
        })?;
        if self.fs.metadata(FIREWALL)?.is_some() {
            self.system(SystemEffect::DisableFirewall, record, context)?;
        }
        self.remove_link(FIREWALL_LINK, "../sbxr-subscription-firewall.service")?;
        self.fs
            .clear_subscription(FIREWALL, &firewall, Mode::from_raw_mode(0o644))?;
        self.system(SystemEffect::Reload, record, context)?;
        if !self.inspect(record)?.absent {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
