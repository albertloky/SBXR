use super::renewal::*;
use super::*;
#[derive(Clone, Debug)]
pub(in crate::host) enum Asset {
    File {
        path: String,
        mode: rustix::fs::RawMode,
        hash: String,
    },
    Link {
        path: String,
        target: String,
    },
    Directory {
        path: String,
        mode: rustix::fs::RawMode,
    },
}
pub(in crate::host) struct HistoricalPlan {
    pub serving: Vec<Asset>,
    pub renewal: Vec<Asset>,
    pub resources: Vec<Asset>,
    pub retired: Vec<Asset>,
}
impl HistoricalPlan {
    pub fn fingerprint(&self) -> String {
        sha256_hex(
            format!(
                "{:?}:{:?}:{:?}:{:?}",
                self.serving, self.renewal, self.resources, self.retired
            )
            .as_bytes(),
        )
    }
}
fn collect(value: &serde_json::Value, result: &mut Vec<ServingAuthority>) -> Result<(), HostError> {
    match value {
        serde_json::Value::Object(o) => {
            if o.contains_key("certificate_generation") {
                let a = authority(value)?;
                if !a.is_http() && !result.contains(&a) {
                    result.push(a);
                }
            }
            for child in o.values() {
                collect(child, result)?;
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                collect(child, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}
impl HistoricalHttps {
    fn file_asset(
        &self,
        path: &str,
        mode: rustix::fs::RawMode,
        expected: Option<&str>,
        plan: &mut Vec<Asset>,
    ) -> Result<(), HostError> {
        if let Some(body) = self.bytes(path, mode, expected)? {
            plan.push(Asset::File {
                path: path.into(),
                mode,
                hash: sha256_hex(&body),
            });
        }
        Ok(())
    }
    fn dir_asset(
        &self,
        path: &str,
        mode: rustix::fs::RawMode,
        allowed: &[String],
        plan: &mut Vec<Asset>,
    ) -> Result<(), HostError> {
        if self
            .fs
            .metadata(path)?
            .is_some_and(|m| m.gid != self.fs.gid)
        {
            return Err(HostError::Foreign);
        }
        if let Some(entries) = self.fs.directory_entries(path, Mode::from_raw_mode(mode))? {
            if entries.iter().any(|name| !allowed.contains(name)) {
                return Err(HostError::Foreign);
            }
            plan.push(Asset::Directory {
                path: path.into(),
                mode,
            });
        }
        Ok(())
    }
    fn lineage(
        &self,
        allowed: &[ServingAuthority],
        plan: &mut Vec<Asset>,
    ) -> Result<(), HostError> {
        let maximum = allowed
            .iter()
            .map(ServingAuthority::certificate_generation)
            .max()
            .unwrap_or(1_000_000);
        let entries = self
            .fs
            .directory_entries(ARCHIVE, Mode::from_raw_mode(0o700))?
            .unwrap_or_default();
        let live = self
            .fs
            .directory_entries(LIVE, Mode::from_raw_mode(0o700))?
            .unwrap_or_default();
        for name in &live {
            if name == "README" {
                let body = self
                    .bytes(
                        &format!("{LIVE}/README"),
                        0o644,
                        Some("7e519cf3c13ff96c0a8e35e6f25fd43cc3c396f7b5c4393bd26ab072dd25c1fa"),
                    )
                    .or_else(|_| {
                        self.bytes(
                            &format!("{LIVE}/README"),
                            0o600,
                            Some(
                                "7e519cf3c13ff96c0a8e35e6f25fd43cc3c396f7b5c4393bd26ab072dd25c1fa",
                            ),
                        )
                    })?
                    .ok_or(HostError::Foreign)?;
                let mode = self
                    .fs
                    .historical_configuration(&format!("{LIVE}/README"))?
                    .ok_or(HostError::Foreign)?
                    .1
                    .as_raw_mode();
                plan.push(Asset::File {
                    path: format!("{LIVE}/README"),
                    mode,
                    hash: sha256_hex(&body),
                });
                continue;
            }
            let index = NAMES
                .iter()
                .position(|part| name == &format!("{part}.pem"))
                .ok_or(HostError::Foreign)?;
            let path = format!("{LIVE}/{name}");
            let target = self.fs.historical_link(&path)?.ok_or(HostError::Foreign)?;
            let basename = target
                .strip_prefix("../../archive/sbxr-subscription/")
                .ok_or(HostError::Foreign)?;
            let (part, generation) =
                certificates::generation(basename).ok_or(HostError::Foreign)?;
            if part != index || generation > maximum || !entries.contains(&basename.to_string()) {
                return Err(HostError::Foreign);
            }
            plan.push(Asset::Link { path, target });
        }
        for name in &entries {
            let (index, generation) = certificates::generation(name).ok_or(HostError::Foreign)?;
            if generation > maximum {
                return Err(HostError::Foreign);
            }
            let hashes: Vec<_> = allowed
                .iter()
                .filter(|a| a.certificate_generation() == generation)
                .map(|a| &a.certificate_sha256()[index])
                .collect();
            if hashes.windows(2).any(|h| h[0] != h[1]) {
                return Err(HostError::Foreign);
            }
            self.file_asset(
                &format!("{ARCHIVE}/{name}"),
                if index == 3 { 0o600 } else { 0o644 },
                hashes.first().map(|h| h.as_str()),
                plan,
            )?;
        }
        self.dir_asset(LIVE, 0o700, &live, plan)?;
        self.dir_asset(ARCHIVE, 0o700, &entries, plan)
    }
    fn configuration_asset(&self, plan: &mut Vec<Asset>) -> Result<(), HostError> {
        if let Some((body, mode)) = self.fs.historical_configuration(RENEWAL_CONFIG)? {
            let text = std::str::from_utf8(&body).map_err(|_| HostError::Foreign)?;
            if !text.contains("archive_dir = /etc/letsencrypt/archive/sbxr-subscription")
                || !text.contains("cert = /etc/letsencrypt/live/sbxr-subscription/cert.pem")
            {
                return Err(HostError::Foreign);
            }
            plan.push(Asset::File {
                path: RENEWAL_CONFIG.into(),
                mode: mode.as_raw_mode(),
                hash: sha256_hex(&body),
            });
        }
        Ok(())
    }
    pub(in crate::host) fn plan(
        &self,
        record: &OwnershipRecord,
    ) -> Result<HistoricalPlan, HostError> {
        let value = record_value(record)?;
        if value["subscription_transport_migration"] == true {
            return Err(HostError::LiveUnavailable);
        }
        let mut plan = HistoricalPlan {
            serving: Vec::new(),
            renewal: Vec::new(),
            resources: Vec::new(),
            retired: Vec::new(),
        };
        let mut active = Vec::new();
        let mut without_retired = value.clone();
        without_retired
            .as_object_mut()
            .ok_or(HostError::Foreign)?
            .remove("https_retirement");
        collect(&without_retired, &mut active)?;
        let legacy_resources = value
            .get("subscription_resources")
            .or_else(|| {
                value
                    .get("subscription_enablement")
                    .and_then(|e| e.get("resources"))
            })
            .filter(|r| r["http"] != true);
        if !active.is_empty() || legacy_resources.is_some() {
            self.lineage(&active, &mut plan.serving)?;
            self.configuration_asset(&mut plan.resources)?;
        }
        if let Some(renewal) = value.get("renewal").or_else(|| {
            value
                .get("subscription_enablement")
                .and_then(|e| e.get("renewal"))
        }) {
            if self.fs.metadata(NEXT)?.is_some() {
                return Err(HostError::Foreign);
            }
            for (path, mode, body) in MANAGED {
                self.file_asset(path, mode, Some(&sha256_hex(body)), &mut plan.renewal)?;
            }
            let entries_present = MANAGED
                .into_iter()
                .take(3)
                .any(|(path, _, _)| self.fs.metadata(path).is_ok_and(|m| m.is_some()));
            if entries_present && self.fs.metadata(EVIDENCE)?.is_none() {
                return Err(HostError::Foreign);
            }
            if let Some(body) = self.bytes(EVIDENCE, 0o600, None)? {
                self.validate_evidence(&body, renewal)?;
                plan.renewal.push(Asset::File {
                    path: EVIDENCE.into(),
                    mode: 0o600,
                    hash: sha256_hex(&body),
                });
            }
        }
        if let Some(retired) = value.get("https_retirement") {
            for (path, _, _) in MANAGED.into_iter().take(3) {
                if self.fs.metadata(path)?.is_some() {
                    return Err(HostError::Foreign);
                }
            }
            if self.fs.metadata(RENEWAL_CONFIG)?.is_some() || self.fs.metadata(NEXT)?.is_some() {
                return Err(HostError::Foreign);
            }
            let serving = authority(&retired["serving"])?;
            self.lineage(&[serving], &mut plan.retired)?;
            let names =
                ["renewal.conf", "recorder.conf", "deploy-hook", "post-hook"].map(str::to_owned);
            let mode = retired["configuration_mode"]
                .as_u64()
                .and_then(|n| rustix::fs::RawMode::try_from(n).ok())
                .ok_or(HostError::Foreign)?;
            let hash = retired["configuration_sha256"]
                .as_str()
                .ok_or(HostError::Foreign)?;
            self.file_asset(
                &format!("{RETIRED}/renewal.conf"),
                mode,
                Some(hash),
                &mut plan.retired,
            )?;
            for ((_, mode, body), name) in MANAGED.into_iter().take(3).zip(names.iter().skip(1)) {
                self.file_asset(
                    &format!("{RETIRED}/{name}"),
                    mode,
                    Some(&sha256_hex(body)),
                    &mut plan.retired,
                )?;
            }
            self.file_asset(
                EVIDENCE,
                0o600,
                Some(
                    retired["evidence_sha256"]
                        .as_str()
                        .ok_or(HostError::Foreign)?,
                ),
                &mut plan.retired,
            )?;
            for (path, mode, body) in MANAGED.into_iter().skip(3) {
                self.file_asset(path, mode, Some(&sha256_hex(body)), &mut plan.retired)?;
            }
            self.dir_asset(RETIRED, 0o700, &names, &mut plan.retired)?;
            if retired["resources"]["recorder_directory_created"] == true {
                self.dir_asset(
                    "etc/systemd/system/snap.certbot.renew.service.d",
                    0o755,
                    &[],
                    &mut plan.retired,
                )?;
            }
        }
        if let Some(resources) = legacy_resources
            && resources["recorder_directory_created"] == true
        {
            self.dir_asset(
                "etc/systemd/system/snap.certbot.renew.service.d",
                0o755,
                &["50-sbxr-recorder.conf".into()],
                &mut plan.resources,
            )?;
        }
        if active.is_empty()
            && legacy_resources.is_none()
            && value.get("https_retirement").is_none()
        {
            for path in [
                ARCHIVE,
                LIVE,
                RENEWAL_CONFIG,
                RETIRED,
                EVIDENCE,
                NEXT,
                ADMISSION,
                WRITER,
                DROPIN,
                DEPLOY,
                POST,
            ] {
                if self.fs.metadata(path)?.is_some() {
                    return Err(HostError::Foreign);
                }
            }
        }
        Ok(plan)
    }
    pub(in crate::host) fn remove_assets(
        &mut self,
        owner: &Arc<HostLock>,
        assets: &[Asset],
    ) -> Result<(), HostError> {
        self.scoped(owner, |this| {
            for asset in assets {
                match asset {
                    Asset::File { path, mode, hash } => {
                        if let Some(body) = this.bytes(path, *mode, Some(hash))? {
                            this.fs
                                .remove_bytes(path, &body, Mode::from_raw_mode(*mode))?;
                        }
                    }
                    Asset::Link { path, target } => this.fs.remove_historical_link(path, target)?,
                    Asset::Directory { path, mode } => {
                        this.fs
                            .remove_historical_directory(path, Mode::from_raw_mode(*mode))?;
                    }
                }
            }
            Ok(())
        })
    }
}
