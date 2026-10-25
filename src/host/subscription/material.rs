use super::*;
pub fn http_firewall_unit(ipv4: &str) -> Result<Vec<u8>, HostError> {
    if !crate::records::ownership_public_ipv4(ipv4) {
        return Err(HostError::Foreign);
    }
    let rule = format!(
        "-d {ipv4}/32 -p tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT"
    );
    Ok(format!("[Unit]\nDescription=SBXR Subscription Firewall\nBefore=sbxr-subscription.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -ec '/usr/sbin/iptables -w -C INPUT {rule} || /usr/sbin/iptables -w -I INPUT 1 {rule}'\nExecStop=/bin/sh -ec 'while /usr/sbin/iptables -w -C INPUT {rule}; do /usr/sbin/iptables -w -D INPUT {rule}; done'\n\n[Install]\nWantedBy=multi-user.target\n").into_bytes())
}
pub(super) fn rule(ipv4: &str) -> String {
    format!(
        "-A INPUT -d {ipv4}/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT"
    )
}
pub(in crate::host) fn firewall(body: &str, ip: &str, present: bool) -> bool {
    body.len() <= 1 << 20
        && body.contains("*filter\n")
        && body.lines().any(|l| l.starts_with(":INPUT "))
        && body.lines().any(|l| l == "COMMIT")
        && if present {
            body.lines().filter(|l| *l == rule(ip)).count() == 1
                && body.matches("--comment sbxr-subscription").count() == 1
        } else {
            !body.contains("sbxr-subscription")
        }
}
pub(in crate::host) fn normalized_rules(body: &str) -> String {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            if line.starts_with(':')
                && let Some((prefix, counter)) = line.split_once('[')
                && let Some(counter) = counter.strip_suffix(']')
                && let Some((a, b)) = counter.split_once(':')
                && !a.is_empty()
                && !b.is_empty()
                && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
            {
                return format!("{prefix}[0:0]");
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
impl<B: HttpRuntime> ProtectedHttpHost<'_, B> {
    pub(super) fn credential_at(
        &self,
        path: &str,
        authority: &ServingAuthority,
    ) -> Result<Option<SubscriptionCredential>, HostError> {
        let Some(bytes) = self
            .fs
            .publication_bytes(path, Mode::from_raw_mode(0o600))?
        else {
            return Ok(None);
        };
        if bytes.len() != 44
            || bytes[43] != b'\n'
            || sha256_hex(&bytes[..43]) != authority.credential_sha256()
        {
            return Err(HostError::Foreign);
        }
        SubscriptionCredential::parse(
            std::str::from_utf8(&bytes[..43]).map_err(|_| HostError::Foreign)?,
        )
        .map(Some)
        .map_err(|_| HostError::Foreign)
    }
    pub(super) fn target(record: &OwnershipRecord) -> Result<ServingAuthority, HostError> {
        match record.http_operation().map_err(|_| HostError::Foreign)? {
            Some(
                HttpOperation::Enablement { target, .. } | HttpOperation::Rotation { target, .. },
            ) => Ok(target),
            Some(HttpOperation::Repair { source, target, .. }) => Ok(target.unwrap_or(source)),
            None => record.serving_authority().ok_or(HostError::Foreign),
        }
    }
    pub(super) fn complete_material(
        &self,
        authority: &ServingAuthority,
        record: &OwnershipRecord,
    ) -> Result<(), HostError> {
        self.credential_at(TOKEN, authority)?
            .ok_or(HostError::Foreign)?;
        for (path, body, mode) in [
            (
                STATE,
                authority.state_bytes().map_err(|_| HostError::Foreign)?,
                0o600,
            ),
            (
                UNIT,
                crate::runtime_handoff::SERVING_UNIT.as_bytes().to_vec(),
                0o644,
            ),
            (FIREWALL, http_firewall_unit(record.public_ipv4())?, 0o644),
        ] {
            if self
                .fs
                .publication_bytes(path, Mode::from_raw_mode(mode))?
                .as_deref()
                != Some(body.as_slice())
            {
                return Err(HostError::Foreign);
            }
        }
        if self.fs.metadata(LINK)?.is_some() {
            self.link_owned(LINK, "../sbxr-subscription.service")?;
        } else if !matches!(
            record.http_operation(),
            Ok(Some(HttpOperation::Enablement { .. }))
        ) {
            return Err(HostError::Foreign);
        }
        self.link_owned(FIREWALL_LINK, "../sbxr-subscription-firewall.service")?;
        Ok(())
    }
    pub(super) fn link_resource(
        &self,
        path: &'static str,
        target: &'static str,
    ) -> Result<Resource, HostError> {
        let relative = Resource {
            path,
            kind: Kind::Link(target),
        };
        if self.fs.metadata(path)?.is_none() || self.fs.observe(relative).ok().flatten().is_some() {
            return Ok(relative);
        }
        let absolute = match path {
            LINK => UNIT,
            FIREWALL_LINK => FIREWALL,
            _ => return Err(HostError::Foreign),
        };
        let resource = Resource {
            path,
            kind: Kind::Link(match absolute {
                UNIT => "/etc/systemd/system/sbxr-subscription.service",
                FIREWALL => "/etc/systemd/system/sbxr-subscription-firewall.service",
                _ => unreachable!(),
            }),
        };
        self.fs.observe(resource)?.ok_or(HostError::Foreign)?;
        Ok(resource)
    }
    pub(super) fn link_owned(
        &self,
        path: &'static str,
        target: &'static str,
    ) -> Result<(), HostError> {
        let resource = self.link_resource(path, target)?;
        self.fs.observe(resource)?.ok_or(HostError::Foreign)?;
        Ok(())
    }
    pub(super) fn install_link(
        &self,
        path: &'static str,
        target: &'static str,
    ) -> Result<(), HostError> {
        self.fs.install(self.link_resource(path, target)?)
    }
    pub(super) fn remove_link(
        &self,
        path: &'static str,
        target: &'static str,
    ) -> Result<(), HostError> {
        self.fs.remove(self.link_resource(path, target)?)
    }
    pub(super) fn staging_empty(&self) -> Result<bool, HostError> {
        Ok(self
            .fs
            .directory_entries(STAGING, Mode::from_raw_mode(0o700))?
            .is_some_and(|v| v.is_empty()))
    }
    pub(super) fn current_credential(
        &self,
        authority: &ServingAuthority,
    ) -> Result<SubscriptionCredential, HostError> {
        self.credential_at(TOKEN, authority)?
            .ok_or(HostError::Foreign)
    }
    pub(super) fn known_paths(&self) -> Result<(), HostError> {
        let names = self
            .fs
            .directory_entries("var/lib/sbxr", Mode::from_raw_mode(0o700))?
            .ok_or(HostError::Foreign)?;
        if names.iter().any(|name| {
            !matches!(
                name.as_str(),
                "installed.json"
                    | "proxy-ownership.json"
                    | ".proxy-ownership.json.next"
                    | "subscription-token"
                    | "subscription-token.sbxr-next"
                    | "subscription-serving.json"
                    | "subscription-serving.json.sbxr-next"
                    | "subscription-staging"
            )
        }) {
            return Err(HostError::Foreign);
        }
        for path in [
            "etc/systemd/system/service.d",
            "usr/lib/systemd/system/service.d",
        ] {
            if self.fs.metadata(path)?.is_some() {
                return Err(HostError::Foreign);
            }
        }
        for unit in [
            "sbxr-subscription.service",
            "sbxr-subscription-firewall.service",
        ] {
            for directory in [
                "etc/systemd/system",
                "run/systemd/system",
                "usr/local/lib/systemd/system",
                "usr/lib/systemd/system",
                "lib/systemd/system",
                "etc/systemd/system.control",
                "run/systemd/system.control",
                "run/systemd/transient",
            ] {
                for suffix in [
                    unit.to_owned(),
                    format!("{unit}.d"),
                    format!("multi-user.target.wants/{unit}"),
                    format!("multi-user.target.requires/{unit}"),
                ] {
                    let path = format!("{directory}/{suffix}");
                    if [UNIT, LINK, FIREWALL, FIREWALL_LINK].contains(&path.as_str()) {
                        continue;
                    }
                    if self.fs.metadata(&path)?.is_some() {
                        return Err(HostError::Foreign);
                    }
                }
            }
        }
        if let Some(names) = self
            .fs
            .directory_entries(STAGING, Mode::from_raw_mode(0o700))?
            && names.iter().any(|n| {
                !matches!(
                    n.as_str(),
                    "credential"
                        | "serving.json"
                        | "credential.sbxr-next"
                        | "serving.json.sbxr-next"
                )
            })
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
}
impl<B: HttpRuntime> SubscriptionHost for ProtectedHttpHost<'_, B> {
    fn root(&self) -> &Path {
        self.fs.path()
    }
    fn uid(&self) -> u32 {
        self.fs.uid
    }
    fn inspect(&self, record: &OwnershipRecord) -> Result<HttpObservation, HostError> {
        self.authority(record)?;
        self.known_paths()?;
        let facts = self.backend.facts()?;
        let mut fingerprint = format!(
            "{}:{}:{}:{}:{}",
            facts.public_ipv4,
            facts.proxy_running,
            normalized_rules(&facts.firewall_rules),
            facts.serving_running,
            facts.quiescent
        );
        let mut absent = true;
        for (path, mode) in [
            (TOKEN, 0o600),
            (STATE, 0o600),
            (UNIT, 0o644),
            (FIREWALL, 0o644),
            (CANDIDATE_TOKEN, 0o600),
            (CANDIDATE_STATE, 0o600),
        ] {
            if let Some(body) = self.fs.publication_bytes(path, Mode::from_raw_mode(mode))? {
                absent = false;
                fingerprint.push_str(&sha256_hex(&body));
            }
            let staged = format!("{path}.sbxr-next");
            if self.fs.metadata(&staged)?.is_some() {
                absent = false;
                fingerprint.push_str(&staged);
                if self
                    .fs
                    .raw(path, Mode::from_raw_mode(mode), 1 << 20)
                    .is_ok()
                {
                    let (body, _) = self
                        .fs
                        .raw(&staged, Mode::from_raw_mode(mode), 1 << 20)?
                        .ok_or(HostError::Foreign)?;
                    fingerprint.push_str(&sha256_hex(&body));
                }
            }
        }
        for (path, target) in [
            (LINK, "../sbxr-subscription.service"),
            (FIREWALL_LINK, "../sbxr-subscription-firewall.service"),
        ] {
            if self.fs.metadata(path)?.is_some() {
                absent = false;
                self.link_owned(path, target)?;
                fingerprint.push_str(path);
            }
        }
        if self.fs.metadata(STAGING)?.is_some() {
            absent = false;
        }
        let material = record
            .serving_authority()
            .is_some_and(|a| self.complete_material(&a, record).is_ok());
        let serving = material
            && facts.serving_running
            && record.serving_authority().is_some_and(|authority| {
                self.current_credential(&authority).is_ok_and(|credential| {
                    self.backend
                        .probe(
                            record,
                            &authority,
                            &credential,
                            &StartContext::new(
                                crate::subscription_serving::Cancellation::new(),
                                std::time::Instant::now() + std::time::Duration::from_secs(3),
                            ),
                        )
                        .is_ok()
                })
            });
        Ok(HttpObservation {
            fingerprint: sha256_hex(fingerprint.as_bytes()),
            absent: absent
                && facts.quiescent
                && !facts.serving_running
                && firewall(&facts.firewall_rules, record.public_ipv4(), false),
            material: material && firewall(&facts.firewall_rules, record.public_ipv4(), true),
            serving,
            proxy: facts.proxy_running,
            public_ipv4: facts.public_ipv4,
        })
    }
    fn begin_change(&mut self) -> Result<(), HostError> {
        if self.owner.is_some() {
            return Err(HostError::Busy);
        }
        let owner = Arc::new(HostLock::existing(self.fs.path(), self.fs.uid)?);
        if self.fs.path() == Path::new("/") {
            self.fs.authorize_native_writes(Some(owner.clone()))?;
        }
        self.owner = Some(owner);
        Ok(())
    }
    fn end_change(&mut self) {
        if self.fs.path() == Path::new("/") {
            let _ = self.fs.authorize_native_writes(None);
        }
        self.owner = None;
    }
    fn effect(
        &mut self,
        effect: HttpEffect,
        record: &OwnershipRecord,
        credential: Option<&SubscriptionCredential>,
        context: &StartContext,
    ) -> Result<(), HostError> {
        self.apply(effect, record, credential, context)
    }
    fn link(&self, record: &OwnershipRecord) -> Result<HttpSubscriptionLink, HostError> {
        let authority = record.serving_authority().ok_or(HostError::Foreign)?;
        self.complete_material(&authority, record)?;
        let credential = self.current_credential(&authority)?;
        HttpSubscriptionLink::new(record.public_ipv4(), &credential).map_err(|_| HostError::Foreign)
    }
}
