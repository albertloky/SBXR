use super::*;
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
    sign::CertifiedKey,
};
use std::time::SystemTime;
use zeroize::Zeroizing;
pub struct CertificateTrust {
    roots: Arc<RootCertStore>,
    now: UnixTime,
    native: bool,
}
impl CertificateTrust {
    pub fn public_roots() -> Self {
        Self {
            roots: Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }),
            native: true,
            now: UnixTime::since_unix_epoch(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
        }
    }
    #[cfg(test)]
    pub(super) fn fixture_for_test_time(mut trust: Self, seconds: u64) -> Self {
        assert!(!trust.native);
        trust.now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds));
        trust
    }
    /// Explicit roots/time are fixture inputs; native recovery uses public_roots.
    pub fn fixture(roots: RootCertStore, now: UnixTime) -> Self {
        Self {
            roots: Arc::new(roots),
            now,
            native: false,
        }
    }
}
pub struct SelectedCertificate {
    authority: ServingAuthority,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: Zeroizing<Vec<u8>>,
    root: std::path::PathBuf,
    native: bool,
    ipv4: String,
}
impl std::fmt::Debug for SelectedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verified historical HTTPS certificate (redacted)")
    }
}
impl SelectedCertificate {
    #[cfg(test)]
    pub(super) fn publication_fixture(mut self, ipv4: &str) -> Self {
        // Filesystem/CAS tests use the existing loopback PEM. This changes only
        // its fixture address after the crypto selector was tested separately;
        // this helper is absent from production and cannot authorize native I/O.
        assert!(!self.native && self.root != Path::new("/"));
        self.ipv4 = ipv4.into();
        self
    }
    pub fn authority(&self) -> &ServingAuthority {
        &self.authority
    }
}
pub(super) fn generation(name: &str) -> Option<(usize, u32)> {
    NAMES.iter().enumerate().find_map(|(index, prefix)| {
        let digits = name.strip_prefix(prefix)?.strip_suffix(".pem")?;
        let value = digits.parse::<u32>().ok()?;
        (value > 0 && value <= 1_000_000 && digits == value.to_string()).then_some((index, value))
    })
}
impl HistoricalHttps {
    pub(super) fn certificate_parts(
        &self,
        authority: &ServingAuthority,
        missing: bool,
    ) -> Result<[Option<Vec<u8>>; 4], HostError> {
        if authority.is_http() {
            return Err(HostError::Foreign);
        }
        let mut result: [Option<Vec<u8>>; 4] = Default::default();
        for (index, name) in NAMES.iter().enumerate() {
            result[index] = self.bytes(
                &format!("{ARCHIVE}/{name}{}.pem", authority.certificate_generation()),
                if index == 3 { 0o600 } else { 0o644 },
                Some(&authority.certificate_sha256()[index]),
            )?;
            if !missing && result[index].is_none() {
                return Err(HostError::Foreign);
            }
        }
        Ok(result)
    }
    /// Select the four currently published links only after exact trust/key/IP checks.
    /// No journal is changed and no certificate/credential is generated.
    pub fn select_published(
        &self,
        accepted: &ServingAuthority,
        ipv4: &str,
        trust: &CertificateTrust,
    ) -> Result<SelectedCertificate, HostError> {
        if self.fs.path() == Path::new("/") && !trust.native {
            return Err(HostError::Foreign);
        }
        if accepted.is_http() {
            return Err(HostError::Foreign);
        }
        let mut selected = 0;
        let mut hashes: [String; 4] = Default::default();
        let mut parts: [Vec<u8>; 4] = Default::default();
        for (index, name) in NAMES.iter().enumerate() {
            let link = self
                .fs
                .historical_link(&format!("{LIVE}/{name}.pem"))?
                .ok_or(HostError::Foreign)?;
            let prefix = format!("../../archive/sbxr-subscription/{name}");
            let value = link
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(".pem"))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(HostError::Foreign)?;
            if value == 0
                || value > 1_000_000
                || link != format!("{prefix}{value}.pem")
                || (selected != 0 && selected != value)
            {
                return Err(HostError::Foreign);
            }
            selected = value;
            parts[index] = self
                .bytes(
                    &format!("{ARCHIVE}/{name}{value}.pem"),
                    if index == 3 { 0o600 } else { 0o644 },
                    None,
                )?
                .ok_or(HostError::Foreign)?;
            hashes[index] = sha256_hex(&parts[index]);
        }
        let target = ServingAuthority::https_digest(
            accepted.link_id(),
            accepted.credential_sha256(),
            selected,
            hashes,
        )
        .map_err(|_| HostError::Foreign)?;
        if selected < accepted.certificate_generation()
            || selected == accepted.certificate_generation() && target != *accepted
            || parts[2] != [parts[0].as_slice(), parts[1].as_slice()].concat()
        {
            return Err(HostError::Foreign);
        }
        let chain: Vec<_> = rustls_pemfile::certs(&mut std::io::Cursor::new(&parts[2]))
            .collect::<Result<_, _>>()
            .map_err(|_| HostError::Foreign)?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&parts[3]))
            .map_err(|_| HostError::Foreign)?
            .ok_or(HostError::Foreign)?;
        let signing =
            rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| HostError::Foreign)?;
        let certified = CertifiedKey::new(chain.clone(), signing);
        certified.keys_match().map_err(|_| HostError::Foreign)?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            trust.roots.clone(),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| HostError::Foreign)?;
        let name = ServerName::IpAddress(
            ipv4.parse::<std::net::IpAddr>()
                .map_err(|_| HostError::Foreign)?
                .into(),
        );
        verifier
            .verify_server_cert(
                chain.first().ok_or(HostError::Foreign)?,
                &chain[1..],
                &name,
                &[],
                trust.now,
            )
            .map_err(|_| HostError::Foreign)?;
        Ok(SelectedCertificate {
            authority: target,
            chain,
            key: Zeroizing::new(parts[3].clone()),
            root: self.fs.path().into(),
            native: trust.native,
            ipv4: ipv4.into(),
        })
    }
    pub fn inspect_serving_state(
        &self,
        target: &ServingAuthority,
    ) -> Result<ServingAuthority, HostError> {
        let bytes = self
            .bytes("var/lib/sbxr/subscription-serving.json", 0o600, None)?
            .ok_or(HostError::Foreign)?;
        let source = ServingAuthority::decode_state(&bytes).map_err(|_| HostError::Foreign)?;
        if source.is_http()
            || target.is_http()
            || source.link_id() != target.link_id()
            || source.credential_sha256() != target.credential_sha256()
            || source.certificate_generation() > target.certificate_generation()
            || source.certificate_generation() == target.certificate_generation()
                && source != *target
        {
            return Err(HostError::Foreign);
        }
        self.certificate_parts(&source, false)?;
        self.certificate_parts(target, false)?;
        Ok(source)
    }
    /// Explicit recovery publication for already recorded source/target only.
    /// The selected target is cryptographically verified against current links.
    pub fn publish_serving_state(
        &mut self,
        owner: &Arc<HostLock>,
        record: &OwnershipRecord,
        selected: &SelectedCertificate,
    ) -> Result<(), HostError> {
        let value = record_value(record)?;
        let activation = value
            .get("certificate_activation")
            .or_else(|| value.get("subscription_repair"))
            .ok_or(HostError::Foreign)?;
        let source = authority(&activation["source"])?;
        let target = authority(&activation["target"])?;
        if selected.ipv4 != record.public_ipv4()
            || selected.root != self.fs.path()
            || self.fs.path() == Path::new("/") && !selected.native
            || target != selected.authority
            || selected.chain.is_empty()
            || selected.key.is_empty()
        {
            return Err(HostError::Foreign);
        }
        if self.fs.path() == Path::new("/")
            && self
                .select_published(
                    &target,
                    record.public_ipv4(),
                    &CertificateTrust::public_roots(),
                )?
                .authority
                != target
        {
            return Err(HostError::Foreign);
        }
        let current = self
            .fs
            .raw(
                "var/lib/sbxr/proxy-ownership.json",
                Mode::from_raw_mode(0o600),
                crate::records::MAX_RECORD_BYTES,
            )?
            .ok_or(HostError::Foreign)?
            .0;
        if OwnershipRecord::decode(&current).map_err(|_| HostError::Foreign)? != *record {
            return Err(HostError::Foreign);
        }
        for name in NAMES {
            if self
                .fs
                .historical_link(&format!("{LIVE}/{name}.pem"))?
                .as_deref()
                != Some(
                    format!(
                        "../../archive/sbxr-subscription/{name}{}.pem",
                        target.certificate_generation()
                    )
                    .as_str(),
                )
            {
                return Err(HostError::Foreign);
            }
        }
        let directory = "var/lib/sbxr/subscription-staging";
        let meta = self.fs.metadata(directory)?.ok_or(HostError::Foreign)?;
        if meta.gid != self.fs.gid
            || self
                .fs
                .directory_entries(directory, Mode::from_raw_mode(0o700))?
                .ok_or(HostError::Foreign)?
                .iter()
                .any(|n| !["serving.json", "serving.json.sbxr-next"].contains(&n.as_str()))
            || self
                .fs
                .metadata("var/lib/sbxr/subscription-serving.json.sbxr-next")?
                .is_some()
        {
            return Err(HostError::Foreign);
        }
        let stored = self.inspect_serving_state(&target)?;
        if stored != source && stored != target {
            return Err(HostError::Foreign);
        }
        self.scoped(owner, |this| {
            let bytes = target.state_bytes().map_err(|_| HostError::Foreign)?;
            if stored == target {
                this.fs.sync_bytes(
                    "var/lib/sbxr/subscription-serving.json",
                    &bytes,
                    Mode::from_raw_mode(0o600),
                )?;
                this.fs.clear_subscription(
                    "var/lib/sbxr/subscription-staging/serving.json",
                    &bytes,
                    Mode::from_raw_mode(0o600),
                )?;
            } else {
                this.fs.publish_subscription(
                    "var/lib/sbxr/subscription-staging/serving.json",
                    &bytes,
                    Mode::from_raw_mode(0o600),
                )?;
                #[cfg(test)]
                if this.publication_fault == Some(1) {
                    return Err(HostError::Injected);
                }
                this.fs.replace_subscription(
                    "var/lib/sbxr/subscription-serving.json",
                    "var/lib/sbxr/subscription-staging/serving.json",
                    &bytes,
                    Mode::from_raw_mode(0o600),
                    &sha256_hex(&source.state_bytes().map_err(|_| HostError::Foreign)?),
                    false,
                )?;
            }
            #[cfg(test)]
            if this.publication_fault == Some(2) {
                return Err(HostError::Injected);
            }
            // Also repeat this fsync when a previous rename removed the last
            // candidate but its staging-directory durability was uncertain.
            this.fs.sync_restoration_directory(
                "var/lib/sbxr/subscription-staging",
                Mode::from_raw_mode(0o700),
            )?;
            this.fs.sync_bytes(
                "var/lib/sbxr/proxy-ownership.json",
                &current,
                Mode::from_raw_mode(0o600),
            )?;
            Ok(())
        })
    }
}
