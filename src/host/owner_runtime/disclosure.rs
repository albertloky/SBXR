//! Independent read-only proofs for confirmed disclosure; no service effect.
use super::*;
use crate::{
    disclosure as d,
    host::filesystem::{Kind, Resource},
};
impl<I: OwnerIo> OwnerRuntime<'_, I> {
    pub(in crate::host) fn disclosure_inspection(
        &self,
        r: &OwnershipRecord,
        owner: &Arc<HostLock>,
    ) -> Result<d::Inspection, HostError> {
        self.installed()?;
        owner.verify()?;
        if r.release_identity() != self.proof.record().release_identity() {
            return Err(HostError::Foreign);
        }
        let ctx = self.context();
        let group = self.text(Observation::Group, &ctx)?;
        let fields = group.split(':').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "sing-box" || !fields[3].is_empty() {
            return Err(HostError::Foreign);
        }
        let gid = fields[2].parse::<u32>().map_err(refused)?;
        // Unknown health never becomes accepted proof. A broken serving runtime
        // still permits the separately verified canonical link in View details.
        let running = self
            .disclosure_running(r, gid, owner, &ctx)
            .unwrap_or_default();
        let serving_surface_safe = if r.serving_authority().is_some() {
            self.fs
                .regular_metadata(
                    crate::host::subscription::TOKEN,
                    Mode::from_raw_mode(0o600),
                    44,
                )?
                .is_none_or(|p| p.gid == self.fs.gid)
                && self
                    .fs
                    .regular_metadata(
                        crate::host::subscription::STATE,
                        Mode::from_raw_mode(0o600),
                        crate::records::MAX_RECORD_BYTES,
                    )?
                    .is_none_or(|p| p.gid == self.fs.gid)
        } else {
            true
        };
        owner.verify()?;
        self.installed()?;
        Ok(d::Inspection {
            release: self.proof.record().release_identity(),
            configuration_gid: gid,
            running,
            serving_surface_safe,
        })
    }
    fn disclosure_running(
        &self,
        r: &OwnershipRecord,
        gid: u32,
        owner: &Arc<HostLock>,
        c: &StartContext,
    ) -> Result<d::RunningFacts, HostError> {
        let host = super::super::linux::observation::ubuntu(&self.fs)?
            && self.text(Observation::Architecture, c)? == "amd64";
        let ip = self.io.public_ipv4(c)?.to_string();
        let mut absent = true;
        for path in [
            "var/lib/sbxr/update.json",
            "var/lib/sbxr/.update.json.next",
            "var/lib/sbxr/.installed.json.prior",
            "var/lib/sbxr/.installed.json.candidate",
            "usr/local/bin/.sbxr-update-prior",
            "usr/local/bin/.sbxr-update-candidate",
            "var/lib/.sbxr-removal.json",
        ] {
            absent &= self.fs.metadata(path)?.is_none();
        }
        let (key, key_proof) = self
            .fs
            .raw(
                "etc/apt/keyrings/sagernet.asc",
                Mode::from_raw_mode(0o644),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        let apt_key = key_proof.gid == self.fs.gid
            && sha256_hex(&key) == crate::server_configuration::PINNED_SING_BOX.signing_key_sha256;
        let (source, source_proof) = self
            .fs
            .raw(
                "etc/apt/sources.list.d/sagernet.sources",
                Mode::from_raw_mode(0o644),
                4096,
            )?
            .ok_or(HostError::Foreign)?;
        let apt_source =
            source_proof.gid == self.fs.gid && source == super::super::linux::APT_SOURCE;
        let package = self.text(Observation::Package, c)? == "1.14.3 amd64 ii";
        let hold = self
            .text(Observation::Hold, c)?
            .lines()
            .filter(|l| *l == "sing-box")
            .count()
            == 1;
        let user = self.text(Observation::User, c)?;
        let fields = user.split(':').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != "sing-box" || fields[3] != gid.to_string() {
            return Err(HostError::Foreign);
        }
        let uid = fields[2].parse::<u32>().map_err(refused)?;
        let state = self
            .fs
            .observe(Resource {
                path: "var/lib/sing-box",
                kind: Kind::OwnedDirectory(Mode::from_raw_mode(0o755), uid, gid),
            })?
            .is_some();
        let (configuration, configuration_proof) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        let configuration_ok = configuration_proof.gid == gid
            && sha256_hex(&configuration) == r.configuration_sha256()
            && crate::server_configuration::ServerConfiguration::decode_supported(&configuration)
                .is_ok();
        let package_identity = uid > 0
            && self.text(Observation::UnitOwner, c)?
                == "sing-box: /usr/lib/systemd/system/sing-box.service";
        let service_provenance = self.known_unit(Unit::Proxy, c).is_ok();
        let active = self.property(Unit::Proxy, Property::ActiveState, c)? == "active";
        let enabled = self.text(Observation::Enabled, c)? == "enabled";
        let listener = self.proxy_running(r, c)?;
        let lock_provisioning = self.lock_provisioning(r)?;
        let validation = package
            && package_identity
            && configuration_ok
            && self
                .io
                .validate_configuration(owner, r.configuration_sha256(), c)?;
        let fingerprint = sha256_hex(
            format!(
                "{}:{ip}:{gid}:{uid}:{}:{}:{}:{}:{}:{}",
                r.encode().map_err(refused)?.len(),
                sha256_hex(&key),
                sha256_hex(&source),
                configuration_proof.gid,
                active,
                enabled,
                self.text(Observation::ProxyProcesses, c)?
            )
            .as_bytes(),
        );
        Ok(d::RunningFacts {
            host,
            public_ipv4_matches: ip == r.public_ipv4(),
            ownership: self.record()? == *r,
            transaction_files_absent: absent,
            apt_key,
            apt_source,
            package,
            hold,
            package_identity,
            configuration: configuration_ok,
            state,
            validation,
            service_provenance,
            lock_provisioning,
            service_enabled: enabled,
            service_active: active,
            listener,
            fingerprint,
        })
    }
    fn lock_provisioning(&self, r: &OwnershipRecord) -> Result<bool, HostError> {
        let unit = "etc/systemd/system/sbxr-mutation-lock.service";
        let link = "etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service";
        let Some(hash) = r.lock_provisioning_sha256() else {
            return Ok(self.fs.metadata(unit)?.is_none() && self.fs.metadata(link)?.is_none());
        };
        let expected = include_bytes!("../../records/lock-provision.service");
        let Some((body, proof)) = self.fs.raw(unit, Mode::from_raw_mode(0o644), 8192)? else {
            return Ok(false);
        };
        if body != expected || sha256_hex(&body) != hash || proof.gid != self.fs.gid {
            return Ok(false);
        }
        Ok(self
            .fs
            .observe(Resource {
                path: link,
                kind: Kind::Link("../sbxr-mutation-lock.service"),
            })
            .ok()
            .flatten()
            .is_some()
            || self
                .fs
                .observe(Resource {
                    path: link,
                    kind: Kind::Link("/etc/systemd/system/sbxr-mutation-lock.service"),
                })?
                .is_some())
    }
}
