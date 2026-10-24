//! Go-compatible fixed publication recovery. The ordinary raw-file reader still
//! rejects every hardlink. Only an exact canonical/staged two-link pair with
//! matching metadata and bytes can recover a known publication.
use super::*;
impl ProtectedFs {
    pub(in crate::host) fn install_configuration_candidate(
        &self,
        body: &[u8],
        gid: u32,
    ) -> Result<(), HostError> {
        self.install_bytes_group(
            "etc/sing-box/.config.json.sbxr-next",
            body,
            Mode::from_raw_mode(0o640),
            gid,
        )
    }
    pub(in crate::host) fn publication_bytes(
        &self,
        path: &str,
        mode: Mode,
    ) -> Result<Option<Vec<u8>>, HostError> {
        match self.raw(path, mode, 1 << 20) {
            Ok(value) => Ok(value.map(|(b, _)| b)),
            Err(_) => {
                let stage = format!("{path}.sbxr-next");
                let (body, proof) = self
                    .raw_with_links(path, mode, 1 << 20, 2)?
                    .ok_or(HostError::Foreign)?;
                let (other, other_proof) = self
                    .raw_with_links(&stage, mode, 1 << 20, 2)?
                    .ok_or(HostError::Foreign)?;
                if body != other || proof != other_proof {
                    return Err(HostError::Foreign);
                }
                Ok(Some(body))
            }
        }
    }
    pub(in crate::host) fn publication_or_stage_bytes(
        &self,
        path: &str,
        mode: Mode,
    ) -> Result<Option<Vec<u8>>, HostError> {
        let canonical = self.publication_bytes(path, mode)?;
        let stage = format!("{path}.sbxr-next");
        if self.metadata(&stage)?.is_none() {
            return Ok(canonical);
        }
        match self.raw(&stage, mode, 1 << 20) {
            Ok(Some((body, _))) => {
                if canonical.as_ref().is_some_and(|current| current != &body) {
                    return Err(HostError::Foreign);
                }
                Ok(canonical.or(Some(body)))
            }
            // publication_bytes already proved the exact canonical/staged pair.
            Err(_)
                if canonical.is_some() && self.raw_with_links(path, mode, 1 << 20, 2).is_ok() =>
            {
                Ok(canonical)
            }
            _ => Err(HostError::Foreign),
        }
    }
    fn clear_publication_stage(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let stage = format!("{path}.sbxr-next");
        if self.metadata(&stage)?.is_none() {
            return Ok(());
        }
        if self.raw(path, mode, 1 << 20).is_err() {
            let (actual, proof) = self
                .raw_with_links(path, mode, 1 << 20, 2)?
                .ok_or(HostError::Foreign)?;
            let (staged, staged_proof) = self
                .raw_with_links(&stage, mode, 1 << 20, 2)?
                .ok_or(HostError::Foreign)?;
            if actual != body || staged != body || proof != staged_proof {
                return Err(HostError::Foreign);
            }
            let (parent, name) = self.parent(&stage, false)?.ok_or(HostError::Unsafe)?;
            if self.raw_with_links(path, mode, 1 << 20, 2)?.map(|(_, p)| p) != Some(proof) {
                return Err(HostError::Unsafe);
            }
            fs::unlinkat(&parent, name.as_str(), AtFlags::empty()).map_err(failure)?;
            fs::fsync(parent).map_err(failure)?;
            self.sync_bytes(path, body, mode)
        } else {
            self.remove_bytes(&stage, body, mode)
        }
    }
    pub(in crate::host) fn publish_subscription(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        if let Some(current) = self.publication_bytes(path, mode)? {
            if current != body {
                return Err(HostError::Foreign);
            }
            self.clear_publication_stage(path, body, mode)?;
            return self.sync_bytes(path, body, mode);
        }
        let stage = format!("{path}.sbxr-next");
        if let Some((current, _)) = self.raw(&stage, mode, 1 << 20)? {
            if current != body {
                return Err(HostError::Foreign);
            }
        } else {
            self.install_bytes(&stage, body, mode)?;
        }
        self.sync_bytes(&stage, body, mode)?;
        let (parent, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let (staged, stage_name) = self.parent(&stage, false)?.ok_or(HostError::Unsafe)?;
        fs::linkat(
            &staged,
            stage_name.as_str(),
            &parent,
            name.as_str(),
            AtFlags::empty(),
        )
        .map_err(failure)?;
        fs::fsync(&parent).map_err(failure)?;
        self.clear_publication_stage(path, body, mode)?;
        self.sync_bytes(path, body, mode)
    }
    pub(in crate::host) fn clear_subscription(
        &self,
        path: &str,
        body: &[u8],
        mode: Mode,
    ) -> Result<(), HostError> {
        if self.metadata(path)?.is_some()
            && self.publication_bytes(path, mode)?.as_deref() != Some(body)
        {
            return Err(HostError::Foreign);
        }
        self.clear_publication_stage(path, body, mode)?;
        self.remove_bytes(path, body, mode)
    }
    pub(in crate::host) fn replace_subscription(
        &self,
        path: &str,
        candidate: &str,
        target: &[u8],
        mode: Mode,
        source_digest: &str,
        token: bool,
    ) -> Result<(), HostError> {
        self.write_allowed()?;
        let (current, current_proof) = self.raw(path, mode, 1 << 20)?.ok_or(HostError::Foreign)?;
        if current == target {
            self.sync_bytes(path, target, mode)?;
            return self.clear_subscription(candidate, target, mode);
        }
        let digest = if token {
            current.strip_suffix(b"\n").ok_or(HostError::Foreign)?
        } else {
            current.as_slice()
        };
        if sha256_hex(digest) != source_digest {
            return Err(HostError::Foreign);
        }
        self.clear_publication_stage(candidate, target, mode)?;
        let (prepared, prepared_proof) = self
            .raw(candidate, mode, 1 << 20)?
            .ok_or(HostError::Foreign)?;
        if prepared != target {
            return Err(HostError::Foreign);
        }
        let (to, name) = self.parent(path, false)?.ok_or(HostError::Unsafe)?;
        let (from, source) = self.parent(candidate, false)?.ok_or(HostError::Unsafe)?;
        if self.raw(path, mode, 1 << 20)?.map(|(_, p)| p) != Some(current_proof)
            || self.raw(candidate, mode, 1 << 20)?.map(|(_, p)| p) != Some(prepared_proof)
        {
            return Err(HostError::Unsafe);
        }
        fs::renameat(&from, source.as_str(), &to, name.as_str()).map_err(failure)?;
        fs::fsync(from).map_err(failure)?;
        fs::fsync(to).map_err(failure)?;
        self.sync_bytes(path, target, mode)
    }
}
