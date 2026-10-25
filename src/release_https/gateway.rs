//! The retained temporary gateway has private, destination-scoped TLS trust.
//! A reviewed CA digest is explicit input, never ambient environment/configuration.
use super::*;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::{fs::File, io::Read, path::Path};
const DIRECTORY: &str = "/root/sbxr-qualification-v3";
const CA_FILE: &str = "ca.crt";
// Exact address owned by the retained transport's reviewed NAT route. Keep the
// logical URL/SNI/hostname api.github.com; never consult fallback public DNS.
const ROUTE: (&str, std::net::SocketAddr) = (
    "api.github.com",
    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(127, 0, 0, 2),
        443,
    )),
);
const MAX_CA_BYTES: usize = 32 << 10;

/// Read-only delivery transport. This does not prove candidate authenticity,
/// stable qualification, process identity or authorization to change a host.
/// Public TLS and all Sigstore policies are unchanged. There is no conversion
/// into public HTTPS transport and no environment/URL/CA-path override.
pub struct CandidateGatewayTransport {
    inner: HttpsTransport,
}
impl fmt::Debug for CandidateGatewayTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected candidate gateway HTTPS transport")
    }
}
impl CandidateGatewayTransport {
    /// The coordinator supplies the independently reviewed exact PEM-file digest.
    /// Read only the retained fixed root-owned staging path on native Linux/root.
    /// This never installs a CA or reads an ambient system trust store.
    /// The immutable CA snapshot expires at this selection's deadline, even if a later
    /// caller tries to reuse the transport with a fresh, longer selection budget.
    pub fn from_retained_gateway(ca_sha256: &str, budget: &SelectionBudget) -> Result<Self> {
        budget.check()?;
        if !cfg!(target_os = "linux") || rustix::process::geteuid().as_raw() != 0 {
            return Err(TrustError::Unavailable);
        }
        Self::from_directory(Path::new(DIRECTORY), 0, ca_sha256, budget)
    }
    fn from_directory(
        directory: &Path,
        uid: u32,
        digest: &str,
        budget: &SelectionBudget,
    ) -> Result<Self> {
        let roots = protected_roots(directory, uid, digest, budget)?;
        let mut inner = HttpsTransport::configured(roots, Some(vec![ROUTE]))?;
        inner.scope = Scope::CandidateGateway(budget.deadline());
        budget.check()?;
        Ok(Self { inner })
    }
}
impl AcquisitionTransport for CandidateGatewayTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        self.inner.get(request, budget)
    }
}
pub(super) fn allowed(raw: &str) -> Result<Url> {
    let prefix = "https://api.github.com/repos/albertloky/SBXR/releases/";
    if !raw.strip_prefix(prefix).is_some_and(|tail| {
        matches!(
            tail,
            "latest" | "assets/1" | "assets/2" | "assets/3" | "assets/4"
        )
    }) {
        return Err(TrustError::Refused);
    }
    checked(raw)
}
fn safe(stat: &Stat, uid: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == uid
        && stat.st_nlink == 1
        && matches!(stat.st_mode & 0o7777, 0o600 | 0o644)
        && stat.st_size > 0
        && stat.st_size <= MAX_CA_BYTES as i64
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_mtime == b.st_mtime
        && a.st_ctime == b.st_ctime
}
fn protected_roots(
    directory: &Path,
    uid: u32,
    digest: &str,
    budget: &SelectionBudget,
) -> Result<rustls::RootCertStore> {
    budget.check()?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(TrustError::Refused);
    }
    let dir = crate::durable::open_directory(directory, uid).map_err(|_| TrustError::Refused)?;
    let fd = fs::openat(
        &dir,
        CA_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| TrustError::Refused)?;
    let before = fs::fstat(&fd).map_err(|_| TrustError::Refused)?;
    if !safe(&before, uid) {
        return Err(TrustError::Refused);
    }
    let file = File::from(fd);
    let mut bytes = Vec::new();
    (&file)
        .take((MAX_CA_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TrustError::Unavailable)?;
    budget.check()?;
    let after = fs::fstat(&file).map_err(|_| TrustError::Refused)?;
    let named =
        fs::statat(&dir, CA_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| TrustError::Refused)?;
    let current =
        crate::durable::open_directory(directory, uid).map_err(|_| TrustError::Refused)?;
    let a = fs::fstat(&dir).map_err(|_| TrustError::Refused)?;
    let b = fs::fstat(current).map_err(|_| TrustError::Refused)?;
    if !same(&before, &after)
        || !same(&after, &named)
        || !safe(&after, uid)
        || a.st_dev != b.st_dev
        || a.st_ino != b.st_ino
        || bytes.len() != before.st_size as usize
        || crate::records::sha256_hex(&bytes) != digest
    {
        return Err(TrustError::Refused);
    }
    roots(&bytes)
}
fn roots(bytes: &[u8]) -> Result<rustls::RootCertStore> {
    if bytes.is_empty() || bytes.len() > MAX_CA_BYTES {
        return Err(TrustError::Refused);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| TrustError::Refused)?
        .trim();
    if !text.starts_with("-----BEGIN CERTIFICATE-----")
        || !text.ends_with("-----END CERTIFICATE-----")
        || text.matches("-----BEGIN ").count() != 1
        || text.matches("-----END ").count() != 1
    {
        return Err(TrustError::Refused);
    }
    let mut reader = bytes;
    let Some(rustls_pemfile::Item::X509Certificate(certificate)) =
        rustls_pemfile::read_one(&mut reader).map_err(|_| TrustError::Refused)?
    else {
        return Err(TrustError::Refused);
    };
    if rustls_pemfile::read_one(&mut reader)
        .map_err(|_| TrustError::Refused)?
        .is_some()
    {
        return Err(TrustError::Refused);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).map_err(|_| TrustError::Refused)?;
    Ok(roots)
}
#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
