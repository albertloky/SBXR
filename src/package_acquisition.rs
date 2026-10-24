//! Exact Go sing-box package pins, bounded public acquisition and read-only
//! installed-package observations. Nothing here installs, holds or removes files.
//!
//! Go authenticates the complete key/DEB by pinned SHA-256, rather than accepting
//! an OpenPGP signature as a substitute. The mutable index only locates bytes;
//! neither its digests nor caller-provided verification callbacks grant trust.
mod probe;
use crate::{
    artifact_trust::{SelectionBudget, TrustError},
    host::{
        HostError,
        process::{Cancellation, CommandRunner, Query},
    },
    server_configuration::{PINNED_SING_BOX, PinnedPackage},
};
pub use probe::ProbeImage;
use reqwest::{Client, Url, header};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    io::{Cursor, Read},
    sync::Arc,
    time::Duration,
};
type Result<T> = std::result::Result<T, TrustError>;
pub const MAX_KEY_BYTES: usize = 1 << 20;
pub const MAX_INDEX_BYTES: usize = 8 << 20;
const MAX_CONTROL_BYTES: usize = 1 << 20;
const INDEX_URL: &str = "https://deb.sagernet.org/dists/*/*/binary-amd64/Packages";
pub const APT_SOURCE: &[u8] = b"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n";

/// Complete pinned material. These bytes still confer no host mutation or cleanup
/// authority; SetupMaterial and the protected host adapters retain that boundary.
pub struct VerifiedPackage {
    key: Vec<u8>,
    deb: Vec<u8>,
}
impl fmt::Debug for VerifiedPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verified pinned sing-box package")
    }
}
impl VerifiedPackage {
    pub fn verify(key: Vec<u8>, deb: Vec<u8>, budget: &SelectionBudget) -> Result<Self> {
        verify_key(&key, budget)?;
        if deb.len() as u64 != PINNED_SING_BOX.size || hash(&deb, budget)? != PINNED_SING_BOX.sha256
        {
            return Err(TrustError::Refused);
        }
        inspect_deb(&deb, budget)?;
        budget.check()?;
        Ok(Self { key, deb })
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn deb(&self) -> &[u8] {
        &self.deb
    }
    pub fn identity(&self) -> &'static PinnedPackage {
        &PINNED_SING_BOX
    }
    /// Go's signing-key fingerprint is the digest of all armored key bytes.
    pub fn key_sha256(&self) -> &'static str {
        PINNED_SING_BOX.signing_key_sha256
    }
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.key, self.deb)
    }
}
fn hash(bytes: &[u8], budget: &SelectionBudget) -> Result<String> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(16 * 1024) {
        budget.check()?;
        hash.update(chunk);
    }
    budget.check()?;
    Ok(format!("{:x}", hash.finalize()))
}
fn verify_key(bytes: &[u8], budget: &SelectionBudget) -> Result<()> {
    budget.check()?;
    if bytes.is_empty()
        || bytes.len() > MAX_KEY_BYTES
        || hash(bytes, budget)? != PINNED_SING_BOX.signing_key_sha256
    {
        return Err(TrustError::Refused);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Resource {
    Key,
    Index,
    Deb(String),
}
/// No arbitrary initial URL or size is accepted from a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRequest {
    resource: Resource,
}
impl PackageRequest {
    pub fn signing_key() -> Self {
        Self {
            resource: Resource::Key,
        }
    }
    pub fn index() -> Self {
        Self {
            resource: Resource::Index,
        }
    }
    pub fn url(&self) -> String {
        match &self.resource {
            Resource::Key => PINNED_SING_BOX.signing_key_url.into(),
            Resource::Index => INDEX_URL.into(),
            Resource::Deb(path) => format!("{}{path}", PINNED_SING_BOX.repository),
        }
    }
    pub fn max_bytes(&self) -> usize {
        match self.resource {
            Resource::Key => MAX_KEY_BYTES,
            Resource::Index => MAX_INDEX_BYTES,
            Resource::Deb(_) => PINNED_SING_BOX.size as usize,
        }
    }
    /// Only the vendor's fixed key redirect and actual Gemfury artifact CDN are
    /// accepted. Authorization happens before the redirected request is sent.
    pub fn permits_redirect(&self, raw: &str, hops: usize) -> bool {
        if hops == 0 || hops > 4 {
            return false;
        }
        let Ok(url) = checked_url(raw) else {
            return false;
        };
        match self.resource {
            Resource::Key => raw == "https://deb.sagernet.org/gpg.key",
            Resource::Index => false,
            Resource::Deb(_) => {
                url.host_str() == Some("gemfury.s3-accelerate.dualstack.amazonaws.com")
                    && url.path().starts_with("/gems/")
                    && url.path().ends_with("/sing_box_1_14_3_linux_amd64_deb")
            }
        }
    }
}
pub struct PackageResponse {
    status: u16,
    body: Box<dyn Read>,
}
impl PackageResponse {
    pub fn new(status: u16, body: impl Read + 'static) -> Self {
        Self {
            status,
            body: Box::new(body),
        }
    }
}
/// Trusted I/O boundary only. Implementations must enforce request redirect
/// policy and the supplied deadline/cancellation throughout blocking reads.
/// All returned bytes are independently bounded and pinned by acquire().
pub trait PackageTransport {
    fn get(
        &mut self,
        request: &PackageRequest,
        budget: &SelectionBudget,
    ) -> Result<PackageResponse>;
}
fn read_response(
    transport: &mut impl PackageTransport,
    request: &PackageRequest,
    budget: &SelectionBudget,
) -> Result<Vec<u8>> {
    budget.check()?;
    let mut response = transport.get(request, budget)?;
    budget.check()?;
    if response.status != 200 {
        return Err(TrustError::Refused);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        budget.check()?;
        let n = response
            .body
            .read(&mut chunk)
            .map_err(|_| TrustError::Unavailable)?;
        budget.check()?;
        if n == 0 {
            return Ok(bytes);
        }
        if n > request.max_bytes().saturating_sub(bytes.len()) {
            return Err(TrustError::Refused);
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
}
pub fn acquire(
    transport: &mut impl PackageTransport,
    budget: &SelectionBudget,
) -> Result<VerifiedPackage> {
    let key = read_response(transport, &PackageRequest::signing_key(), budget)?;
    verify_key(&key, budget)?;
    let index = read_response(transport, &PackageRequest::index(), budget)?;
    let request = package_request(&index, budget)?;
    let deb = read_response(transport, &request, budget)?;
    VerifiedPackage::verify(key, deb, budget)
}

/// The HTTPS index is a locator, never a replacement for the compiled-in pins.
pub fn package_request(index: &[u8], budget: &SelectionBudget) -> Result<PackageRequest> {
    budget.check()?;
    if index.is_empty() || index.len() > MAX_INDEX_BYTES {
        return Err(TrustError::Refused);
    }
    let text = std::str::from_utf8(index).map_err(|_| TrustError::Refused)?;
    if text.contains('\r') || text.bytes().any(|b| b == 0 || b == 127) {
        return Err(TrustError::Refused);
    }
    let mut selected = None;
    for block in text.split("\n\n").filter(|b| !b.trim().is_empty()) {
        budget.check()?;
        let fields = fields(block)?;
        if fields.get("package").map(String::as_str) != Some(PINNED_SING_BOX.name)
            || fields.get("version").map(String::as_str) != Some(PINNED_SING_BOX.version)
            || fields.get("architecture").map(String::as_str) != Some(PINNED_SING_BOX.architecture)
        {
            continue;
        }
        if selected.is_some()
            || fields.get("size") != Some(&PINNED_SING_BOX.size.to_string())
            || fields.get("sha256").map(String::as_str) != Some(PINNED_SING_BOX.sha256)
        {
            return Err(TrustError::Refused);
        }
        let path = fields.get("filename").ok_or(TrustError::Refused)?;
        if !path.starts_with("files/")
            || !path.ends_with("/sing-box_1.14.3_linux_amd64.deb")
            || path.len() > 512
            || !path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(TrustError::Refused);
        }
        selected = Some(PackageRequest {
            resource: Resource::Deb(path.clone()),
        });
    }
    budget.check()?;
    selected.ok_or(TrustError::Refused)
}
fn fields(text: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::<String, String>::new();
    let mut last: Option<String> = None;
    for line in text.lines() {
        if line.len() > 4096 || line.bytes().any(|b| b < b' ' && b != b'\t') {
            return Err(TrustError::Refused);
        }
        if line.starts_with([' ', '\t']) {
            let last = last.as_ref().ok_or(TrustError::Refused)?;
            result
                .get_mut(last)
                .ok_or(TrustError::Refused)?
                .push_str(&format!("\n{line}"));
            continue;
        }
        let (key, value) = line.split_once(':').ok_or(TrustError::Refused)?;
        if result.len() >= 128
            || key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || result
                .insert(key.to_ascii_lowercase(), value.trim().into())
                .is_some()
        {
            return Err(TrustError::Refused);
        }
        last = Some(key.to_ascii_lowercase());
    }
    Ok(result)
}

// Inspect only metadata. Data and maintainer scripts are never extracted or run.
fn inspect_deb(bytes: &[u8], budget: &SelectionBudget) -> Result<()> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err(TrustError::Refused);
    }
    let mut offset = 8usize;
    for name in [
        "debian-binary",
        "control.tar.gz",
        "data.tar.gz",
        "_gpgorigin",
    ] {
        budget.check()?;
        let header = bytes.get(offset..offset + 60).ok_or(TrustError::Refused)?;
        if &header[58..] != b"`\n"
            || std::str::from_utf8(&header[..16])
                .map_err(|_| TrustError::Refused)?
                .trim()
                != name
        {
            return Err(TrustError::Refused);
        }
        let size = number(&header[48..58], 10)?;
        offset = offset.checked_add(60).ok_or(TrustError::Refused)?;
        let end = offset.checked_add(size).ok_or(TrustError::Refused)?;
        let member = bytes.get(offset..end).ok_or(TrustError::Refused)?;
        if member.is_empty() {
            return Err(TrustError::Refused);
        }
        match name {
            "debian-binary" if member != b"2.0\n" => return Err(TrustError::Refused),
            "control.tar.gz" => inspect_control(member, budget)?,
            "_gpgorigin" if member.len() > 4096 => return Err(TrustError::Refused),
            _ => {}
        }
        offset = end.checked_add(size % 2).ok_or(TrustError::Refused)?;
        if size % 2 == 1 && bytes.get(end) != Some(&b'\n') {
            return Err(TrustError::Refused);
        }
    }
    if offset != bytes.len() {
        return Err(TrustError::Refused);
    }
    Ok(())
}
fn inspect_control(compressed: &[u8], budget: &SelectionBudget) -> Result<()> {
    if compressed.len() > MAX_CONTROL_BYTES {
        return Err(TrustError::Refused);
    }
    let mut decoder = flate2::bufread::GzDecoder::new(compressed);
    let mut tar = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        budget.check()?;
        let n = decoder.read(&mut chunk).map_err(|_| TrustError::Refused)?;
        if n == 0 {
            break;
        }
        if n > MAX_CONTROL_BYTES.saturating_sub(tar.len()) {
            return Err(TrustError::Refused);
        }
        tar.extend_from_slice(&chunk[..n]);
    }
    if !decoder.into_inner().is_empty() {
        return Err(TrustError::Refused);
    }
    let mut offset = 0usize;
    let mut control = None;
    loop {
        budget.check()?;
        let h = tar.get(offset..offset + 512).ok_or(TrustError::Refused)?;
        if h.iter().all(|b| *b == 0) {
            if tar.len() - offset < 1024
                || tar.len() % 512 != 0
                || tar[offset..].iter().any(|b| *b != 0)
            {
                return Err(TrustError::Refused);
            }
            break;
        }
        let checksum: usize = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    usize::from(*b)
                }
            })
            .sum();
        let name = tar_text(&h[..100])?;
        if number(&h[148..156], 8)? != checksum
            || !matches!(&h[257..265], b"ustar\0\x30\x30" | b"ustar  \0")
            || h[345..500].iter().any(|b| *b != 0)
            || !matches!(h[156], b'0' | 0 | b'5')
            || (!matches!(name, "." | "./")
                && (!name.starts_with("./")
                    || name
                        .split('/')
                        .skip(1)
                        .any(|part| part.is_empty() || part == "." || part == "..")))
        {
            return Err(TrustError::Refused);
        }
        let size = number(&h[124..136], 8)?;
        if h[156] == b'5' && (size != 0 || !matches!(name, "." | "./")) {
            return Err(TrustError::Refused);
        }
        let start = offset + 512;
        let end = start.checked_add(size).ok_or(TrustError::Refused)?;
        let member = tar.get(start..end).ok_or(TrustError::Refused)?;
        if name == "./control" {
            if control.is_some() || !matches!(h[156], b'0' | 0) {
                return Err(TrustError::Refused);
            }
            control = Some(member);
        }
        offset = end
            .checked_add((512 - size % 512) % 512)
            .ok_or(TrustError::Refused)?;
        if offset > tar.len() || tar[end..offset].iter().any(|b| *b != 0) {
            return Err(TrustError::Refused);
        }
    }
    let control = std::str::from_utf8(control.ok_or(TrustError::Refused)?)
        .map_err(|_| TrustError::Refused)?;
    let metadata = fields(control)?;
    for (field, expected) in [
        ("package", PINNED_SING_BOX.name),
        ("version", PINNED_SING_BOX.version),
        ("architecture", PINNED_SING_BOX.architecture),
    ] {
        if metadata.get(field).map(String::as_str) != Some(expected) {
            return Err(TrustError::Refused);
        }
    }
    Ok(())
}
fn number(bytes: &[u8], radix: u32) -> Result<usize> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| TrustError::Refused)?
        .trim_matches([' ', '\0']);
    if value.is_empty() || !value.bytes().all(|b| b >= b'0' && b < b'0' + radix as u8) {
        return Err(TrustError::Refused);
    }
    usize::from_str_radix(value, radix).map_err(|_| TrustError::Refused)
}
fn tar_text(bytes: &[u8]) -> Result<&str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err(TrustError::Refused);
    }
    std::str::from_utf8(&bytes[..end]).map_err(|_| TrustError::Refused)
}

/// Independent dpkg and apt-mark facts, matching Go's running inspection. A
/// stale hold alone never proves an installed or held package. No mutation runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstalledPackage {
    pub present: bool,
    pub exact_held_package: bool,
    pub apt_hold: bool,
}
pub fn inspect_installed(
    runner: &impl CommandRunner,
    stop: &Cancellation,
) -> std::result::Result<InstalledPackage, HostError> {
    if stop.cancelled() {
        return Err(HostError::Cancelled);
    }
    let package = runner.query(Query::Package, stop)?;
    let hold = runner.query(Query::Hold, stop)?;
    if stop.cancelled() {
        return Err(HostError::Cancelled);
    }
    if hold.code() != 0 {
        return Err(HostError::Unsafe);
    }
    let apt_hold = hold
        .text()?
        .split_whitespace()
        .any(|name| name == PINNED_SING_BOX.name);
    if package.code() == 1 {
        return Ok(InstalledPackage {
            present: false,
            exact_held_package: false,
            apt_hold,
        });
    }
    let parts: Vec<_> = package.text()?.split_whitespace().collect();
    if package.code() != 0
        || parts.len() != 3
        || parts[0] != PINNED_SING_BOX.version
        || parts[1] != PINNED_SING_BOX.architecture
    {
        return Err(HostError::Foreign);
    }
    Ok(InstalledPackage {
        present: true,
        exact_held_package: parts[2] == "hi",
        apt_hold,
    })
}

/// Native public HTTPS with the same pinned TLS roots, bounded DNS/request
/// timing and cancellation pattern as release_https; no proxy or ambient auth.
pub struct PackageHttps {
    runtime: tokio::runtime::Runtime,
    client: Client,
}
impl fmt::Debug for PackageHttps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Public package HTTPS transport")
    }
}
impl PackageHttps {
    pub fn new() -> Result<Self> {
        Self::configured(
            rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            None,
        )
    }
    fn configured(
        roots: rustls::RootCertStore,
        resolve: Option<std::net::SocketAddr>,
    ) -> Result<Self> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| TrustError::Unavailable)?;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| TrustError::Unavailable)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut builder = Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .pool_max_idle_per_host(0)
            .http1_max_headers(96)
            .hickory_dns(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("SBXR/", env!("CARGO_PKG_VERSION")));
        if let Some(address) = resolve {
            builder = builder.resolve("sing-box.app", address);
        }
        let client = builder.build().map_err(|_| TrustError::Unavailable)?;
        Ok(Self { runtime, client })
    }
    async fn fetch(
        &self,
        request: &PackageRequest,
        budget: &SelectionBudget,
    ) -> Result<PackageResponse> {
        let mut current = checked_url(&request.url())?;
        for hop in 0..=4 {
            budget.check()?;
            let mut response = self
                .client
                .get(current.clone())
                .header(header::ACCEPT, "application/octet-stream")
                .header(header::ACCEPT_ENCODING, "identity")
                .timeout(
                    budget
                        .deadline()
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .send()
                .await
                .map_err(|_| TrustError::Unavailable)?;
            budget.check()?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .ok_or(TrustError::Refused)?;
                if !request.permits_redirect(location, hop + 1) {
                    return Err(TrustError::Refused);
                }
                current = checked_url(location)?;
                continue;
            }
            if status != 200 {
                return Ok(PackageResponse::new(status, Cursor::new(Vec::new())));
            }
            if response
                .headers()
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|h| h.as_bytes() != b"identity")
                || response
                    .content_length()
                    .is_some_and(|n| n > request.max_bytes() as u64)
            {
                return Err(TrustError::Refused);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| TrustError::Unavailable)?
            {
                budget.check()?;
                if chunk.len() > request.max_bytes().saturating_sub(body.len()) {
                    return Err(TrustError::Refused);
                }
                body.extend_from_slice(&chunk);
            }
            budget.check()?;
            return Ok(PackageResponse::new(status, Cursor::new(body)));
        }
        Err(TrustError::Refused)
    }
}
impl PackageTransport for PackageHttps {
    fn get(
        &mut self,
        request: &PackageRequest,
        budget: &SelectionBudget,
    ) -> Result<PackageResponse> {
        budget.check()?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let result = self.runtime.block_on(async {
            tokio::select! {
                result = self.fetch(request, budget) => result,
                _ = async { loop { if budget.check().is_err() { break; } tokio::time::sleep(Duration::from_millis(20)).await; } } => Err(TrustError::Interrupted),
            }
        });
        budget.check()?;
        result
    }
}
fn checked_url(raw: &str) -> Result<Url> {
    if raw.len() > 8192
        || !raw.starts_with("https://")
        || raw.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\')
    {
        return Err(TrustError::Refused);
    }
    let url = Url::parse(raw).map_err(|_| TrustError::Refused)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(TrustError::Refused);
    }
    let authority = raw[8..]
        .split(['/', '?'])
        .next()
        .ok_or(TrustError::Refused)?;
    let host = url.host_str().ok_or(TrustError::Refused)?;
    if authority != host && authority != format!("{host}:443") {
        return Err(TrustError::Refused);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread, time::Instant};
    const CONTROL: &[u8] = include_bytes!("../tests/testdata/package_acquisition/control.tar.gz");
    fn tar() -> Vec<u8> {
        let mut result = Vec::new();
        flate2::read::GzDecoder::new(CONTROL)
            .read_to_end(&mut result)
            .unwrap();
        result
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    #[test]
    fn control_metadata_requires_exact_name_version_and_architecture() {
        inspect_control(CONTROL, &SelectionBudget::new()).unwrap();
        for (from, to) in [
            (
                b"Package: sing-box".as_slice(),
                b"Package: bad-name".as_slice(),
            ),
            (b"Version: 1.14.3", b"Version: 1.14.4"),
            (b"Architecture: amd64", b"Architecture: arm64"),
        ] {
            let mut data = tar();
            let i = data.windows(from.len()).position(|v| v == from).unwrap();
            data[i..i + from.len()].copy_from_slice(to);
            assert!(inspect_control(&gzip(&data), &SelectionBudget::new()).is_err());
        }
    }
    #[test]
    fn malformed_compression_tar_and_member_shapes_refuse_without_extraction() {
        for data in [
            CONTROL[..CONTROL.len() - 1].to_vec(),
            [CONTROL, b"garbage"].concat(),
            gzip(&vec![0; MAX_CONTROL_BYTES + 1]),
            gzip(&[]),
        ] {
            assert!(inspect_control(&data, &SelectionBudget::new()).is_err());
        }
        for index in [0, 148, 257, 345, 1000] {
            let mut data = tar();
            data[index] ^= 1;
            assert!(inspect_control(&gzip(&data), &SelectionBudget::new()).is_err());
        }
        for bytes in [b"".as_slice(), b"!<arch>\n", b"!<arch>\nmalformed"] {
            assert!(inspect_deb(bytes, &SelectionBudget::new()).is_err());
        }
    }
    fn tls_server(
        response: impl Into<Vec<u8>>,
        stall: bool,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let response = response.into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cert = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
            "../tests/testdata/package_acquisition/server.pem"
        )))
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut Cursor::new(include_bytes!(
            "../tests/testdata/package_acquisition/server-key.pem"
        )))
        .unwrap()
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, socket);
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).ok() != Some(1) {
                    return;
                }
                request.push(byte[0]);
                if request.len() > 8192 {
                    return;
                }
            }
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            if stall {
                thread::sleep(Duration::from_millis(250));
            }
        });
        (address, handle)
    }
    fn local_client(address: std::net::SocketAddr, trusted: bool) -> PackageHttps {
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            for cert in rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
                "../tests/testdata/package_acquisition/ca.pem"
            ))) {
                roots.add(cert.unwrap()).unwrap();
            }
        }
        PackageHttps::configured(roots, Some(address)).unwrap()
    }
    #[test]
    fn real_https_enforces_certificate_status_and_encoded_response_bounds() {
        for (response, trusted, accepted) in [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nkey".as_slice(),true,true),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nkey",false,false),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n",true,false),
            (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\nConnection: close\r\n\r\nkey",true,false),
            (b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",true,false),
        ] {
            let (address,server)=tls_server(response,false);
            let mut client=local_client(address,trusted);
            let result=read_response(&mut client,&PackageRequest::signing_key(),&SelectionBudget::new());
            assert_eq!(result.is_ok(),accepted);if let Ok(body)=result {assert_eq!(body,b"key");}
            server.join().unwrap();
        }
        let (address, server) = tls_server(
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            false,
        );
        assert!(
            read_response(
                &mut local_client(address, true),
                &PackageRequest::signing_key(),
                &SelectionBudget::new()
            )
            .is_err()
        );
        server.join().unwrap();
    }
    #[test]
    fn real_https_deadline_interrupts_a_stalled_response() {
        let (address, server) = tls_server(b"", true);
        let mut client = local_client(address, true);
        let start = Instant::now();
        let budget = SelectionBudget::until(start + Duration::from_millis(100));
        assert!(matches!(
            client.get(&PackageRequest::signing_key(), &budget),
            Err(TrustError::Interrupted)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
    #[test]
    fn real_https_chunked_overflow_truncation_and_mid_body_cancellation_refuse() {
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100001\r\n"
                .to_vec();
        response.extend_from_slice(&vec![b'x'; MAX_KEY_BYTES + 1]);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (address, server) = tls_server(response, false);
        assert!(
            read_response(
                &mut local_client(address, true),
                &PackageRequest::signing_key(),
                &SelectionBudget::new()
            )
            .is_err()
        );
        server.join().unwrap();
        let (address, server) = tls_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\na".as_slice(),
            false,
        );
        assert!(
            read_response(
                &mut local_client(address, true),
                &PackageRequest::signing_key(),
                &SelectionBudget::new()
            )
            .is_err()
        );
        server.join().unwrap();
        let (address, server) = tls_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\na".as_slice(),
            true,
        );
        let budget = Arc::new(SelectionBudget::new());
        let cancelled = Arc::clone(&budget);
        let stop = thread::spawn(move || {
            thread::sleep(Duration::from_millis(75));
            cancelled.cancel();
        });
        assert!(matches!(
            read_response(
                &mut local_client(address, true),
                &PackageRequest::signing_key(),
                &budget
            ),
            Err(TrustError::Interrupted)
        ));
        stop.join().unwrap();
        server.join().unwrap();
    }
    #[test]
    fn client_construction_and_cancelled_request_need_no_network() {
        let mut client = PackageHttps::new().unwrap();
        let budget = SelectionBudget::new();
        budget.cancel();
        assert!(matches!(
            client.get(&PackageRequest::signing_key(), &budget),
            Err(TrustError::Interrupted)
        ));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(matches!(PackageHttps::new(), Err(TrustError::Unavailable)));
        });
    }
}
