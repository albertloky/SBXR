//! Certificate-verified, bounded public HTTPS acquisition without host effects.
//! The repository-tool preflight can opt into narrowly scoped API authentication.
//! Redirect authorization precedes each GET. Redirects are credential-free.
mod gateway;
mod probe;
use crate::artifact_trust::{
    AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
};
pub use gateway::CandidateGatewayTransport;
pub use probe::{ProbeObservation, PublicProbeTransport};
use reqwest::{Client, Url, header};
use std::{fmt, io::Cursor, sync::Arc, time::Duration};
type Result<T> = std::result::Result<T, TrustError>;
pub const GITHUB_API_VERSION: &str = "2026-03-10";
const POLL: Duration = Duration::from_millis(20);
pub struct HttpsTransport {
    runtime: tokio::runtime::Runtime,
    client: Client,
    scope: Scope,
    #[cfg(any(test, feature = "candidate-preflight-auth"))]
    candidate_preflight_auth: Option<header::HeaderValue>,
}
/// Native lifecycle delivery selection after current-process authentication.
/// Candidate delivery does not change acquire_latest's stable proof requirements.
pub(crate) enum LifecycleTransport {
    Public(HttpsTransport),
    Candidate(CandidateGatewayTransport),
}
impl LifecycleTransport {
    pub(crate) fn new(candidate: Option<CandidateGatewayTransport>) -> Result<Self> {
        match candidate {
            Some(transport) => Ok(Self::Candidate(transport)),
            None => HttpsTransport::new().map(Self::Public),
        }
    }
}
impl AcquisitionTransport for LifecycleTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        match self {
            Self::Public(transport) => transport.get(request, budget),
            Self::Candidate(transport) => transport.get(request, budget),
        }
    }
}
#[derive(Clone, Copy)]
enum Scope {
    Public,
    CandidateGateway {
        until: std::time::Instant,
        port: u16,
    },
}
impl fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Public HTTPS transport")
    }
}
impl HttpsTransport {
    pub fn new() -> Result<Self> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::configured(roots, None)
    }
    fn configured(
        roots: rustls::RootCertStore,
        resolve: Option<Vec<(&str, std::net::SocketAddr)>>,
    ) -> Result<Self> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| TrustError::Unavailable)?;
        let tls = tls_config(roots)?;
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
        if let Some(resolve) = resolve {
            for (host, address) in resolve {
                builder = builder.resolve(host, address);
            }
        }
        let client = builder.build().map_err(|_| TrustError::Unavailable)?;
        Ok(Self {
            runtime,
            client,
            scope: Scope::Public,
            #[cfg(any(test, feature = "candidate-preflight-auth"))]
            candidate_preflight_auth: None,
        })
    }
    /// Fixed sandbox-safe public IPv4 probe. Uses asynchronous DNS and the same
    /// verified TLS transport; no getent subprocess or /proc access is required.
    pub(crate) fn public_ipv4(&self, budget: &SelectionBudget) -> Result<std::net::Ipv4Addr> {
        self.ipv4_at("https://api.ipify.org/", budget)
    }
    fn ipv4_at(&self, url: &str, budget: &SelectionBudget) -> Result<std::net::Ipv4Addr> {
        budget.check()?;
        if !matches!(self.scope, Scope::Public) {
            return Err(TrustError::Refused);
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let result = self.runtime.block_on(async {
            tokio::select! {
                result = async {
                    let mut response = self.client.get(url).header(header::ACCEPT_ENCODING,"identity")
                        .timeout(budget.deadline().saturating_duration_since(std::time::Instant::now()))
                        .send().await.map_err(|_| TrustError::Unavailable)?;
                    if response.status() != 200 || response.headers().contains_key(header::CONTENT_ENCODING)
                        || response.headers().contains_key(header::LOCATION)
                        || response.content_length().is_some_and(|n| n > 64) { return Err(TrustError::Refused); }
                    let mut body = Vec::new();
                    while let Some(chunk) = response.chunk().await.map_err(|_| TrustError::Unavailable)? {
                        budget.check()?;
                        if chunk.len() > 64usize.saturating_sub(body.len()) { return Err(TrustError::Refused); }
                        body.extend_from_slice(&chunk);
                    }
                    let text = std::str::from_utf8(&body).map_err(|_| TrustError::Refused)?.trim();
                    let ip: std::net::Ipv4Addr = text.parse().map_err(|_| TrustError::Refused)?;
                    if text != ip.to_string() || !crate::records::ownership_public_ipv4(text) { return Err(TrustError::Refused); }
                    Ok(ip)
                } => result,
                _ = async { loop { if budget.check().is_err() { break; } tokio::time::sleep(POLL).await; } } => Err(TrustError::Interrupted),
            }
        });
        budget.check()?;
        result
    }
    fn check_budget(&self, budget: &SelectionBudget) -> Result<()> {
        budget.check()?;
        if matches!(self.scope, Scope::CandidateGateway { until, .. } if std::time::Instant::now() >= until)
        {
            return Err(TrustError::Interrupted);
        }
        Ok(())
    }
    fn deadline(&self, budget: &SelectionBudget) -> std::time::Instant {
        match self.scope {
            Scope::Public => budget.deadline(),
            Scope::CandidateGateway { until, .. } => until.min(budget.deadline()),
        }
    }
    fn admit(&self, raw: &str, budget: &SelectionBudget) -> Result<Url> {
        budget.check()?;
        match self.scope {
            Scope::Public => initial(raw),
            Scope::CandidateGateway { until, .. } => {
                if std::time::Instant::now() >= until {
                    return Err(TrustError::Interrupted);
                }
                gateway::allowed(raw)
            }
        }
    }
    fn permits_redirect(&self, request: &AcquisitionRequest, raw: &str, hop: usize) -> bool {
        matches!(self.scope, Scope::Public) && request.permits_redirect(raw, hop)
    }
    async fn fetch(
        &self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
        mut probe: Option<&mut ProbeObservation>,
    ) -> Result<AcquisitionResponse> {
        let mut current = self.admit(request.url(), budget)?;
        for hop in 0..=4 {
            self.check_budget(budget)?;
            let remaining = self
                .deadline(budget)
                .saturating_duration_since(std::time::Instant::now());
            // Keep the canonical URL for admission and response identity. Only
            // the candidate client sends the actual request to private loopback.
            let mut destination = current.clone();
            if let Scope::CandidateGateway { port, .. } = self.scope {
                destination
                    .set_host(Some("127.0.0.1"))
                    .map_err(|_| TrustError::Refused)?;
                destination
                    .set_port(Some(port))
                    .map_err(|_| TrustError::Refused)?;
            }
            let mut outgoing = self
                .client
                .get(destination)
                .header(header::ACCEPT, request.accept())
                .header(header::ACCEPT_ENCODING, "identity")
                .timeout(remaining);
            if current.host_str() == Some("api.github.com") {
                outgoing = outgoing.header("X-GitHub-Api-Version", GITHUB_API_VERSION);
            }
            #[cfg(any(test, feature = "candidate-preflight-auth"))]
            if hop == 0
                && matches!(self.scope, Scope::Public)
                && candidate_preflight_api_request(request, &current)
                && let Some(auth) = &self.candidate_preflight_auth
            {
                outgoing = outgoing.header(header::AUTHORIZATION, auth.clone());
            }
            if let Some(probe) = probe.as_deref_mut() {
                probe.start_hop(current.host_str(), hop);
            }
            let mut response = outgoing.send().await.map_err(|_| TrustError::Unavailable)?;
            self.check_budget(budget)?;
            let status = response.status().as_u16();
            if let Some(probe) = probe.as_deref_mut() {
                probe.observe_response(status, response.headers());
            }
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let next = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(TrustError::Refused)?;
                if !self.permits_redirect(request, next, hop + 1) {
                    return Err(TrustError::Refused);
                }
                current = checked(next)?;
                continue;
            }
            let mut links = response.headers().get_all(header::LINK).iter();
            let link = match (links.next(), links.next()) {
                (None, _) => false,
                // GitHub can attach this advisory to a complete attestation response.
                (Some(value), None)
                    if matches!(self.scope, Scope::Public)
                        && current.host_str() == Some("api.github.com")
                        && current.path().starts_with("/repos/albertloky/SBXR/attestations/sha1:")
                        && value.as_bytes() == br#"<https://docs.github.com/en/rest/about-the-rest-api/api-versions>; rel="deprecation"; type="text/html""# =>
                {
                    false
                }
                _ => true,
            };
            if status != 200 {
                return Ok(AcquisitionResponse::new(
                    status,
                    Cursor::new(Vec::<u8>::new()),
                    link,
                ));
            }
            if response
                .headers()
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|v| v.as_bytes() != b"identity")
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
                self.check_budget(budget)?;
                if chunk.len() > request.max_bytes().saturating_sub(body.len()) {
                    return Err(TrustError::Refused);
                }
                body.extend_from_slice(&chunk);
            }
            self.check_budget(budget)?;
            return Ok(AcquisitionResponse::new(status, Cursor::new(body), link));
        }
        Err(TrustError::Refused)
    }

    fn get_with_probe(
        &self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
        probe: Option<&mut ProbeObservation>,
    ) -> Result<AcquisitionResponse> {
        self.admit(request.url(), budget)?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let result=self.runtime.block_on(async {
            tokio::select! {
                result=self.fetch(request,budget,probe)=>result,
                _=async {loop {if self.check_budget(budget).is_err(){break}tokio::time::sleep(POLL).await;}}=>Err(TrustError::Interrupted),
            }
        });
        // A transport timeout racing cancellation/deadline must never escape as
        // an ordinary error or late success after this selection was interrupted.
        self.check_budget(budget)?;
        result
    }
}
impl AcquisitionTransport for HttpsTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        self.get_with_probe(request, budget, None)
    }
}
#[cfg(any(test, feature = "candidate-preflight-auth"))]
fn candidate_preflight_api_request(request: &AcquisitionRequest, url: &Url) -> bool {
    use crate::artifact_trust::PublicRequestStage;
    use crate::release_identity::REPOSITORY;

    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Some(path) = url
        .path()
        .strip_prefix("/repos/")
        .and_then(|path| path.strip_prefix(REPOSITORY))
        .and_then(|path| path.strip_prefix('/'))
    else {
        return false;
    };
    match request.stage {
        PublicRequestStage::LatestMetadata => path == "releases/latest" && url.query().is_none(),
        PublicRequestStage::NativeAttestations => {
            url.query() == Some("predicate_type=release&per_page=100")
                && path
                    .strip_prefix("attestations/sha1:")
                    .is_some_and(|commit| {
                        commit.len() == 40
                            && commit
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    })
        }
        PublicRequestStage::ReleaseIndex | PublicRequestStage::ReleaseArchive => {
            url.query().is_none()
                && path.strip_prefix("releases/assets/").is_some_and(|id| {
                    id.parse::<u64>()
                        .is_ok_and(|value| value != 0 && value.to_string() == id)
                })
        }
        _ => false,
    }
}

fn tls_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| TrustError::Unavailable)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
fn checked(raw: &str) -> Result<Url> {
    if !raw.starts_with("https://")
        || raw.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\')
        || raw.contains('#')
    {
        return Err(TrustError::Refused);
    }
    let url = Url::parse(raw).map_err(|_| TrustError::Refused)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|p| p != 443)
        || url.host_str().is_none()
    {
        return Err(TrustError::Refused);
    }
    let authority = raw[8..]
        .split(['/', '?'])
        .next()
        .ok_or(TrustError::Refused)?;
    if authority != url.host_str().ok_or(TrustError::Refused)?
        && authority != format!("{}:443", url.host_str().ok_or(TrustError::Refused)?)
    {
        return Err(TrustError::Refused);
    }
    Ok(url)
}
fn initial(raw: &str) -> Result<Url> {
    let url = checked(raw)?;
    if !matches!(
        url.host_str(),
        Some("api.github.com" | "tmaproduction.blob.core.windows.net")
    ) {
        return Err(TrustError::Refused);
    }
    Ok(url)
}
#[cfg(test)]
#[path = "release_https_tests.rs"]
mod tests;

pub(crate) fn inspect_gateway_ca(bytes: &[u8]) -> Result<()> {
    gateway::roots(bytes).map(|_| ())
}
