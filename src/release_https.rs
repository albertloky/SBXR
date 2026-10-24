//! Certificate-verified, bounded public HTTPS acquisition. No credentials,
//! executable handling or host effects. Redirect authorization precedes each GET.
use crate::artifact_trust::{
    AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
};
use reqwest::{Client, Url, header};
use std::{fmt, io::Cursor, sync::Arc, time::Duration};
type Result<T> = std::result::Result<T, TrustError>;
pub const GITHUB_API_VERSION: &str = "2026-03-10";
const POLL: Duration = Duration::from_millis(20);
pub struct HttpsTransport {
    runtime: tokio::runtime::Runtime,
    client: Client,
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
        if let Some(resolve) = resolve {
            for (host, address) in resolve {
                builder = builder.resolve(host, address);
            }
        }
        let client = builder.build().map_err(|_| TrustError::Unavailable)?;
        Ok(Self { runtime, client })
    }
    async fn fetch(
        &self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        let mut current = initial(request.url())?;
        for hop in 0..=4 {
            budget.check()?;
            let remaining = budget
                .deadline()
                .saturating_duration_since(std::time::Instant::now());
            let mut outgoing = self
                .client
                .get(current.clone())
                .header(header::ACCEPT, request.accept())
                .header(header::ACCEPT_ENCODING, "identity")
                .timeout(remaining);
            if current.host_str() == Some("api.github.com") {
                outgoing = outgoing.header("X-GitHub-Api-Version", GITHUB_API_VERSION);
            }
            let mut response = outgoing.send().await.map_err(|_| TrustError::Unavailable)?;
            budget.check()?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let next = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(TrustError::Refused)?;
                if !request.permits_redirect(next, hop + 1) {
                    return Err(TrustError::Refused);
                }
                current = checked(next)?;
                continue;
            }
            let link = response.headers().contains_key(header::LINK);
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
                budget.check()?;
                if chunk.len() > request.max_bytes().saturating_sub(body.len()) {
                    return Err(TrustError::Refused);
                }
                body.extend_from_slice(&chunk);
            }
            budget.check()?;
            return Ok(AcquisitionResponse::new(status, Cursor::new(body), link));
        }
        Err(TrustError::Refused)
    }
}
impl AcquisitionTransport for HttpsTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        budget.check()?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(TrustError::Unavailable);
        }
        let result=self.runtime.block_on(async {
            tokio::select! {
                result=self.fetch(request,budget)=>result,
                _=async {loop {if budget.check().is_err(){break}tokio::time::sleep(POLL).await;}}=>Err(TrustError::Interrupted),
            }
        });
        // A transport timeout racing cancellation/deadline must never escape as
        // an ordinary error or late success after this selection was interrupted.
        budget.check()?;
        result
    }
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
