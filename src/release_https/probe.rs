//! Typed observations for the opt-in repository probe.
use super::{
    AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, HttpsTransport, Result,
    SelectionBudget,
};
use crate::artifact_trust::PublicRequestStage;
use reqwest::header::{self, HeaderMap};

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeDestination {
    #[serde(rename = "github_api")]
    GitHubApi,
    AttestationStorage,
    #[serde(rename = "github_release_cdn")]
    GitHubReleaseCdn,
    #[serde(rename = "other_github_content")]
    OtherGitHubContent,
    Other,
}

/// Site and response categories only. Raw request and response data stay in the
/// normal transport and cannot be serialized through this type.
#[derive(serde::Serialize)]
pub struct ProbeObservation {
    stage: PublicRequestStage,
    destination: Option<ProbeDestination>,
    redirect_count: usize,
    http_status: Option<u16>,
    rate_limit_exhausted: Option<bool>,
    retry_after_present: bool,
}

impl ProbeObservation {
    fn new(stage: PublicRequestStage) -> Self {
        Self {
            stage,
            destination: None,
            redirect_count: 0,
            http_status: None,
            rate_limit_exhausted: None,
            retry_after_present: false,
        }
    }

    pub(super) fn start_hop(&mut self, host: Option<&str>, redirect_count: usize) {
        *self = Self {
            destination: Some(match host {
                Some("api.github.com") => ProbeDestination::GitHubApi,
                Some("tmaproduction.blob.core.windows.net") => ProbeDestination::AttestationStorage,
                Some("release-assets.githubusercontent.com") => ProbeDestination::GitHubReleaseCdn,
                Some(host) if host.ends_with(".githubusercontent.com") => {
                    ProbeDestination::OtherGitHubContent
                }
                _ => ProbeDestination::Other,
            }),
            redirect_count,
            ..Self::new(self.stage)
        };
    }

    pub(super) fn observe_response(&mut self, status: u16, headers: &HeaderMap) {
        self.http_status = Some(status);
        self.retry_after_present = headers.contains_key(header::RETRY_AFTER);
        if matches!(self.destination, Some(ProbeDestination::GitHubApi)) {
            let mut remaining = headers.get_all("x-ratelimit-remaining").iter();
            if let (Some(value), None) = (remaining.next(), remaining.next()) {
                self.rate_limit_exhausted = value
                    .to_str()
                    .ok()
                    .filter(|v| {
                        !v.is_empty() && v.len() <= 5 && v.bytes().all(|b| b.is_ascii_digit())
                    })
                    .and_then(|v| v.parse::<u16>().ok())
                    .map(|v| v == 0);
            }
        }
    }
}

pub struct PublicProbeTransport {
    inner: HttpsTransport,
    last: Option<ProbeObservation>,
}

impl PublicProbeTransport {
    pub fn new() -> Result<Self> {
        HttpsTransport::new().map(Self::from_transport)
    }

    pub(super) fn from_transport(inner: HttpsTransport) -> Self {
        Self { inner, last: None }
    }

    pub fn diagnostic(&self) -> Option<&ProbeObservation> {
        self.last.as_ref()
    }
}

impl AcquisitionTransport for PublicProbeTransport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        let mut observation = ProbeObservation::new(request.stage);
        let result = self
            .inner
            .get_with_probe(request, budget, Some(&mut observation));
        self.last = Some(observation);
        result
    }
}
