//! Repository CLI diagnostics only: never log URLs, headers, bodies or credentials.
use sbxr::artifact_trust::{
    AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
};

pub(crate) struct DiagnosticTransport<T> {
    inner: T,
    last: serde_json::Value,
}
impl<T> DiagnosticTransport<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            last: serde_json::Value::Null,
        }
    }
    pub(crate) fn diagnostic(&self) -> serde_json::Value {
        self.last.clone()
    }
}
impl<T: AcquisitionTransport> AcquisitionTransport for DiagnosticTransport<T> {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse, TrustError> {
        let category = if request.url().ends_with("/releases/latest") {
            "latest_metadata"
        } else if request.url().contains("/releases/tags/") {
            "tagged_metadata"
        } else if request.url().contains("/attestations/") {
            "native_attestations"
        } else if request.accept() == "application/octet-stream" {
            "release_asset"
        } else {
            "other_public_request"
        };
        let result = self.inner.get(request, budget);
        let (outcome, status) = match &result {
            Ok(response) => ("response", Some(response.status())),
            Err(TrustError::Refused) => ("refused", None),
            Err(TrustError::Unavailable) => ("unavailable", None),
            Err(TrustError::Interrupted) => ("interrupted", None),
        };
        self.last = serde_json::json!({"request_category":category,"transport_outcome":outcome,"http_status":status});
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbxr::{release_acquisition::AuthenticatedArchive, release_identity::Architecture};
    use std::io::Cursor;

    struct Response(u16);
    impl AcquisitionTransport for Response {
        fn get(
            &mut self,
            _: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<AcquisitionResponse, TrustError> {
            Ok(AcquisitionResponse::new(
                self.0,
                Cursor::new(b"private response body".to_vec()),
                false,
            ))
        }
    }
    #[test]
    fn distinguishes_http_refusal_from_evidence_refusal_without_changing_decision() {
        for (status, expected) in [
            (403, TrustError::Refused),
            (429, TrustError::Unavailable),
            (200, TrustError::Refused),
        ] {
            let mut transport = DiagnosticTransport::new(Response(status));
            let result = AuthenticatedArchive::acquire_latest(
                &mut transport,
                Architecture::Amd64,
                &SelectionBudget::new(),
            );
            assert_eq!(result.err(), Some(expected));
            assert_eq!(
                transport.diagnostic(),
                serde_json::json!({"request_category":"latest_metadata","transport_outcome":"response","http_status":status})
            );
            assert!(!transport.diagnostic().to_string().contains("private"));
        }
    }
    struct Failure(TrustError);
    impl AcquisitionTransport for Failure {
        fn get(
            &mut self,
            _: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<AcquisitionResponse, TrustError> {
            Err(self.0)
        }
    }
    #[test]
    fn preserves_transport_errors_and_reports_no_invented_http_status() {
        for (error, name) in [
            (TrustError::Refused, "refused"),
            (TrustError::Unavailable, "unavailable"),
            (TrustError::Interrupted, "interrupted"),
        ] {
            let mut transport = DiagnosticTransport::new(Failure(error));
            assert!(transport.diagnostic().is_null());
            let result = AuthenticatedArchive::acquire_latest(
                &mut transport,
                Architecture::Amd64,
                &SelectionBudget::new(),
            );
            assert_eq!(result.err(), Some(error));
            assert_eq!(
                transport.diagnostic(),
                serde_json::json!({"request_category":"latest_metadata","transport_outcome":name,"http_status":null})
            );
        }
    }
}
