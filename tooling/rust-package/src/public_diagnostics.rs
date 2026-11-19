//! Repository CLI diagnostics only: never log URLs, headers, bodies or credentials.
use sbxr::artifact_trust::{
    AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
};
use sbxr::release_https::ProbeObservation;
use std::path::Path;

// The typed observation exposes only the bounded fields from the public transport.
// Receipt failures must not affect the verifier's output or decision.
pub(crate) fn retain_http_receipt(
    output: serde_json::Value,
    path: &Path,
    observation: Option<&ProbeObservation>,
) -> serde_json::Value {
    retain_serialized_receipt(output, path, observation.map(serde_json::to_vec))
}

fn retain_serialized_receipt(
    output: serde_json::Value,
    path: &Path,
    receipt: Option<serde_json::Result<Vec<u8>>>,
) -> serde_json::Value {
    if let Some(Ok(bytes)) = receipt {
        let _ = sbxr_rust_package::write_exclusive(path, &bytes);
    }
    output
}

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

    pub(crate) fn inner(&self) -> &T {
        &self.inner
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
    #[test]
    fn exclusive_receipt_write_preserves_the_actual_verifier_result() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let directory =
            std::env::temp_dir().join(format!("sbxr-http-receipt-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0.join("receipt.json"));
                let _ = fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("receipt.json");
        let expected = serde_json::json!({
            "outcome":"refused", "release_identity":null, "sequence":null,
            "acquisition_diagnostic":{"request_category":"latest_metadata","transport_outcome":"response","http_status":403}
        });
        let receipt = serde_json::json!({
            "stage":"latest_metadata","destination":"github_api","redirect_count":0,"http_status":403,
            "rate_limit_exhausted":true,"retry_after_present":false
        });
        let output = crate::verify_public(&mut DiagnosticTransport::new(Response(403)), None);
        assert_eq!(output, expected);
        assert_eq!(
            retain_serialized_receipt(output.clone(), &path, Some(serde_json::to_vec(&receipt))),
            expected
        );
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            receipt
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            retain_serialized_receipt(
                output,
                &path,
                Some(serde_json::to_vec(&serde_json::Value::Null))
            ),
            expected
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
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
