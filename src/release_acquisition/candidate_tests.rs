//! Synthetic semantic fixtures never issue an authenticated candidate proof.
//! Genuine signed material tests use the real verifier and retain its exact bytes.
use super::*;
use crate::release_identity::ReleaseSupport;
use serde_json::json;
struct Fixture {
    manifest: Value,
    wire: Value,
    selected: ReleaseIdentity,
}
fn release(index: &ReleaseIndex, id: u64) -> Value {
    let identity = index.identity();
    let mut assets = index.assets().to_vec();
    assets.push(AssetProof::for_bytes("release-index.json", index.bytes()).unwrap());
    assets.sort_by(|a, b| a.name().cmp(b.name()));
    json!({"tag":identity.tag(),"commit":identity.commit(),"sequence":index.sequence(),"release_id":id,"release_identity":{"repository":REPOSITORY,"tag":identity.tag(),"commit":identity.commit(),"release_index_sha256":identity.index_sha256()},"assets":assets})
}
impl Fixture {
    fn new() -> Self {
        let assets = vec![
            AssetProof::for_bytes("install.sh", b"inert fixture").unwrap(),
            AssetProof::for_bytes("sbxr-linux-amd64.tar.gz", b"inert amd fixture").unwrap(),
            AssetProof::for_bytes("sbxr-linux-arm64.tar.gz", b"inert arm fixture").unwrap(),
        ];
        let index = ReleaseIndex::build(
            "v9.0.0",
            &"a".repeat(40),
            200,
            assets.clone(),
            Some(ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![]).unwrap()),
        )
        .unwrap();
        let baseline = ReleaseIndex::build(
            "v8.0.0",
            &"b".repeat(40),
            199,
            assets,
            Some(ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![]).unwrap()),
        )
        .unwrap();
        let selected = index.identity();
        let r = release(&index, 50);
        let base = release(&baseline, 49);
        let chain=vec![("candidate-preflight","accepted"),("candidate-draft-construction","actions-required"),("candidate-draft-verification","accepted")].into_iter().map(|(s,o)|json!({"stage":s,"outcome":o,"facts_sha256":"1".repeat(64),"decision_sha256":"2".repeat(64)})).collect::<Vec<_>>();
        let manifest = json!({"schema":"sbxr-qualification-manifest-v3","repository":REPOSITORY,"mode":"v3","source_state":"v3-subscription-clean","workflow":{"path":".github/workflows/candidate.yml","ref":"albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main","commit":selected.commit(),"run_id":"1234","run_url":"https://github.com/albertloky/SBXR/actions/runs/1234"},"approval":{"state":"approved","environments":[{"name":"acceptance-vps"}],"decision_chain":chain},"releases":[r],"native_evidence":[{"path":"native/native-v9.0.0-amd64/evidence/native-amd64.json","sha256":"3".repeat(64)},{"path":"native/native-v9.0.0-arm64/evidence/native-arm64.json","sha256":"4".repeat(64)}],"acceptance_vps_checklist_sha256":"5".repeat(64),"candidate_failure_state_sha256":"6".repeat(64),"pinned_actions":[format!("actions/checkout@{}","a".repeat(40))],"rescue":null,"v3_attempt":{"schema":"sbxr-v3-qualification-attempt-v3","candidate_index":std::str::from_utf8(index.bytes()).unwrap(),"support":{"scope":"subscription-clean-install-only","contract":"sbxr-subscription-update-v1","sources":[]},"sources":[],"evidence_policy":"mvp-http-live-v1","required_scenarios":["mvp-install","mvp-subscription","mvp-credentials","mvp-serving","mvp-removal"],"attempt_id":"run-1234-attempt-1","run_attempt":1,"baseline":base}});
        let wire_assets=r["assets"].as_array().unwrap().iter().enumerate().map(|(i,a)|json!({"name":a["name"],"size":a["size"],"digest":format!("sha256:{}",a["sha256"].as_str().unwrap()),"state":"uploaded","url":format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/{}",i+1)})).collect::<Vec<_>>();
        let wire = json!({"tag_name":selected.tag(),"target_commitish":selected.commit(),"body":"","draft":false,"prerelease":false,"immutable":true,"assets":wire_assets});
        Self {
            manifest,
            wire,
            selected,
        }
    }
    fn inspect(&self) -> Result<Inspected> {
        inspect(
            &serde_json::to_vec(&self.manifest).unwrap(),
            &serde_json::from_value(self.wire.clone()).unwrap(),
            &self.selected,
        )
    }
    fn signed_wrong_manifest_metadata(&self) -> Vec<u8> {
        let mut wire = self.wire.clone();
        wire["sbxr_qualification"] = json!({"manifest":STANDARD.encode(serde_json::to_vec(&self.manifest).unwrap()),"bundle":STANDARD.encode(include_bytes!("../../internal/softwarelifecycle/adapter/github/testdata/github-attestation.bundle"))});
        serde_json::to_vec(&wire).unwrap()
    }
}
#[test]
fn untrusted_semantics_bind_clean_install_workflow_approval_assets_and_raw_index() {
    let mut f = Fixture::new();
    let inspected = f.inspect().unwrap();
    assert_eq!(inspected.metadata.identity, f.selected);
    assert_eq!(inspected.metadata.sequence, 200);
    assert_eq!(
        inspected.index,
        f.manifest["v3_attempt"]["candidate_index"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    f.manifest["v3_attempt"]["proxy_profile"] = json!("vless-vmess");
    assert!(f.inspect().is_ok());
    f.manifest["v3_attempt"]["automated_only_scenarios"] = json!([]);
    assert!(
        f.inspect().is_err(),
        "two-node profile retains the Go nil automated-only contract"
    );
    // A structural positive is not an authenticated archive and has no public conversion.
}
#[test]
fn each_signed_security_binding_and_current_scope_refuses_mutation() {
    let f = Fixture::new();
    for (path, value) in [
        ("/schema", json!("sbxr-qualification-manifest-v1")),
        ("/repository", json!("foreign/repo")),
        ("/mode", json!("normal")),
        ("/source_state", json!("v3-recurring")),
        ("/rescue", json!({})),
        ("/workflow/path", json!(".github/workflows/other.yml")),
        (
            "/workflow/ref",
            json!("albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/other"),
        ),
        ("/workflow/commit", json!("b".repeat(40))),
        ("/workflow/run_id", json!("01234")),
        (
            "/workflow/run_url",
            json!("https://github.com/albertloky/SBXR/actions/runs/1235"),
        ),
        ("/approval/state", json!("unapproved")),
        ("/approval/environments/0/name", json!("production")),
        ("/approval/decision_chain/1/outcome", json!("accepted")),
        (
            "/approval/decision_chain/2/stage",
            json!("candidate-preflight"),
        ),
        ("/approval/decision_chain/0/facts_sha256", json!("bad")),
        ("/candidate_failure_state_sha256", json!("bad")),
        ("/acceptance_vps_checklist_sha256", json!("bad")),
        ("/native_evidence/0/path", json!("../foreign")),
        ("/native_evidence/1/sha256", json!("bad")),
        ("/pinned_actions/0", json!("actions/checkout@main")),
        ("/releases/0/commit", json!("b".repeat(40))),
        ("/releases/0/sequence", json!(201)),
        ("/releases/0/release_id", json!(0)),
        ("/releases/0/assets/0/size", json!(1)),
        ("/releases/0/assets/0/sha256", json!("7".repeat(64))),
        (
            "/v3_attempt/schema",
            json!("sbxr-v3-qualification-attempt-v2"),
        ),
        ("/v3_attempt/candidate_index", json!("changed raw bytes")),
        ("/v3_attempt/support/sources", json!(null)),
        (
            "/v3_attempt/support/scope",
            json!("subscription-clean-install-repair"),
        ),
        ("/v3_attempt/support/contract", json!("foreign")),
        ("/v3_attempt/sources", json!([{}])),
        ("/v3_attempt/evidence_policy", json!("mvp-live-v1")),
        ("/v3_attempt/required_scenarios", json!(["mvp-install"])),
        ("/v3_attempt/attempt_id", json!("run-9999-attempt-1")),
        ("/v3_attempt/run_attempt", json!(0)),
        ("/v3_attempt/baseline/sequence", json!(200)),
        ("/v3_attempt/baseline/release_id", json!(50)),
    ] {
        let mut bad = Fixture {
            manifest: f.manifest.clone(),
            wire: f.wire.clone(),
            selected: f.selected.clone(),
        };
        *bad.manifest.pointer_mut(path).unwrap() = value;
        assert!(bad.inspect().is_err(), "{path}");
    }
    for (key, value) in [
        ("owner_exception", json!("owner-exception")),
        ("automated_only_scenarios", json!(["mvp-install"])),
        ("late_confirmation_review", json!({})),
        ("live89_correction_review", json!({})),
        ("proxy_profile", json!("plugin")),
        ("unknown", json!(true)),
    ] {
        let mut bad = Fixture::new();
        bad.manifest["v3_attempt"][key] = value;
        assert!(bad.inspect().is_err(), "{key}");
    }
}
#[test]
fn raw_unknown_duplicate_null_and_changed_metadata_are_not_authority() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&f.manifest).unwrap();
    let mut duplicate = b"{\"repository\":\"albertloky/SBXR\",".to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    let wire: WireRelease = serde_json::from_value(f.wire.clone()).unwrap();
    assert!(inspect(&duplicate, &wire, &f.selected).is_err());
    for path in [
        "",
        "/approval",
        "/workflow",
        "/releases/0",
        "/releases/0/release_identity",
        "/releases/0/assets/0",
    ] {
        let mut bad = Fixture::new();
        let v = if path.is_empty() {
            &mut bad.manifest
        } else {
            bad.manifest.pointer_mut(path).unwrap()
        };
        v["unknown"] = json!(true);
        assert!(bad.inspect().is_err(), "{path}");
    }
    for path in ["/sources", "/support", "/baseline"] {
        let mut bad = Fixture::new();
        *bad.manifest["v3_attempt"].pointer_mut(path).unwrap() = Value::Null;
        assert!(bad.inspect().is_err(), "{path}");
    }
    for (path, value) in [
        ("/draft", json!(true)),
        ("/immutable", json!(false)),
        ("/prerelease", json!(true)),
        (
            "/assets/0/digest",
            json!(format!("sha256:{}", "8".repeat(64))),
        ),
        ("/assets/0/url", json!("https://foreign.example.invalid/1")),
    ] {
        let mut bad = Fixture::new();
        *bad.wire.pointer_mut(path).unwrap() = value;
        assert!(bad.inspect().is_err(), "{path}");
    }
}
struct OnlyMetadata {
    body: Vec<u8>,
    requests: Vec<String>,
}
impl AcquisitionTransport for OnlyMetadata {
    fn get(
        &mut self,
        r: &AcquisitionRequest,
        b: &SelectionBudget,
    ) -> Result<trust::AcquisitionResponse> {
        b.check()?;
        self.requests.push(r.url().into());
        if self.requests.len() != 1 || !r.url().ends_with("/releases/latest") {
            return Err(TrustError::Unavailable);
        }
        Ok(trust::AcquisitionResponse::new(
            200,
            std::io::Cursor::new(self.body.clone()),
            false,
        ))
    }
}
#[test]
fn genuine_bundle_cannot_sign_a_different_manifest_or_authorize_any_asset_get() {
    let f = Fixture::new();
    let body = f.signed_wrong_manifest_metadata();
    let mut t = OnlyMetadata {
        body: body.clone(),
        requests: vec![],
    };
    let selected = crate::records::ReleaseIdentity::new(
        f.selected.tag(),
        f.selected.commit(),
        f.selected.index_sha256(),
    )
    .unwrap();
    assert!(
        AuthenticatedCandidateArchive::acquire(
            &mut t,
            &selected,
            Architecture::Amd64,
            &SelectionBudget::new()
        )
        .is_err()
    );
    assert_eq!(
        t.requests.len(),
        1,
        "no asset request before genuine exact-manifest authentication"
    );
    assert!(
        Metadata::decode_exact(&body, &f.selected).is_err(),
        "candidate is never accepted by the stable route"
    );
    let cancelled = SelectionBudget::new();
    cancelled.cancel();
    t.requests.clear();
    assert_eq!(
        AuthenticatedCandidateArchive::acquire(&mut t, &selected, Architecture::Amd64, &cancelled)
            .unwrap_err(),
        TrustError::Interrupted
    );
    assert!(t.requests.is_empty());
    let genuine = include_bytes!(
        "../../internal/softwarelifecycle/adapter/github/testdata/github-attestation.bundle"
    );
    let policy = trust::VerificationPolicy::candidate_manifest(
        "0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476",
    )
    .unwrap();
    assert!(trust::verify_bundle(genuine, &policy, &SelectionBudget::new()).is_ok());
    assert!(
        trust::verify_candidate_manifest(
            genuine,
            &serde_json::to_vec(&f.manifest).unwrap(),
            &SelectionBudget::new()
        )
        .is_err()
    );
}
#[test]
fn canonical_bounded_gateway_byte_encoding_is_required() {
    for raw in ["", "!", "YQ", "YQ==\n"] {
        assert!(decode_base64(raw, 10).is_err());
    }
    assert_eq!(decode_base64("YQ==", 1).unwrap(), b"a");
    assert!(decode_base64("YWI=", 1).is_err());
}

#[test]
fn candidate_gateway_requires_the_exact_bounded_proof_wrapper() {
    let f = Fixture::new();
    let original: Value = serde_json::from_slice(&f.signed_wrong_manifest_metadata()).unwrap();
    for proof in [
        Value::Null,
        json!({}),
        json!({"manifest":"!", "bundle":"!"}),
        json!({"manifest":"YQ==", "bundle":"YQ==", "unknown":true}),
    ] {
        let mut wire = original.clone();
        wire["sbxr_qualification"] = proof;
        let selected = crate::records::ReleaseIdentity::new(
            f.selected.tag(),
            f.selected.commit(),
            f.selected.index_sha256(),
        )
        .unwrap();
        let mut t = OnlyMetadata {
            body: serde_json::to_vec(&wire).unwrap(),
            requests: vec![],
        };
        assert!(
            AuthenticatedCandidateArchive::acquire(
                &mut t,
                &selected,
                Architecture::Amd64,
                &SelectionBudget::new()
            )
            .is_err()
        );
        assert_eq!(t.requests.len(), 1);
    }
}
#[test]
fn interrupted_candidate_response_cannot_grant_late_authority() {
    use std::io::{Cursor, Read};
    struct CancelRead {
        bytes: Cursor<Vec<u8>>,
        stop: crate::subscription_serving::Cancellation,
    }
    impl Read for CancelRead {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            let n = self.bytes.read(dst)?;
            self.stop.cancel();
            Ok(n)
        }
    }
    struct Transport {
        body: Vec<u8>,
        stop: crate::subscription_serving::Cancellation,
        calls: usize,
    }
    impl AcquisitionTransport for Transport {
        fn get(
            &mut self,
            _: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<trust::AcquisitionResponse> {
            self.calls += 1;
            Ok(trust::AcquisitionResponse::new(
                200,
                CancelRead {
                    bytes: Cursor::new(self.body.clone()),
                    stop: self.stop.clone(),
                },
                false,
            ))
        }
    }
    let f = Fixture::new();
    let stop = crate::subscription_serving::Cancellation::new();
    let budget = SelectionBudget::new().with_cancellation(stop.clone());
    let mut t = Transport {
        body: f.signed_wrong_manifest_metadata(),
        stop,
        calls: 0,
    };
    let selected = crate::records::ReleaseIdentity::new(
        f.selected.tag(),
        f.selected.commit(),
        f.selected.index_sha256(),
    )
    .unwrap();
    assert_eq!(
        AuthenticatedCandidateArchive::acquire(&mut t, &selected, Architecture::Amd64, &budget)
            .unwrap_err(),
        TrustError::Interrupted
    );
    assert_eq!(t.calls, 1);
}
