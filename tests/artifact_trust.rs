//! Offline trust-policy tests. Synthetic claims never establish authentication.
use release_identity::{AssetProof, RELEASE_ASSET_NAMES, ReleaseIdentity};
use sbxr::artifact_trust::*;
use sbxr::{records, release_identity};
use std::io::{self, Cursor, Read};
use std::time::{Duration, Instant};

const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TAG: &str = "v3.2.1";
const NATIVE_COMMIT: &str = "c5e17a62e06a1d201570249c61fae531e9244e1b";
const MANIFEST_SHA256: &str = "0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476";
const CANDIDATE_BUNDLE: &[u8] = include_bytes!(
    "../internal/softwarelifecycle/adapter/github/testdata/github-attestation.bundle"
);
const NATIVE_BUNDLE: &[u8] = include_bytes!(
    "../internal/softwarelifecycle/adapter/github/testdata/github_release_bundle.json"
);

fn expected() -> ExpectedRelease {
    let proofs = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::new(name, 1, &"a".repeat(64)).unwrap())
        .collect();
    ExpectedRelease::new(
        ReleaseIdentity::new(TAG, COMMIT, &"a".repeat(64)).unwrap(),
        proofs,
    )
    .unwrap()
}

#[test]
fn genuine_candidate_bundle_authenticates_exact_workflow_manifest_digest_and_payload() {
    let policy = VerificationPolicy::candidate_manifest(
        "0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476",
    )
    .unwrap();
    let bundle = include_bytes!(
        "../internal/softwarelifecycle/adapter/github/testdata/github-attestation.bundle"
    );
    let verified = verify_bundle(bundle, &policy, &SelectionBudget::new()).unwrap();
    assert_eq!(verified.policy(), &policy);
    assert_eq!(verified.bundle_sha256(), records::sha256_hex(bundle));
    let parsed =
        sigstore_verify::types::Bundle::from_json(std::str::from_utf8(bundle).unwrap()).unwrap();
    let sigstore_verify::types::SignatureContent::DsseEnvelope(envelope) = parsed.content else {
        panic!("fixture must be DSSE")
    };
    assert_eq!(verified.payload(), envelope.payload.as_bytes());
    assert!(!format!("{verified:?}").contains("predicate"));
    let wrong = VerificationPolicy::candidate_manifest(&"c".repeat(64)).unwrap();
    assert_eq!(
        verify_bundle(bundle, &wrong, &SelectionBudget::new()).unwrap_err(),
        TrustError::Refused
    );
}

#[test]
fn genuine_native_bundle_authenticates_tsa_and_exact_sha1_but_foreign_claims_refuse() {
    let policy = VerificationPolicy::native_release(NATIVE_COMMIT).unwrap();
    let verified = verify_bundle(NATIVE_BUNDLE, &policy, &SelectionBudget::new()).unwrap();
    assert_eq!(verified.policy(), &policy);
    assert_eq!(verified.bundle_sha256(), records::sha256_hex(NATIVE_BUNDLE));
    let payload: serde_json::Value = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(payload["subject"][0]["digest"]["sha1"], NATIVE_COMMIT);
    assert_eq!(payload["predicate"]["repository"], "bdehamer/delme");
    let wrong = VerificationPolicy::native_release(COMMIT).unwrap();
    assert_eq!(
        verify_bundle(NATIVE_BUNDLE, &wrong, &SelectionBudget::new()).unwrap_err(),
        TrustError::Refused
    );
    let proofs = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::new(name, 1, &"a".repeat(64)).unwrap())
        .collect();
    let expected = ExpectedRelease::new(
        ReleaseIdentity::new(TAG, NATIVE_COMMIT, &"a".repeat(64)).unwrap(),
        proofs,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(NATIVE_BUNDLE).unwrap();
    let mut transport = Transport::ok(page(vec![
        serde_json::json!({"initiator":"github", "bundle":value}),
    ]));
    match verify_native_release(&mut transport, &expected, &SelectionBudget::new()) {
        Ok(claims) => panic!(
            "foreign claims admitted: {:?}, count {}, index {:?}",
            claims.identity(),
            claims.proof_count(),
            claims.asset("release-index.json")
        ),
        Err(error) => assert_eq!(error, TrustError::Refused),
    }
}

fn bundle_value(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}
fn flip_base64(value: &mut serde_json::Value) {
    let mut bytes = value.as_str().unwrap().as_bytes().to_vec();
    bytes[8] = if bytes[8] == b'A' { b'B' } else { b'A' };
    *value = String::from_utf8(bytes).unwrap().into();
}
fn changed_payload(body: &[u8], change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    use sigstore_verify::types::{Bundle, PayloadBytes, SignatureContent};
    let mut bundle = Bundle::from_json(std::str::from_utf8(body).unwrap()).unwrap();
    let SignatureContent::DsseEnvelope(envelope) = &mut bundle.content else {
        panic!("expected DSSE")
    };
    let mut payload: serde_json::Value =
        serde_json::from_slice(envelope.payload.as_bytes()).unwrap();
    change(&mut payload);
    envelope.payload = PayloadBytes::new(encoded(payload));
    serde_json::to_vec(&bundle).unwrap()
}

#[test]
fn signature_certificate_payload_and_timestamp_tampering_are_rejected() {
    for (body, policy) in [
        (
            NATIVE_BUNDLE,
            VerificationPolicy::native_release(NATIVE_COMMIT).unwrap(),
        ),
        (
            CANDIDATE_BUNDLE,
            VerificationPolicy::candidate_manifest(MANIFEST_SHA256).unwrap(),
        ),
    ] {
        let mut signature = bundle_value(body);
        flip_base64(&mut signature["dsseEnvelope"]["signatures"][0]["sig"]);
        let mut certificate = bundle_value(body);
        let material = &mut certificate["verificationMaterial"];
        if material.get("certificate").is_some() {
            flip_base64(&mut material["certificate"]["rawBytes"]);
        } else {
            flip_base64(&mut material["x509CertificateChain"]["certificates"][0]["rawBytes"]);
        }
        let payload = changed_payload(body, |value| {
            value["predicate"]["unsigned_extra"] = "tampered".into();
        });
        let mut multiple = bundle_value(body);
        let signature_copy = multiple["dsseEnvelope"]["signatures"][0].clone();
        multiple["dsseEnvelope"]["signatures"]
            .as_array_mut()
            .unwrap()
            .push(signature_copy);
        let mut wrong_type = bundle_value(body);
        wrong_type["dsseEnvelope"]["payloadType"] = "application/json".into();
        for bad in [
            encoded(signature),
            encoded(certificate),
            payload,
            encoded(multiple),
            encoded(wrong_type),
        ] {
            assert_eq!(
                verify_bundle(&bad, &policy, &SelectionBudget::new()).unwrap_err(),
                TrustError::Refused
            );
        }
    }
    let mut no_timestamp = bundle_value(NATIVE_BUNDLE);
    no_timestamp["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"] =
        serde_json::json!([]);
    let mut altered_timestamp = bundle_value(NATIVE_BUNDLE);
    flip_base64(
        &mut altered_timestamp["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
            [0]["signedTimestamp"],
    );
    let policy = VerificationPolicy::native_release(NATIVE_COMMIT).unwrap();
    for bad in [no_timestamp, altered_timestamp] {
        assert_eq!(
            verify_bundle(&encoded(bad), &policy, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
}

#[test]
fn candidate_requires_authenticated_rekor_proof_and_observer_time() {
    let mut no_log = bundle_value(CANDIDATE_BUNDLE);
    no_log["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
    let mut no_set = bundle_value(CANDIDATE_BUNDLE);
    no_set["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap()
        .remove("inclusionPromise");
    let mut changed_time = bundle_value(CANDIDATE_BUNDLE);
    changed_time["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = "1".into();
    let mut changed_set = bundle_value(CANDIDATE_BUNDLE);
    flip_base64(
        &mut changed_set["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]["signedEntryTimestamp"],
    );
    let mut changed_merkle_root = bundle_value(CANDIDATE_BUNDLE);
    flip_base64(
        &mut changed_merkle_root["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"],
    );
    let mut borrowed_tsa = bundle_value(CANDIDATE_BUNDLE);
    borrowed_tsa["verificationMaterial"]["timestampVerificationData"] =
        bundle_value(NATIVE_BUNDLE)["verificationMaterial"]["timestampVerificationData"].clone();
    let policy = VerificationPolicy::candidate_manifest(MANIFEST_SHA256).unwrap();
    for bad in [
        no_log,
        no_set,
        changed_time,
        changed_set,
        changed_merkle_root,
        borrowed_tsa,
    ] {
        assert_eq!(
            verify_bundle(&encoded(bad), &policy, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
}

#[test]
fn forged_subjects_cannot_rebind_a_genuine_signature_to_different_bytes() {
    let native = changed_payload(NATIVE_BUNDLE, |payload| {
        payload["subject"][0]["digest"]["sha1"] = COMMIT.into()
    });
    let candidate = changed_payload(CANDIDATE_BUNDLE, |payload| {
        payload["subject"][0]["digest"]["sha256"] = "c".repeat(64).into()
    });
    for (body, policy) in [
        (native, VerificationPolicy::native_release(COMMIT).unwrap()),
        (
            candidate,
            VerificationPolicy::candidate_manifest(&"c".repeat(64)).unwrap(),
        ),
    ] {
        assert_eq!(
            verify_bundle(&body, &policy, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
    assert!(verify_candidate_manifest(CANDIDATE_BUNDLE, b"{}", &SelectionBudget::new()).is_err());
    assert!(
        verify_candidate_manifest(
            CANDIDATE_BUNDLE,
            b"{\"a\":1,\"a\":1}",
            &SelectionBudget::new()
        )
        .is_err()
    );
    assert!(verify_candidate_manifest(CANDIDATE_BUNDLE, b"", &SelectionBudget::new()).is_err());
}

#[test]
fn genuine_signatures_do_not_bypass_go_unknown_bundle_field_refusals() {
    let policy = VerificationPolicy::candidate_manifest(MANIFEST_SHA256).unwrap();
    let mut root = bundle_value(CANDIDATE_BUNDLE);
    root["unknown"] = true.into();
    let mut material = bundle_value(CANDIDATE_BUNDLE);
    material["verificationMaterial"]["unknown"] = true.into();
    let mut envelope = bundle_value(CANDIDATE_BUNDLE);
    envelope["dsseEnvelope"]["unknown"] = true.into();
    let mut signature = bundle_value(CANDIDATE_BUNDLE);
    signature["dsseEnvelope"]["signatures"][0]["unknown"] = true.into();
    let mut tlog = bundle_value(CANDIDATE_BUNDLE);
    tlog["verificationMaterial"]["tlogEntries"][0]["unknown"] = true.into();
    for bad in [root, material, envelope, signature, tlog] {
        assert_eq!(
            verify_bundle(&encoded(bad), &policy, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
    for path in [
        "/verificationMaterial/tlogEntries/0/logId",
        "/verificationMaterial/tlogEntries/0/kindVersion",
        "/verificationMaterial/tlogEntries/0/inclusionPromise",
        "/verificationMaterial/tlogEntries/0/inclusionProof",
        "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint",
    ] {
        let mut bad = bundle_value(CANDIDATE_BUNDLE);
        bad.pointer_mut(path).unwrap()["unknown"] = true.into();
        assert_eq!(
            verify_bundle(&encoded(bad), &policy, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
    let native = VerificationPolicy::native_release(NATIVE_COMMIT).unwrap();
    for path in [
        "/verificationMaterial/certificate",
        "/verificationMaterial/timestampVerificationData",
        "/verificationMaterial/timestampVerificationData/rfc3161Timestamps/0",
    ] {
        let mut bad = bundle_value(NATIVE_BUNDLE);
        bad.pointer_mut(path).unwrap()["unknown"] = true.into();
        assert_eq!(
            verify_bundle(&encoded(bad), &native, &SelectionBudget::new()).unwrap_err(),
            TrustError::Refused
        );
    }
}

#[test]
fn complete_native_claim_set_is_inspected_without_granting_trust() {
    let body = include_bytes!("testdata/artifact_trust/native-statement.json");
    let claims = inspect_native_claim_set(
        &[body.as_slice(), body.as_slice()],
        &expected(),
        &SelectionBudget::new(),
    )
    .unwrap();
    assert_eq!(claims.identity().tag(), TAG);
    assert_eq!(claims.proof_count(), 2);
    assert!(format!("{claims:?}").contains("Unauthenticated"));
}

#[test]
fn cancelled_and_expired_selection_refuse_before_acceptance() {
    let expired = SelectionBudget::until(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        inspect_native_claim_set(&[], &expected(), &expired).unwrap_err(),
        TrustError::Interrupted
    );
    let cancelled = SelectionBudget::new();
    cancelled.cancel();
    assert_eq!(
        inspect_native_claim_set(&[], &expected(), &cancelled).unwrap_err(),
        TrustError::Interrupted
    );
}

fn statement() -> serde_json::Value {
    serde_json::from_slice(include_bytes!(
        "testdata/artifact_trust/native-statement.json"
    ))
    .unwrap()
}
fn encoded(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn inspected(statements: &[&[u8]]) -> Result<UnauthenticatedReleaseClaims, TrustError> {
    inspect_native_claim_set(statements, &expected(), &SelectionBudget::new())
}

#[test]
fn equivalent_claims_can_differ_in_ids_format_and_subject_order() {
    let original = encoded(statement());
    let mut equivalent = statement();
    equivalent["predicate"]["databaseId"] = "different nonempty opaque id".into();
    equivalent["subject"].as_array_mut().unwrap().swap(1, 4);
    let equivalent = serde_json::to_vec_pretty(&equivalent).unwrap();
    let mut other = statement();
    other["predicate"]["tag"] = "v3.2.0".into();
    other["predicate"]["purl"] = "pkg:github/albertloky/SBXR@v3.2.0".into();
    other["subject"][0]["uri"] = "pkg:github/albertloky/SBXR@v3.2.0".into();
    other["subject"][1]["digest"]["sha256"] = "c".repeat(64).into();
    let other = encoded(other);
    assert_eq!(
        inspected(&[&original, &other, &equivalent])
            .unwrap()
            .proof_count(),
        3
    );
    assert!(inspected(&[&other]).is_err());
    assert!(inspected(&[]).is_err());
    assert!(inspected(&vec![original.as_slice(); 99]).is_ok());
    assert!(inspected(&vec![original.as_slice(); 100]).is_err());
}

#[test]
fn every_conflicting_or_invalid_proof_refuses_in_either_order() {
    let valid = encoded(statement());
    let mut changes = Vec::new();
    for (path, replacement) in [
        ("_type", "https://in-toto.io/Statement/v0.1"),
        (
            "predicateType",
            "https://in-toto.io/attestation/release/v0.1",
        ),
    ] {
        let mut v = statement();
        v[path] = replacement.into();
        changes.push(v);
    }
    for (key, replacement) in [
        ("repository", "attacker/SBXR"),
        ("purl", "pkg:github/attacker/SBXR@v3.2.1"),
        ("tag", "v03.2.1"),
        ("databaseId", ""),
        ("ownerId", ""),
        ("packageId", ""),
        ("repositoryId", ""),
    ] {
        let mut v = statement();
        v["predicate"][key] = replacement.into();
        changes.push(v);
    }
    let mut v = statement();
    v["subject"][0]["digest"]["sha1"] = "c".repeat(40).into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1]["digest"]["sha256"] = "c".repeat(64).into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1]["digest"]["sha256"] = "A".repeat(64).into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1]["digest"]["sha1"] = COMMIT.into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1]["uri"] = "unexpected".into();
    changes.push(v);
    let mut v = statement();
    v["subject"][0]["name"] = "unexpected".into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1]["name"] = "unknown.tar.gz".into();
    changes.push(v);
    let mut v = statement();
    v["subject"][2]["name"] = "install.sh".into();
    changes.push(v);
    let mut v = statement();
    v["subject"].as_array_mut().unwrap().pop();
    changes.push(v);
    let mut v = statement();
    v["predicate"]["unknown"] = "no".into();
    changes.push(v);
    let mut v = statement();
    v["predicate"]["ownerId"] = serde_json::Value::Null;
    changes.push(v);
    let mut v = statement();
    v["predicate"]["ownerId"] = 123.into();
    changes.push(v);
    let mut v = statement();
    v["subject"][1] = serde_json::json!(["install.sh", {"sha256":"a".repeat(64)}]);
    changes.push(v);
    for v in changes {
        let bad = encoded(v);
        assert_eq!(inspected(&[&valid, &bad]).unwrap_err(), TrustError::Refused);
        assert_eq!(inspected(&[&bad, &valid]).unwrap_err(), TrustError::Refused);
    }
    // An invalid apparent other-tag claim cannot be skipped.
    let other = String::from_utf8(valid.clone())
        .unwrap()
        .replace(TAG, "v3.2.0")
        .replace(COMMIT, &"c".repeat(40));
    assert!(inspected(&[&valid, other.as_bytes()]).is_err());
}

#[test]
fn unique_json_rejects_escaped_nested_duplicates_and_trailing_documents() {
    let body = String::from_utf8(encoded(statement())).unwrap();
    for bad in [
        body.replacen(
            "\"ownerId\":\"456\"",
            "\"ownerId\":\"456\",\"owner\\u0049d\":\"456\"",
            1,
        ),
        body.replacen(
            "\"sha1\":",
            "\"sha1\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"sha1\":",
            1,
        ),
        format!("{body} {{}}"),
        "[]".into(),
        "null".into(),
        String::new(),
        " ".repeat(MAX_BUNDLE_BYTES + 1),
    ] {
        assert!(inspected(&[bad.as_bytes()]).is_err());
    }
    assert!(inspected(&[format!(" \n{body}\n").as_bytes()]).is_ok());
}

#[test]
fn exact_asset_metadata_set_and_index_binding_are_required() {
    let identity = ReleaseIdentity::new(TAG, COMMIT, &"a".repeat(64)).unwrap();
    let asset = AssetProof::new("release-index.json", 1, &"a".repeat(64)).unwrap();
    assert!(ExpectedRelease::new(identity.clone(), vec![asset.clone()]).is_err());
    let mut assets: Vec<_> = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::new(name, 1, &"a".repeat(64)).unwrap())
        .collect();
    assets.push(asset);
    assert!(ExpectedRelease::new(identity.clone(), assets).is_err());
    let changed = ReleaseIdentity::new(TAG, COMMIT, &"c".repeat(64)).unwrap();
    let assets = RELEASE_ASSET_NAMES
        .iter()
        .map(|name| AssetProof::new(name, 1, &"a".repeat(64)).unwrap())
        .collect();
    assert!(ExpectedRelease::new(changed, assets).is_err());
}

#[test]
fn root_bytes_and_signer_policies_match_preserved_go_contract() {
    let native = VerificationPolicy::native_release(COMMIT).unwrap();
    assert_eq!(native.signer(), "https://dotcom.releases.github.com");
    assert_eq!(native.issuer(), None);
    assert_eq!(native.digest_algorithm(), "sha1");
    assert_eq!(native.digest(), COMMIT);
    assert_eq!(native.signed_timestamp_threshold(), 1);
    assert_eq!(native.transparency_log_threshold(), 0);
    assert_eq!(native.observer_timestamp_threshold(), 0);
    let candidate = VerificationPolicy::candidate_manifest(&"a".repeat(64)).unwrap();
    assert_eq!(candidate.signer(), CANDIDATE_SIGNER);
    assert_eq!(candidate.issuer(), Some(CANDIDATE_ISSUER));
    assert_eq!(candidate.digest_algorithm(), "sha256");
    assert_eq!(candidate.digest(), "a".repeat(64));
    assert_eq!(candidate.signed_timestamp_threshold(), 0);
    assert_eq!(candidate.transparency_log_threshold(), 1);
    assert_eq!(candidate.observer_timestamp_threshold(), 1);
    for policy in [native, candidate] {
        let root = policy.root();
        assert_eq!(
            records::sha256_hex(root.bytes().unwrap()),
            root.fingerprint()
        );
    }
    for bad in [
        "",
        "main",
        &"A".repeat(40),
        &"a".repeat(39),
        &"a".repeat(41),
    ] {
        assert!(VerificationPolicy::native_release(bad).is_err());
    }
    for bad in ["", &"A".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
        assert!(VerificationPolicy::candidate_manifest(bad).is_err());
    }
}

#[test]
fn candidate_subject_binds_exact_manifest_bytes_and_one_subject() {
    let manifest = b"offline manifest\n";
    let subject = serde_json::json!({"name":"qualification-manifest.json", "digest":{"sha256":records::sha256_hex(manifest)}});
    let valid = serde_json::json!({"_type":"https://in-toto.io/Statement/v1", "subject":[subject.clone()], "predicateType":"https://slsa.dev/provenance/v1", "predicate":{}});
    let body = encoded(valid.clone());
    assert!(inspect_candidate_statement(&body, manifest).is_ok());
    assert!(inspect_candidate_statement(&body, b"offline manifest").is_err());
    assert!(inspect_candidate_statement(&body, b"").is_err());
    assert!(inspect_candidate_statement(&body, &vec![0; (1 << 20) + 1]).is_err());
    let mut duplicate = valid.clone();
    duplicate["subject"].as_array_mut().unwrap().push(subject);
    let mut bad_name = valid.clone();
    bad_name["subject"][0]["name"] = "other.json".into();
    let mut extra_digest = valid.clone();
    extra_digest["subject"][0]["digest"]["sha1"] = COMMIT.into();
    for bad in [duplicate, bad_name, extra_digest] {
        assert!(inspect_candidate_statement(&encoded(bad), manifest).is_err());
    }
    let ignored_duplicate = String::from_utf8(body)
        .unwrap()
        .replace("\"predicate\":{}", "\"predicate\":{\"a\":1,\"\\u0061\":1}");
    assert!(inspect_candidate_statement(ignored_duplicate.as_bytes(), manifest).is_err());
}

fn inline() -> serde_json::Value {
    serde_json::json!({"initiator":"github", "bundle":{"mediaType":"unverified fixture"}})
}
fn page(entries: Vec<serde_json::Value>) -> Vec<u8> {
    encoded(serde_json::json!({"attestations":entries}))
}

#[test]
fn native_page_requires_complete_unsaturated_all_github_history() {
    let budget = SelectionBudget::new();
    assert!(NativeAttestations::decode(&page(vec![inline(); 99]), false, &budget).is_ok());
    for (body, linked) in [
        (page(vec![]), false),
        (page(vec![inline(); 100]), false),
        (page(vec![inline()]), true),
        (b"{\"attestations\":null}".to_vec(), false),
        (
            page(vec![
                serde_json::json!({"initiator":"external", "bundle":{}}),
                inline(),
            ]),
            false,
        ),
        (
            page(vec![
                inline(),
                serde_json::json!({"initiator":"external", "bundle":{}}),
            ]),
            false,
        ),
        (
            page(vec![serde_json::json!({"initiator":"github", "bundle":[]})]),
            false,
        ),
        (b"{\"attestations\":[],\"attestations\":[]}".to_vec(), false),
        (
            b"{\"attestations\":[{\"initiator\":\"github\",\"bundle\":{\"a\":1,\"a\":1}}]}"
                .to_vec(),
            false,
        ),
    ] {
        assert_eq!(
            NativeAttestations::decode(&body, linked, &budget).unwrap_err(),
            TrustError::Refused
        );
    }
}

#[test]
fn bundle_source_selection_retains_inline_precedence_and_exact_blob_host() {
    let budget = SelectionBudget::new();
    let both =
        serde_json::json!({"initiator":"github", "bundle":{}, "bundle_url":"http://attacker.test"});
    let got = NativeAttestations::decode(&page(vec![both]), false, &budget).unwrap();
    assert!(matches!(&got.bundles()[0], UnverifiedBundle::Inline(bytes) if bytes == b"{}"));
    let valid = "https://tmaproduction.blob.core.windows.net/path/bundle?sig=opaque";
    let got = NativeAttestations::decode(
        &page(vec![
            serde_json::json!({"initiator":"github", "bundle":null, "bundle_url":valid}),
        ]),
        false,
        &budget,
    )
    .unwrap();
    assert!(matches!(&got.bundles()[0], UnverifiedBundle::SnappyUrl(url) if url == valid));
    assert!(!format!("{got:?}").contains("sig=opaque"));
    for url in [
        "http://tmaproduction.blob.core.windows.net/a",
        "https://tmaproduction.blob.core.windows.net.attacker.test/a",
        "https://tmaproduction.blob.core.windows.net@attacker.test/a",
        "https://user@tmaproduction.blob.core.windows.net/a",
        "https://tmaproduction.blob.core.windows.net:444/a",
        "https://tmaproduction.blob.core.windows.net/a#fragment",
        "https://tmaproduction.blob.core.windows.net/",
        "https://tmaproduction.blob.core.windows.net/a\nheader",
        "https://tmaproduction.blob.core.windows.net/a\\b",
        "https://tmaproduction.blob.core.windows.net/💥",
    ] {
        assert!(
            NativeAttestations::decode(
                &page(vec![
                    serde_json::json!({"initiator":"github", "bundle_url":url})
                ]),
                false,
                &budget
            )
            .is_err()
        );
    }
}

#[test]
fn json_depth_and_node_limits_bound_ignored_metadata_too() {
    let mut value = serde_json::json!({"attestations":[inline()]});
    value["untrusted_metadata"] = serde_json::json!(vec![0; 100_001]);
    assert_eq!(
        NativeAttestations::decode(&encoded(value), false, &SelectionBudget::new()).unwrap_err(),
        TrustError::Refused
    );
    let deep = format!("{{\"metadata\":{}0{}}}", "[".repeat(130), "]".repeat(130));
    assert!(NativeAttestations::decode(deep.as_bytes(), false, &SelectionBudget::new()).is_err());
}

struct Transport {
    body: Vec<u8>,
    status: u16,
    link: bool,
    seen: Vec<(String, String, usize)>,
    cancel: bool,
}
impl Transport {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            status: 200,
            link: false,
            seen: vec![],
            cancel: false,
        }
    }
}
impl AcquisitionTransport for Transport {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse, TrustError> {
        assert!(budget.deadline() <= Instant::now() + SELECTION_TIMEOUT);
        self.seen.push((
            request.url().into(),
            request.accept().into(),
            request.max_bytes(),
        ));
        assert!(request.permits_redirect("https://release-assets.githubusercontent.com/path", 4));
        assert!(request.permits_redirect("https://objects.githubusercontent.com/path", 1));
        assert!(request.permits_redirect("https://objects.githubusercontent.com:443/path", 1));
        for url in [
            "http://objects.githubusercontent.com/path",
            "https://objects.githubusercontent.com.attacker.test/path",
            "https://attacker@objects.githubusercontent.com/path",
            "https://objects.githubusercontent.com:444/path",
            "https://objects.githubusercontent.com/path#fragment",
            "https://objects.githubusercontent.com/\r\nheader",
            "https://objects.githubusercontent.com\\@attacker.test/path",
            "https://.githubusercontent.com/path",
        ] {
            assert!(!request.permits_redirect(url, 1), "{url}");
        }
        assert!(!request.permits_redirect("https://objects.githubusercontent.com/path", 5));
        if self.cancel {
            budget.cancel();
        }
        Ok(AcquisitionResponse::new(
            self.status,
            Cursor::new(self.body.clone()),
            self.link,
        ))
    }
}

#[test]
fn cancelled_read_cannot_return_digest_checked_material() {
    use std::sync::Arc;
    struct Reader {
        budget: Arc<SelectionBudget>,
    }
    impl Read for Reader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            output[0] = b'x';
            self.budget.cancel();
            Ok(1)
        }
    }
    struct ReadTransport {
        budget: Arc<SelectionBudget>,
    }
    impl AcquisitionTransport for ReadTransport {
        fn get(
            &mut self,
            _: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<AcquisitionResponse, TrustError> {
            Ok(AcquisitionResponse::new(
                200,
                Reader {
                    budget: self.budget.clone(),
                },
                false,
            ))
        }
    }
    let budget = Arc::new(SelectionBudget::new());
    let mut transport = ReadTransport {
        budget: budget.clone(),
    };
    let proof = AssetProof::for_bytes("install.sh", b"x").unwrap();
    assert_eq!(
        acquire_digest_checked_asset(&mut transport, 1, &proof, &budget).unwrap_err(),
        TrustError::Interrupted
    );
}

#[test]
fn raw_snappy_bundle_acquisition_preserves_exact_genuine_signed_bytes() {
    let url = "https://tmaproduction.blob.core.windows.net/offline-fixture";
    let budget = SelectionBudget::new();
    let proofs = NativeAttestations::decode(
        &page(vec![
            serde_json::json!({"initiator":"github", "bundle_url":url}),
        ]),
        false,
        &budget,
    )
    .unwrap();
    let compressed = snap::raw::Encoder::new()
        .compress_vec(NATIVE_BUNDLE)
        .unwrap();
    let mut transport = Transport::ok(compressed);
    let acquired = proofs.acquire_bundle(0, &mut transport, &budget).unwrap();
    assert_eq!(acquired, NATIVE_BUNDLE);
    assert_eq!(
        transport.seen[0],
        (
            url.into(),
            "application/octet-stream".into(),
            MAX_BUNDLE_BYTES
        )
    );
    let verified = verify_bundle(
        &acquired,
        &VerificationPolicy::native_release(NATIVE_COMMIT).unwrap(),
        &budget,
    )
    .unwrap();
    assert_eq!(verified.bundle_sha256(), records::sha256_hex(NATIVE_BUNDLE));
    let mut untouched = Transport::ok(vec![]);
    assert!(proofs.acquire_bundle(1, &mut untouched, &budget).is_err());
    assert!(untouched.seen.is_empty());
}

#[test]
fn raw_snappy_bundle_decoding_refuses_bombs_invalid_data_and_duplicate_json() {
    let budget = SelectionBudget::new();
    let proofs = NativeAttestations::decode(&page(vec![serde_json::json!({"initiator":"github", "bundle_url":"https://tmaproduction.blob.core.windows.net/offline-fixture"})]), false, &budget).unwrap();
    let mut encoder = snap::raw::Encoder::new();
    let oversized_json = encoded(serde_json::json!({"padding":"x".repeat(MAX_BUNDLE_BYTES)}));
    assert!(oversized_json.len() > MAX_BUNDLE_BYTES);
    let huge = encoder.compress_vec(&oversized_json).unwrap();
    assert!(huge.len() < MAX_BUNDLE_BYTES);
    for bad in [
        vec![255; 10],
        encoder.compress_vec(b"").unwrap(),
        encoder.compress_vec(b"[]").unwrap(),
        encoder.compress_vec(b"{\"a\":1,\"a\":1}").unwrap(),
        huge,
    ] {
        let mut transport = Transport::ok(bad);
        assert_eq!(
            proofs
                .acquire_bundle(0, &mut transport, &budget)
                .unwrap_err(),
            TrustError::Refused
        );
    }
}

#[test]
fn signature_verification_obeys_existing_cancellation_and_selection_deadline() {
    let policy = VerificationPolicy::candidate_manifest(MANIFEST_SHA256).unwrap();
    let cancelled = SelectionBudget::new();
    cancelled.cancel();
    assert_eq!(
        verify_bundle(CANDIDATE_BUNDLE, &policy, &cancelled).unwrap_err(),
        TrustError::Interrupted
    );
    let expired = SelectionBudget::until(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        verify_bundle(CANDIDATE_BUNDLE, &policy, &expired).unwrap_err(),
        TrustError::Interrupted
    );
}

#[test]
fn injectable_acquisition_binds_exact_repository_and_bounded_page() {
    let mut transport = Transport::ok(page(vec![inline()]));
    let result =
        acquire_native_attestations(&mut transport, COMMIT, &SelectionBudget::new()).unwrap();
    assert_eq!(result.bundles().len(), 1);
    assert_eq!(
        transport.seen[0],
        (
            format!(
                "https://api.github.com/repos/albertloky/SBXR/attestations/sha1:{COMMIT}?predicate_type=release&per_page=100"
            ),
            "application/vnd.github+json".into(),
            MAX_BUNDLE_BYTES
        )
    );
    for status in [408, 429, 500, 503] {
        transport.status = status;
        assert_eq!(
            acquire_native_attestations(&mut transport, COMMIT, &SelectionBudget::new())
                .unwrap_err(),
            TrustError::Unavailable
        );
    }
    for status in [201, 301, 403, 404] {
        transport.status = status;
        assert_eq!(
            acquire_native_attestations(&mut transport, COMMIT, &SelectionBudget::new())
                .unwrap_err(),
            TrustError::Refused
        );
    }
    let mut linked = Transport::ok(page(vec![inline()]));
    linked.link = true;
    assert!(acquire_native_attestations(&mut linked, COMMIT, &SelectionBudget::new()).is_err());
    let mut cancel = Transport::ok(page(vec![inline()]));
    cancel.cancel = true;
    assert_eq!(
        acquire_native_attestations(&mut cancel, COMMIT, &SelectionBudget::new()).unwrap_err(),
        TrustError::Interrupted
    );
    let mut huge = Transport::ok(vec![b' '; MAX_BUNDLE_BYTES + 1]);
    assert!(acquire_native_attestations(&mut huge, COMMIT, &SelectionBudget::new()).is_err());
    let mut untouched = Transport::ok(vec![]);
    assert!(acquire_native_attestations(&mut untouched, "main", &SelectionBudget::new()).is_err());
    assert!(untouched.seen.is_empty());
}

#[test]
fn downloaded_asset_requires_exact_length_and_digest_before_return() {
    let body = b"offline artifact\n";
    let proof = AssetProof::for_bytes("install.sh", body).unwrap();
    let mut transport = Transport::ok(body.to_vec());
    assert_eq!(
        acquire_digest_checked_asset(&mut transport, 123, &proof, &SelectionBudget::new()).unwrap(),
        body
    );
    assert_eq!(
        transport.seen[0],
        (
            "https://api.github.com/repos/albertloky/SBXR/releases/assets/123".into(),
            "application/octet-stream".into(),
            body.len()
        )
    );
    for bad in [
        b"offline artifact".to_vec(),
        b"offline artifact\nX".to_vec(),
        b"offline ArtifacT\n".to_vec(),
        vec![],
    ] {
        let mut transport = Transport::ok(bad);
        assert!(
            acquire_digest_checked_asset(&mut transport, 123, &proof, &SelectionBudget::new())
                .is_err()
        );
    }
    let mut untouched = Transport::ok(body.to_vec());
    assert!(
        acquire_digest_checked_asset(&mut untouched, 0, &proof, &SelectionBudget::new()).is_err()
    );
    assert!(untouched.seen.is_empty());
}

struct FailingReader;
impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("private transport detail"))
    }
}
struct FailedReadTransport;
impl AcquisitionTransport for FailedReadTransport {
    fn get(
        &mut self,
        _: &AcquisitionRequest,
        _: &SelectionBudget,
    ) -> Result<AcquisitionResponse, TrustError> {
        Ok(AcquisitionResponse::new(200, FailingReader, false))
    }
}

#[test]
fn read_errors_are_secret_free_and_invalid_bundles_never_authenticate() {
    let error =
        acquire_native_attestations(&mut FailedReadTransport, COMMIT, &SelectionBudget::new())
            .unwrap_err();
    assert_eq!(error, TrustError::Unavailable);
    assert!(!format!("{error} {error:?}").contains("private transport detail"));
    let mut inline = Transport::ok(page(vec![inline()]));
    assert_eq!(
        verify_native_release(&mut inline, &expected(), &SelectionBudget::new()).unwrap_err(),
        TrustError::Refused
    );
    let mut compressed = Transport::ok(page(vec![
        serde_json::json!({"initiator":"github", "bundle_url":"https://tmaproduction.blob.core.windows.net/path"}),
    ]));
    assert_eq!(
        verify_native_release(&mut compressed, &expected(), &SelectionBudget::new()).unwrap_err(),
        TrustError::Refused
    );
    assert_eq!(compressed.seen.len(), 2);
}

#[test]
fn cancelled_owner_session_refuses_genuine_proofs_without_late_acceptance() {
    let stop = sbxr::subscription_serving::Cancellation::new();
    let budget = SelectionBudget::new().with_cancellation(stop.clone());
    budget.check().unwrap();
    stop.cancel();
    let policy = VerificationPolicy::native_release(NATIVE_COMMIT).unwrap();
    assert_eq!(
        verify_bundle(NATIVE_BUNDLE, &policy, &budget).unwrap_err(),
        TrustError::Interrupted
    );
    assert!(SelectionBudget::new().check().is_ok());
}

#[test]
fn cancelling_one_selection_does_not_cancel_the_enclosing_owner_session() {
    let session = sbxr::subscription_serving::Cancellation::new();
    let first = SelectionBudget::new().with_cancellation(session.clone());
    first.cancel();
    assert_eq!(first.check(), Err(TrustError::Interrupted));
    assert!(!session.is_cancelled());
    SelectionBudget::new()
        .with_cancellation(session)
        .check()
        .unwrap();
}
