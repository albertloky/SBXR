//! Genuine public proofs: no test-only verification boundary.
use base64::{Engine, engine::general_purpose::STANDARD};
use sbxr::{artifact_trust::*, records::sha256_hex, release_identity::*};
use std::io::Cursor;
const META: &[u8] = include_bytes!("testdata/public_release/release.json");
const INDEX: &[u8] = include_bytes!("testdata/public_release/release-index.json");
const PAGE: &[u8] = include_bytes!("testdata/public_release/attestations.json");
const BLOBS: [&[u8]; 3] = [
    include_bytes!("testdata/public_release/bundle-1.json.sn"),
    include_bytes!("testdata/public_release/bundle-2.json.sn"),
    include_bytes!("testdata/public_release/bundle-3.json.sn"),
];
struct Frozen;
impl AcquisitionTransport for Frozen {
    fn get(
        &mut self,
        r: &AcquisitionRequest,
        _: &SelectionBudget,
    ) -> Result<AcquisitionResponse, TrustError> {
        let body = if r.url().starts_with("https://api.github.com/") {
            PAGE.to_vec()
        } else {
            let page: serde_json::Value = serde_json::from_slice(PAGE).unwrap();
            let i = page["attestations"]
                .as_array()
                .unwrap()
                .iter()
                .position(|e| e["bundle_url"].as_str() == Some(r.url()))
                .ok_or(TrustError::Refused)?;
            BLOBS[i].to_vec()
        };
        Ok(AcquisitionResponse::new(200, Cursor::new(body), false))
    }
}
#[test]
fn genuine_three_proof_sbxr_set_and_exact_signed_index_are_accepted() {
    let meta: serde_json::Value = serde_json::from_slice(META).unwrap();
    let commit = meta["target_commitish"].as_str().unwrap();
    let assets: Vec<_> = meta["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            AssetProof::new(
                a["name"].as_str().unwrap(),
                a["size"].as_u64().unwrap(),
                a["digest"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("sha256:")
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let id = ReleaseIdentity::new("v3.1.118", commit, &sha256_hex(INDEX)).unwrap();
    let expected = ExpectedRelease::new(id.clone(), assets.clone()).unwrap();
    let claims = verify_native_release(&mut Frozen, &expected, &SelectionBudget::new()).unwrap();
    assert_eq!(claims.proof_count(), 3);
    assert_eq!(claims.identity(), &id);
    verify_release_index(REPOSITORY, "v3.1.118", commit, INDEX, &assets).unwrap();
}
#[test]
fn genuine_payload_tampering_is_rejected_cryptographically() {
    let raw = snap::raw::Decoder::new().decompress_vec(BLOBS[0]).unwrap();
    let mut bundle: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let payload = STANDARD
        .decode(bundle["dsseEnvelope"]["payload"].as_str().unwrap())
        .unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    // Change only an authenticated asset name. The statement remains valid JSON,
    // retains its exact signed commit and SHA-256 binding and matches the policy.
    // Only verification of the existing DSSE signature can authenticate this edit.
    let subject = statement["subject"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s["digest"]["sha256"].is_string())
        .unwrap();
    subject["name"] = "forged-public-asset".into();
    bundle["dsseEnvelope"]["payload"] = STANDARD
        .encode(serde_json::to_vec(&statement).unwrap())
        .into();
    let meta: serde_json::Value = serde_json::from_slice(META).unwrap();
    assert!(
        verify_bundle(
            &serde_json::to_vec(&bundle).unwrap(),
            &VerificationPolicy::native_release(meta["target_commitish"].as_str().unwrap())
                .unwrap(),
            &SelectionBudget::new()
        )
        .is_err()
    );
}
