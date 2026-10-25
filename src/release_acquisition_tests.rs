use super::*;
use crate::{
    artifact_trust::AcquisitionResponse, records::sha256_hex, release_identity::ReleaseSupport,
};
use std::io::Cursor;
struct Fixture {
    record: InstalledRecord,
    executable: Vec<u8>,
    index: ReleaseIndex,
    metadata: Vec<u8>,
    bodies: BTreeMap<String, Vec<u8>>,
    requests: Vec<String>,
}
impl AcquisitionTransport for Fixture {
    fn get(
        &mut self,
        request: &AcquisitionRequest,
        budget: &SelectionBudget,
    ) -> Result<AcquisitionResponse> {
        budget.check()?;
        self.requests.push(request.url().into());
        let body = self
            .bodies
            .get(request.url())
            .ok_or(TrustError::Unavailable)?
            .clone();
        Ok(AcquisitionResponse::new(200, Cursor::new(body), false))
    }
}
impl Fixture {
    fn new() -> Self {
        Self::with_markers(&[])
    }
    fn with_markers(markers: &[u8]) -> Self {
        let old = identity::read_executable_identity(include_bytes!(
            "../tests/testdata/release_identity/go-amd64-valid.bin"
        ))
        .unwrap();
        let commit = "c5e17a62e06a1d201570249c61fae531e9244e1b";
        let mut payload = old.payload().to_vec();
        payload.extend_from_slice(markers);
        let executable =
            identity::stamp_executable(&payload, "v3.1.118", commit, 192, Architecture::Amd64)
                .unwrap();
        let archive = crate::release_archive::tests::archive(&executable);
        let assets = vec![
            AssetProof::for_bytes("install.sh", b"inert installer").unwrap(),
            AssetProof::for_bytes("sbxr-linux-amd64.tar.gz", &archive).unwrap(),
            AssetProof::for_bytes("sbxr-linux-arm64.tar.gz", b"unused arm fixture").unwrap(),
        ];
        let index = ReleaseIndex::build(
            "v3.1.118",
            commit,
            192,
            assets,
            Some(ReleaseSupport::new(SupportScope::CleanInstallOnly, vec![]).unwrap()),
        )
        .unwrap();
        let mut proofs = index.assets().to_vec();
        proofs.push(AssetProof::for_bytes("release-index.json", index.bytes()).unwrap());
        proofs.sort_by(|a, b| a.name().cmp(b.name()));
        let mut body = include_str!("release_acquisition/testdata/clean-record.txt")
            .replace("{tag}", "v3.1.118")
            .replace("{commit}", commit)
            .replace("{index}", index.identity().index_sha256())
            .replace("{hash}", &"a".repeat(64));
        for proof in &proofs {
            body.push_str(&format!(
                "Asset: {} {} {}\n",
                proof.name(),
                proof.size(),
                proof.sha256()
            ));
        }
        let assets:Vec<_>=proofs.iter().enumerate().map(|(i,p)|serde_json::json!({"name":p.name(),"size":p.size(),"digest":format!("sha256:{}",p.sha256()),"state":"uploaded","url":format!("https://api.github.com/repos/albertloky/SBXR/releases/assets/{}",i+1)})).collect();
        let metadata=serde_json::to_vec(&serde_json::json!({"tag_name":"v3.1.118","target_commitish":commit,"body":body,"draft":false,"prerelease":false,"immutable":true,"assets":assets})).unwrap();
        let record = InstalledRecord::new(
            crate::records::ReleaseIdentity::new(
                "v3.1.118",
                commit,
                index.identity().index_sha256(),
            )
            .unwrap(),
            192,
            "amd64",
            &sha256_hex(&executable),
        )
        .unwrap();
        let mut bodies = BTreeMap::new();
        bodies.insert(
            format!("https://api.github.com/repos/{REPOSITORY}/releases/tags/v3.1.118"),
            metadata.clone(),
        );
        for (i, p) in proofs.iter().enumerate() {
            let body = match p.name() {
                "release-index.json" => index.bytes().to_vec(),
                "sbxr-linux-amd64.tar.gz" => archive.clone(),
                _ => vec![],
            };
            bodies.insert(
                format!(
                    "https://api.github.com/repos/{REPOSITORY}/releases/assets/{}",
                    i + 1
                ),
                body,
            );
        }
        Self {
            record,
            executable,
            index,
            metadata,
            bodies,
            requests: vec![],
        }
    }
    fn finish(&mut self) -> Result<AuthenticatedInstalled> {
        let metadata = Metadata::decode(&self.metadata, &self.record)?;
        let claims = trust::fixture_claims(&metadata.expected()?);
        complete(
            self,
            self.record.clone(),
            &self.executable.clone(),
            &metadata,
            &claims,
            Architecture::Amd64,
            &SelectionBudget::new(),
        )
    }
}
pub(super) fn verified_fixture() -> (AuthenticatedInstalled, Vec<u8>) {
    let mut f = Fixture::new();
    (f.finish().unwrap(), f.executable)
}
#[test]
fn authenticated_boundary_binds_raw_index_archive_and_installed_bytes() {
    let mut f = Fixture::new();
    let admitted = f.finish().unwrap();
    assert!(admitted.record() == &f.record);
    assert_eq!(admitted.index().bytes(), f.index.bytes());
    assert_eq!(f.requests.len(), 2);
    for asset in ["release-index.json", "sbxr-linux-amd64.tar.gz"] {
        let mut f = Fixture::new();
        let m = Metadata::decode(&f.metadata, &f.record).unwrap();
        f.bodies
            .get_mut(&format!(
                "https://api.github.com/repos/{REPOSITORY}/releases/assets/{}",
                m.assets[asset].id
            ))
            .unwrap()
            .push(b'x');
        assert!(f.finish().is_err());
    }
    let mut f = Fixture::new();
    f.executable.push(b'x');
    assert!(f.finish().is_err());
}
#[test]
fn genuine_foreign_signature_cannot_authorize_sbxr_or_download_assets() {
    let mut f = Fixture::new();
    let page = serde_json::json!({"attestations":[{"initiator":"github","bundle":serde_json::from_slice::<serde_json::Value>(include_bytes!("../internal/softwarelifecycle/adapter/github/testdata/github_release_bundle.json")).unwrap()}]});
    f.bodies.insert(format!("https://api.github.com/repos/{REPOSITORY}/attestations/sha1:{}?predicate_type=release&per_page=100",f.record.release_identity().commit()),serde_json::to_vec(&page).unwrap());
    let record = f.record.clone();
    let bytes = f.executable.clone();
    assert!(
        AuthenticatedInstalled::acquire(&mut f, record, &bytes, &bytes, &SelectionBudget::new())
            .is_err()
    );
    assert_eq!(f.requests.len(), 2);
    assert!(
        f.requests
            .iter()
            .all(|url| !url.contains("/releases/assets/"))
    );
}
#[test]
fn metadata_acceptance_and_identity_failures_stop_before_network_authority() {
    let f = Fixture::new();
    let original: serde_json::Value = serde_json::from_slice(&f.metadata).unwrap();
    for (field, value) in [
        ("draft", serde_json::json!(true)),
        ("prerelease", serde_json::json!(true)),
        ("immutable", serde_json::json!(false)),
        ("target_commitish", serde_json::json!("a".repeat(40))),
        ("sbxr_qualification", serde_json::json!({})),
    ] {
        let mut bad = original.clone();
        bad[field] = value;
        assert!(Metadata::decode(&serde_json::to_vec(&bad).unwrap(), &f.record).is_err());
    }
    for suffix in ["?token=secret", "/", "#secret"] {
        let mut bad = original.clone();
        let url = bad["assets"][0]["url"].as_str().unwrap().to_owned();
        bad["assets"][0]["url"] = format!("{url}{suffix}").into();
        assert!(Metadata::decode(&serde_json::to_vec(&bad).unwrap(), &f.record).is_err());
    }
    let duplicate = f.metadata.iter().position(|b| *b == b'{').unwrap();
    let mut bad = f.metadata.clone();
    bad.splice(
        duplicate + 1..duplicate + 1,
        b"\"draft\":false,".iter().copied(),
    );
    assert!(Metadata::decode(&bad, &f.record).is_err());
    let mut f = Fixture::new();
    let bytes = f.executable.clone();
    let mut changed = bytes.clone();
    changed.push(b'x');
    let r = f.record.clone();
    assert!(
        AuthenticatedInstalled::acquire(&mut f, r, &bytes, &changed, &SelectionBudget::new())
            .is_err()
    );
    assert!(f.requests.is_empty());
}
#[test]
fn acceptance_record_refuses_missing_duplicate_or_incompatible_required_lines() {
    let f = Fixture::new();
    let value: serde_json::Value = serde_json::from_slice(&f.metadata).unwrap();
    let body = value["body"].as_str().unwrap();
    let metadata = Metadata::decode(&f.metadata, &f.record).unwrap();
    let proofs: Vec<_> = metadata.assets.values().map(|a| a.proof.clone()).collect();
    let mut cases = vec![(body.to_owned(), true)];
    for line in body.lines() {
        if line.starts_with("# ") {
            continue;
        }
        cases.push((body.replace(&format!("{line}\n"), ""), false));
        cases.push((format!("{body}{line}\n"), false));
    }
    for bad in [
        body.replace("mvp-http-live-v1", "mvp-live-v1"),
        body.replace("mvp-serving", "mvp-renewal"),
        format!("{body}Owner exception: fabricated\n"),
        body.replace("HTTP; subscription", "HTTPS; subscription"),
    ] {
        cases.push((bad, false));
    }
    for (body, want) in &cases {
        assert_eq!(
            acceptance::check(body, &metadata.identity, &proofs).is_ok(),
            *want,
            "required field case refused/accepted incorrectly"
        );
    }
    if let Some(path) = std::env::var_os("SBXR_ACCEPTANCE_CASES") {
        let cases:Vec<_>=cases.into_iter().map(|(body,want)|serde_json::json!({"body":body,"want":want,"tag":metadata.identity.tag(),"commit":metadata.identity.commit(),"index":metadata.identity.index_sha256(),"assets":proofs})).collect();
        std::fs::write(path, serde_json::to_vec(&cases).unwrap()).unwrap();
    }
}

#[test]
fn paginated_exact_metadata_is_refused_before_proof_or_asset_requests() {
    struct Linked {
        body: Vec<u8>,
        calls: usize,
    }
    impl AcquisitionTransport for Linked {
        fn get(
            &mut self,
            r: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<AcquisitionResponse> {
            self.calls += 1;
            assert!(r.url().contains("/releases/tags/"));
            Ok(AcquisitionResponse::new(
                200,
                Cursor::new(self.body.clone()),
                true,
            ))
        }
    }
    let f = Fixture::new();
    let mut transport = Linked {
        body: f.metadata,
        calls: 0,
    };
    assert!(matches!(
        AuthenticatedInstalled::acquire(
            &mut transport,
            f.record,
            &f.executable,
            &f.executable,
            &SelectionBudget::new()
        ),
        Err(TrustError::Refused)
    ));
    assert_eq!(transport.calls, 1);
}

#[test]
fn exact_authenticated_archive_derives_record_and_refuses_unbound_or_interrupted_current_bytes() {
    let mut f = Fixture::new();
    let release = f.record.release_identity();
    let selected =
        ReleaseIdentity::new(release.tag(), release.commit(), release.index_sha256()).unwrap();
    let metadata = Metadata::decode_exact(&f.metadata, &selected).unwrap();
    let claims = trust::fixture_claims(&metadata.expected().unwrap());
    let archive = acquire_archive(
        &mut f,
        &metadata,
        &claims,
        Architecture::Amd64,
        &SelectionBudget::new(),
    )
    .unwrap();
    assert!(archive.record() == &f.record);
    assert_eq!(archive.executable(), f.executable);
    assert!(
        archive
            .bind_current(archive.executable(), b"different", &SelectionBudget::new())
            .is_err()
    );
    let budget = SelectionBudget::new();
    budget.cancel();
    assert!(matches!(
        archive.bind_current(archive.executable(), archive.executable(), &budget),
        Err(TrustError::Interrupted)
    ));
    let changed =
        ReleaseIdentity::new("v3.1.117", selected.commit(), selected.index_sha256()).unwrap();
    assert!(Metadata::decode_exact(&f.metadata, &changed).is_err());
}

pub(super) fn verified_fixture_with_markers(markers: &[u8]) -> (AuthenticatedInstalled, Vec<u8>) {
    let mut f = Fixture::with_markers(markers);
    (f.finish().unwrap(), f.executable)
}

#[test]
fn canonical_latest_metadata_never_bypasses_native_signature_verification() {
    let mut f = Fixture::new();
    let request = AcquisitionRequest::latest_metadata();
    f.bodies.insert(request.url().into(), f.metadata.clone());
    assert!(
        AuthenticatedArchive::acquire_latest(&mut f, Architecture::Amd64, &SelectionBudget::new())
            .is_err()
    );
    assert_eq!(f.requests.first().unwrap(), request.url());
    assert!(f.requests.iter().any(|url| url.contains("attestations")));
    assert!(
        !f.requests
            .iter()
            .any(|url| url.contains("/releases/assets/"))
    );
    for key in ["draft", "prerelease"] {
        let mut f = Fixture::new();
        let mut value: serde_json::Value = serde_json::from_slice(&f.metadata).unwrap();
        value[key] = true.into();
        f.bodies
            .insert(request.url().into(), serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            AuthenticatedArchive::acquire_latest(
                &mut f,
                Architecture::Amd64,
                &SelectionBudget::new()
            ),
            Err(TrustError::Refused)
        ));
        assert_eq!(f.requests.len(), 1);
    }
    struct Counter(usize);
    impl AcquisitionTransport for Counter {
        fn get(
            &mut self,
            _: &AcquisitionRequest,
            _: &SelectionBudget,
        ) -> Result<AcquisitionResponse> {
            self.0 += 1;
            Err(TrustError::Unavailable)
        }
    }
    let mut f = Counter(0);
    let budget = SelectionBudget::new();
    budget.cancel();
    assert!(matches!(
        AuthenticatedArchive::acquire_latest(&mut f, Architecture::Amd64, &budget),
        Err(TrustError::Interrupted)
    ));
    assert_eq!(f.0, 0);
}

#[test]
fn public_exact_tag_is_not_latest_or_an_unsigned_structural_shortcut() {
    for selected in ["v3.2.1", "v9.9.9"] {
        let mut f = Fixture::new();
        let wire: serde_json::Value = serde_json::from_slice(&f.metadata).unwrap();
        let actual = wire["tag_name"].as_str().unwrap().to_owned();
        let tag = if selected == "v3.2.1" {
            actual.as_str()
        } else {
            selected
        };
        let request = AcquisitionRequest::release_metadata(tag).unwrap();
        f.bodies.insert(request.url().into(), f.metadata.clone());
        assert!(
            AuthenticatedArchive::acquire_public_tag(
                &mut f,
                tag,
                Architecture::Amd64,
                &SelectionBudget::new()
            )
            .is_err()
        );
        assert_eq!(f.requests.first().unwrap(), request.url());
        assert!(!f.requests.iter().any(|s| s.contains("/releases/assets/")));
        assert_eq!(
            f.requests.iter().any(|s| s.contains("attestations")),
            tag == actual
        );
        assert!(!f.requests.iter().any(|s| s.ends_with("/latest")));
    }
}
