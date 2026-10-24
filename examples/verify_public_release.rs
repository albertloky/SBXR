//! Repository-only evidence checker. Never executes or installs supplied bytes.
use sbxr::{
    artifact_trust::{
        AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
    },
    records::{InstalledRecord, ReleaseIdentity, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
    release_https::HttpsTransport,
    release_identity::ReleaseIndex,
};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::Path,
};
const META: &[u8] = include_bytes!("../tests/testdata/public_release/release.json");
const INDEX: &[u8] = include_bytes!("../tests/testdata/public_release/release-index.json");
const PAGE: &[u8] = include_bytes!("../tests/testdata/public_release/attestations.json");
const BLOBS: [&[u8]; 3] = [
    include_bytes!("../tests/testdata/public_release/bundle-1.json.sn"),
    include_bytes!("../tests/testdata/public_release/bundle-2.json.sn"),
    include_bytes!("../tests/testdata/public_release/bundle-3.json.sn"),
];
struct Replay(BTreeMap<String, Vec<u8>>);
impl AcquisitionTransport for Replay {
    fn get(
        &mut self,
        r: &AcquisitionRequest,
        _: &SelectionBudget,
    ) -> Result<AcquisitionResponse, TrustError> {
        Ok(AcquisitionResponse::new(
            200,
            Cursor::new(self.0.get(r.url()).ok_or(TrustError::Refused)?.clone()),
            false,
        ))
    }
}
fn read(path: &Path) -> Result<Vec<u8>, TrustError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| TrustError::Refused)?;
    let info = rustix::fs::fstat(&fd).map_err(|_| TrustError::Refused)?;
    if rustix::fs::FileType::from_raw_mode(info.st_mode) != rustix::fs::FileType::RegularFile
        || info.st_size < 0
        || info.st_size as usize > sbxr::release_identity::MAX_EXECUTABLE_BYTES
    {
        return Err(TrustError::Refused);
    }
    let mut b = vec![];
    std::fs::File::from(fd)
        .take(sbxr::release_identity::MAX_EXECUTABLE_BYTES as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| TrustError::Refused)?;
    if b.len() > sbxr::release_identity::MAX_EXECUTABLE_BYTES {
        return Err(TrustError::Refused);
    }
    Ok(b)
}
fn verify() -> Result<(), TrustError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !(args.len() == 1 || args.len() == 2 && args[1] == "--public") {
        return Err(TrustError::Refused);
    }
    let archive = read(&Path::new(&args[0]).join("sbxr-linux-amd64.tar.gz"))?;
    let executable = sbxr::release_archive::unpack(&archive, &SelectionBudget::new())?;
    let index = ReleaseIndex::decode(INDEX).map_err(|_| TrustError::Refused)?;
    let identity = index.identity();
    let record = InstalledRecord::new(
        ReleaseIdentity::new(identity.tag(), identity.commit(), identity.index_sha256())
            .map_err(|_| TrustError::Refused)?,
        index.sequence(),
        "amd64",
        &sha256_hex(&executable),
    )
    .map_err(|_| TrustError::Refused)?;
    let admitted = if args.len() == 2 {
        AuthenticatedInstalled::acquire(
            &mut HttpsTransport::new()?,
            record,
            &executable,
            &executable,
            &SelectionBudget::new(),
        )?
    } else {
        let mut sources = BTreeMap::new();
        sources.insert(
            format!(
                "https://api.github.com/repos/albertloky/SBXR/releases/tags/{}",
                identity.tag()
            ),
            META.to_vec(),
        );
        sources.insert(format!("https://api.github.com/repos/albertloky/SBXR/attestations/sha1:{}?predicate_type=release&per_page=100",identity.commit()),PAGE.to_vec());
        let page: serde_json::Value =
            serde_json::from_slice(PAGE).map_err(|_| TrustError::Refused)?;
        for (i, e) in page["attestations"]
            .as_array()
            .ok_or(TrustError::Refused)?
            .iter()
            .enumerate()
        {
            sources.insert(
                e["bundle_url"].as_str().ok_or(TrustError::Refused)?.into(),
                BLOBS[i].to_vec(),
            );
        }
        let meta: serde_json::Value =
            serde_json::from_slice(META).map_err(|_| TrustError::Refused)?;
        for asset in meta["assets"].as_array().ok_or(TrustError::Refused)? {
            let bytes = match asset["name"].as_str() {
                Some("release-index.json") => INDEX.to_vec(),
                Some("sbxr-linux-amd64.tar.gz") => archive.clone(),
                _ => continue,
            };
            sources.insert(
                asset["url"].as_str().ok_or(TrustError::Refused)?.into(),
                bytes,
            );
        }
        AuthenticatedInstalled::acquire(
            &mut Replay(sources),
            record,
            &executable,
            &executable,
            &SelectionBudget::new(),
        )?
    };
    if admitted.index().identity() != identity {
        return Err(TrustError::Refused);
    }
    println!(
        "Verified v3.1.118/192 release and installed bytes; no artifact executed, installed or deployment-qualified."
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    if verify().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("Public release evidence refused.");
        std::process::ExitCode::FAILURE
    }
}
