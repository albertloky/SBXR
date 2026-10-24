//! Repository-only evidence checker. Never executes supplied bytes or installs
//! on a real host. Recovery writes only fixed paths in a disposable owned root.
use sbxr::{
    artifact_trust::{
        AcquisitionRequest, AcquisitionResponse, AcquisitionTransport, SelectionBudget, TrustError,
    },
    records::ReleaseIdentity,
    release_acquisition::AuthenticatedArchive,
    release_https::HttpsTransport,
    release_identity::{Architecture, ReleaseIndex},
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
    let selected = ReleaseIdentity::new(identity.tag(), identity.commit(), identity.index_sha256())
        .map_err(|_| TrustError::Refused)?;
    let admitted = if args.len() == 2 {
        AuthenticatedArchive::acquire(
            &mut HttpsTransport::new()?,
            &selected,
            Architecture::Amd64,
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
        AuthenticatedArchive::acquire(
            &mut Replay(sources),
            &selected,
            Architecture::Amd64,
            &SelectionBudget::new(),
        )?
    };
    if admitted.index().identity() != identity || admitted.executable() != executable {
        return Err(TrustError::Refused);
    }
    admitted.bind_current(&executable, &executable, &SelectionBudget::new())?;
    restore_fixture(&admitted)?;
    println!(
        "Verified v3.1.118/192 release and exact temporary-root restoration; no artifact executed or deployed."
    );
    Ok(())
}
fn restore_fixture(archive: &AuthenticatedArchive) -> Result<(), TrustError> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = std::env::temp_dir().join(format!("public-restore-{}", std::process::id()));
    fs::create_dir(&root).map_err(|_| TrustError::Refused)?;
    let result = (|| -> Result<(), TrustError> {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| TrustError::Refused)?;
        for path in ["run/lock", "var/lib", "usr/local/bin"] {
            fs::create_dir_all(root.join(path)).map_err(|_| TrustError::Refused)?;
        }
        let mut record = sbxr::removal::commit_removal(None, &archive.record().release_identity())
            .map_err(|_| TrustError::Refused)?;
        while sbxr::removal::checkpoint(&record).map_err(|_| TrustError::Refused)?
            < sbxr::removal::checkpoint_limit(&record).map_err(|_| TrustError::Refused)?
        {
            record = sbxr::removal::next_checkpoint(&record).map_err(|_| TrustError::Refused)?;
        }
        let authority = record.encode().map_err(|_| TrustError::Refused)?;
        let path = root.join("var/lib/.sbxr-removal.json");
        fs::write(&path, &authority).map_err(|_| TrustError::Refused)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| TrustError::Refused)?;
        let restored = {
            let mut host = sbxr::host::restoration::RestorationHost::injected(&root)
                .map_err(|_| TrustError::Refused)?;
            host.restore(archive, &SelectionBudget::new())
                .map_err(|_| TrustError::Refused)?
        };
        if restored.record() != archive.record()
            || fs::read(path).map_err(|_| TrustError::Refused)? != authority
        {
            return Err(TrustError::Refused);
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root).map_err(|_| TrustError::Refused);
    result.and(cleanup)
}
fn main() -> std::process::ExitCode {
    if verify().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("Public release evidence refused.");
        std::process::ExitCode::FAILURE
    }
}
