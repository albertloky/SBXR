//! Current clean-install-only HTTP Acceptance Record contract from the Go reader.
use crate::{
    artifact_trust::TrustError,
    release_identity::{AssetProof, REPOSITORY, ReleaseIdentity},
};
type Result<T> = std::result::Result<T, TrustError>;
const SUPPORT: &str = "{\"scope\":\"subscription-clean-install-only\",\"sources\":[],\"contract\":\"sbxr-subscription-update-v1\"}";
pub(super) fn check(body: &str, identity: &ReleaseIdentity, assets: &[AssetProof]) -> Result<u64> {
    if body.is_empty()
        || body.len() > 64 << 10
        || body.contains(['\r', '\0'])
        || !body.ends_with('\n')
        || body.matches("# SBXR Acceptance Record\n").count() != 1
        || body.contains("# SBXR Installer-Updater Acceptance Record\n")
    {
        return Err(TrustError::Refused);
    }
    for (key, wanted) in [
        ("Status: ", "Qualified"),
        ("Repository: ", REPOSITORY),
        ("Tag: ", identity.tag()),
        ("Commit: ", identity.commit()),
        ("Module Verification: ", "Passed"),
        ("Seam Verification: ", "Passed"),
        (
            "Integrated Verification: ",
            "Passed on live Ubuntu Server 24.04 amd64 and Karing macOS",
        ),
        ("Codex Live Acceptance: ", "Passed"),
        ("Owner Acceptance: ", "Not required"),
        (
            "Stable result code: ",
            "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION",
        ),
        ("Runner: ", "Ubuntu Server 24.04 linux/amd64"),
        (
            "Public verifier: ",
            "1.3.0 26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485",
        ),
        ("Secret-safe result: ", "Passed"),
        (
            "Qualification role: ",
            "Clean-installed subscription-capable V3 release",
        ),
        ("Karing macOS: ", "Passed"),
        (
            "Natural timer firing and naturally due certificate renewal: ",
            "Not observed",
        ),
        (
            "Unsupported new or renamed renewal route: ",
            "May execute before detection; historical outcomes unknown",
        ),
        ("Release index SHA-256: ", identity.index_sha256()),
        ("Release support: ", SUPPORT),
        ("Evidence policy: ", "mvp-http-live-v1"),
        ("Incoming source upgrades: ", "Not applicable"),
        ("Two-release update/recovery: ", "Not applicable"),
        (
            "Live acceptance coverage: ",
            "Five normal product journeys; interruption, contention, drift, forced outage and scheduled-refresh variants not observed live",
        ),
        (
            "Karing connectivity evidence: ",
            "Real subscription import, one node, fresh per-node latency and manual refresh; selected connection preserved; no Karing browsing or automatic-refresh timing claim",
        ),
        (
            "Subscription transport: ",
            "HTTP; subscription credentials and configuration are exposed to interception and tampering",
        ),
    ] {
        if value(body, key)? != wanted {
            return Err(TrustError::Refused);
        }
    }
    let package = value(body, "Proxy package: ")?;
    if !matches!(
        package,
        "sing-box 1.13.19 amd64 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf"
            | "sing-box 1.14.3 amd64 ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e"
    ) {
        return Err(TrustError::Refused);
    }
    if !workflow(value(body, "Workflow evidence: ")?)
        || !hash(value(body, "Detailed evidence SHA-256: ")?)
    {
        return Err(TrustError::Refused);
    }
    let version = value(body, "Go toolchain: ")?
        .strip_prefix("go")
        .ok_or(TrustError::Refused)?;
    if !version_parts(version, &['.'], 3, 3) {
        return Err(TrustError::Refused);
    }
    let karing: Vec<_> = value(body, "Karing package: ")?.split(' ').collect();
    if karing.len() != 4
        || karing[0] != "karing"
        || !matches!(karing[2], "macos-arm64" | "macos-amd64")
        || !hash(karing[3])
        || !version_parts(karing[1], &['.', '-'], 1, 6)
    {
        return Err(TrustError::Refused);
    }
    for prefix in [
        "Owner exception: ",
        "Automated-only scenarios (not live): ",
        "Automated-only result: ",
        "Automated-only checks (not live): ",
        "Karing checks not performed: ",
        "Recurring evidence policy: ",
        "Recurring live acceptance coverage: ",
        "Recurring Karing evidence: ",
        "Journey: ",
    ] {
        if body.lines().any(|l| l.starts_with(prefix)) {
            return Err(TrustError::Refused);
        }
    }
    let expected = [
        "mvp-install",
        "mvp-subscription",
        "mvp-credentials",
        "mvp-serving",
        "mvp-removal",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for line in body.lines().filter_map(|l| l.strip_prefix("Scenario: ")) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3
            || !expected.contains(&fields[0])
            || !seen.insert(fields[0])
            || !hash(fields[1])
            || !fields[2].strip_suffix("#artifacts").is_some_and(workflow)
        {
            return Err(TrustError::Refused);
        }
    }
    if seen.len() != 5 {
        return Err(TrustError::Refused);
    }
    for asset in assets {
        if value(body, &format!("Asset: {} ", asset.name()))?
            != format!("{} {}", asset.size(), asset.sha256())
        {
            return Err(TrustError::Refused);
        }
    }
    let sequence = value(body, "Sequence: ")?;
    if !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TrustError::Refused);
    }
    sequence
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or(TrustError::Refused)
}
fn version_parts(text: &str, pattern: &[char], min: usize, max: usize) -> bool {
    let parts: Vec<_> = text.split(pattern).collect();
    (min..=max).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}
fn value<'a>(body: &'a str, key: &str) -> Result<&'a str> {
    let mut found = body.lines().filter_map(|l| l.strip_prefix(key));
    let first = found.next().ok_or(TrustError::Refused)?;
    if found.next().is_some() {
        return Err(TrustError::Refused);
    }
    Ok(first)
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn workflow(s: &str) -> bool {
    s.strip_prefix("https://github.com/albertloky/SBXR/actions/runs/")
        .is_some_and(|id| {
            !id.starts_with('0') && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
        })
}
