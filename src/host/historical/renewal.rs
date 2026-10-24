use super::*;
pub(in crate::host) const DROPIN: &str =
    "etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf";
pub(in crate::host) const DEPLOY: &str = "etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription";
pub(in crate::host) const POST: &str = "etc/letsencrypt/renewal-hooks/post/sbxr-subscription";
pub(in crate::host) const EVIDENCE: &str = "var/lib/sbxr/renewal-attempts.json";
pub(in crate::host) const NEXT: &str = "var/lib/sbxr/.renewal-attempts.json.next";
pub(in crate::host) const ADMISSION: &str = "var/lib/sbxr/renewal-admission.lock";
pub(in crate::host) const WRITER: &str = "var/lib/sbxr/renewal-writer.lock";
pub(in crate::host) const MANAGED: [(&str, rustix::fs::RawMode, &[u8]); 5] = [
    (
        DROPIN,
        0o644,
        b"[Service]\nExecStart=\nExecStart=/usr/local/bin/sbxr --certbot-recorder\n",
    ),
    (
        DEPLOY,
        0o700,
        b"#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-deploy-hook\n",
    ),
    (
        POST,
        0o700,
        b"#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-post-hook\n",
    ),
    (ADMISSION, 0o600, b"sbxr renewal admission v1\n"),
    (WRITER, 0o600, b"sbxr renewal writer v1\n"),
];
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: u32,
    recorder_id: String,
    established_at: String,
    attempts: Vec<Attempt>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    attempt_id: String,
    invocation: String,
    started_at: String,
    boot_id: String,
    recorder_pid: u32,
    process_tick: u64,
    lineage_before: String,
    completion: Option<Completion>,
    owned_deploy_hook: Option<Hook>,
    owned_post_hook: Option<Hook>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    exit_code: u32,
    completed_at: String,
    owned_outcome: String,
    lineage_after: String,
    #[serde(default)]
    failure: Option<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hook {
    role: String,
    outcome: String,
    recorded_at: String,
    #[serde(default)]
    lineage_target: String,
}
#[derive(Clone, Debug)]
pub struct UnfinishedRenewal {
    pub boot_id: String,
    pub pid: u32,
    pub tick: u64,
}
fn receipt_generation(value: &str) -> Option<u64> {
    let part = value
        .strip_prefix("../../archive/sbxr-subscription/cert")?
        .strip_suffix(".pem")?;
    let n = part.parse::<u64>().ok()?;
    (n > 0 && n <= i64::MAX as u64 && part == n.to_string()).then_some(n)
}
pub(super) fn stamp(value: &str) -> Result<i128, HostError> {
    let bad = || HostError::Foreign;
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(bad());
    }
    let n = |a, z| {
        std::str::from_utf8(&b[a..z])
            .ok()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(bad)
    };
    let (mut y, m, d, h, min, s) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&m) || d < 1 || d > days[(m - 1) as usize] || h > 23 || min > 59 || s > 59
    {
        return Err(bad());
    }
    let mut end = 19;
    let mut nano = 0;
    if b[end] == b'.' || b[end] == b',' {
        end += 1;
        let start = end;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if start == end {
            return Err(bad());
        }
        let digits = &b[start..end];
        for i in 0..9 {
            nano = nano * 10 + digits.get(i).map(|b| i128::from(b - b'0')).unwrap_or(0);
        }
    }
    let offset = if b.get(end) == Some(&b'Z') && end + 1 == b.len() {
        0
    } else if end + 6 == b.len() && matches!(b[end], b'+' | b'-') && b[end + 3] == b':' {
        let hh = n(end + 1, end + 3)?;
        let mm = n(end + 4, end + 6)?;
        if hh > 23 || mm > 59 {
            return Err(bad());
        }
        (hh * 60 + mm) * 60 * if b[end] == b'+' { 1 } else { -1 }
    } else {
        return Err(bad());
    };
    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let year = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let day = era * 146097 + year * 365 + year / 4 - year / 100 + doy - 719468;
    Ok(i128::from(day * 86400 + h * 3600 + min * 60 + s - offset) * 1_000_000_000 + nano)
}
impl HistoricalHttps {
    pub(in crate::host) fn validate_evidence(
        &self,
        bytes: &[u8],
        authority: &serde_json::Value,
    ) -> Result<Vec<UnfinishedRenewal>, HostError> {
        if bytes.len() > 16 << 10 {
            return Err(HostError::Foreign);
        }
        let e: Evidence = serde_json::from_slice(bytes).map_err(|_| HostError::Foreign)?;
        if e.schema != 1
            || e.recorder_id
                != authority["recorder_id"]
                    .as_str()
                    .ok_or(HostError::Foreign)?
            || e.attempts.len() > 32
        {
            return Err(HostError::Foreign);
        }
        let maximum = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| HostError::Unsafe)?
            .as_nanos() as i128
            + 300_000_000_000;
        let mut latest = stamp(&e.established_at)?;
        if latest > maximum {
            return Err(HostError::Foreign);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut unfinished = Vec::new();
        for a in e.attempts {
            let started = stamp(&a.started_at)?;
            let before = receipt_generation(&a.lineage_before).ok_or(HostError::Foreign)?;
            if a.attempt_id.len() != 32
                || !a
                    .attempt_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !ids.insert(a.attempt_id)
                || !["snap-certbot-renew-v1", "snap-certbot-certonly-v1"]
                    .contains(&a.invocation.as_str())
                || a.recorder_pid == 0
                || a.process_tick == 0
                || a.boot_id.is_empty()
                || started < latest
                || started > maximum
            {
                return Err(HostError::Foreign);
            }
            let completed = a
                .completion
                .as_ref()
                .map(|c| stamp(&c.completed_at))
                .transpose()?;
            for (role, hook) in [
                ("--certbot-deploy-hook", &a.owned_deploy_hook),
                ("--certbot-post-hook", &a.owned_post_hook),
            ] {
                if let Some(h) = hook {
                    let at = stamp(&h.recorded_at)?;
                    if h.role != role
                        || !["succeeded", "failed"].contains(&h.outcome.as_str())
                        || role == "--certbot-deploy-hook"
                            && receipt_generation(&h.lineage_target).is_none()
                        || role == "--certbot-post-hook" && !h.lineage_target.is_empty()
                        || at < started
                        || at > maximum
                        || completed.is_some_and(|done| at > done)
                    {
                        return Err(HostError::Foreign);
                    }
                }
            }
            if let (Some(d), Some(p)) = (&a.owned_deploy_hook, &a.owned_post_hook)
                && stamp(&p.recorded_at)? < stamp(&d.recorded_at)?
            {
                return Err(HostError::Foreign);
            }
            if let Some(c) = a.completion {
                let after = receipt_generation(&c.lineage_after).ok_or(HostError::Foreign)?;
                let none = a.owned_deploy_hook.is_none() && a.owned_post_hook.is_none();
                let renewed = a.invocation == "snap-certbot-certonly-v1" && none
                    || matches!((&a.owned_deploy_hook,&a.owned_post_hook),(Some(d),Some(p)) if d.lineage_target==c.lineage_after && d.outcome=="succeeded" && p.outcome=="succeeded");
                let outcome = if before == after && none {
                    "no-op"
                } else if after > before && renewed {
                    "renewed"
                } else {
                    "incomplete"
                };
                let done = completed.ok_or(HostError::Foreign)?;
                if c.exit_code > 255
                    || done < started
                    || done > maximum
                    || c.owned_outcome != outcome
                {
                    return Err(HostError::Foreign);
                }
                // Optional failure diagnostics never grant cleanup authority.
                let _ = c.failure;
                latest = done;
            } else {
                unfinished.push(UnfinishedRenewal {
                    boot_id: a.boot_id,
                    pid: a.recorder_pid,
                    tick: a.process_tick,
                });
                latest = started;
            }
        }
        Ok(unfinished)
    }
    pub(in crate::host) fn unfinished(
        &self,
        record: &OwnershipRecord,
    ) -> Result<Vec<UnfinishedRenewal>, HostError> {
        let v = record_value(record)?;
        if let Some(r) = v.get("renewal").or_else(|| {
            v.get("subscription_enablement")
                .and_then(|e| e.get("renewal"))
        }) && let Some(body) = self.bytes(EVIDENCE, 0o600, None)?
        {
            return self.validate_evidence(&body, r);
        }
        Ok(Vec::new())
    }
}
