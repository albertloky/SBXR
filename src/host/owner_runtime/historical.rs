//! Local retained renewal-route inspection; never invokes Certbot or ACME.
use super::*;
use crate::host::historical::UnfinishedRenewal;
use crate::host::linux::HistoricalRuntimeFacts;
fn calendar(body: &str) -> bool {
    let entries: Vec<_> = body.split("OnCalendar=").skip(1).collect();
    if entries.len() != 2 {
        return false;
    }
    let mut morning = 0;
    for entry in entries {
        let Some(time) = entry.strip_prefix("*-*-* ").and_then(|s| s.get(..8)) else {
            return false;
        };
        let parts: Vec<_> = time.split(':').map(str::parse::<u32>).collect();
        if parts.len() != 3 {
            return false;
        }
        let (Ok(h), Ok(m), Ok(s)) = (&parts[0], &parts[1], &parts[2]) else {
            return false;
        };
        if *h > 23 || *m > 59 || *s > 59 {
            return false;
        }
        morning += usize::from(*h < 12);
    }
    morning == 1
}
pub(super) fn firewall_commands(body: &str, expected: &[&str]) -> bool {
    let values: Vec<String> = if body.trim().starts_with('{') {
        body.trim()
            .split("} {")
            .map(|s| {
                format!(
                    "{{{}}}",
                    s.trim().trim_start_matches('{').trim_end_matches('}')
                )
            })
            .collect()
    } else {
        body.lines().map(str::to_owned).collect()
    };
    values.len() == expected.len()
        && values.iter().zip(expected).all(|(v, e)| {
            let e = e
                .strip_prefix("/bin/sh -ec '")
                .and_then(|s| s.strip_suffix('\''));
            e.is_some_and(|s| observation::exact_exec(v, "/bin/sh", &format!("/bin/sh -ec {s}")))
        })
}

impl<I: OwnerIo> OwnerRuntime<'_, I> {
    pub(super) fn historical_facts(
        &self,
        record: &OwnershipRecord,
        attempts: &[UnfinishedRenewal],
    ) -> Result<HistoricalRuntimeFacts, HostError> {
        let historical = if self.fs.path() == Path::new("/") {
            crate::host::historical::HistoricalHttps::native_unreleased()?
        } else {
            crate::host::historical::HistoricalHttps::injected(self.fs.path())?
        };
        historical.renewal_hooks_safe()?;
        let current = self.io.current().map_err(refused)?;
        if current.uid != self.fs.uid
            || current.executable_sha256 != self.proof.record().executable_sha256()
        {
            return Err(HostError::Foreign);
        }
        if self.record()? != *record {
            return Err(HostError::Foreign);
        }
        let c = self.context();
        let mut values = Vec::new();
        let mut text = |q| -> Result<String, HostError> {
            let out = self.io.historical(q, &c)?;
            if out.code() != 0 {
                return Err(HostError::Foreign);
            }
            let s = out.text()?.to_owned();
            values.push(s.clone());
            Ok(s)
        };
        use HistoricalObservation as Q;
        let exec = text(Q::Service("ExecStart"))?;
        let official = observation::exact_exec(
            &exec,
            "/usr/bin/snap",
            "/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew",
        ) || observation::exact_exec(
            &exec,
            "/usr/bin/snap",
            "/usr/bin/snap run --timer=\"00:00~24:00/2\" certbot.renew",
        );
        if !official
            && !observation::exact_exec(
                &exec,
                "/usr/local/bin/sbxr",
                "/usr/local/bin/sbxr --certbot-recorder",
            )
        {
            return Err(HostError::Foreign);
        }
        for (q, want) in [
            (
                Q::Service("FragmentPath"),
                "/etc/systemd/system/snap.certbot.renew.service",
            ),
            (Q::Timer("LoadState"), "loaded"),
            (
                Q::Timer("FragmentPath"),
                "/etc/systemd/system/snap.certbot.renew.timer",
            ),
            (Q::Timer("DropInPaths"), ""),
            (Q::Timer("Unit"), "snap.certbot.renew.service"),
            (Q::Timer("UnitFileState"), "enabled"),
            (Q::Timer("ActiveState"), "active"),
        ] {
            if text(q)? != want {
                return Err(HostError::Foreign);
            }
        }
        if !calendar(&text(Q::Timer("TimersCalendar"))?) {
            return Err(HostError::Foreign);
        }
        let snap = text(Q::Snap)?;
        let lines: Vec<_> = snap.lines().collect();
        if lines.len() != 2
            || lines[0].split_whitespace().collect::<Vec<_>>()
                != ["Name", "Version", "Rev", "Tracking", "Publisher", "Notes"]
        {
            return Err(HostError::Foreign);
        }
        let fields: Vec<_> = lines[1].split_whitespace().collect();
        if fields.len() != 6
            || fields[0] != "certbot"
            || fields[4] != "certbot-eff✓"
            || !["classic", "classic,held"].contains(&fields[5])
        {
            return Err(HostError::Foreign);
        }
        let version: Vec<_> = fields[1].split('.').map(str::parse::<u32>).collect();
        if version.len() != 3
            || version.iter().any(Result::is_err)
            || version[0].as_ref().is_ok_and(|n| *n < 5)
            || version[0] == Ok(5) && version[1].as_ref().is_ok_and(|n| *n < 4)
        {
            return Err(HostError::Foreign);
        }
        let changes = text(Q::Changes)?;
        let mut lines = changes.lines();
        if let Some(header) = lines.next()
            && header.split_whitespace().collect::<Vec<_>>()
                != ["ID", "Status", "Spawn", "Ready", "Summary"]
        {
            return Err(HostError::Foreign);
        }
        for l in lines {
            let f: Vec<_> = l.split_whitespace().collect();
            if f.len() < 2 || !["Done", "Error", "Undone"].contains(&f[1]) {
                return Err(HostError::Foreign);
            }
        }
        let mut quiet = true;
        if !attempts.is_empty() {
            let boot = text(Q::Boot)?;
            for a in attempts {
                if a.boot_id != boot {
                    continue;
                }
                let exists = self.io.historical(Q::ProcessExists(a.pid), &c)?;
                if exists.code() == 1 {
                    continue;
                }
                if exists.code() != 0 {
                    return Err(HostError::Foreign);
                }
                let p = self.io.process(a.pid)?;
                if p.start_ticks == a.tick {
                    quiet = false;
                }
            }
        }
        Ok(HistoricalRuntimeFacts {
            fingerprint: sha256_hex(values.join(";").as_bytes()),
            renewal_quiet: quiet,
            official_route: official,
        })
    }
}
