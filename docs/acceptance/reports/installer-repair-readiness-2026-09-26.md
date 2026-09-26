# Installer repair readiness — 2026-09-26

**The installer repair is implemented and native-regression-tested, but a fresh
live attempt was not dispatched. Read-only preparation found insufficient
reconstructed certificate capacity for the complete four-operation plan.**

This report records observations around 12:59 UTC / 20:59 HKT. It is not future
host readiness, a certificate reservation, a live pass or publication approval.

## Completed repair and fresh source check

- Repair commit: [1979cab](https://github.com/albertloky/SBXR/commit/1979cab6ff6af81b45ce7ac42f1a7b4f530c67eb).
  The generated-installer regression reproduced the original refusal before the
  fix and passed afterward. [Native Verify 36235048916](https://github.com/albertloky/SBXR/actions/runs/36235048916)
  passed ordinary/race tests, vet, packaging, packaged command/menu and
  package-surface secret-marker checks on Ubuntu 24.04 amd64 and arm64.
- Fresh production `verify-public-latest` returned `accepted` for immutable
  `v3.1.81/159`, commit `ed759a0ccaef5d1ffd14be5a41a0e915a6268ff7`, index SHA-256
  `91782e8cebbb649971989883687911479798f2411e6c49055ed7f06dd277c27f`.
  Fresh API metadata still identified release ID `395789410` as Latest.
- The [v3.1.83 attempt](v3.1.83-recurring-live-installer-refusal-2026-09-26.md)
  remains a separate failed attempt. Its accepted prefix cannot qualify a new
  candidate. No burned release was edited or reused.

## Certificate capacity blocks dispatch

The fresh retained Certbot files and sanitized events were byte-identical to
the stopped attempt's final CA observation. The two successful source
preparations on 26 September remain the only additional proved operations since
the earlier capacity review; repeated log lines are not separate operations.

The earlier estimate was 4.237581 operations at 08:21:04 UTC. Subtracting the two
proved operations and allowing the documented refill gives approximately
**2.374064 at 12:59:30 UTC**, below the **four** required for both source
preparations plus clean-candidate enablement and managed replacement.

[Let's Encrypt's current policy](https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers),
checked on 26 September, permits five certificates per exact identifier set and
refills one request per 34 hours. Under the retained ledger's assumptions, four
operations become available around **28 September 20:16:25 UTC / 29 September
04:16:25 HKT**. This is an evidence-based estimate, not an authoritative CA
balance or guarantee. It assumes no unseen issuance elsewhere, takes no ARI
exemption and reserves nothing. No certificate request was made as a probe.

## Host and attendance observations

The read-only host check found no listed product-owned or operator-staging paths,
relevant product/Certbot processes, held named locks, owned firewall entries or
qualification hosts entry. SSH, rsyslog and snapd were active; NTP was synchronized,
and no failed units were listed. The original `/var/log` identity/0775 mode,
immediate child inventory, pinned Snap package receipts and rsyslog tmpfiles rule
matched the previous reviewed baseline. Rsyslog validation and logrotate debug
checks passed. No product, permission, package, timer or host configuration was
changed by this preflight.

The Owner confirmed availability through **27 September 01:30 HKT**, including
Karing and cleanup, conditional on readiness. Certificate capacity prevented use
of that window. In addition, the observed Certbot timer at 22:18 HKT and Snap
refresh at 01:25 HKT fall inside that proposed session; future permission windows
must account for fresh schedules without disabling shared scheduling controls.

Fresh outside-client, Karing and full declaration/signing readiness were not
completed after the capacity blocker was established. No candidate identity was
allocated, workflow dispatched, live scenario started or publication attempted.

## Resumption boundary

Choose a new attended window after the estimated refill threshold, then refresh
CA activity/capacity, release identity, host/package/scheduling, outside-client
and Karing prerequisites. Finish the complete declaration and source/CI review
before dispatch. All eight recurring scenarios and cleanup must be observed in
the new attempt; stable publication retains its separate review and approval.
No future run or reminder is arranged by this report.

Private observations are under [`.scratch/acceptance/i358p/`](../../../.scratch/acceptance/i358p/),
including `ca-current.json`, `ca-capacity-current.json`, `host-current.json`,
release/workflow metadata and `public-latest-verification.json`. Native repair
receipts remain under [`.scratch/acceptance/i358ci/`](../../../.scratch/acceptance/i358ci/).
