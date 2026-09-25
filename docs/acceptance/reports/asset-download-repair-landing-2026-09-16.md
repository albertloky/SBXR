# Download repair landing and MVP preparation — 2026-09-16

**Landing is complete.** The preparation sections below record the state before
dispatch. The subsequent `v3.1.74` attempt passed two live journeys, then failed
the credential observation deadline. It was stopped and its VPS/process/file
cleanup verified; the Owner also confirmed final UI cleanup. See the
[final candidate report](v3.1.74-mvp-live-2026-09-16.md). There is no qualified
candidate or successful Acceptance Record from that attempt.

The release-asset download repair is committed and pushed as
`261a5c8814bcf25d25a31cd14f597bfbe1735d2c` on `main`.
[Native Verify 35086088427](https://github.com/albertloky/SBXR/actions/runs/35086088427)
passed on Ubuntu amd64 and arm64, including ordinary and race tests, vet,
packaging, the packaged menu, and secret checks.

The original interrupted GET, correction, and before/after regression evidence
are documented in [the repair report](asset-download-repair-2026-09-16.md).
Independent Standards and Spec reviews each found zero issues. No source
correction was necessary during landing. All 11 unrelated untracked documents
were preserved byte-for-byte, and the commit contains only the 11 repair,
test, workflow, and directly related documentation files.

## Fresh candidate preparation

The existing canonical preflight and declaration checks accept proposed tag
`v3.1.74`, sequence `152`, for the committed revision. Sequence 152 is unused:
the earlier unsigned v3.1.73 attempt did not reach signing and has no release,
tag, or burned identity. A new tag distinguishes this proposed attempt.

Fresh SSH checks confirmed the disposable Ubuntu 24.04 amd64 host is clean,
SSH and the original timers are active, and the original Certbot/snap revisions
and unrelated preflight resources remain. The Mac's physical `en0` interface
reached temporary listeners on TCP 80, 443, and 8443; those listeners closed.
The outside sing-box archive and executable match the retained vendor receipt.

Karing 1.2.25 build 2802 is running, its installed signature verifies, and the
official current package metadata and retained DMG digest match. A fresh latency
observation for the Owner's original selected connection was requested and is
still pending. No Karing selection, settings, or profiles were changed.

Fresh sanitized Certbot history contains no successful issuance after September
13 at 12:44:44 UTC and no remaining renewal lineage. The retained CA retry time
and the currently verified [official refill policy](https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers)
support budgeting two requests: initial enablement and one reviewed replacement.
This calculation is not a reservation and cannot exclude issuance elsewhere
for the same identifier. No production certificate was requested in preparation.

## Boundary at preparation

At this preparation snapshot the candidate had **not been dispatched**. There
was no candidate workflow, signed manifest, or Acceptance Record yet.

| Journey | Result |
|---|---|
| `mvp-install` | Not run |
| `mvp-subscription` | Not run |
| `mvp-credentials` | Not run |
| `mvp-renewal` | Not run |
| `mvp-removal` | Not run |

The prepared next step was to obtain the requested Karing readiness observation,
refresh stale readiness facts, and dispatch exactly one candidate using the
[current MVP procedure](../mvp-live-acceptance.md). That attempt is now stopped;
do not resume it or dispatch another under the earlier single-candidate scope.
Stable publication remains separate and has not occurred.

Run artifacts and the detailed continuation handoff are in
[the local run directory](../../../.scratch/acceptance/mvp-20260916-1038/), including
`HANDOFF.md`, `verify-final.json`, `verify.log`, canonical preflight/declaration
results, package receipts, host observations, and `ca-readiness.md`.
