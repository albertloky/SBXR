# MVP snap hard-link checker correction — 2026-09-22

**Implemented and regression-tested, including the full isolated amd64
checker/SSH/package rehearsal. Not live-validated.** Work stayed on `main`,
based on `d69bf8fce444f5d35d458c2f7c68035fdff24eaa`. No commit, push, candidate
dispatch, VPS connection, certificate request or Karing change occurred.

## Correction

The [v3.1.78 attempt](v3.1.78-mvp-live-2026-09-22.md) stopped because the checker
required each snap image to have exactly one hard link. The retained observations
show root-owned, mode-0600 images linked into snapd's cache, with unchanged
reviewed receipts. This layout agrees with
[snapd's cache implementation](https://github.com/canonical/snapd/blob/master/store/cache.go),
whose cache insertion and retrieval use hard links.

The [checker](../../../.github/scripts/mvp-inspect-window.py) now allows hard links
only at its snap-image check. Regular-file type, root:root ownership, no
group/other write permission, no extended attributes, and exact version,
revision, size and SHA-256 comparisons remain. It neither requires a cache
entry nor pins a cache link count. It does not modify images or cache entries.

The generic protected-file check remains single-link by default. Its operator,
installed-record, executable, ownership, renewal and lock callers are unchanged.
The snap receipt loop was extracted without changing its ordering or output so
that real filesystem regressions can exercise it directly. Product code, release
policy, collector, menu driver, launcher and permission wrapper are unchanged.

The existing amd64 rehearsal now creates actual image/cache hard links and
checks that each staged operator file still refuses an additional link. Its
cleanup also verifies both snap and cache fixture names are gone.

## Evidence

Local logs and audits: [`.scratch/acceptance/h22/`](../../../.scratch/acceptance/h22/).

| Check | Result |
|---|---|
| Original-source reproduction | The exact checker from `HEAD` failed through the documented streamed SSH caller on the linked Certbot fixture with `MVP_WINDOW_REFUSED unsafe-file:/var/lib/snapd/snaps/certbot_999999.snap`. `red-full-linux.log`. |
| Focused tests | All 17 tests passed on root Ubuntu ARM64 and amd64. Nine exercise actual filesystem hard links, ownership, permissions, xattrs, file types, content/receipt drift and the retained strict rule. CLI responses and the snap directory location are fixtures. `green-linux.log`, `green-full-linux.log`. |
| Full amd64 rehearsal | Six accepted observations and 26 expected refusals passed through the documented SSH call, including real pinned-DEB install/hold/purge and the unchanged permission wrapper. `green-full-linux.log`. |
| Failure cleanup | A deliberate assertion after Running exited 1 as expected. Independent audits after the original refusal, successful rehearsal and injected failure all matched the pre-test baseline: package inventory, log identities and fixture/account absence, including cache aliases. `*-linux-audit.json`, `injected-failure-linux.log`. |
| Native checks | Focused Go wrapper, `GOTOOLCHAIN=go1.26.6 go test ./... -count=1`, and `go vet ./...` passed on macOS. Root-Linux skips there are not counted as Linux evidence. Python syntax and final diff checks passed. |

Both VMs used checksum-verified Ubuntu 24.04 images, restricted egress and
loopback-only SSH forwards. Guest checker/test hashes matched the local source.
Temporary files, VM processes, listeners, disks and ephemeral keys were removed;
the pre-existing ARM64 base image and all pre-existing untracked documents were
preserved. See `source-sha256.txt` and `cleanup.json`.

The snap CLI/images, SBXR records and menu remain synthetic fixtures; this does
not test snapd installation/refresh, a real SBXR candidate, outside proxy traffic,
certificate issuance or Karing. The previously failed candidate remains failed.
No live retry or release qualification is implied by these regression results.
