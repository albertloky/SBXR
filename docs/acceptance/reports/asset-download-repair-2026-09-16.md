# Unsigned candidate asset download repair — 2026-09-16

This is a bounded workflow transport repair based on
`7f04c12c75c29611f67feb780298a5e56d9dda68`. It is not a live acceptance result
or permission to publish a stable release. The changes are in the working tree;
no replacement candidate was launched.

## Original failure and cause

Candidate **v3.1.73**, sequence **152**, at the revision above failed in
[workflow 35067639476](https://github.com/albertloky/SBXR/actions/runs/35067639476).
Preflight and both native builds succeeded. At `2026-09-16T07:30:42Z`, the
draft job's authenticated asset GET failed with `read: connection reset by peer`
while fetching the amd64 archive. Signing and live acceptance never started.
The original failed attempt remains failed.

The candidate workflow, shared release recheck, and release-history collector
were unchanged between the earlier successful draft/signing revision
`b97b56859e32d10b0a303ad2a98d7734340ff0eb` and the assessed revision. The recent
certificate diagnostics and availability presentation changes do not explain
this execution path.

The supported software cause is that a single interrupted, read-only asset
request immediately aborted draft construction. The command wrote directly to
its destination and had no recovery for a reset. The following canonical
verification never consumed that failed download. The original logs do not
record its partial byte count, and they cannot identify which peer or
intermediary reset the connection. A GitHub outage, runner network fault, and
other network explanations remain unproven.

A controlled local TCP server reproduces the reset with the real `gh api`
subprocess, including a redirect. The existing release recheck fails this
regression before the correction. The server also exercises a reset after an
observed partial body has reached disk. It uses fixture credentials and local
HTTP only; production TLS behavior is not replaced or disabled.

## Correction

`download-release-asset.py` owns the repeated authenticated asset-read operation
used by candidate preparation, draft verification, handoff, stable observations,
history collection, and qualified-release rechecks. It:

- Makes the same authenticated `gh api` GET, retaining normal redirect handling.
- Allows **one** fresh GET only for the observed TCP read-reset diagnostic.
  This re-enters the API for a fresh redirect and starts from byte zero, without
  an artificial delay or resuming an incomplete body.
- Writes to a private temporary directory and atomically replaces the requested
  destination only after successful completion. Exhaustion preserves any
  existing destination and returns failure; callers stop before consuming it.
- Logs each failed read, exit status, and discarded byte count while redacting
  URLs that may contain temporary credentials. `GH_DEBUG` is suppressed for
  this binary transfer to prevent verbose credential-bearing output.

HTTP errors, content mismatches, and a second reset still fail. Release creation,
upload, deletion, signing, certificate issuance, and candidate dispatch are not
retried. Existing release identity, size, digest, canonical qualification,
attestation, and cleanup checks remain in their original callers. The helper
does not decide that downloaded bytes are trusted.

The additional helper is justified by this observed failure and the seven
existing copies of the same asset-read operation. Git history and the existing
hash checks establish identity and detect bad bytes; they cannot complete an
interrupted GET. No new release gate or persistent baseline was added.

## Verification and evidence

Artifacts are retained in
[the repair run directory](../../../.scratch/acceptance/asset-download-repair-20260916/).

| Check | Result / evidence |
|---|---|
| Existing script with reset followed by a healthy response | Failed as expected; `regression-before.log` |
| Corrected transport on macOS, real gh 2.101.0 | Seven tests passed; `regression-after.log` |
| Ubuntu 24.04 amd64, real gh 2.100.0 | Same seven tests passed; `native-ubuntu-regression.log` |
| Successful first download and fresh-redirect recovery | Exact expected bytes, bounded request counts |
| Reset before headers and after partial bytes | Recovery succeeds; original diagnostic retained with URL redacted |
| Two consecutive resets, including partial bodies | Failure after two attempts; old destination preserved, temporary bodies removed |
| HTTP 401, 403, 404, 429, 500, 502 | Failure after one attempt, including error messages containing reset words |
| Real release recheck | Reset recovery passes; wrong identity, metadata size, and content digest still fail |
| Release history's temporary working directory | Real subprocess collection and reset recovery pass |
| `go test ./... -count=1` and `go test -race ./... -count=1` | Each passed nine packages and failed only the two host tests affected by the long macOS temporary path; original outputs retained |
| Host package ordinary and race reruns with short `TMPDIR` | Both passed; all 10 packages are covered by passing results across the full runs and focused reruns |
| `go vet ./...`, shell/Python syntax, diff whitespace | Passed |

The failed runner image documents gh 2.100.0 in its
[included software](https://github.com/actions/runner-images/blob/ubuntu24/20260907.300/images/ubuntu/Ubuntu2404-Readme.md).
For the Ubuntu check, that CLI archive was fetched from its official release,
checked against release metadata size and SHA-256, and used only from a temporary
test directory. No global package was installed. The
[gh API documentation](https://cli.github.com/manual/gh_api) describes the
authenticated GET operation retained by the helper.

The first broad macOS checks hit two unchanged host-runtime tests because this
run's long `TMPDIR` produced a 130-byte Unix socket address. A direct bind
experiment refused that address and accepted a 102-byte path through a short
alias to the same in-repository directory. The affected host package was rerun
with the shorter path; no product code, assertions, or timeouts were changed.
See `macos-temp-path-experiment.json` and the `go-host-*-short-path.log` files.

## Cleanup and limits

The Ubuntu fixture directory and its temporary CLI were removed; see
`native-cleanup.log`. The tests used loopback listeners and fixture credentials.
No SBXR installation, certificate request, Karing change, release mutation, or
candidate dispatch occurred during this repair. All 11 unrelated untracked
acceptance, research, and ADR files were preserved byte-for-byte.

The historical v3.1.73 report and raw evidence remain unchanged. Its retained
independent API observations show 404 for the candidate release, tag, and burn.
The successful `cleanup-unqualified` job alone was not that proof: its relevant
steps were skipped because no qualification boundary artifact existed. Early
failure facts were not uploaded by the original workflow. This repair does not
rewrite that evidence or broaden unsigned cleanup policy.

These checks demonstrate bounded handling of the reproduced reset; they do not
identify the source or frequency of the hosted network failure. Full native
Verify for a committed repaired revision and a fresh five-journey MVP acceptance
remain separate from this local repair. No stable release is qualified by it.
