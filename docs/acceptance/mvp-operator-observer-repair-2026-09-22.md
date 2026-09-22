# MVP operator observer repair — 2026-09-22

## Outcome and scope

**Implemented and focused-regression-tested; full local operator sign-off is
still open. Not live-validated.** Work stayed on `main`, based on
`477a0d7a32da683b0a0b00551696e363cfbc4e6c`. No commit, push, candidate dispatch,
VPS connection, public CA request, outside-client launch or Karing change was
performed. Product source, release policy, collector, driver, launcher, permission
wrapper and supervisor are unchanged.

The new read-only observer completed its real dpkg/SSH lifecycle rehearsal.
A subsequent, separate unchanged driver suite failed its deadline fixture in
the emulated amd64 VM. Further tests stopped at that unexpected result; no
repair of that separate case or timeout increase was attempted. Cleanup was
independently verified before destroying the disposable VM.

## Confirmed defect and correction

The retained v3.1.77 observations show successful setup followed by an operator
assertion failure: `installed_proxy_package` was null because the run-local
observer queried dpkg only when the temporary DEB existed. The product's
`installPackage` deliberately removes that verified download after installation.
The actual installed package was `1.13.19 amd64 hold ok installed` (`hi `), not the
observer's assumed `ii`. Renewal-idle inspection was accidentally inside that
same conditional. A later operator cleanup assessment also compared the
Ownership Record's package string directly with the declaration object.

The [source-owned observer](../../.github/scripts/mvp-inspect-window.py) and its
[documented streamed SSH caller](mvp-protected-log-parent-2026-09-19.md#read-only-state-checks-corrected-september-22)
replace those handwritten checks:

- Always query installed package state, independently of the temporary DEB.
- In Running, require the declared version/architecture, `hold ok installed`,
  the approved binary digest, and the product's package-identity string.
- Require the temporary artifact to be absent in the named steady states,
  including broken-symlink detection. Do not modify SBXR to retain it.
- Inspect renewal completion independently of the artifact.
- Distinguish Not installed, installed/Not set up, Running and removed checks.
- Compare the original log identities, reviewed snap receipts and exact four
  staged operator files; refuse residual window state, held locks, active writers
  and insufficient timer margin. Emit no private record or process arguments.

This adds no product authority, new acceptance journey or automatic pass. The
observer is streamed from reviewed source, not staged as a fifth operator file.
Candidate verification, full footprint absence, legal menu Review, CA capacity,
logging health and live outside/Karing observations remain separate.

## Validation

Artifacts are retained locally under
[`.scratch/acceptance/o22/`](../../.scratch/acceptance/o22/).

| Check | Result and boundary |
|---|---|
| Red contract regression | The original DEB-gated package logic returned null with an absent artifact and missed the refusal/renewal cases. Retained in `red-contract.log`. |
| Final portable contracts | All 8 tests passed, including wrong version/architecture, unheld/config-files/missing package, wrong binary, stale/broken paths, Ownership Record representation, unfinished ownership and renewal completion. `green-contract-final.log`. |
| Real observer lifecycle | Passed 28 documented SSH invocations: 6 accepted observations across Not installed, Not set up, Running and removed; 22 expected refusals. Actual official amd64 DEB installed, held, removed and purged with real dpkg. `linux-observer-final.log`. |
| Permission windows | Successful fixture Check through the unchanged actual driver/launcher/wrapper, and actual package purge through the unchanged wrapper; original log identity and no retained state afterward. These are not product Complete removal acceptance results. |
| Failed-test cleanup | A deliberate assertion after a successful Running observation exited 1 as expected. Package, account, operator, timer, lock and shared-directory fixtures were removed. Before/after audits were byte-identical, including log identities and unrelated package inventory. `linux-injected-failure.log`, `before-failure-audit.json`, `after-failure-audit.json`. |
| Fixture guard | Explicit optimized-Python refusal was added during final review and tested separately; `-O` cannot disable destructive-fixture assertions. Normal lifecycle results above precede this test-only guard addition; production observer bytes are identical. `optimized-fixture-refusal.log`. |
| Ordinary Go suite | Final `GOTOOLCHAIN=go1.26.6 go test ./... -count=1` passed on macOS, followed by `go vet ./...`. Platform-specific skips are not Linux validation. |
| Source/docs review | Documented caller syntax, focused Go wrapper, Python syntax, final diff whitespace and all 21 preexisting untracked-file digests checked. |

The official Ubuntu Server 24.04 amd64 cloud image matched the HTTPS-published
checksum `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
The guest used QEMU TCG on the ARM Mac, with `restrict=on` from first boot and
only a loopback SSH forward. The pinned DEB was copied from the existing verified
local public package, not downloaded by the guest:

```text
DEB size:   24597120
DEB SHA:    fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf
binary SHA: 031042edfd30a215e4c69d83eb7d13c194e6ef50c782e2e1308d9d8fa128454a
observer:   0eb75d4cf79e5bc9a30ffd376a5e1f77c7ad738d013bd67f69aa3dc81a54882c
```

SBXR Installed/Ownership Records and the numbered menu were synthetic. Snap
CLI responses/images were fixtures. The actual sing-box service stayed masked;
no proxy traffic or certificate issuance was attempted. dpkg, the installed
binary, SSH, systemd timer, kernel locks, filesystem and permission-window
mechanisms were real.

The first native full-suite run used `t-go`, making its Unix socket path 104
bytes and triggering the already documented macOS socket-path limit. The failed
log is retained as `go-test-long-tmpdir.log`. Repeating with the guide's shorter
`t` path (101 bytes) passed without code, assertion or timeout changes.

## Separate unresolved validation failure

After the new observer and its expected-failure cleanup passed, the unchanged
`test_mvp_protected_menu.py` was rerun in the same amd64 TCG guest. It passed
missing/unsafe shared-directory refusal, argument refusal, normal completion,
nonzero exit and protocol-error cleanup/restoration. Its existing **three-second
deadline** case then failed at the assertion requiring a nonempty process
journal: the journal was `[]`.

That is a failed fixture run, not a proved product defect and not a passing
interruption proof. Slow emulation is a plausible contributor, **not an
established cause**. No timeout was increased, assertion weakened or product
change made. The subsequent real-SSH suite in the command sequence did not run.
The earlier unchanged driver/SSH results remain historical evidence; they do
not turn this new failure into a pass.

The driver's own cleanup completed, and an independent audit matched the
pre-test baseline exactly (`after-driver-failure-audit.json`). The VM's SSH and
rsyslog were active before normal shutdown. At `2026-09-22T03:39:31Z`, its process
and loopback listener were absent; only this run's VM disks, seed and ephemeral
keys were deleted. `cleanup.json` records the exact deletions. Source inputs,
checksums, test logs and secret-safe audits remain.

**Next work requires a separate bounded investigation of that deadline fixture,
preferably comparing measured startup/readiness in an appropriate disposable
Linux environment with the existing timeout unchanged.** Do not dispatch another
candidate or claim complete local operator sign-off from this repair alone.
