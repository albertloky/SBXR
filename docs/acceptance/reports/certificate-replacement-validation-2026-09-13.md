# Supported certificate replacement: repair and validation

The v3.1.71 MVP attempt could not prove certificate replacement: ordinary
`snap.certbot.renew.service` completed with exit 0, recorded `no-op`, and left
the certificate unchanged. A healthy subscription exposed no reviewed action
for immediate replacement. This change resolves that missing product entry
point and updates the current procedure without weakening its replacement check.

## Implemented behavior

- **Replace subscription certificate** is offered for a Running proxy with an
  Available subscription, matching accepted/published/loaded certificate, and
  healthy accepted renewal evidence.
- Review describes one managed replacement of the owned lineage, HTTP-01's
  public TCP 80 requirement, activation interruption, and preservation of the
  subscription link, proxy configuration, and Client Identity.
- Execution revalidates the reviewed facts under the existing mutation lock
  and reuses the existing managed Certbot replacement, certificate validation,
  activation, and durable recovery path. Direct success has the distinct code
  `PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED`.
- **Repair subscription** remains fault-specific. **Finish subscription
  change** retains its existing cleanup/forward-completion behavior. No
  ownership schema, new transaction, qualification gate, evidence format, or
  acceptance checklist was introduced.
- The terminal and staged menu driver both recognize the new action and exact
  confirmation prompt. The current [MVP procedure](../mvp-live-acceptance.md#certificate-replacement-procedure)
  uses it instead of treating a successful ordinary renewal invocation as proof
  of replacement.

Certbot documents that successful exit status can also mean renewal was not
necessary, and that forced replacement can target an existing certificate.
The existing SBXR-managed replacement command supplies that behavior while
preserving SBXR's ownership and activation sequence. See the official
[Certbot renewal guide](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

## Regression and integration results

| Check | Result |
|---|---|
| Product and terminal race tests | Passed: `go test -race ./internal/proxyinstallation ./internal/proxyinstallation/adapter/terminal`. |
| Focused replacement tests | Passed: review/decline/success, unchanged link and proxy identity, stale-review refusal, healthy-evidence admission, fault-only Repair behavior, interrupted Finish recovery, and terminal success/failure rendering. |
| Full local host-adapter suite | Passed with repository-local `TMPDIR` after shortening the validation directory to fit macOS Unix socket paths. |
| Repository integration and command entry point | Passed: `go test . ./cmd/sbxr`. |
| Other Proxy Installation packages | Sing-box and subscription-serving tests passed during the subpackage run. |
| Static checks | `go vet ./internal/proxyinstallation/... ./cmd/sbxr` and `git diff --check` passed. |
| Menu subprocess tests | 14 tests: all passed on Ubuntu; 12 passed locally with two Linux-only cleanup cases skipped on macOS. |
| MVP evidence tests | All five Python tests passed; existing evidence submission format is unchanged. |
| Ubuntu renewal/process fixture | Passed the compiled Linux renewal/Certbot tests, including real child-process certificate-file publication, failure, cancellation, lock exclusion/release, sanitized environment, null stdin/stdout/stderr, and durable exit/outcome receipts. |
| Ubuntu real SSH fixture | All 12 cases passed, including the new confirmation/result exchange, staged helper lookup, stdin submission, deadlines, escaped-process cleanup, and evidence submission. Final source also passed with its workspace/TMPDIR under `/root`. |

The new issuer-process fixture actually publishes distinct locally trusted
certificate files; it does not replace the process runner with a callback that
returns success. It tests filesystem, process, lock, descriptor, environment,
and receipt behavior. It does **not** contact an ACME CA. The SSH fixture uses a
scripted menu peer to test the real SSH/menu transport; product execution and
legality are covered by separate module/terminal tests. These fixture results
are not live qualification acceptance.

## Validation corrections and preserved failures

- Before the menu-driver fix, the new action regression failed with
  `phase=confirmation-unsupported`. The same test passed after adding the exact
  prompt; an incomplete action result is still rejected.
- The first long repository-local `TMPDIR` exceeded the macOS Unix socket path
  limit in two runtime-start tests. The run was moved to the shorter
  `.scratch/acceptance/cert/` with `TMPDIR` under `t/`; the full host suite then
  passed. Production socket behavior and timeouts were unchanged.
- An agent's diagnostic run using the default macOS temporary directory hit
  host fixture ownership checks. That result was not accepted as validation;
  the final passing suite used the required repository-owned directory.
- Making the SSH fixture honor `TMPDIR` exposed its existing `/root` isolation
  mount hiding a workspace beneath `/root`. The fixture now retains a directory
  descriptor and binds the same directory back into its private namespace.
  The first bind attempt was canonicalized to the hidden pathname; the final
  bind disables that canonicalization. The original failure and targeted
  diagnostic are retained alongside the final passing 12-case result. This is
  test-only path handling; no VPS mount changes escaped the fixture namespace.

## Cleanup and limits

Cleanup was verified on `107.175.53.219` at **08:54:24 UTC on September 13**.
Both temporary fixture workspace paths, test processes, and test listeners
were absent. SBXR and sing-box remained uninstalled. SSH was active; the
original certbot/core24/snapd revisions and the three checked timers were
unchanged. `/root/sbxr-357-certbot-preflight` remained. Karing was not operated
or changed during this repair phase.

Run evidence and handoff are retained locally in
[`.scratch/acceptance/cert/`](../../../.scratch/acceptance/cert/).
Disposable test binaries, archives, and temporary fixtures were removed.
Unrelated scratch, research, and previous acceptance reports were preserved.

The procedure is **implemented and regression-tested**. Actual ACME issuance,
outside trusted TLS for a replacement produced by the new packaged menu action,
and full qualification acceptance remain **not live-validated**. No candidate
was launched, signed, or qualified and no stable release was published in this
phase. One fresh qualification is now justified when explicitly instructed;
there is no automatic retry or replacement-candidate loop.
