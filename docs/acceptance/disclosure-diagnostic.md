# Disclosure-only diagnostic

This is a non-qualifying diagnostic, not a replacement for the five
[HTTP acceptance journeys](http-subscription-live.md). It cannot create an
acceptance record or support stable publication. A separate approved live window
is required; local tests do not authorize dispatch or host changes.

The signed attempt contains `diagnostic` with integer `start_unix`,
`test_until_unix` and `finish_unix`. The latter two are exactly two and three
hours after the approved start. Its only declared scenario is `mvp-install`;
this identifies the existing installation/removal clock envelope, not a claim
that the complete installation qualification passed. The normal source,
release-history, asset, signature, proxy-package and host checks remain.
No Owner exception, VMess profile or attended Karing wait is permitted.

Record and verify the installed Karing package and its preservation baseline.
Keep its historical `karing_latest_checked_at` value without claiming a fresh
Latest check. This mode does not require an upgrade, import, refresh, profile
change or credential rotation. Ordinary qualification still checks latest Karing.

## Execution procedure to review before dispatch

1. Freeze the tested source and signed candidate, current host/key identities,
   installed Karing baseline and existing guarded removal callers. Bind all
   callers to the diagnostic request and draft paths below; never reuse a
   historical caller's constants. Verify the M1 900-second restoration envelope
   and preservation inventory offline before admitting live work.
2. Declare the approved absolute start, two-hour test cutoff and three-hour
   restoration deadline. Set `security_cutoff_unix` to that exact finish value.
   Build/sign/queue time consumes this window. Dispatch `candidate.yml` only
   under separate push/dispatch/live authorization.
3. The installer and Rust client use the private HTTPS gateway on loopback port
   9443. Run the bound transport script’s `install "$TAG"` command under the
   existing supervisor. It verifies the bootstrap, then runs the installer in private gateway mode.
   Read the CA from the staging directory. Other programs keep their normal GitHub connection.
   Port 443 remains available for the product proxy. No HTTP subscription is enabled.
   The diagnostic collector exclusively creates
   `/root/sbxr-diagnostic-run-<run-id>-attempt-<attempt>/`. It snapshots the
   identities, metadata and bytes of `/root/sbxr-qualification-evidence` and
   `/root/mvp-observation-draft.json`; it never writes, moves or removes them.
   An unexpected retained object, link, permission or subsequent change refuses.
4. Obtain `diagnostic-handoff.json` and independently bind its state hash and
   manifest to the current run. Use `<directory>/request.json` as
   `SBXR_QUALIFICATION_REQUEST`, and `<directory>/observation-draft.json` as
   `SBXR_QUALIFICATION_DRAFT`, with the reviewed `mvp-observe.py` clock and its
   hash. Start the unsealed recorder through its ordinary `start` command.
   Every `exact_candidate` invocation must explicitly receive the manifest path
   as its first argument and this request path as its second argument. Use
   `diagnostic-restoration.py` to validate the request against the authenticated
   manifest and approved diagnostic window; do not invent `attended_finish_by`.
   Do not use the ordinary collector or its `submit` interface.
5. Run one packaged install/setup, Check and disclosure through the existing
   bounded driver. Pass `--diagnostic-output` for disclosure: the driver discards its entire
   stdout transcript before capture, retaining only allowlisted stderr timing
   and refusal metadata plus the supervised exit status. Do not create a client
   export for this diagnostic. Require the disclosure stdout capture to be empty
   on both success and failure; preserve its producer-bound empty receipt.
   The request lasts at most 30 minutes and ends at least 60 seconds before the
   approved finish. Its ordinary-operation cutoff is the earlier of the approved
   two-hour cutoff and 15 minutes before the request deadline. The existing
   driver enforces this through `operation-deadline`; `cleanup-deadline` retains
   the remainder. Ordinary callers use that already-reserved operation cutoff
   without subtracting the same 900 seconds again. If the runtime or approved
   finish is earlier, `operation_cutoff` tightens ordinary work to at least 900
   seconds before that earlier finish. Guarded-removal reserves remain unchanged. No late diagnostic action may consume that removal reserve.
6. Mark the diagnostic stopped in the existing cleanup review and perform only
   the supported, identity-checked M1 removal path. Verify host/package/service/
   account/firewall preservation, SSH, original Karing state and scoped secret
   cleanup. Do not seal the recorder before removal. Do not improvise deletion
   or reconstruct missing authority if a check refuses.
7. Only after that verification, exclusively write `<directory>/operator-finished.json`
   with exactly `manifest_sha256`, `request_sha256`, and
   `status: "operator-finished"`, bound to the frozen state. This is a notification,
   **not proof of restoration or qualification**. The collector independently
   checks the unchanged old evidence, request and namespace identities and
   absence of the SBXR executable/state before returning. The workflow then
   runs the unchanged guarded transport teardown. Independently verify the gateway stopped and the host trust,
   routing and hosts file still match the baseline.
8. Preserve the diagnostic namespace and secret-free receipts as evidence.
   On refusal, timeout or disconnect, retain the actual failure and report any
   unproved restoration. The workflow's existing transport exit trap remains;
   it does not perform product removal. There is no `STOP` write, evidence
   deletion, acceptance-record edit, stable publication or automatic draft
   finalization in the diagnostic branch. Its draft remains unqualified and
   requires the existing explicit disposition before a later candidate.

These checks do not prove a live run will succeed. The private, run-specific
caller bindings and final restoration receipt are reviewed execution inputs;
they are not supplied by a successful local fixture test.
