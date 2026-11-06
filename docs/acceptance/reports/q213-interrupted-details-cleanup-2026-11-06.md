# Build 213: interrupted details, removal authentication and administrative cleanup

Candidate **v3.1.139 / 213**, source
`f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3`, failed qualification run
[42023983739](https://github.com/albertloky/SBXR/actions/runs/42023983739).
This report describes November 5–6 observations, not current host readiness or
permission for another attempt. Raw private evidence remains under
`.scratch/acceptance/q213-full-20261105/`; it is not committed.

## Observed journey and limits

Packaged installation and Standard setup completed. The first details command was
started once with the unchanged 90-second budget. Its initial Owner review took
about 37.738 seconds and details writing 19.547 seconds. The driver accepted the
continuation prompt and sent Enter around 60.092 seconds, then began observing a
fresh return-menu review. The Mac connection was interrupted. The retained capture
ends around 79.98 seconds with about 10.02 seconds remaining; no final result JSON,
complete return frame or terminal timeout/refusal was captured.

The complete details cycle is **unverified**: this is neither a pass nor proof
that build 213 exceeded 90 seconds. The captured input event proves a write/flush,
not product consumption. The driver source matches the frozen candidate copy and
the observed fresh-frame behavior matches the current terminal contract. No
additional product defect or performance fix is established by this truncated
trace. Outside traffic, subscription/Karing, credential and later journeys were
not completed. The action was not replayed.

## Confirmed removal sequencing error

Terminal failure submission completed at 13:19:59 UTC on November 5, before
supported removal began at 13:20:20. The collector immediately ends on an accepted
failure; the candidate workflow's EXIT trap tears down the qualification gateway
and protected candidate handoff. The removal attempt exited before menu selection,
with no stdout. Subsequent status-only diagnosis failed in public authentication,
and read-only inspection established that temporary transport/trust were absent.

Public entry requires authenticated delivery before constructing the menu. Full
handoff absence selects stable authentication; the signed but unqualified build
213 draft cannot pass as a Qualified Stable Release. The strict refusal is correct.
This establishes an operator sequencing error, not a demonstrated defect in the
removal transaction. Submitting terminal failure was incorrectly treated as an
evidence write that could precede supported cleanup.

The bounded repository correction adds a fixed secret-safe warning immediately
before terminal failure publication and clarifies cleanup ordering in the current
HTTP guide. When safe, authorized and within the existing window, supported
cleanup precedes terminal submission. If cleanup is blocked, report its actual
incomplete/unknown state. No new success requirement, acknowledgement, transport
extension, authentication bypass, schema or product behavior is introduced.

## Separately approved cleanup

The original window expired with the test service still running. The Owner
explicitly approved the reviewed administrative cleanup and a new 30-minute
attended window beginning **02:12:14 UTC on November 6** (10:12 Hong Kong).
Fresh ownership/readiness checks matched the retained installation.

The service was stopped and disabled at 02:18:37 UTC. Administrative removal
completed at **02:27:46 UTC**, and independent host checks finished at **02:31:03
UTC**, before the 02:42:14 cutoff. They confirmed removal of the test-owned
sing-box package, hold, account/group, configuration/credentials, services,
repository/key and exact SBXR installation. No listeners remained on ports 443,
8443 or 9443; strict SSH worked and `dpkg --audit` was clean. Temporary transport,
trust and routing remained absent; no new trust or routing changes were used.

Packages, holds, account/group entries and normalized firewall rules matched the
pre-install baseline. The 149 recorded baseline paths had no unexplained changes:
passwd/group/hosts retained original bytes and permissions with normal replacement
inodes. Build 212/213 evidence, unrelated resources and original Karing profiles,
settings and selection were preserved; no candidate Karing profile had been added.
The candidate draft, assets, signature and failed result were not changed.

This was **administrative removal**, not a passing supported-product removal
journey. No cleanup blocker remains from that approved recovery. Evidence and
hashes are in `live/admin-cleanup-completed-20261106.json` in the private run root.

## Repository verification and remaining decisions

The pre-existing source f067ca2 passed all four jobs in
[Verify 42009536182](https://github.com/albertloky/SBXR/actions/runs/42009536182).
The earlier unchanged a3d01a9 retry, run 42003224687 attempt 2, ended cancelled.
Neither CI result supplies a successful live qualification.

The new warning-before-publication regression failed against the original helper
in all three cleanup-status cases. Review caught a closed-stderr failure in the
initial diagnostic; its regression failed before the write was made best-effort.
All four collector tests (20 subcases) then passed, including unchanged failure
facts, successful submissions without a warning, closed stderr, truncated/dropped
transfers, changed requests and preserved existing results. These execute actual
Bash/child publication commands over local files with an SSH transport fixture;
they do not exercise a real remote collector or qualification gateway.

The existing menu-driver suite passed 67 tests with four platform-specific skips.
Shell syntax, whitespace and local documentation links passed. Independent review
found no remaining material issue after the stderr correction. The complete root Go integration package passed in 99.522 seconds. Go vet and
module integrity checks passed; the initial offline vet lacked pinned transitive
module metadata, then passed with normal metadata retrieval and unchanged
manifests. Evidence is under `.scratch/acceptance/q213fix-tests/` and
`.scratch/acceptance/q3f/`. Final-source CI is still pending at this commit.
No new VPS operation or publication is part of this continuation.

Before a new qualification, build 213 needs a specific disposition/preservation
decision: its failed draft remains unresolved and must not be silently reused,
deleted, burned or promoted. Prepare a fresh candidate only after the chosen
handling is authorized and verified, final source CI passes, and collision/history
checks succeed. Review operator capture/interruption and cleanup ordering offline,
then obtain approval for the exact candidate, effects and attended window with
fresh host/client readiness and cleanup access. Keep the full 90-second details
cycle and all five HTTP journeys unproved until actually observed. Stable
publication requires successful exact-candidate qualification/cleanup and its
separate explicit approval.
