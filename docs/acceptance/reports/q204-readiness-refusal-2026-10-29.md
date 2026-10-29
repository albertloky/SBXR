# q204 readiness refusal and offline diagnosis — 2026-10-29

Candidate `v3.1.130 / 204`, commit
`8ef6898573d8e7886d11c65b693f79d7c502787f`, was **not qualified**.
[Run 40811037642](https://github.com/albertloky/SBXR/actions/runs/40811037642)
completed cancelled after the operator stopped on the first readiness refusal.
Native/assembly checks, draft construction and signing passed. Local attestation
verification and exact qualification-boundary replay passed. The signed draft
release `427453228` remains preserved. No second attempt, burn, draft deletion or
publication followed. The old unknown-signing draft `426359967` remains untouched.

## What the saved evidence establishes

Packaged installation and exact installed-byte verification passed. During the
single initial details invocation the first menu reported unsafe/unsupported host
observations and offered no setup action. Its network readiness diagnostic named
`Timeout`. The native records identify two bounded commands:

- `getent ahostsv4 api.ipify.org`: query 81 timed out after 5.004319 seconds.
- `getent ahosts google.com`: query 165 timed out after 5.004540 seconds.

At each timeout the last observation placed the process in its loop, leader not
exited, zero stdout/stderr bytes, neither pipe at EOF. These are last sampled
states, not kernel wait-channel or DNS packet observations. Other calls to both
queries before and after the timeouts completed successfully. This proves
intermittent command noncompletion within the five-second limit, not its cause.
It does not distinguish resolver/NSS delay, upstream response loss, scheduling or
another child-runtime cause. No extra live probe was performed to fill that gap.

`NativeReadOnly::query` in `src/host/process.rs` supplies the five-second bound;
`src/host/network.rs` propagates resolution failure. The Standard review fails
closed when its state observation fails. A later review recomputes current facts,
so later successful queries can make setup available. No guard was bypassed.

The details driver returned zero because it selected View details, received the
continuation prompt, returned to the menu and exited normally. Its contract in
`.github/scripts/v3-menu-session.py` does not assert readiness or setup success.
The operator inspected the first menu rather than treating that exit or later
redraw as a passing qualification gate. Setup was never applied; no proxy
credentials, sing-box deployment, outside test clients or Karing profile were
created. None of the five complete live journeys passed.

## Restoration

Supported software-only removal passed. Independent inspection caught dangling
qualification CA aliases after the workflow transport trap. The exact recorded
alias identities and run-owned recorder/request files were checked, their evidence
retained, and only those leftovers removed. By 04:17 UTC the original host trust
bundle, hosts, routes, SSH state and protected evidence matched the baseline;
owned resources were absent and original Karing profiles/settings/connection/TUN
were preserved. Credential-free outside requests bound to the approved interface
were refused on 443/8443; test-client loopback ports were closed. A bare TCP
connect through the existing TUN was inconclusive and was not used as rejection
proof. Cleanup is not a passing removal journey.

## GitHub failure-evidence boundary

The failure-evaluation step logged `Resource not accessible by integration
(HTTP 403)` and exited 1. The later explicit decision-stop step also exited 1 as
designed. The first 403 must not be described as only the intentional stop.
The saved log does not name the denied endpoint. The script contains artifact,
attestation, job, release and asset reads; absence of intervening output does not
uniquely identify which failed. No denied request was retried, no alternate token
was substituted and no token permission was expanded.

The bounded offline repair adds fixed operation labels and an EXIT diagnostic to
that evaluation step. It preserves the original failure status, authentication,
unsigned-proof requirements and explicit action-time stops. It logs no command,
token or payload. Inert shell regressions inject failures in artifact listing,
artifact download and attestation verification. All three fail against the old
workflow because the operation label is missing; all pass with the diagnostic.
The complete 16-test workflow safety suite and repository-root Go workflow
integration suite (90.024 seconds) pass. This improves future failure
localization; it does **not** resolve or retroactively identify q204's HTTP 403.

Private evidence is retained under `.scratch/acceptance/q204-full-20261029/live/`
(`closeout.json`, `restoration-summary.json`, original menu/diagnostic captures,
`diagnostic-timing-summary.json`, and `cleanup-unqualified.log`). Offline test
outputs are under `.scratch/acceptance/q204-offline/`. These are observations of
this attempt, not authority for another live run. A new live diagnostic or attempt,
security-sensitive permission change, draft disposal, burn or publication needs
its applicable separate approval. No stable-readiness claim is made.
