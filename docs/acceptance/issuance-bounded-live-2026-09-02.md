# Issuance-bounded repair: failed first live attempt

Attempt `run-33592907845-attempt-1` used `repair-issuance-bounded-v1`,
candidate `v3.1.1`, Release Sequence `84`, commit
`dd6fc91c9b860487bb5ae4da6ea81ccac78b00ba`, and Release Index SHA-256
`002723f3e2153ee7c5e4d5db18a7bd730e56f16e01cfb8986ebb3fea8cdf5342`.
Both candidate-native architecture jobs passed their full normal/race suites,
vet, module verification, and package checks. The signed manifest was created
at `2026-09-02T05:15:52Z` after the Owner-approved environment gate.

The first `baseline-clean` request began at `2026-09-02T05:17:38Z`.
Fresh VPS preflight passed at `2026-09-02T05:18:19Z`; the unchanged candidate's
public installer and `Not set up` state passed at `2026-09-02T05:18:39Z`.
The operator invoked reviewed Start setup through the packaged menu. The original
SSH continuity connection and setup command connection then closed unexpectedly.
No baseline pass or later scenario was submitted.

The fault was in the Mac control invocation, not established as a product defect:
`ProxyCommand=/usr/bin/nc -b en0 -w 10 %h %p`. macOS `nc(1)` explicitly applies
`-w` to idle established connections. The command therefore severed quiet SSH
connections after ten seconds, including the separate continuity session.
Read-only reconnection at `2026-09-02T05:19:04Z` found `Proxy status: Running`
and `PROXY-INSTALLATION-SETUP-COMPLETE`. That observation did not repair the
failed continuity requirement or justify further test mutations.

Canonical `v3-scenario-failure` facts were accepted with `unexpected-failure`,
`boundary: observed`, `host_state: Running`, `stop_test_mutations: true`, and
`burn_required: true`. The existing supported failure-cleanup path performed
reviewed Complete removal. At `2026-09-02T05:20:28Z`, fresh inspection proved
product and transport absence, including no listeners on 80/443/8443/9443.
Separate canonical cleanup facts were accepted as `completed` / `Not installed`;
the outcome remained `failed`. Exact attempt-owned temporary files were removed.
No subscription enablement, production CA order, or Karing profile change occurred.

[Candidate workflow 33592907845](https://github.com/albertloky/SBXR/actions/runs/33592907845)
finished with failed acceptance and successful failure finalization. `v3.1.1`
is a failed prerelease, and `refs/tags/release-burned/v3.1.1` records the burn.
Public stable `v3.1.0` is unchanged. No live scenario from this attempt is reusable.

The corrected invocation omits `nc -w`, uses SSH `ConnectTimeout=12`, and retains
SSH server-alive checks. The same physical-interface-bound connection answered at
`2026-09-02T05:20:11Z` and again at `2026-09-02T05:20:56Z`, proving survival of
a 45-second command-idle interval without changing Mac routing or Karing settings.
The qualification procedure now requires this check before signing.
A fresh Release Identity and the complete retained live matrix remain required.
Natural timer firing and naturally due renewal remain excluded and Not observed.
