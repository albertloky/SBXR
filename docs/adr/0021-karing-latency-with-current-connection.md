---
status: accepted
---

# Qualify Karing without switching the Owner connection

On 2026-09-02 Albert approved per-node Karing latency tests instead of switching
his current connection to SBXR. For the ADR-0018 repair only, use signed policy
`repair-issuance-bounded-v3`. Retain ADR-0020's exact 25 live scenarios, 29
automated-only scenarios, and two automated-only lifecycle checks. Supersede only
the conflicting final Karing requirements in ADR-0016/0019/0020 and
#342/#335/#356/#357; historical policies and attempts keep their original meaning.
Production behavior and Client Identity revocation rules do not change.

Replace exactly these four `karing-final` checks:

```text
direct-and-proxied-traffic old-established-session-terminated traffic-restored direct-refresh-correction-or-confirmed-fallback
```

Require these five additional checks, in this evidence order:

```text
current-connection-preserved fresh-initial-node-latency fresh-revoked-identity-latency-refused same-link-refresh-before-replacement-latency fresh-replacement-node-latency
```

The four latency/refresh events must have nondecreasing actual timestamps:
initial success, old-credential failure, same-link refresh, replacement success.
Test the exact SBXR node against the configured URL, not a selector, fallback,
another node, cached latency, or ICMP/TCP-only probe. Confirm privately that the
cached UUID is still old at failure, then changes only after the same real HTTPS
link refresh; preserve other fields/name. Coordinate automatic refresh so it
cannot update the UUID before the negative check. A timeout alone does not prove
revocation: independently prove outside-target health and server-side refusal.

Preserve the current selected connection, unrelated profiles, DNS, routing, TUN,
and Owner settings throughout. Do not select SBXR, redirect ordinary Mac traffic
through it, or disconnect/restart the current connection to force a test. Karing's
latency handler can request a VPN start/restart when configuration is dirty. If
the exact package cannot test without disturbing the current connection, stop
before that action and report missing evidence; do not claim success or bypass it.

Keep all other final checks: exact official package, trusted real link, one remote
profile/node, fields/name/settings, manual and genuinely due five-minute automatic
refresh, UUID-only replacement, outside-target health, HTTPS outage preserving the
cached node with successful fresh latency, same-link recovery, Complete removal,
unusable outside access, full absence, and secret cleanup. Final owned-process
termination and old-new-connection refusal remain server-side observations.
Earlier `identity-*` scenarios retain their full independent outside-session,
revocation, startup, and fallback proof, without using the Owner's Karing route.

Require these exact public Acceptance Record lines:

```text
Karing connectivity evidence: Fresh per-node latency; current connection preserved; no Karing browsing or established-session claim
Karing checks not performed: karing-final/direct-and-proxied-traffic karing-final/old-established-session-terminated karing-final/traffic-restored karing-final/direct-refresh-correction-or-confirmed-fallback
```

These omitted Karing checks are neither live passes nor new automated-only checks.
Reject missing, altered, duplicate, or scope-inappropriate disclosures. Preserve
production TLS trust, three planned issuances, exact bytes, all original clocks,
failure burns, and fresh-attempt requirements. Natural timer firing and naturally
due certificate renewal remain Not observed. The unsigned v3.1.12 / Sequence 95
candidate used the old contract and was cancelled before signing; its draft was
removed by verified workflow cleanup. A new candidate needs final-tree verification.

Source: Karing `v1.2.24.2709` [latency button](https://github.com/KaringX/karing/blob/v1.2.24.2709/lib/screens/server_select_screen.dart#L1400)
and [per-node URL test](https://github.com/KaringX/karing/blob/v1.2.24.2709/lib/app/modules/server_manager.dart#L1536).
Static source inspection is not a live Karing pass.
