# Rust q202 Standard Review and DNS comparison — 2026-10-28

The direct SBXR test reached **Standard Review: Ready** and cancelled without
Apply. It does **not** establish a DNS fix or a qualified release. No product
change is justified by the new capture alone.

## Bound evidence

| Capture | Exact source / run | Observed result |
| --- | --- | --- |
| q201 details cycle | `e7cb40d59ac9f8975852f807f7b887599744b969`, [40477934924](https://github.com/albertloky/SBXR/actions/runs/40477934924) | Passed in 66.276 native seconds; a DestinationDns timeout occurred during the returned status review. |
| q201 selected Standard Review | Same source/run | Refused with `PROXY-INSTALLATION-ACTION-REFUSED`; the same review emitted `guard=network`, `cause=timeout` following PublicIpDns. No Apply. |
| q202 direct Standard Review | `8b23422373507169e28fbc2ca7e81f692511131d`, [40613098549](https://github.com/albertloky/SBXR/actions/runs/40613098549) | Ready; cancelled, returned to menu and exited in **69.469417 native / 72.325559 SSH seconds**, within the unchanged 90-second limit. No Apply. |

Local comparison re-read all three original captures, verified their recorded
SHA-256 digests and matched native query IDs to their begin/end phases:

| Timeout | Query phase | Enclosing phase | Duration |
| --- | --- | --- | --- |
| q201 details, ID 660 | DestinationDns: `/usr/bin/getent ahosts google.com` | Returned `review-status` / `open-tunnel` | 5.002226 s |
| q201 selected Review, ID 543 | PublicIpDns: `/usr/bin/getent ahostsv4 api.ipify.org` | `review-action`; exact failed network guard recorded | 5.003251 s |
| q202, ID 112 | DestinationDns: `/usr/bin/getent ahosts google.com` | Initial `review-status` / `open-tunnel` | 5.004471 s |

The q202 timeout receipt preceded the first menu selection by **6.618003 s**.
The selected Review's captured DNS queries completed successfully; its Ready result did
not reuse the failed query as positive admission. Each capture also contains
successful DNS queries taking roughly 7–31 ms. These observations demonstrate
intermittent bounded-query failure, not its underlying cause.

All three timeouts report the same **last-observed** state: leader `not-exited`,
location `loop`, zero captured stdout/stderr bytes and both EOF flags false.
This is not a fresh process inspection at timeout. It does not prove upstream
DNS/NSS failure, child scheduling delay, a blocked syscall or a descriptor leak.
No observed exited-leader/open-output-pipe timeout is present in these captures;
that does not rule it out in uncaptured history. No external observer was used.

## Source interpretation and repair decision

[`process.rs`](../../../src/host/process.rs) retains fixed commands, cleared
environment, five-second child-loop deadline, cancellation, bounded nonblocking
output and owned process-group cleanup. [`network.rs`](../../../src/host/network.rs)
propagates the current query failure. [`linux.rs`](../../../src/host/linux.rs)
requires fresh network admission for the selected Standard Review.
[`owner.rs`](../../../src/proxyinstallation/owner.rs) permits independent
journey observation; a failed optional opening cannot substitute for a successful
selected action's own review.

Comparing q201's source to q202's source shows no DNS-command, resolver-policy,
network-admission or timeout repair. The relevant process change is the
[passive observer hook](../../../src/host/dns_observer.rs); no probe was attached.
Ready in one later invocation is therefore not evidence of a causal fix.
Increasing deadlines, changing DNS policy, caching a prior positive admission or
weakening refusal would be speculative. **No implementation or regression-test
change was made.** The local checks were capture-hash verification, phase/query
ordering and duration recomputation, source-diff review and documentation checks;
no live query, reproduction, cloud workspace or new workflow was run.

## Completion, exclusions and next step

The approved q202 test installed authenticated SBXR only. Standard Review was
cancelled with No; no sing-box installation, deployed proxy credentials, public
proxy service, outside traffic or Karing changes occurred. Review's transient
TCP 443 availability bind closed without an accepting service or firewall change.
Software-only Complete removal passed; this safety cleanup is not a passed M5.
Independent restoration passed **33 checks at 2026-10-28T02:12:04.686087Z**,
including exact hosts/CA bytes, routing/firewall rules, accounts/packages, SSH,
retained lock identity, owned absence and previous evidence preservation.

Because the five journeys were intentionally unperformed, q202 was submitted
once as `evidence-refused`. [v3.1.128 / 202](https://github.com/albertloky/SBXR/releases/tag/v3.1.128)
is permanently burned and immutable failed non-Latest. **v3.1.118 / 192 remains
Latest.** Neither successful Review nor software removal proves Apply, proxy
setup, subscription, rotation, serving restart or full removal qualification.

The next product-verification step is a **fresh authenticated candidate's actual
Apply and five HTTP journeys**, continuing only after its normal readiness gate.
It needs fresh bounded live approval for RackNerd-only temporary gateway/CA and
hosts/NAT restoration, package/service installation and ports 443/8443, disposable
credential creation/rotation/revocation, isolated client/Karing use with BWH
preserved, and independently verified cleanup. Signed-failure consequences remain;
no stable publication or retry is implied. Another Review-only capture is not
proposed. The intermittent query cause remains an explicit unresolved limit.

Private, immutable run evidence and comparison are in
[the q202 run directory](../../../.scratch/acceptance/q202-direct-20261028-1/):
`live/final-result.json`, `live/final-host-restoration.json`,
`live/single-standard-review.{private,stderr}` and
`analysis/capture-comparison.json`. Prior refusal evidence stays unchanged in
[q201](../../../.scratch/acceptance/q201-retry-20261027-1/live/repair-handoff.json).
These local links may be unavailable in a fresh clone. No operational secrets or
raw resolver output are included here.
