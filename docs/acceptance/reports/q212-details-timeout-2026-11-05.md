# Build 212: details timeout and verified scoped cleanup

Observed 2026-11-05. Candidate v3.1.138 / 212, source
`13431bc29500bf20dc108dc325590403d0ca056c`,
[qualification run 41958829811](https://github.com/albertloky/SBXR/actions/runs/41958829811).
This is a failed qualification, not a release acceptance record.

Both native builds, packaging, draft verification and signing passed. The exact
approved live gate was approved. Packaged installation and Standard VLESS setup
completed; the initial details/menu cycle failed at its unchanged 90-second
output deadline. No additional attempt was performed.

The details driver began at 04:40:04 UTC and returned failure at 04:41:36 UTC.
Its first menu frame arrived about 39.237 seconds after driver start, and details
input at 47.083 seconds. Native initial status review took 36.276 seconds; the
subsequent aggregate details review did not complete. These timings identify
repeated review work for offline diagnosis, not a proved complete causal account.

Outside proxy traffic, HTTP subscription enablement/import/refresh, credential
rotation and the remaining live journeys were not reached. Original Karing
settings and connection were preserved; no candidate profile was created.

## Cleanup

Separate approved failure cleanup used reviewed Complete removal and completed
at 04:46:18 UTC. Final scoped checks completed at 04:51:47 UTC: product resources,
transport service/staging, temporary CA and aliases, hosts mapping, NAT redirect
and recorder were absent. Package/account/group inventories and protected baseline
file contents matched. passwd/group/hosts inode metadata changed through atomic
replacement, with identical final contents. Preserved lock and pre-existing Rust
directory identity matched. Outside TCP 22 was reachable and 443/8443 refused;
this is cleanup evidence, not a positive proxy or subscription test.

Evidence and incomplete observation records were retained. The failed build 211
draft/assets and unrelated resources were preserved. This bounded check does not
assert whole-machine identity beyond the recorded baseline.

## Workflow and remaining decisions

Failure finalization and bounded failure-evidence staging succeeded. The
cleanup-unqualified job stopped at `Stop for an explicit candidate failure decision`.
That release-disposition gate is distinct from the verified host cleanup.
Draft release 434759360 remains a draft, unpublished and unchanged. No burn,
reservation update, deletion, new candidate or stable publication is authorized
by the subsequent offline project review.

Private local evidence: old SBXR workspace
`.scratch/acceptance/q212-full-20261105/`, including OUTCOME.json, terminal workflow
state, final draft metadata, timing captures and scoped cleanup comparisons.
The full-project follow-up is tracked in
[the review specification](../../../specs/001-project-review/spec.md).
