# Release and qualification scripts

This directory contains the current release-support tooling. The current live
producer is the `mvp-live-v1` collector described in
[MVP live acceptance](../../docs/acceptance/mvp-live-acceptance.md); it records
explicit human observations and does not run the historical V4 protocol.

| Area | Entry points |
|---|---|
| Candidate declaration and dispatch | `v3-candidate-dispatch.sh` |
| MVP observation assembly and submission | `v3-mvp-evidence.py`, `v3-recurring-evidence.sh` |
| Packaged public-menu helpers | `v3-packaged-live.sh`, `v3-menu-session.py` |
| Candidate transport | `v3-qualification-transport.sh` |
| Release history and publication support | `release-history.sh`, `prepare-burn-tag.sh`, `recheck-qualified-release.sh`, `qualification-gateway-readiness.sh` |

Focused helper tests live in `tests/`, including
`tests/test_mvp_evidence.py` and `tests/test_ssh_boundary.py`. The former
outside-probe mode is retired. Repository-root Go tests are split by concern:
`release_workflow_test.go` covers native CI; `release_candidate_workflow_test.go`
covers candidate preparation; `release_stable_workflow_test.go` covers
publication/failure; and `release_collector_test.go`,
`release_packaged_driver_test.go`, and `release_transport_test.go` cover their
matching script boundaries. The former V4 operator producer is retired; retrieve
it only to interpret historical records at
[commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator).
