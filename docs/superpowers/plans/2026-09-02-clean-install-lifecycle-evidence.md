# Clean-install lifecycle evidence revision

Owner approved ADR-0020. Reuse the existing signed policy, scenario validator,
Acceptance Record, and public verifier; add no workflow or configurable waiver.

- [x] Add failing v2 qualification/public-reader regressions, preserving v1.
- [x] Admit v2 only for repair; remove exactly two lifecycle live checks and
  publish/verify their exact automated-only disclosure.
- [x] Prove extra omissions, false live claims, and changed disclosures refuse.
- [x] Run focused tests, then `GOTOOLCHAIN=go1.26.6 go test -p 1 ./...`,
  `GOTOOLCHAIN=go1.26.6 go test -p 1 -race ./...`, `GOTOOLCHAIN=go1.26.6 go vet ./...`,
  and `GOTOOLCHAIN=go1.26.6 go mod verify`; review the final diff.
- [ ] Update acceptance procedure and tracker decision, commit/push exact files.
- [ ] Recheck host/packages/release history; qualify a fresh signed candidate
  through all 25 live scenarios and full Karing, then publish stable only on pass.

Prior failed-attempt observations cannot be reused. No multi-day renewal test.

Local verification adjustment: concurrent full normal/race/reviewer runs caused
10-minute package timeouts in unchanged installer/removal tests. Both affected
tests passed separately without code changes (117.439s and 1.264s). Rerun all
normal/race packages sequentially with `-p 1`; retain the default package timeout
and all live scenario/transport deadlines. Independent specification review
found no blocker. Approved tracker pointers: #342 comment 5506809472 and #331
comment 5506825047.
