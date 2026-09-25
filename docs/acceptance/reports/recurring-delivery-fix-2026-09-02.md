# Recurring delivery correction — 2026-09-02

## Scope and result

Albert authorized all follow-on fixes for the remaining live acceptance without
repeated approval prompts. Natural multi-day Certbot renewal remains excluded.
This report does not claim live acceptance or authorize a new stable publication.

The existing gateway and GitHub Adapter now admit signed version-3 recurring
candidates while retaining exact manifest, workflow, approval, asset, index, and
source binding. Qualification-wire Release Identities use lowercase field names;
the Adapter explicitly maps them before comparing both signed source lists with
the verified package index. First-clean and historical contracts remain intact.

Both new recurring-path regressions failed before their respective fixes and
passed afterward. Negative cases cover missing, extra, reordered, or mismatched
sources; wrong state/scope; missing lists; changed index; unapproved manifest;
and wrong workflow commit. No new product entry point, qualification authority,
release-policy waiver, protected-record edit, or alternate updater was introduced.

## Unchangeable source boundary

Direct inspection of the immutable `v3.1.0` source at
`c0667a12ea914f2d0c86d73d52bfb8b40fea054a` confirms:

- `qualificationLatest` admits version 3 only for `v3-subscription-clean`.
- `qualificationSupport` requires first-clean scope and empty source lists.
- Historical version-1 candidate delivery rejects an index with support metadata.
- Production update requires recurring support naming the installed source.
- Without a candidate envelope, discovery requires a qualified stable Acceptance
  Record plus release attestation. Creating such a record before the required
  tests would fabricate qualification evidence.

Therefore an unchanged `v3.1.0` updater cannot consume the recurring candidate.
The new code can repair candidate admission for future source packages, but not
retroactively repair a published immutable executable. ADR-0016 requires the
unchanged source updater and forbids a bridge, patched source, or alternate
migration route. Its current qualification policy cannot be satisfied by a
code-only correction here.

No known-failing signed attempt was launched, no identity was consumed, no VPS
test mutation occurred, and no source-upgrade pass was recorded. Other remaining
packaged and Karing cases remain unperformed. The previous root/Linux lock tests
are still mechanics evidence only. Release policy and published `v3.1.0` remain
unchanged.

## Verification

With `GOTOOLCHAIN=go1.26.6`, all of these completed successfully:

- Full suite: `go test -p 1 -timeout 30m ./... -count=1`.
- Focused source/gateway race tests and recurring qualification scope tests:
  `go test -race -p 1 -timeout 30m ./internal/softwarelifecycle/... ./cmd/sbxr-release -run 'TestSource|TestQualificationGateway|TestQualificationCommandRequiresActualRecurringSubscriptionSources|TestQualificationCommandRequiresExplicitSubscriptionScope' -count=1`.
  The top-level Software Lifecycle package had no matches in this focused run;
  its normal tests passed in the full suite.
- `go vet ./...`, `go mod verify`, and Linux amd64/arm64 `CGO_ENABLED=0 go build ./...`.
- `git diff --check`, independent spec/security review, and independent final
  code-quality review.

These are source and automated verification results, not new live acceptance.
