---
status: accepted
---

# Reuse the accepted live89 evidence after correcting the operator record

On 2026-10-04 the Owner accepted all five HTTP live journeys for
**v3.1.89 / sequence 167**, source
`1723e06aca91465dc687b0ac72f06a2e48f8974d`, in qualification
[run 37189061844](https://github.com/albertloky/SBXR/actions/runs/37189061844).
The cleanup request grouped removal of the test profile, clearing copied test
links and clipboard contents, and preservation of the original client selection
and settings. The actual notification was delivered at
`2026-10-04T10:04:15.493836Z`. The Owner's unqualified “confirm removed” reply was
reported at approximately `10:08:51Z` and first read by the operator at
`10:08:59Z`, before the original `10:09:15.493836Z` timeout.

The operator read that grouped confirmation too narrowly and submitted failed
facts at `10:10:58Z`. Automatic finalization published the immutable failed
prerelease at `10:12:18Z`. The Owner explicitly corrected the interpretation and
accepted qualification. The correction was recorded at
`2026-10-04T10:15:18.740923+00:00`; this is a later administrative recording time,
not a replacement observation time. The original removal response callback
remains null, and the incomplete draft and original failure remain preserved.

The Owner then approved a narrow release-rule change in message
`Sentinel_ba7c180a25608191b6b57161f7552fe1`, reported at approximately
`2026-10-04T11:49:19Z`, following the concrete request
`Sentinel_4452cfee45e48191a2dc4699b653af24`, delivered at
`2026-10-04T11:18:37.866571Z`. That decision permits the implementation and local
verification below. Signing, candidate dispatch and stable publication remain
separate actions.

## One fresh target with unchanged product behavior

Only the fresh, unused **v3.1.90 / sequence 168** may consume this correction.
Normal candidate preflight must still establish that both authorities are unused.
The target retains `subscription-clean-install-only`,
`sbxr-subscription-update-v1`, `mvp-http-live-v1`, empty support and attempt
sources, and the five HTTP journey identifiers. It has no `owner_exception`,
`late_confirmation_review` or automated-only scenario claim.

The signed attempt's `live89_correction_review` binds the exact tested base,
the fresh target commit/tag/sequence, the approved archive digest, the unchanged
source-tree digest and the complete release-policy diff digest. The workflow
reproduces this review from committed Git inputs before candidate preparation
and again before accepting the correction result. The review describes source
comparison under the recorded Owner decision; it is not a new human signature
or an external live observation.

Every file under `cmd/sbxr` and `internal`, together with `go.mod`, `go.sum` and
`cmd/sbxr-release/bootstrap.go`, must match the tested base exactly. There is no
production-reader allowlist. Unrelated unfinished runtime, removal or session
work must remain outside the fresh candidate commit; a changed protected tree
refuses evidence reuse. Release tooling and documentation may implement this
bounded policy, with their complete diff bound by the review.

Fresh native builds must additionally prove that the unstamped executable
payloads for both `amd64` and `arm64` have the exact archived live89 payload
digests. The check validates the embedded identity and payload digest before
comparison. SBXR builds with `-buildvcs=false` and `-trimpath`, then appends its
release identity; it does not use version/commit linker flags. The new identity
stamp, archive, index and installer metadata bind the fresh commit and release
and therefore differ from live89. The correction never claims that all four new
assets or the complete stamped executables are byte-identical to live89.

The source and payload pins are:

| Bound input | SHA-256 |
|---|---|
| Protected Git source tree | `d1b3eddefcee885e636c6467b9c8ddbe9958592c0187a0b2fdd218013a28dc84` |
| Unstamped `amd64` executable payload | `2a39346a228641fd7776f453a9b8f85a897a1ce4b58bc4e678456e7429cf9e55` |
| Unstamped `arm64` executable payload | `8d43e1e7fbde0db0b1c099f80b3a9e397e2d7a05aec35eb9318538172c35c2c1` |

The tested proxy package, official Karing package, runner, host and client facts
remain bound to the archived manifest. They describe the original observations,
not a newly visited VPS or client. The HTTP exposure disclosure, empty incoming
sources, old-updater refusal and installer refusal over existing state retain
their clean-install-only meanings.

## Exact evidence and truthful Acceptance Record

The `live89-evidence-correction-result` stage requires the newly verified signed
qualification boundary and the closed set of approved secret-safe archival
bytes. Source-owned content pins are checked against the supplied contents.
Missing, additional, duplicate or altered evidence refuses; caller approval
flags, replacement hash assertions or another target cannot authorize reuse.
The preserved prior manifest digest is
`baecc683e242f023b1d5337be858f99292b92d6af8a6ada006c8d2bfddaf886e`.

The stage emits an accepted clean HTTP Acceptance Record using the existing
public format. Its ordinary accepted headers describe the accepted functional
evidence and fresh automated qualification. Explicit provenance in the same
record states that all live tests came from v3.1.89/167, the original workflow
failed, the grouped cleanup interpretation was corrected, and no fresh target
live run occurred. The record preserves the actual notification, approximate
reply time, first-read time and later correction-recording time without creating
a response callback or backdating validation.

The five `Scenario:` references identify imported evidence in the new workflow's
retained archive: four original scenario digests and, for `mvp-removal`, the
approved archival correction bundle digest. The fifth reference is explicitly
disclosed as that bundle; it is not a fabricated normal scenario document.
The stage does not synthesize an all-observed removal draft or claim that the
ordinary collector accepted the original fifth scenario. Existing public and
frozen readers validate the ordinary clean HTTP record without installed
product changes.

## Preserved release gates

v3.1.89 remains an immutable failed prerelease, and
`refs/tags/release-burned/v3.1.89` remains intact. No original CI result, release
body, signed manifest, observation, submission timestamp or burn is rewritten.
The archived result's `corrected_payload_sha256` identifies the corrected launch
script; it is not an accepted scenario or executable-payload digest.

The fresh target requires its own successful native and candidate workflow,
normal asset verification, protected signing approval and attestations. Stable
preflight still requires that successful fresh workflow, unchanged signed draft
assets/body, a mutable draft, current release-history baseline and the unchanged
burn inventory from its own preflight. Ordinary failure, withdrawal and burn
handling still apply to the fresh target. Stable publication requires its
separate approval and normal public verification.

This amends ADR-0028 only for the named correction and fresh target. It waives no
missing product test, changes no ordinary deadline and creates no general
evidence-transfer route. Local validation establishes implementation and
regression coverage; it does not mean the fresh target has been built, signed,
dispatched or published.
