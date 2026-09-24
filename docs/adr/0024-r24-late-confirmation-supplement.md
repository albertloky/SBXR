---
status: accepted
---

# Validate the approved r24 late-human-confirmation supplement

On 2026-09-24 the Owner approved the bounded exception recorded in
[the decision record](../acceptance/late-confirmation-exception-2026-09-24.md)
and requested validator implementation. Accept the retained functional evidence
and the subsequent Owner cleanup confirmation as an explicit supplement, not a
retroactively successful timed workflow.

The `mvp-late-confirmation-supplement` qualification stage recognizes only
`owner-approved-r24-late-confirmation-2026-09-24`. Its source-owned SHA-256 pins
bind the exact secret-safe archival inputs: v3.1.80/158, source
`1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52`, run 35965345632 attempt 2, its signed
manifest, four journey observations, restart/removal/cleanup receipts, original
failure, and the actual late Owner confirmation. Input hashes are calculated
from supplied document contents, not accepted as caller assertions. Missing,
additional, duplicate or altered evidence refuses. An approval boolean cannot
substitute for the approved evidence.

The decision is `accepted-supplement`, with `release_eligible: false`, the
original failed outcome and burn reference, and the real confirmation-recording
timestamp. Cleanup's actual execution time remains unknown. It emits neither
an Acceptance Record nor a publication action. It does not mean the validator
repeated the live observations or verified new external state.

This extends ADR-0023 only by recognizing this separately labelled historical
supplement. Ordinary scenario deadlines, original failure/burn handling,
automated requirements, and the v3.1.0 exception remain unchanged. In particular,
stable preflight must reject this supplement as an ordinary live result.

## One designated fresh target

The Owner subsequently approved completing the release integration and running
fresh automated qualification for **v3.1.81 / sequence 159**. Only that pair may
use this exception. The signed attempt binds the exact new commit, prior source,
archival supplement hash, runtime tree hash and complete policy diff hash.
`.github/scripts/late-confirmation-review.py` reproduces that review from Git
both before candidate preparation and before the exception result. The reviewer
is explicitly Codex source comparison under Owner approval, not a new human
signature.

Proxy/menu source, build dependencies and installed production source are
unchanged from r24 except the three explicitly reviewed release-record reader
files. New binaries have new identity and are **not byte-identical** to r24.
Native automated checks exercise the changed readers and normal build paths.
The exception result also requires the exact archived package, host, outside
runner and macOS declarations. These describe the prior tested environment,
not newly collected live observations.

Normal candidate history, native checks, artifact verification, attestation,
protected signing approval, failure/burn handling and separate stable-publication
approval remain required. The raw supplement is never enough. The qualified
record discloses reused prior evidence, real late confirmation and unknown
cleanup execution time; it contains no fresh Scenario results. Public readers
and stable finalization recognize that same exact profile. v3.1.80 remains
failed/burned. No VPS journey or CA operation is part of this exception path.
This is not a general evidence-transfer waiver or publication authorization.
