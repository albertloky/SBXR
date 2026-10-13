---
status: accepted
---

# Review main divergence before publishing an exact qualified candidate

The Owner approved this release eligibility change on 2026-10-12. A newer main
commit alone makes an otherwise valid exact candidate **pending review**. It does
not invalidate its passed qualification or consume its Release Identity. This
refines the publication safeguard in ADR-0016 and ADR-0028; changed candidate
source or release assets still require their own qualification. Historical
failures and burns, including the scoped ADR-0029 correction, remain unchanged.

Before approving publication, review every newer main commit and the full
candidate-to-main diff. Record the exact candidate SHA, reviewed current-main
SHA, divergence digest, security assessment and rationale for continued evidence
applicability. The digest binds the ordered `git log --format=%H CANDIDATE..MAIN`
bytes, one NUL byte and `git diff --binary --no-ext-diff --no-textconv CANDIDATE MAIN --`
bytes. The release helper reproduces these inputs from committed Git objects;
dirty working files are not review inputs. Filename categories do not establish
security relevance. A documentation-only divergence can retain valid evidence
after explicit review; changes affecting tested behavior require a replacement
candidate and qualification.

Stable preflight hashes the candidate's committed checklist. Newer checklist
edits belong to the divergence review rather than silently replacing the tested
candidate's qualification inputs. The live89 payload verifier similarly takes the
exact candidate SHA explicitly; checkout HEAD cannot replace the tested identity.

The existing protected `stable-publication` environment remains the approval
mechanism. Its approval decision chain binds the canonical stable-preflight facts
and decision digests, thereby binding the exact signed candidate, all asset names,
sizes and digests, reviewed main and divergence assessment together. The workflow
retains the full diff and commit review beside those facts and shows the candidate,
main and asset bindings before approval. A dispatch assessment alone authorizes no
publication. `unreviewed`, `security-fixes-missing`, a missing review or a stale
binding cannot emit a publication action. Security fixes omitted by the candidate
require a replacement that includes them and new qualification; this path provides
no security waiver.

The workflow observes main again after approval and checks it immediately before
each publication PATCH. Further drift pauses again, preserving qualification and
requiring a review and approval for the new exact main SHA. A pending review skips
publication/finalization and burn handling; validation errors, actual publication
failures, expiry and explicit abandonment retain existing failure/burn semantics.
There is no atomic GitHub compare-and-publish transaction: these checks bound the
race immediately before the publication request, rather than locking main.

Current action generation always requires the fresh remote-main observation and
bound approval chain, including unchanged-main publication. Omitting fields cannot
claim historical status. The separate `stable-publication-record-verification`
stage validates a complete previously accepted canonical publication record and
returns `accepted-record` with no actions. It preserves historical interpretation
without authorizing publication, propagation observations or current finalization. Existing signed manifests,
Acceptance Records and public/frozen asset readers retain their wire contracts.
Local implementation/tests do not authorize dispatch, signing, publication or VPS
mutations. Publication of an exact candidate still requires separate approval.
