---
status: accepted
---

# One-release Owner exception for v3.1.0

On 2026-09-02 Albert explicitly approved stable publication with a one-release policy and validator exception after being told that the required live VPS and Karing checks remain missing. This supersedes only ADR-0016's live-evidence publication requirement for `v3.1.0`, Release Sequence `83`, under `first-subscription-clean-install`. The signed qualification manifest must bind `owner-approved-v3.1.0-sequence-83` to the exact Release Identity and unchanged assets. No incoming upgrade is supported.

Retain native amd64/arm64 automated verification, pinned tools, exact asset/index and attestation checks, protected-environment approval, complete stable history and baseline checks, secret scans of all generated artifacts, public verification, immutable publication, and failure cleanup/burn rules. Waive the live packaged VPS matrix, outside-network proof, final exact Karing journey, and live-capture coverage for this release only. Do not run or fabricate these scenarios. Package identities in the attempt remain planned inputs, not live observations. The record and final publication evidence must state `Not performed; waived by Owner for this release`, `Live qualification: Incomplete`, and `static-official-evidence-passed-live-karing-pending`. Automated scan success is not proof of live secret containment.

This release is stable by explicit Owner exception, not by completed live qualification. Subscription and Client Identity rotation are not fully proved. The exception cannot be used for another tag or Release Sequence, cannot revive a burned identity, and cannot make a failed automated check pass. Later releases retain the full qualification gate, including real supported-source upgrades. A failed signed attempt consumes this identity under existing burn rules; another exception needs new Owner approval.
