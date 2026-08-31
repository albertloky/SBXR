# Installer-Updater release acceptance

This is the historical Installer-Updater Release Qualification procedure for unchanged packaged Installer-Updater bytes. Its evidence retains that interpretation; it does not qualify the V3 subscription extension or retain the historical full proxy product. [ADR-0016](../docs/adr/0016-v3-proxy-product-and-modules.md) and [#342 Testing Decisions](https://github.com/albertloky/SBXR/issues/342) govern V3 and recurring subscription qualification. The procedure below does not waive the requirement to prove each declared source through its actual packaged updater.

## Release pair and identity

The first normal pair is release A `v2.0.0`, sequence `17`, and release B `v2.0.1`, sequence `18`. Both remain GitHub drafts during qualification. Each draft contains exactly:

```text
install.sh
release-index.json
sbxr-linux-amd64.tar.gz
sbxr-linux-arm64.tar.gz
```

One keyless-signed qualification manifest binds `albertloky/SBXR`, the trusted workflow and run, exact commit, both tags and sequences, both Release Identities, all asset names, sizes, and SHA-256 digests, and the approved qualification run. Keep the manifest root-only on the Acceptance VPS.

The locked qualification channel may route the unchanged Pasteable Install Command to draft A and A's production GitHub Adapter to draft B. It must not add a public command, menu action, lifecycle state, transaction path, hidden test mode, or unsigned environment override.

## Automated package verification

Run native verification on Ubuntu Server 24.04 for `amd64` and `arm64`. Require all repository tests, supported race checks, `go vet ./...`, dependency and workflow contract tests, native packaged execution, and secret scans to pass.

Prove through production seams:

- exact four-asset cardinality, names, bounds, digests, archive shape, ELF architecture, embedded identity, Release Identity, and sequence;
- agreement among GitHub metadata, release body, signed attestation, index, downloaded bytes, and Acceptance Record;
- refusal of missing, extra, duplicate, malformed, changed, oversized, unattested, differently bound, late-replaced, or secret-bearing material;
- separate safe release-refused and transport-unavailable outcomes;
- opened-object binding for production reads;
- non-root `install.sh` returns `SOFTWARE-LIFECYCLE-INSTALL-HOST-REFUSED` without mutation;
- direct non-root `sbxr` prints one safe refusal, exits `1`, and performs no release lookup or mutation;
- while Update owns `/run/lock/sbxr.lock`, packaged Install, Update, and Recover return their exact concurrent-mutation outcomes without mutation; and
- a Check invalidated by changed local identity, lock, or recovery facts returns `SOFTWARE-LIFECYCLE-CHECK-CONCURRENT-CHANGE` and gives no update authority.

## Live packaged `amd64` journey

Use one approved disposable Ubuntu Server 24.04 `amd64` Acceptance VPS.

1. Prove a clean Acceptance Baseline and establish one direct SSH session.
2. Run the exact public command:

   ```sh
   curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash
   ```

   The locked channel must select exact draft A, install A, and enter A's real numbered menu.
3. Prove A's Release Identity, sequence, architecture, executable digest, Installed Record, ownership, modes, exact two-file durable layout, and `Ready` state.
4. Keep the original SSH session established and prove a fresh second SSH connection.
5. Through A's real menu, select `1. Check for updates`. Require exact higher-sequence draft B.
6. Select `2. Update SBXR`. Require its fresh check, download of only B's `amd64` archive, complete verification, and production Software Lifecycle transaction.
7. Prove exact active B, its Installed Record, no transaction residue, `Ready`, the original SSH session, and a fresh second SSH connection.

`arm64` requires native automated package proof but no live VPS journey.

## External interruption and recovery

Use external process control. The shipped executable must have no qualification-only pause point. Run separate scenarios that interrupt:

- before durable `Prepared`: exact A stays `Ready` and recognized residue is removed;
- after `Prepared` but before candidate activation completes: Recover restores exact A;
- after candidate activation but before durable `Committed`: the candidate reads A's schema-1 record and restores exact A under the `Prepared` direction; and
- after durable `Committed` but before cleanup completes: Recover retains exact B and finishes cleanup.

After each recovery, prove the original SSH session and a fresh second SSH connection. Reuse the VPS only after Software Lifecycle proves the expected Release Identity, `Ready`, the exact two-file layout, no transaction material, and an available lock. Reimage on uncertainty.

## Stable no-update truth

After stable B is publicly verified, require:

- B's Pasteable Install Command returns `SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT`;
- Check returns `SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT`;
- Update performs its fresh check and returns `SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT`; and
- all three paths leave bytes, Installed Record, ownership, modes, digests, Release Identity, and filesystem contents unchanged.

## Acceptance Records

A and B each get one machine-verifiable public Acceptance Record in the release body and retained workflow evidence, not as a release asset. Each record binds its Release Identity, sequence, four asset digests, workflow URL, runner facts, software versions, stage statuses, stable code, secret-safe result, and evidence links. Both link to the same complete qualification run.

A is the clean-installed source release. B is the discovered, installed, recovered, final Latest release. Require:

```text
Module Verification: Passed
Seam Verification: Passed
Integrated Verification: Passed on live Ubuntu Server 24.04 amd64
Codex Live Acceptance: Passed
Owner Acceptance: Not required
```

The normal stable code is `RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION`. Automated and Acceptance VPS evidence must not claim Albert performed Owner Acceptance.

## Stable publication

1. Re-fetch and prove annotated tag `archive/full-product-v1.0.15` resolves to `14fdf0a3decb6c653f9669438bf40221813b9d7d` with annotation `Archive the final SBXR full proxy product at v1.0.15`.
2. Reverify both draft identities, the signed manifest, Acceptance Records, and exact asset bytes against the passed run.
3. Publish A directly from its unchanged draft as stable and immutable. Re-download and verify its four assets, signed attestation, release body, Release Identity, and stable status.
4. Publish B directly from its unchanged draft as stable, immutable, and GitHub's canonical Latest release. Re-download and verify the same facts, Latest selection, and equality of latest and pinned `install.sh` bytes.

Publication may change only final draft metadata and the release bodies. It must not rebuild, replace, add, or remove an asset.

If A verifies but B fails publication or public verification, keep A stable, delete only failed B and its releasable tag, burn that tag and Release Identity, and restart with a higher tag and sequence. If A fails public verification, delete A and do not publish B. Never repair or republish a failed immutable identity.

## Qualification failure and rescue

On prepublication failure, publish both failed drafts as immutable prereleases with separate failed Acceptance Records, retain the workflow evidence, and burn both tags and Release Identities. A correction uses new tags, sequences, assets, manifests, records, and a fresh run.

A rescue release is allowed only when a retained reproducible defect in installed A makes the normal A-to-B menu journey impossible. It must pass the complete automated contract plus live proof of clean B installation, direct replacement of exact lower-sequence A, final B identity and two-file layout, SSH continuity, stable B no-update behavior, and no unrelated host change. Use code `RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION` and name the defect, failed normal stage, and waiver evidence. The next B-to-C transition must pass the normal menu-update contract; rescue cannot waive two consecutive normal transitions.
