# V3 Packaged Live Qualification

This is the required first-V3 stage inside Release Qualification. It qualifies one exact signed draft Release Identity by clean direct installation. It does not use a prior V3 release, update from V2, or migrate V1 or V2.

> Scope: this first-V3 baseline and `sbxr-v3-packaged-live-evidence-v1` retain their original interpretation. [ADR-0016](../adr/0016-v3-proxy-product-and-modules.md) and [#342 Testing Decisions](https://github.com/albertloky/SBXR/issues/342) extend the same Release Qualification gate for recurring V3 releases, declared source upgrades, subscription scenarios, and separate exact Karing macOS evidence. This baseline alone cannot qualify that extension; no new procedure or runtime admission is implemented by this authority handoff.

## Bound authority

- Verify the signed qualification manifest, one Release Identity, Release Sequence, four asset names, sizes, digests, and unchanged packaged executable.
- Bind Proxy Package Identity and the identical official outside-client package identity to `sing-box` `1.13.19` `amd64`, signing-key SHA-256 `803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1`, size `24597120`, and DEB SHA-256 `fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf`.
- Start only after the signed `acceptance-vps` boundary. Any later failure burns the candidate through the existing failed-prerelease path.

## Required journey

1. Prove a clean Ubuntu Server 24.04 `amd64` VPS and a distinct GitHub-hosted Ubuntu `amd64` runner route.
2. Install the exact candidate with the Pasteable Install Command. Prove the executable and Installed Record identity.
3. Through the packaged numbered menu, prove `Not set up`, review and confirm Start setup, then prove local `Running` and `PROXY-INSTALLATION-SETUP-COMPLETE`.
4. Prove all secret-safe View details facts.
5. Confirm Show client configuration. Stream only the bounded JSON to `/dev/shm/sbxr-v3-client.json` on the runner with mode `0600`; never print it.
6. Validate and run the exact official client. Prove direct runner egress differs from VPS egress and proxied TCP egress matches it.
7. Stop the client and prove its process, loopback listener, extracted package, log, and memory-backed configuration are absent.
8. Confirm Complete removal and prove `SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED`, `SBXR is not installed.`, and complete owned-resource absence.

## Five required failure cases

1. Add one reversible footprint conflict. Prove Start setup refusal before mutation, remove only the conflict, and restore `Not set up`.
2. Observe public `Progress: Validate configuration`, send `SIGSTOP` then `SIGKILL`, prove pre-commit `Setup incomplete`, use Finish cleanup, and restore `Not set up`.
3. Observe public `Progress: Activation committed`, send `SIGSTOP` then `SIGKILL`, prove committed `Setup incomplete`, use Finish setup, and reach `Running`.
4. Add one reversible owned-resource metadata mismatch. Prove Complete removal refusal before mutation, restore exact metadata, and return to `Running`.
5. Observe public `Progress: Removal committed`, send `SIGSTOP` then `SIGKILL`, prove `Removal incomplete`, use Finish removal, and reach `Not installed`.

No pause hook, hidden test mode, alternate transaction path, or second product harness is permitted.

## Evidence and refusal

Retain only canonical `sbxr-v3-packaged-live-evidence-v1` facts, ordered stage completion times, and their SHA-256. The complete journey must finish within two hours. Do not retain Client Configuration, UUID, REALITY private key, raw public addresses, raw commands, or raw terminal, package-manager, validator, VPS, or runner output. Scan retained evidence and available captures for exact known secrets plus private-key and authorization patterns without redaction. Missing, stale, mismatched, incomplete, retained, mistimed, or secret-bearing facts refuse qualification.

Automated tests for this procedure do not claim that a VPS, outside client, immutable candidate, packaged journey, or Owner Acceptance passed.
