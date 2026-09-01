# V3 Packaged Live Qualification

This is the required first-V3 stage inside Release Qualification. It qualifies one exact signed draft Release Identity by clean direct installation. It does not use a prior V3 release, update from V2, or migrate V1 or V2.

> Historical scope: the first-V3 baseline below and `sbxr-v3-packaged-live-evidence-v1` retain their original interpretation. They cannot qualify a recurring subscription-capable release. The versioned recurring contract is documented next; it implements [#356](https://github.com/albertloky/SBXR/issues/356) under [ADR-0016](../adr/0016-v3-proxy-product-and-modules.md) and [#342 Testing Decisions](https://github.com/albertloky/SBXR/issues/342).

## Recurring V3 evidence contract

Use the same `.github/workflows/candidate.yml`, `acceptance-vps` approval, `sbxr-release qualification` command, failure finalization, and `.github/workflows/stable.yml`. No new release asset, product dispatch, or transaction harness is introduced. The workflow's `v3` input now requests evidence version `2`; it cannot use historical evidence or normal/rescue qualification to bypass recurring obligations.

The workflow accepts a canonical, secret-safe `v3_attempt` JSON declaration. The wire fields are defined by `v3QualificationAttempt` in `cmd/sbxr-release/qualification_recurring.go`. Canonical means sorted object keys, no whitespace outside string values, no unknown/duplicate keys, no omitted required fields, and no trailing newline. The declaration binds:

- Exact active source Release Identities, sequences, four asset digests/sizes, actual Ownership Record schema, and accepted public verification. Include then-current Qualified Stable Release. Older sources add three required packaged scenarios each; no unlisted source is admitted.
- Proxy Package Identity, initial Certbot/snap/Karing packages, and the explicitly planned package set after supported snap refresh. Each package has repository, name, version, architecture, size, and SHA-256. Packages cannot drift between scenarios. A declared change is not permission to change unrelated resources.
- One Acceptance VPS ID plus SHA-256 of its `/etc/machine-id`, Ubuntu Server 24.04 `amd64`, Go `1.26.6`, public-verifier identity, independent outside-runner/Mac IDs, macOS version, and exact Karing macOS architecture.
- The complete ordered required scenario list, `scenario_limit_seconds:1800`, `karing_limit_seconds:7200`, and `validation_limit_seconds:300`. Required IDs are fixed by `requiredV3Scenarios`; their observation requirements are fixed by `requiredV3Checks`. No optional-family or waiver field exists.

The sign job rechecks the actual public Latest source and latest official stable Karing release metadata. Missing official asset digest or mismatched package facts refuse; do not substitute another package. Before any scenario, it binds a fresh `run-<run_id>-attempt-<run_attempt>` ID and actual start/package-check times into `sbxr-qualification-manifest-v2`, then uses the existing workflow attestation. The manifest's sole candidate entry binds the exact built Release Identity and four assets. Input start-time placeholders are replaced before the attempt exists; observed scenario timestamps are never rewritten.

### Operator handoff and per-scenario validation

`.github/scripts/v3-recurring-evidence.sh` is an evidence collector, not a live test driver. An approved Codex/operator must drive the real packaged paths on the same disposable VPS and the exact Mac package. The collector does not install, inject faults, invoke private product helpers, invent an updater route, or manufacture passes. It does not start the historical two-release gateway for the new evidence format.

After the signed handoff is available, the collector creates root-only `/run/sbxr-qualification/v3-evidence/request.json`. Each request names the scenario, manifest digest, earliest start, and inclusive duration limit. Read the signed artifact and request, then:

1. Perform fresh preflight on the bound VPS. Prove the initial installation/ownership, package, clock, outside-runner, exclusion, and supported effective renewal-route facts. Start/completion times describe actual work, including preflight, injection, recovery, and verification.
2. Drive the supported packaged scenario. Observe its commitment boundary; a signal or phase label alone is not proof. Record the required observations through protected comparison channels. Keep complete links, Client Identities, credential digests, request data, artifacts/configurations, raw process output, and Infrastructure Secrets out of evidence.
3. Prepare canonical `sbxr-v3-scenario-evidence-v2`: attempt/scenario IDs, candidate assets/identity, exact source where applicable, same VPS identity, independent `operation-<number>` and optional `link-<number>`, initial/final state, observed boundary, expected/actual result, recovery direction, package sets, actual start/preflight/completion/validation times, previous scenario digest, and evidence references. Each reference contains a typed observation, its actual time, and SHA-256 of that canonical observation. Arbitrary text and raw captures have no accepted field.
4. Submit the cumulative prefix in the normal qualification facts envelope with `stage:"v3-scenario-result"`. Use `sbxr-v3-packaged-live-evidence-v2`, the exact signed manifest and boundary facts, and the actual evaluation time. Run `sbxr-release qualification` locally as the validation event, within five minutes of completion. Atomically deliver the unchanged facts as root-owned, regular, one-link `0600` `result.json` in the handoff directory. Do not retain the secret-bearing comparison inputs.
5. The workflow validates original bytes before JSON normalization, checks the signed manifest digest, exact prefix and requested ID, and independently checks receipt against its current clock. It retains only validated facts/decisions in `handoff/v3-scenarios/`. An earlier record cannot be replaced, retimed, borrowed from another attempt, or treated as a fresh host observation. Wait for the next request before starting more test mutations.

The full matrix preserves baseline clean install/setup/refusal/outside-traffic/SSH/removal; adds enablement/conversion, both link/repair/activation boundaries, interrupted managed renewal plus reviewed repair, recorder and shared-route failures, supported snap refresh and unsupported-route accounting, Client Identity revocation/session/startup/fallback, every source's own updater and both recovery directions, update refusals, all pending-operation removal takeovers, exclusion/reboot/shared-route/finalization/exact-restoration, and secret containment. See the normative parent for the actual mechanics; required observation names are not a substitute for those observations.

The final `karing-final` scenario must be last, within two uninterrupted hours, and end in Complete removal. It requires the real HTTPS Subscription Link, one remote profile/node, exact fields/name/settings, direct/proxied traffic, manual refresh, a genuinely due five-minute automatic refresh, old-session termination and new-connection refusal, unchanged-link replacement adoption, outside-target distinction, direct-refresh correction or separately confirmed fallback, outage preservation/recovery, full absence, and qualification-secret/process cleanup.

### One Acceptance Record and failure handling

After final evidence validation, the same command produces the one public `sbxr-acceptance-record-v2` with `RELEASE-V3-SUBSCRIPTION-QUALIFICATION`. The workflow reuses that exact record; the stable gate deterministically revalidates its original facts, not a rewritten timeline. Final validation and record production must be within five minutes of final completion. The record binds packages, runners, sources, candidate bytes, and scenario digests linked to the existing workflow artifact. There are still exactly four public release assets.

Two limits remain explicit in the record:

- Natural timer firing and naturally due certificate renewal are **Not observed**. Official schedule integration, recorder start/outcome, targeted production issuance, canonical publication, accepted activation, and outside TLS remain separate mandatory observations. Use the supported interrupted managed attempt and reviewed Repair subscription, not healthy repair, an arbitrary root Certbot invocation, or a dry run. This does not waive Karing's genuinely due automatic refresh.
- An unsupported new/renamed renewal route **may execute before detection; historical outcomes remain unknown**. Prove supported-route inspection and detected `Problem detected`; do not claim universal bypass prevention or an observed historical renewal.

On the first unexpected failure, timeout, unexplained drift, or refused evidence, stop test mutations. The collector publishes `STOP` and emits secret-safe `v3-scenario-failure` facts/decision with known boundary/state (or explicit `unknown`/`Unknown`), expected/actual result, and exact candidate burn requirement. Safety cleanup is a separate typed record; successful cleanup cannot change `outcome:"failed"`. The existing post-sign finalizer burns the candidate and publishes failed-prerelease evidence. A fresh identity and a complete new attempt are required; no earlier pass is reusable. The collector does not delete uncertain product authority or run automatic product cleanup.

**Current feasibility is not waived.** [#344's packaged-source investigation](344-packaged-source-upgrade-investigation.md) found no supported updater/recovery invocation in the inspected current schema-1 source. Recheck the actual then-current source. If its own unchanged package cannot perform the required path, stop: no helper executable, patched prior bytes, invented intermediate release, or synthetic evidence can qualify it. Passing automated evidence-validation tests is not VPS or Karing acceptance.

## Historical first-V3 baseline

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
