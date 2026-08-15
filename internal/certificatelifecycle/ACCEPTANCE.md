# Certificate Lifecycle acceptance

## Automated Module and Seam Verification

Run:

```sh
go test ./internal/certificatelifecycle/... ./internal/connectionprofiles/...
```

Stable checks:

- `CERTIFICATE-PREREQUISITES`: healthy and fail-closed `View` coverage for issuer, registration inputs, both lineages, DNS, effective CAA, HTTP-01 prerequisites, scheduler reporting, due facts, and marker safety.
- `CERTIFICATE-PLAN`: deterministic one-use Plan coverage for the reviewed Owner email and agreement, fixed `sbxr-ip` and `sbxr-domain` identities, typed staging-before-production order, forbidden raw command arguments, and isolated staging material.
- `CERTIFICATE-CERTBOT-SEAM`: bounded official-shape `certbot --version` and `certbot certonly --help all` coverage, supported Snap and pip-virtual-environment detection, exact `--required-profile shortlived` and `--required-profile tlsserver` command construction, anchored active-certificate observation, RFC 9773 certificate-identifier construction, bounded same-origin ACME Renewal Information, explicit unavailable fallback, malformed/timeout/contradictory handling, forbidden `--preferred-profile`, and raw-output redaction.
- `CERTIFICATE-IP-TRANSACTION`: exact IPv4 and IPv6 selection, one temporary HTTP-01 open and close, staging-before-production ordering, fixed Subscription Serving activation, Required pre- and post-publication checks, and no Xray step.
- `CERTIFICATE-IP-CANDIDATE`: exact IP SAN, key match, trusted complete chain, current 150-to-170-hour lifetime, server usage, root ownership, `0700`/`0600` regular non-symlink candidate material, and marker-safe failures.
- `CERTIFICATE-IP-ACTIVATION`: bounded Certbot failure, isolated staging cleanup, active `root:root 0755`/`0644` versioned serving material, atomic pointer switch, fixed `sbxr-subscription.service` reload or restart, normal-trust IP HTTPS proof, activation refusal, prior-pointer restore, and prior HTTPS re-proof.
- `CERTIFICATE-DOMAIN-TRANSACTION`: separate revision-bound HTTP-01 open and close, isolated `sbxr-domain` staging, exact `tlsserver` production order, complete sing-box configuration validation before the pointer switch, fixed `sing-box.service` restart, and distinct Required Hysteria2, TUIC, and AnyTLS checks.
- `CERTIFICATE-DOMAIN-CANDIDATE`: exact DNS SAN, key match, trusted complete chain, current 40-to-50-day lifetime, server usage, root-owned `0700`/`0600` candidate material, and marker-safe failures.
- `CERTIFICATE-DOMAIN-ACTIVATION`: one active `root:root 0755` serving set with `0644` chain and key, one shared atomic pointer, configuration and restart refusal, a short-lived `0600` native sing-box probe derived from the exact active Connection Profiles configuration, separate normal-verification Hysteria2, TUIC, and AnyTLS connections to the selected VPS address, one-consumer failure, prior-pointer restart and three-consumer re-proof, no second order, unchanged Certbot lineage, and old private-key-set cleanup only after durable Complete.
- `CERTIFICATE-RENEWAL-POLICY`: `go test ./internal/certificatelifecycle -run 'Test(IPRenewalPolicyControlsDueAndRetryWindows|DomainRenewalPolicyUsesARIOrFifteenDayFallback|StandingIPPolicyPersistsFailureAcrossSchedulerProcesses|StandingPolicyPersistsDomainFailureSeparately)'` covers the 72-hour IP point, 24-hour warning, valid ARI window, explicit 15-day fallback, malformed-ARI refusal, and cross-process bounded retry for both lineages.
- `CERTIFICATE-RENEWAL-HISTORY`: `go test ./internal/certificatelifecycle/adapter/ubuntu -run TestRenewalAttemptStore` covers separate atomic root-only IP/domain persistence, restart reload, lineage-specific cleanup, and malformed or symlinked-history refusal.
- `CERTIFICATE-RENEWAL-STATE`: `go test ./internal/state -run 'Test(PrepareIPCertificateRenewalCommitAllowsOnlyStandingScope|PrepareDomainCertificateRenewalCommitAllowsOnlyStandingScope|CertificateRenewalSchedulerUsesRealOneUseSystemChangesLock)'` covers unchanged logical certificate identifiers and pointer paths, separate planning after the real System Changes lock, serial IP-then-domain execution, one publication per success, durable Complete, cleanup, and both five-step transactions.
- `CERTIFICATE-RENEWAL-SCHEDULER`: `go test ./internal/certificatelifecycle -run 'Test(SystemdUnitsOwnOnePersistentRandomizedTwiceDailyRenewal|SchedulerRunsOnlyOneFreshIPAttemptPerEvaluation|SchedulerEvaluatesBothDueLineagesSerially|StandingDomainRenewalRequiresARIAndNarrowState)'` covers the one service/timer pair, persistent randomized evaluation, branch isolation, fixed serial order, separate locks, and one-use narrow Plans without separate lineage or Certbot-owned units.

The automated result may say only that the controlled Module and Ubuntu seam passed. It does not prove real ACME registration, real staging or production issuance, public reachability, live activation, real renewal, outside-VPS HTTPS, or Release Qualification.

## Live IP-order checks

On one explicitly approved Acceptance VPS and exact Release Identity:

1. Confirm `/snap/bin/certbot` is version `5.4` or newer and exposes `--ip-address` and `--required-profile`. Record only the version, source class, capability booleans, stable check code, and pass/fail result.
2. Review the Owner email and subscriber agreement without copying the email into evidence.
3. Recheck the selected IP, committed Direct TLS Hostname, exact DNS-only A/AAAA set, effective CAA, public route, time synchronization, unrelated port-80 ownership, and SBXR firewall authority.
4. Identify any unrelated port-80 listener and leave it running. Refuse the order until port 80 is safely available; never stop or adopt that listener.
5. Record that Xray and REALITY on port 443 remain running before, during, and after the IP branch.
6. Run the isolated `sbxr-ip` staging order, then its exact production order, only in ticket #95's approved Change Set. On success, interruption, timeout, order failure, activation rollback, and restart recovery, prove the exact recorded HTTP-01 rule handle is absent without flushing unrelated rules.
7. Prove the active pair through `https://<selected-IP>:10443` with normal trust and exact IP verification. Do not use an insecure override.
8. Cause one controlled Required activation failure, then prove the prior pointer, `sbxr-subscription.service`, and prior HTTPS response were restored without a second order or a Certbot-lineage rewrite. An unprovable restore must remain `Recovery Required`.
9. Keep real staging issuance, production issuance, real renewal, outside-VPS IP HTTPS, Integrated Verification, Codex Live Acceptance, and any required Owner Acceptance Pending until those checks actually run.

The redacted Acceptance Record must exclude the Owner email, ACME account data, raw Certbot output, private keys, command environment, transaction material, complete certificate files, secret-derived data, Client Access Values, and any false issuance claim.

## Live IP-renewal checks

On one explicitly approved Acceptance VPS and exact Release Identity:

1. Confirm only `sbxr-cert-renew.service` and `sbxr-cert-renew.timer` own certificate scheduling, the timer is enabled with `Persistent=true`, and no Certbot-owned or lineage-specific timer is active.
2. With more than 72 hours remaining, run the service and prove it performs no mutation, creates no transaction, does not open port 80, and leaves the active certificate and Desired State revision unchanged.
3. At 72 hours or less, prove one fresh IP renewal Change Set obtains the global lock, opens only the recorded HTTP-01 rule, passes staging and production ordering, activates Subscription Serving, publishes exactly one revision, proves post-publication agreement, records durable Complete, and removes transaction material.
4. Hold the global lock and prove no Plan is built and no queue is created. Confirm the next eligible attempt is within 1 hour, or within 15 minutes below 24 hours, and builds new observations and a new Plan only after obtaining the lock.
5. Force one ordinary order or activation failure while the prior certificate is valid. Confirm no retry before 6 hours, then confirm a fresh attempt is eligible; throughout, the prior pair remains active and the exact port-80 handle is absent.
6. Restart the scheduler process between the failure and both retry checks. Confirm `/var/lib/sbxr/certificate-renewal/ip-attempt.json` is a root-owned regular `0600` file containing only schema, time, and typed outcome; successful renewal removes it. Malformed or symlinked history must stop without mutation.
7. Interrupt before publication, after activation, and after publication. Prove restart resolution rolls back before publication, proves agreement after publication, never publishes twice, and enters Recovery Required only when the IP lineage or rollback cannot be proved.
8. Keep real or safely forced renewal, public ACME traffic, outside-VPS HTTPS, Integrated Verification, Codex Live Acceptance, and Owner Acceptance Pending unless each check actually ran.

## Live domain-order checks

On the same explicitly approved Acceptance VPS and exact Release Identity:

1. Repeat the exact listener, route, time, DNS, CAA, selected-address, and temporary HTTP-01 handle checks independently for `sbxr-domain`; keep Xray and REALITY on `443/TCP` running.
2. Run the isolated `sbxr-domain` staging order, then the exact production `--required-profile tlsserver --cert-name sbxr-domain -d <Direct-TLS-Hostname>` order. Prove staging cannot change production lineage or trust.
3. Prove the candidate has exactly the committed DNS SAN, matching key, normal trust, server usage, current validity, a plausible 40-to-50-day lifetime, and safe root-only candidate files.
4. Validate the complete sing-box configuration before activation. Prove the active domain directory is `root:root 0755`, its chain and key are `0644`, and only Hysteria2, TUIC, and AnyTLS reference its one shared pointer.
5. From outside the VPS, check Hysteria2, TUIC, and AnyTLS separately using the selected VPS address as the destination and the exact Direct TLS Hostname as the normally verified name. Do not set `insecure` or weaken trust.
6. Cause configuration refusal, restart failure, and one controlled consumer failure. Each must restore the prior pointer, restart sing-box, re-prove all three prior consumers, leave `sbxr-domain` unchanged, close the exact HTTP-01 handle, and perform no second order.
7. Keep real staging issuance, production issuance, renewal, outside-VPS direct-profile checks, Integrated Verification, Codex Live Acceptance, and Owner Acceptance Pending unless each was actually performed.

## Live domain-renewal checks

On the same explicitly approved Acceptance VPS and exact Release Identity:

1. Prove the scheduler checks `sbxr-ip` and then `sbxr-domain` serially. When both are due, confirm each obtains and releases the global lock separately and publishes at most one revision.
2. Supply valid ACME Renewal Information whose suggested window is in the future, then active. Prove no domain mutation before the window and one fresh domain Change Set after its start. If renewal information is explicitly unavailable, prove the exact fallback is 15 days remaining; malformed or contradictory information must stop.
3. Hold the lock during the domain branch. Prove no Plan or queue is created, then release it and prove the next eligible evaluation rebuilds all observations and a different one-use Plan under the lock.
4. Force domain order and activation failures. Prove the prior shared pair remains active for Hysteria2, TUIC, and AnyTLS, the exact port-80 handle is absent, no second order occurs after activation failure, and only `/var/lib/sbxr/certificate-renewal/domain-attempt.json` records the bounded retry fact.
5. Interrupt before and after domain publication. Prove rollback or restart agreement, one publication, durable Complete, transaction cleanup, and Recovery Required whenever the current or prior shared lineage cannot be proved.
6. Expire each lineage separately. Prove IP expiry reports Subscription Serving Failed and domain expiry reports Hysteria2, TUIC, and AnyTLS Failed; neither path permits insecure HTTP, disabled verification, a custom trust anchor, or another certificate lineage.
7. In the coordinated client row, retrieve one offered representation from the exact real `https://<selected-IP>:10443/s/<256-bit-subscription-token>/...` endpoint with normal IP SAN and chain validation and no insecure override before connecting each represented profile. Keep the Client Access Value out of evidence.
8. Record `sbxr-ip` staging, production, and renewal rows separately from `sbxr-domain` staging, staging-renewal, production, and production-renewal rows. Leave every unperformed live, outside-VPS, Integrated, Codex, or Owner row honestly Pending.

## Current acceptance status

| Stage | Owner | Status | Evidence |
|---|---|---|---|
| Module Verification | Codex | Passed for prerequisites, IP issuance and activation, domain issuance and activation, IP renewal, and serial IP-then-domain renewal | `CERTIFICATE-PREREQUISITES`, `CERTIFICATE-PLAN`, both candidate and transaction branches, both activation and rollback branches, renewal policy/history/State, and the one serial scheduler pass with marker-safe results. Real issuance and renewal remain Pending. |
| Seam Verification — controlled Ubuntu fixtures | Codex | Passed | Official-shape Certbot capability and invocation, anchored public-certificate observation, bounded same-origin ACME Renewal Information, exact temporary HTTP-01 authority, filesystem ownership and modes, atomic pointers, fixed service activation, normal-verification IP HTTPS, and separate Hysteria2, TUIC, and AnyTLS checks pass without an Owner credential or public ACME order. |
| Integrated Verification | Integrated release runner | Pending — integrated release | The complete executable still needs all-Module wiring, private-command and systemd installation, real service coordination, and one exact Release Identity. |
| Codex Live Acceptance | Codex, only during an approved Acceptance Run | Pending — approved Acceptance Run | No Acceptance VPS, public ACME order, real certificate, real renewal, or outside Acceptance Client was used. |
| Owner Acceptance | Albert | Pending if the first release or an affected maintained-client surface requires it | Automation cannot claim Albert's maintained client, device, network, or workflow acceptance. |

Module accepted; Release Qualification pending. The fixed `sbxr-ip` and `sbxr-domain` lineages, qualified standalone HTTP-01 boundary, isolated staging, strict candidate checks, atomic serving pointers, checked rollback, narrow standing renewal policy, and one persistent randomized serial scheduler are verified locally. Real `sbxr-ip` staging, production, and renewal; real `sbxr-domain` staging, staging renewal, production, and production renewal; public reachability; outside-VPS normal-verification checks; Integrated Verification; Codex Live Acceptance; required Owner Acceptance; and Release Qualification remain Pending. Unperformed rows stay Pending.

Require current email and agreement guidance plus exact field boundaries with:

```sh
go test ./internal/certificatelifecycle ./cmd/sbxr -run 'Test(CertificateInputGuidanceOwnsEmailAndCurrentAgreementFacts|ManagedCertificateInputsStayFieldLocalUntilExactAgreement)$' -count=1
```

These automated checks do not claim public ACME issuance or Owner Acceptance.
