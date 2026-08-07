# Certificate Lifecycle acceptance

## Automated Module and Seam Verification

Run:

```sh
go test ./internal/certificatelifecycle/... ./internal/connectionprofiles/...
```

Stable checks:

- `CERTIFICATE-PREREQUISITES`: healthy and fail-closed `View` coverage for issuer, registration inputs, both lineages, DNS, effective CAA, HTTP-01 prerequisites, scheduler reporting, due facts, and marker safety.
- `CERTIFICATE-PLAN`: deterministic one-use Plan coverage for the reviewed Owner email and agreement, fixed `sbxr-ip` and `sbxr-domain` identities, typed staging-before-production order, forbidden raw command arguments, and isolated staging material.
- `CERTIFICATE-CERTBOT-SEAM`: bounded official-shape `certbot --version` and `certbot certonly --help all` coverage, supported Snap and pip-virtual-environment detection, exact `--required-profile shortlived` and `--required-profile tlsserver` command construction, forbidden `--preferred-profile`, malformed-output refusal, and raw-output redaction.
- `CERTIFICATE-IP-TRANSACTION`: exact IPv4 and IPv6 selection, one temporary HTTP-01 open and close, staging-before-production ordering, fixed Subscription Serving activation, Required pre- and post-publication checks, and no Xray step.
- `CERTIFICATE-IP-CANDIDATE`: exact IP SAN, key match, trusted complete chain, current 150-to-170-hour lifetime, server usage, root ownership, `0700`/`0600` regular non-symlink candidate material, and marker-safe failures.
- `CERTIFICATE-IP-ACTIVATION`: bounded Certbot failure, isolated staging cleanup, `0750`/`0640` versioned serving material, atomic pointer switch, fixed `sbxr-subscription.service` reload or restart, normal-trust IP HTTPS proof, activation refusal, prior-pointer restore, and prior HTTPS re-proof.
- `CERTIFICATE-DOMAIN-TRANSACTION`: separate revision-bound HTTP-01 open and close, isolated `sbxr-domain` staging, exact `tlsserver` production order, complete sing-box configuration validation before the pointer switch, fixed `sing-box.service` restart, and distinct Required Hysteria2, TUIC, and AnyTLS checks.
- `CERTIFICATE-DOMAIN-CANDIDATE`: exact DNS SAN, key match, trusted complete chain, current 40-to-50-day lifetime, server usage, root-owned `0700`/`0600` candidate material, and marker-safe failures.
- `CERTIFICATE-DOMAIN-ACTIVATION`: one `0750` sing-box-group serving set with `0640` chain and key, one shared atomic pointer, configuration and restart refusal, a root-only `0600` native sing-box probe configuration, separate normal-verification Hysteria2, TUIC, and AnyTLS connections to the selected VPS address, one-consumer failure, prior-pointer restart and three-consumer re-proof, no second order, unchanged Certbot lineage, and old private-key-set cleanup only after durable Complete.

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

## Live domain-order checks

On the same explicitly approved Acceptance VPS and exact Release Identity:

1. Repeat the exact listener, route, time, DNS, CAA, selected-address, and temporary HTTP-01 handle checks independently for `sbxr-domain`; keep Xray and REALITY on `443/TCP` running.
2. Run the isolated `sbxr-domain` staging order, then the exact production `--required-profile tlsserver --cert-name sbxr-domain -d <Direct-TLS-Hostname>` order. Prove staging cannot change production lineage or trust.
3. Prove the candidate has exactly the committed DNS SAN, matching key, normal trust, server usage, current validity, a plausible 40-to-50-day lifetime, and safe root-only candidate files.
4. Validate the complete sing-box configuration before activation. Prove the active domain directory is root-owned by the `sing-box` group at `0750`, its chain and key are `0640`, and only Hysteria2, TUIC, and AnyTLS reference its one shared pointer.
5. From outside the VPS, check Hysteria2, TUIC, and AnyTLS separately using the selected VPS address as the destination and the exact Direct TLS Hostname as the normally verified name. Do not set `insecure` or weaken trust.
6. Cause configuration refusal, restart failure, and one controlled consumer failure. Each must restore the prior pointer, restart sing-box, re-prove all three prior consumers, leave `sbxr-domain` unchanged, close the exact HTTP-01 handle, and perform no second order.
7. Keep real staging issuance, production issuance, renewal, outside-VPS direct-profile checks, Integrated Verification, Codex Live Acceptance, and Owner Acceptance Pending unless each was actually performed.

## Current acceptance status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `go test ./...` passed on the committed implementation. |
| Seam Verification | Passed | The same full-suite run passed the controlled official-shape Ubuntu Adapter checks. |
| Integrated Verification | Pending | Later integrated release. |
| Codex Live Acceptance | Pending | Requires an approved Acceptance Run and exact Release Identity. |
| Owner Acceptance | Pending if later affected surface requires it | Automation cannot claim this for Albert. |
