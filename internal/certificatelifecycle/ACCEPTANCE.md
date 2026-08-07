# Certificate Lifecycle acceptance

## Automated Module and Seam Verification

Run:

```sh
go test ./internal/certificatelifecycle ./internal/certificatelifecycle/adapter/ubuntu
```

Stable checks:

- `CERTIFICATE-PREREQUISITES`: healthy and fail-closed `View` coverage for issuer, registration inputs, both lineages, DNS, effective CAA, HTTP-01 prerequisites, scheduler reporting, due facts, and marker safety.
- `CERTIFICATE-PLAN`: deterministic one-use Plan coverage for the reviewed Owner email and agreement, fixed `sbxr-ip` and `sbxr-domain` identities, typed staging-before-production order, forbidden raw command arguments, and isolated staging material.
- `CERTIFICATE-CERTBOT-SEAM`: bounded official-shape `certbot --version` and `certbot certonly --help all` coverage, supported Snap and pip-virtual-environment detection, exact `--required-profile shortlived` and `--required-profile tlsserver` command construction, forbidden `--preferred-profile`, malformed-output refusal, and raw-output redaction.
- `CERTIFICATE-IP-TRANSACTION`: exact IPv4 and IPv6 selection, one temporary HTTP-01 open and close, staging-before-production ordering, fixed Subscription Serving activation, Required pre- and post-publication checks, and no Xray step.
- `CERTIFICATE-IP-CANDIDATE`: exact IP SAN, key match, trusted complete chain, current 150-to-170-hour lifetime, server usage, root ownership, `0700`/`0600` regular non-symlink candidate material, and marker-safe failures.
- `CERTIFICATE-IP-ACTIVATION`: bounded Certbot failure, isolated staging cleanup, `0750`/`0640` versioned serving material, atomic pointer switch, fixed `sbxr-subscription.service` reload or restart, normal-trust IP HTTPS proof, activation refusal, prior-pointer restore, and prior HTTPS re-proof.

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

## Current acceptance status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `go test ./...` passed on the committed implementation. |
| Seam Verification | Passed | The same full-suite run passed the controlled official-shape Ubuntu Adapter checks. |
| Integrated Verification | Pending | Later integrated release. |
| Codex Live Acceptance | Pending | Requires an approved Acceptance Run and exact Release Identity. |
| Owner Acceptance | Pending if later affected surface requires it | Automation cannot claim this for Albert. |
