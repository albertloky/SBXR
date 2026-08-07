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

The automated result may say only that pre-order observations and Plans passed. It does not prove ACME registration, staging or production issuance, public reachability, certificate validity, activation, rollback, renewal, or Release Qualification.

## Later live-order checks

On one explicitly approved Acceptance VPS and exact Release Identity:

1. Confirm `/snap/bin/certbot` is version `5.4` or newer and exposes `--ip-address` and `--required-profile`. Record only the version, source class, capability booleans, stable check code, and pass/fail result.
2. Review the Owner email and subscriber agreement without copying the email into evidence.
3. Recheck the selected IP, committed Direct TLS Hostname, exact DNS-only A/AAAA set, effective CAA, public route, time synchronization, unrelated port-80 ownership, and SBXR firewall authority.
4. For `sbxr-ip`, run the isolated staging command, then the exact production command, only in ticket #95's approved Change Set.
5. For `sbxr-domain`, run the isolated staging command, then the exact production command, only in ticket #96's approved Change Set.
6. Keep Integrated Verification, Codex Live Acceptance, and any required Owner Acceptance Pending until those checks actually run. Do not infer issuance from this ticket's tests or Plan.

The redacted Acceptance Record must exclude the Owner email, ACME account data, raw Certbot output, private keys, command environment, transaction material, complete certificate files, secret-derived data, Client Access Values, and any false issuance claim.

## Current acceptance status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `go test ./...` passed on the committed implementation. |
| Seam Verification | Passed | The same full-suite run passed the controlled official-shape Ubuntu Adapter checks. |
| Integrated Verification | Pending | Later integrated release. |
| Codex Live Acceptance | Pending | Requires an approved Acceptance Run and exact Release Identity. |
| Owner Acceptance | Pending if later affected surface requires it | Automation cannot claim this for Albert. |
