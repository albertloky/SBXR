# Approved clean-install repair: implementation verified, live preflight blocked

## Decision and implementation

Albert approved the clean-install repair route after the unchanged public
`v3.1.0` updater failed the recurring-candidate feasibility check. ADR-0018
records the explicit `subscription-clean-install-repair` scope. Incoming sources
must be empty; the exact public `v3.1.0` baseline and complete history are checked
again at publication. A previous published stable repair refuses another repair.
Failed attempts still burn their identities. ADR-0017 cannot waive repair evidence.

The existing index, bootstrap, GitHub Adapter, signed candidate transport, and
qualification command now accept this scope consistently. The existing
clean-install matrix is unchanged; incoming upgrades and two-release transaction
recovery are Not applicable, not Passed. No old executable or protected product
record was patched. No stable publication is authorized by this implementation.

## Verification

Regression tests were observed failing before their fixes at the index, signed
candidate, and generated installer boundaries. The repair command test exercises
preflight, signed attempt, the complete scenario contract, acceptance generation,
publication checks, failure/burn handling, changed history, and waiver refusal.
Independent spec/security and code-quality reviews found no actionable issues.

Using `GOTOOLCHAIN=go1.26.6`, these checks passed:

- `go test -p 1 -timeout 30m ./... -count=1` (all packages).
- `go test -race -p 1 -timeout 30m ./internal/softwarelifecycle/... ./cmd/sbxr-release -run 'TestSource|TestVerifyLatestReleaseIndex|TestOwnerException|TestCheckRefusesCleanInstall|TestQualificationCommandBindsCleanInstallRepair|TestRepairScope|TestQualificationGateway|TestGeneratedInstallerAcceptsCleanInstallRepairIndex' -count=1`.
- `go vet ./...` and `go mod verify`.
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` and the corresponding
  `GOARCH=arm64` build.
- Formatting and `git diff --check`.

These results do not prove live VPS, production CA, or Karing acceptance.

## Live preflight: certificate issuance budget

The retained matrix cannot fit the current one-address, six-hour transport
session. The following six scenarios alone each need a separate installation
with a real issued certificate, followed by complete owned removal:

1. `remove-enable-postcommit`
2. `remove-link-precommit`
3. `remove-link-postcommit`
4. `remove-repair-precommit`
5. `remove-repair-postcommit`
6. `remove-activation-precommit`

This is a lower bound, not the complete issuance count. Each successful Complete
removal deletes the dedicated lineage and certificate generations. The next
scenario cannot reuse them through supported setup/enablement. Earlier enablement,
activation, and managed-renewal cases, plus final Karing, need additional issuance.

The [current Let's Encrypt rate policy](https://letsencrypt.org/docs/rate-limits/)
(updated 2026-08-05, checked 2026-09-02) permits five certificates for an exact
identifier set in seven days, with one token restored every 34 hours. There is
no override for this limit. Even a full unused bucket cannot supply these six
fresh issuances within six hours. The exact remaining bucket for this address
was not queried or assumed; no new order was submitted to probe it.

The installed official Certbot `5.8.0`, snap revision `5893`, was inspected
read-only. Its `acme/client.py` SHA-256 is
`67c2eb9173b6bb1f1b6f8ff284450bab40cfe4aaedd20c8be04aa060fbed07ea`.
`ClientV2.new_order` constructs the order from identifiers and profile without
ARI's replacement field. Checking renewal information alone therefore does not
establish the rate-limit exemption. More importantly, complete removal leaves no
owned lineage for the next fresh enablement to replace. No Certbot patch, new
account, staging certificate, extra identifier, or protected-state restoration
was used to change this conclusion.

At `2026-09-02T03:37:21Z`, fresh checks still found no SBXR executable, Ownership
Record directory, finalization authority, candidate transport, evidence directory,
or dedicated renewal configuration on `RackNerd`. No host, package, Karing app,
profile, or client setting was changed during this preflight. No candidate was
dispatched, no signed attempt was started, and no release identity was burned.

Natural timer firing and naturally due renewal remain excluded and Not observed.
This separate production-rate constraint is not a natural-renewal test. Completing
all retained live cases requires an explicit qualification-plan change; the
implementation above does not silently reduce the matrix, change certificate
trust, or extend the transport lifetime. All previously unperformed live cases
remain unperformed.
