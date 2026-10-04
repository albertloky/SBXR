---
status: accepted
---

# Clean installation only

On 2026-10-04 the Owner directed: “We don't need to update. We just need to
uninstall and install the new version. We don't need the update.” This supersedes
the current incoming-upgrade requirement in ADR-0025 and the automatic legacy
HTTPS migration entrypoints in ADR-0026. Their historical records and exact-release
repair rules retain their original meaning.

The current release support scope is `subscription-clean-install-only`, with
contract `sbxr-subscription-update-v1` and an explicit `sources: []`. The signed
attempt also has `sources: []`, `evidence_policy: "mvp-http-live-v1"`, and exactly
`mvp-install`, `mvp-subscription`, `mvp-credentials`, `mvp-serving`, `mvp-removal`.
It has no Owner exception or automated-only scenario claim. Release history and
the verified publication baseline remain necessary release-order facts; they do
not become an incoming source. Do not widen the old
`subscription-clean-install-repair` baseline restriction to implement this scope.

Production Check/Update must not offer or perform a new software update. Normal
root startup and completed lifecycle recovery must not initiate legacy HTTPS
migration. There is no background software updater. Keep proved historical
transaction recovery and applicable setup, credential, subscription and removal
recovery; do not delete their authority readers or exact removal-finisher route.

An existing installation is removed through its existing exact-release reviewed
Complete removal and recovery route before fresh installation. Downtime, loss of
old client access, new credentials and new client setup require the concrete live
authorization. An absent host needs neither an old source installation nor removal.
The installer must refuse remaining installation authority/resources. An exact
same-release no-op and restoration of the proved removal finisher remain recovery
behaviors, not an upgrade route.

The five HTTP live journeys require zero subscription CA issuances. The former
two HTTPS source preparations and their CA wait disappear with their three source
journeys. Keep relevant recovery regressions at ordinary test level and retain
artifact/attestation trust, native checks, real outside traffic and Karing,
credential revocation, deadlines, cleanup and publication safeguards. Do not adopt
unfinished multi-session tooling as a prerequisite for this scope.

Latest is conditional on proved refusal by the unchanged old updater and the
installer over existing state. Without that proof, retain a non-Latest candidate.
No local check is a packaged live pass or permission to build, sign, upload,
install, publish, commit, push or tag a new candidate. Changed source requires a
new reviewed candidate commit and new qualification evidence.
