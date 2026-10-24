# Offline acquisition fixtures

`clean-record.txt` is a synthetic Acceptance Record template, not live evidence.
Unit tests bind its placeholders to inert stamped ELF/archive/index bytes and
exercise 85 valid/adversarial record variants. An independent run of the preserved
Go `latestAcceptanceRecord` plus `qualifiedReleaseSupport` agrees with all cases;
its copied parser and outputs live under `.scratch/acceptance/rust-acquire/`.

`generate-archive.go` uses the Go 1.26.6 standard tar/gzip writers to produce
`go-single-member.tar.gz`, containing only the inert text `inert Go archive fixture`.
Regenerate from the repository root with
`GOTOOLCHAIN=go1.26.6 go run src/release_acquisition/testdata/generate-archive.go`.
No contained bytes are executed or extracted to disk by Rust tests.

Positive downstream integration uses a private unit-test-only authenticated-claims
constructor. Product builds cannot access it. The public acquisition entry uses
real Sigstore verification and refuses a preserved genuine foreign-repository
bundle before downloading assets. A genuine valid SBXR native/v0.2 fixture remains
missing, so these fixtures do not demonstrate a complete positive signed release,
production installation, restoration or live qualification.
