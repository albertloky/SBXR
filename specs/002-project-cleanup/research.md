# Research and decisions

## Navigation cleanup

Decision: add missing Rust/test/package/spec areas to the documentation map and a
small work index. Rationale: existing map lists only Go product directories despite
this checkout containing 251 tracked files under src and 109 under tests.
Alternative: move code to make the old map true; rejected as unnecessary disruption.

## Preserve reference and evidence

Decision: retain Go source, root integration tests, historical reports, fixtures,
and private scratch. Rationale: AGENTS/code map explicitly retain their roles;
missing historical scratch links identify private evidence, not public-navigation defects.
Alternative: delete old-looking content; rejected because age does not prove obsolescence.

## Tooling and ownership

Decision: reuse installed Spec Kit and isolated Rust toolchain offline. No installation.
Existing feature 001 records qualification and pending T018; do not edit it. Thread
inventory did not return during assessment, so active ownership could not be fully
verified. Keep edits to this new feature and navigation only and report through Agnes.
No unknown technology choice or new dependency requires delegated research.

## Boundaries

No runtime defect is established by this maintenance pass. Source refactoring,
release-policy changes and live cleanup would require their own evidence and owner
coordination. Existing ignore rules cover observed scratch, Rust target and Python
bytecode outputs; no speculative broad ignore patterns are needed.

## Continued source inspection after ownership update

Agnes confirmed the prior qualification turn is completed and not actively editing.
Decision: proceed with pure-output cleanup, preserving all its artifacts and records.
A 12-line duplication scan over non-test Rust source found repeated operation stages,
HTTPS setup, redaction macros, lock admission, record fields, protected-file opens,
process admission and runtime observations. These are retained: mechanical similarity
does not prove the same authority or compatibility contract.

Confirmed removable code: the standard Base64 encoder duplicates the pinned base64
dependency already used by tunnel code, and the configuration digest duplicates
records::sha256_hex exactly. The installed dependency source documents encode_string
as appending to a supplied String with standard padded output. Use it directly,
avoiding both the custom encoder and its intermediate allocation. Existing RFC
vectors and Go-generated artifacts provide independent expected values.

Alternative of generalizing validation, transport, redaction or state-machine helpers
is rejected for this cleanup because it broadens risk without a demonstrated defect.
