// Package state is the sole persistence boundary for SBXR Desired State.
//
// The Module owns one typed JSON document at /var/lib/sbxr/state/state.json.
// Its directories are root-owned mode 0700 and the file is root-owned mode
// 0600. The envelope binds a supported schema, positive revision, exact Release
// Identity, last completed Change Set, and an internal SHA-256 payload integrity
// checksum. That checksum detects unintended change; it is neither encryption
// nor protection from root and is never returned as Owner-facing evidence.
//
// Load returns either a proven Clean VPS baseline or one protected, complete,
// typed current snapshot. It refuses partial, unknown, unsafe, or
// lineage-disagreeing documents with a stable secret-safe Finding and Recovery
// Required. Load never adopts Observed State, changes files, interprets stored
// secrets, or exposes rejected content.
//
// Schema 1 is the first and only persisted schema, so its deterministic
// migration path currently contains zero steps. Load and PrepareCommit return
// that exact path plus Release Identity compatibility facts for review. Every
// other schema is refused; no fictional predecessor or reverse migration is
// retained solely for testing. The first real successor must add one explicit
// embedded transformation and its persisted predecessor fixture.
//
// PrepareCommit derives exactly revision N+1 from one exact Load result and
// binds it to the candidate, reviewed Plan, managed-input checksums, Change Set,
// and deterministic least-privilege service copies. The opaque prepared commit
// is consumed by the first Apply attempt and cannot be replayed. It preserves
// the exact prior state bytes for a later rollback snapshot without exposing or
// interpreting their protected values. Preparation never publishes or mutates
// storage during preparation. After System Changes preserves its transaction
// material and passes every pre-publication gate, the opaque transaction writes
// the candidate beside current State, flushes and verifies it, atomically
// replaces current State, flushes the directory, and returns an exact readback
// agreement. State never marks the Change Set Complete or owns rollback.
package state
