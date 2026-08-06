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
// PrepareCommit derives exactly revision N+1 from one exact Load result and
// binds it to the candidate, reviewed Plan, managed-input checksums, Change Set,
// and deterministic least-privilege service copies. The opaque prepared commit
// is consumed by the first Apply attempt and cannot be replayed. It preserves
// the exact prior state bytes for a later rollback snapshot without exposing or
// interpreting their protected values. Preparation never publishes or mutates
// storage; durable transaction publication belongs to System Changes.
package state
