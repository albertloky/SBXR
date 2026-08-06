// Package state is the sole read boundary for SBXR Desired State.
//
// The Module owns one typed JSON document at /var/lib/sbxr/state/state.json.
// Its directories are root-owned mode 0700 and the file is root-owned mode
// 0600. The envelope binds a supported schema, positive revision, exact Release
// Identity, last completed Change Set, and an internal SHA-256 payload integrity
// checksum. That checksum detects unintended change; it is neither encryption
// nor protection from root and is never returned as Owner-facing evidence.
//
// Load returns either a proven Clean VPS baseline or one protected current
// snapshot. A missing, damaged, substituted, permission-broadened, or
// lineage-disagreeing current document produces a stable secret-safe Finding
// and Recovery Required. Load never adopts Observed State, changes files, or
// exposes rejected content. Its Correction Flow permits correcting the named
// boundary when safe, Check again, or returning Back; it has no force-adopt,
// arbitrary-path, raw-editor, or Continue-anyway path.
//
// PrepareCommit belongs to a later State Module slice.
package state
