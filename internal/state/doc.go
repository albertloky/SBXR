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
// PrepareCommit performs the candidate-validation portion of preparation. It
// invokes every owning Module's typed semantic-validation Seam and emits only
// the deterministic least-privilege service copies required by enabled
// Connection Profiles, with byte checksums and fixed ownership/modes. General
// serialization of protected values and prepared bytes remains blocked; only
// an owning validator receives a narrow reader for its own secret category.
// PrepareCommit does not publish those copies or grant one-use mutation
// authority; those transaction bindings belong to the next State slice.
package state
