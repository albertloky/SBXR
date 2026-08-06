# State Module acceptance

This file defines procedures and owners only. Run results belong in the implementation issue or the one release Acceptance Record. Evidence must contain stable finding codes and commands, but no raw `state.json`, Client Access Value, Infrastructure Secret, checksum, or secret-derived value.

## `STATE-MODULE-LOAD` — Module Verification — Codex

Run:

```sh
go test ./internal/state
```

Pass when the `Load` Interface proves clean absence, valid Managed and Change in progress snapshots, strict typed JSON, duplicate-key and unknown-field refusal, supported Release Identity, checksum integrity, every lineage outcome, complete secret-safe findings, and marker absence. This check owns the `Load` and Correction Flow behavior.

## `STATE-ARCHITECTURE` — Module Verification — Codex

Run:

```sh
go test .
```

Pass when the root registry contains exactly the eleven approved Modules; the repository contains only approved product-package shapes; dependencies are standard-library-first, acyclic, and downward; and production code cannot import tests, fixtures, evidence, acceptance tooling, generic dumping grounds, or unregistered Modules. This check owns repository placement.

## `STATE-SEAM-STORAGE` — Seam Verification — Codex

Run the controlled filesystem check as root on the supported Linux environment:

```sh
go test -v ./internal/state/adapter/filesystem
```

Pass only when `TestRootOwnershipSeam` runs rather than skips and the complete check proves fixed `state.json` placement, root ownership, exact `0700`/`0600` modes, stable durable reads, and refusal of symbolic links, hard links, path substitution, unexpected types, broader modes, wrong owners, and corruption. Redacted evidence records test names and status only.

## `STATE-LIVE-STORAGE` — Codex Live Acceptance — Codex

During one explicitly approved Acceptance Run, use the exact Release Identity and an Acceptance VPS with a proven Acceptance Baseline. Verify the real `/var/lib/sbxr/state/state.json` boundary, root ownership, exact `0700`/`0600` modes, corruption refusal, restart read, and absence of protected content in findings. Destructive corruption must use only the transaction-scoped Acceptance Run procedure and restore or reimage the disposable VPS afterward.

If no approved Acceptance Run occurred, record `Pending`; automated results do not satisfy this check.

## `STATE-OWNER` — Owner Acceptance — Albert

Normally `Not required` because this slice has no maintained-client or Owner-visible workflow. The first SBXR v1 release still follows the release-level risk decision. A later Owner-visible migration or Correction Flow change must name its exact Owner procedure.
