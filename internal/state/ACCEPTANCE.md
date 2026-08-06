# State Module acceptance

This file defines procedures and owners only. Run results belong in the implementation issue or the one release Acceptance Record. Evidence must contain stable finding codes and commands, but no raw `state.json`, Client Access Value, Infrastructure Secret, checksum, or secret-derived value.

## `STATE-MODULE-LOAD` — Module Verification — Codex

Run:

```sh
go test ./internal/state
```

Pass when the `Load` Interface proves clean absence, valid Managed and Change in progress snapshots, a complete typed Desired State, exact field names, duplicate-key and unknown-field refusal, supported Release Identity, checksum integrity, every lineage outcome, cross-section validation, complete secret-safe findings, and marker absence. This check owns the `Load` and Correction Flow behavior.

## `STATE-MODULE-PREPARE` — Module Verification — Codex

Run:

```sh
go test ./internal/state -run '^TestPrepareCommit'
```

Pass when the candidate-validation portion of `PrepareCommit` requires an exact Release Identity, invokes every owning Module's typed validator, and refuses incomplete candidates, missing or refusing validators, unrelated service values, and invalid manifests before mutation. The complete fixture must cover every typed section. Unique secret markers must prove that general serialization cannot render protected values, each enabled service receives only its required values, and a service with no enabled Connection Profile receives no runtime copy.

The exact ownership contract is:

| Persisted meaning | Semantic validator and secret owner |
| --- | --- |
| Installation identity and pinned software | Software Lifecycle |
| Six Connection Profiles and their Client Access Values | Connection Profiles |
| Subscription settings and token | Subscription Publication |
| Cloudflare authority, immutable bindings, management token, and tunnel run token | Cloudflare Tunnel |
| Certificate policy, identities, and serving pointers | Certificate Lifecycle |
| Network Policy inputs | Network Policy |

State owns structural and cross-section validation, typed persistence, protected serialization, and secret-safe refusal. It invokes the owning validators but does not replace them, test or rotate credentials, expose values through general rendering, or adopt Observed State. During those calls only, Connection Profiles receives readers for its Client Access Values and Infrastructure Secrets, Subscription Publication receives a Client Access Value reader, and Cloudflare Tunnel receives an Infrastructure Secret reader; readers cannot be upgraded to another secret category and are revoked after return or panic. Modules without owned secrets receive no reader. `xray.service` and `sing-box.service` copies belong to Connection Profiles; `cloudflared.service` belongs to Cloudflare Tunnel; `sbxr-subscription.service` belongs to Subscription Serving. Each private manifest binds the owning Module, candidate revision, later Change Set, exact serialized bytes, owner `root`, service group, directory mode `0750`, file mode `0640`, and SHA-256. Prepared bytes and their full checksum-bearing manifests remain opaque and non-renderable until issue #65 introduces their one-use System Changes handoff.

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

## `STATE-SEAM-SERVICE-MATERIAL` — Seam Verification — Codex

Run:

```sh
go test -v ./internal/state -run '^TestPrepareCommit'
```

Pass when protected JSON serialization produces every required byte-stable service copy and no copy for an unused service. Every produced manifest must carry the exact owning Module, owner, group, `0750` directory mode, `0640` file mode, candidate revision, later Change Set, and matching SHA-256. Marker checks must prove unrelated secrets, comments, provenance, complete Desired State, and disabled-profile credentials are absent.

This is preparation proof only. Applying the owner and modes to live service paths is part of the later System Changes seam. If that seam has not run, record it `Pending`; this check does not prove publication or live service behavior.

## `STATE-LIVE-STORAGE` — Codex Live Acceptance — Codex

During one explicitly approved Acceptance Run, use the exact Release Identity and an Acceptance VPS with a proven Acceptance Baseline. Verify the real `/var/lib/sbxr/state/state.json` boundary, root ownership, exact `0700`/`0600` modes, corruption refusal, restart read, and absence of protected content in findings. The later Integrated Verification must also prove that prepared service material reaches each owning service without unrelated values. Destructive corruption must use only the transaction-scoped Acceptance Run procedure and restore or reimage the disposable VPS afterward.

If no approved Acceptance Run occurred, record `Pending`; automated results do not satisfy this check.

## `STATE-OWNER` — Owner Acceptance — Albert

Normally `Not required` because this slice has no maintained-client or Owner-visible workflow. The first SBXR v1 release still follows the release-level risk decision. A later Owner-visible migration or Correction Flow change must name its exact Owner procedure.
