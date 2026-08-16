---
status: accepted
---

# Add the Cloudflare Profile Setup Module

SBXR adds Cloudflare Profile Setup as the thirteenth deep Module. It owns the complete Owner-visible Managed-to-Managed outcome that sets up VLESS XHTTP, VLESS WebSocket, Hysteria2, TUIC, and AnyTLS together after Cloudflare-free first Installation.

The Module lives at `internal/cloudflareprofilesetup`. Its conceptual Interface is exactly `View`, `Plan`, and `Apply`. Production uses one concrete Interface created by `New(Dependencies)`. SBXR does not add a public Go interface type or an `internal/cloudflareprofilesetup/adapter/` package.

The Module can depend on exactly Network Policy, Cloudflare Tunnel, Certificate Lifecycle, Connection Profiles, Subscription Publication, State, and System Changes. Installation and Cloudflare Profile Setup remain independent. Installation stops depending on Cloudflare Tunnel and does not call Cloudflare, accept a Cloudflare credential, or add provider facts to Desired State revision `1`.

Cloudflare Profile Setup coordinates typed facts but does not take ownership from its dependencies. System Changes remains the only owner of the global mutation lock, journal, Rollback Snapshot, execution, cancellation checkpoints, rollback, forward recovery, and Recovery Required. Cloudflare Profile Setup submits exactly one composed Change Set through System Changes.

This decision supersedes only the fixed Module-count clauses in ADR-0005 and ADR-0009. Their transaction-only recovery boundary, Installation ownership, and all other decisions remain authoritative. The complete staged behavior is specified in [Specification amendment: staged Installation and Cloudflare Profile Setup](https://github.com/albertloky/SBXR/issues/209) and is not duplicated here.
