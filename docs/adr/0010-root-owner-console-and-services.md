---
status: accepted
---

# Run the Owner Console and managed services as root

SBXR accepts the Pasteable Install Command and later launches from a root or sudo-authorized non-root Owner Launch Identity. The complete Owner Console always runs as root. A root Owner Launch Identity starts it directly. A non-root Owner Launch Identity authenticates before SBXR shows a Console screen. An authentication refusal makes no change. A privileged process opens the downloaded candidate without following links. It proves the ownership, mode, link count, Release Identity, and digest. It executes the same open file descriptor. Installation drafts stay in memory and SBXR discards them when the Console exits.

Xray, sing-box, cloudflared, and Subscription Serving use `User=root` and `Group=root` without separate service identities. They retain applicable systemd containment. Runtime service configuration, proxy credentials, subscription material, the Cloudflare Tunnel run token, and TLS private keys use `root:root 0644`. The reviewed installation Plan states that every local Linux identity can read them. Desired State, Cloudflare management credentials, transaction journals, recovery material, and health events remain root-only. Owner Console does not show a root label or warning banner.

Existing `v1.0.6` installations cannot update to this design. SBXR supplies no bridge release or migration guidance. The Owner must independently use the existing separately confirmed Complete removal flow. This flow deletes old service identities only after `Irreversible removal started`. It preserves no configuration or credentials. The Owner can then do a fresh installation. Privilege and service-identity changes can qualify for stable publication with package tests only. Automated Ubuntu integration and live VPS acceptance are not required.

Installation preserves its six-action Interface: Review, Confirm Reclamation, Apply, Inspect, Request Cancellation, and Recover. Software Lifecycle retains release delivery and Complete removal. State retains persistence. System Changes retains Change Sets and recovery. Owner Console retains presentation. Unrelated Module ownership does not change.

This decision supersedes ADR-0002 only where it requires a non-root Owner Console, separate service identities, narrow short-lived root operations, or root-only access to the listed runtime material. It supersedes ADR-0007 only where it launches the authenticated SBXR executable as the original non-root Owner Launch Identity or applies stronger qualification requirements to privilege and service-identity changes. This decision accepts full root authority for the interactive Console and managed services. It accepts local disclosure of runtime credentials, no guided migration, and package-test-only qualification. In exchange, SBXR gets one execution model and root-or-non-root command entry.
