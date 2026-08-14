---
status: superseded in part by ADR-0010
---

# Distributed security ownership and trust boundaries

ADR-0010 supersedes this decision where it required a non-root Owner Console, separate service identities, short-lived root operations, or root-only access to runtime service material. The complete Owner Console and managed services now run as root. Runtime service material uses `root:root 0644`. Desired State, Cloudflare management credentials, transaction journals, recovery material, and health events remain root-only. The authenticated dashboard deliberately exposes Client Access Values for convenience, while Infrastructure Secrets remain protected, external authority is scoped, and redaction and network protections cannot be bypassed. The canonical original decision is [Define security ownership and trust boundaries](https://github.com/albertloky/SBXR/issues/9#issuecomment-5175290085).
