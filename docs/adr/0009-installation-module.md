---
status: superseded by ADR-0014
---

# Installation Module

SBXR adds Installation as a twelfth deep Module because the complete review-first move from proven **Not installed** to proven **Managed** now has enough cross-Module Plan composition, Destructive Reclamation confirmation, fresh pre-Apply validation, State preparation, privileged handoff, operation tracking, cancellation, and restart coordination to earn one interface and one owner. Installation exposes only the Owner actions Review, Confirm Reclamation, Apply, Inspect, Request Cancellation, and Recover; keeps pre-Apply state memory-only; consumes one opaque Approval per Apply attempt; returns domain results for a presentation adapter; and preserves the current Owner experience.

This decision supersedes only ADR-0005's statement that SBXR has exactly eleven deep Modules. Software Lifecycle retains release verification and staging; Network Policy retains admission and fresh proof; State retains persistence rules; System Changes retains the global mutation lock, durable checkpoints, rollback, forward recovery, and durable Change Set ownership; Owner Console retains presentation; and Installation does not own update, downgrade, repair, Complete removal, or Pasteable Install Command bootstrap behavior. Startup asks System Changes for the pending Change Set kind and dispatches only unfinished initial Installation to Installation recovery. The production cutover is one tested vertical replacement with no parallel installation implementation.
