---
status: superseded by ADR-0005
---

# Managed lifecycle and recovery

SBXR uses five explicit installation statuses, durable start/completion and rollback checkpoints, strict health gates with navigable Correction Flows, review-first updates, bounded self-contained Recovery Points, and automatic IP-certificate renewal under a narrow Owner-approved standing policy; ordinary interruption rolls back, while separately confirmed Complete removal alone continues forward after its point of no return. These choices keep lifecycle orchestration behind the owning deep Modules and prevent uncertain State, recovery evidence, or host changes from being treated as safe; the canonical decision is [Define the managed lifecycle and recovery behavior](https://github.com/albertloky/SBXR/issues/8#issuecomment-5178856927).
