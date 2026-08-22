---
status: superseded by ADR-0014
---

# Keep Installation conflict seams in Network Policy

Network Policy alone decides which exact address, port, protocol, service identity, resource identity, or path is an SBXR-owned seam for one reviewed Installation candidate. It supplies the candidate listener seams as typed inputs to the Ubuntu Adapter; the Adapter observes all listeners but collects reclamation evidence only for listeners that collide with those requested seams. Non-conflicting listeners remain observed and bound into fresh checks without entering Destructive Reclamation, while a real collision still uses the existing port correction, refusal, and Protected Host Foundation rules.

The Ubuntu Adapter does not infer conflict meaning independently from Installation intent, because that would duplicate candidate-policy rules outside Network Policy. It also does not inventory every listener executable and ask Network Policy to discard unrelated targets later, because protected operating-system services would enter destructive inventory before the owning Module established a conflict.
