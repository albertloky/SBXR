---
status: accepted
---

# Run subscription-absent identity qualification before certificate issuance

On 2026-09-08 Albert approved speeding up live acceptance by retaining bounded
renewal proof and reducing avoidable production certificate requests. New repair
attempts use `repair-issuance-bounded-v4`. This extends ADR-0021 and supersedes
ADR-0019's scenario order and three-request budget only for that signed policy.
Historical v1/v2/v3 attempts keep their original meaning.

Move `identity-absent` immediately after `baseline-removal`, before
`enable-schema1`. Use the candidate's supported installation and setup to obtain
a Running proxy with no subscription. Prove the existing identity replacement,
old-session termination, connection refusal, replacement traffic, continued
subscription absence, and confirmed manual fallback checks. Then use reviewed
Complete removal and prove Not installed within the same 30-minute scenario.
No certificate is requested in this scenario. Its v4 evidence appends exactly
`candidate-supported-setup-origin`, `schema1-rotation-origin`,
`reviewed-complete-removal`, `complete-owned-absence`, and
`no-certificate-request` after the existing five observations. Its initial state
remains Running (proved after supported setup); its final state is Not installed.

Identity rotation upgrades the ownership schema to 2. Therefore the next
`enable-schema1` scenario must perform fresh supported installation/setup and
prove its schema-1 origin before enabling HTTPS. Reusing the post-rotation
record or editing its schema would destroy that separate evidence obligation.
The additional cleanup and setup require no certificate issuance.

Plan two production issuances: initial `enable-schema1` and the existing
interrupted managed-renewal / reviewed repair replacement. Preserve the resulting
healthy installation through the remaining scenarios and final Karing journey.
This is an issuance budget, not a certificate-authority capacity guarantee.

Keep all 25 live scenarios, all 29 automated-only scenarios, the two automated-only
lifecycle checks, every ADR-0021 Karing observation and disclosure, and independent
server-side identity/session proof. Keep the signed exact-byte binding, fresh
attempt requirement, original scenario/client/validation/transport deadlines,
secret containment, and stop-and-burn rules. The validator must reject the old
scenario order under v4, the new order under historical policies, and missing
subscription-absent cleanup evidence. The public Acceptance Record names v4.

Natural timer firing and naturally due renewal remain Not observed. There is no
multi-day renewal-observation gate. Official schedule integration, actual repair
replacement, activation, and outside TLS remain required. Karing's genuinely due
automatic refresh is a separate retained check.

Before selecting a fresh candidate, verify the full operator procedure and
checker locally, refresh issuance history without issuing a probe, and budget
capacity using the current official rate policy. A capacity wait is distinct
from a natural-renewal test. Do not change identifiers/accounts, borrow old
passes, restore removed lineage material, or consume a certificate to discover
whether capacity is available.

The managed-renewal interruption must be observed before Certbot can make a CA
request. A verified external hold of the actual child before its network work may
supply that boundary; merely sending a signal or observing the snap launcher does
not. If the intended boundary cannot be established safely, stop the attempt
rather than spending an unbudgeted issuance or claiming the planned saving.
