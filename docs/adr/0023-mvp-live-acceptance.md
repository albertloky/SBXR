---
status: accepted
---

# Use five product journeys for current MVP live acceptance

On 2026-09-12 the Owner selected the five-journey scope from the module/test
review. `mvp-live-v1` is the current evidence policy within the existing
`subscription-clean-install-repair` scope for the subscription-capable MVP.
It retains ordinary regression tests, supported-artifact
trust, a real disposable Ubuntu Server, genuinely outside proxy traffic, trusted
HTTPS, and a real Karing import/refresh while preserving the Owner's selected
connection.

The live record names exactly these journey identifiers:

```text
mvp-install
mvp-subscription
mvp-credentials
mvp-renewal
mvp-removal
```

They cover normal installation and use; subscription enablement and Karing;
one proxy-UUID and one subscription-URL rotation with old access revoked; the
supported Certbot renewal/activation route; and ordinary restart followed by
Complete removal. This scope does not require an incoming-upgrade proof,
natural timer firing, or a naturally due client auto-refresh.

The earlier v1–v4 records, their scenario identifiers, and their validation
rules retain their original interpretation. The historical V4 procedure is not
the procedure for `mvp-live-v1`. This decision changes acceptance scope only:
it retains the existing evidence envelope, hash chain, deadlines, and failed-run
handling, and introduces no product behavior, transport change, or new rule for
those mechanisms.

Forced interruptions, lock/contention exercises, metadata-drift and forced
outage cases, snap refresh, a five-minute auto-refresh wait, the 24-hour V4
rehearsal, and the V4 six-surface capture inventory are not recurring MVP live
requirements. Relevant ordinary regressions and supported artifact verification
remain required. The known historical scenario 03 refusal is a separate bounded
regression investigation; it is neither a new MVP journey nor evidence of a
successful release.
