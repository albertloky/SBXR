---
status: accepted
---

# Bind clean-install lifecycle checks to reachable evidence

On 2026-09-02 Albert approved moving only `lifecycle-menu/explicit-confirmation`
and `lifecycle-menu/clean-install-target-refused` to mandatory native automated
evidence for the ADR-0018 repair. The single-candidate clean-install attempt has
neither an available supported update nor actual lifecycle recovery authority;
its same-identity Check returns Already current before update-support refusal.
Neither observation can be produced honestly on that live path.

New attempts may select signed `repair-issuance-bounded-v2`. It retains ADR-0019's
25 live scenarios and exact ordered 29 automated-only scenarios, but excludes
exactly those two checks from live `lifecycle-menu` evidence. The Acceptance
Record must additionally publish the exact ordered line:

```text
Automated-only checks (not live): lifecycle-menu/explicit-confirmation lifecycle-menu/clean-install-target-refused
```

Both exclusions remain mandatory in native amd64/arm64 automated verification,
not live passes or Not applicable. The public verifier rejects missing, altered,
duplicate, or scope-inappropriate disclosures. Policy v1 and historical attempts
retain their original contracts. No other scenario, check, production behavior,
release support, clock, failure burn, trust rule, or Karing journey changes.
Natural timer firing and naturally due renewal remain Not observed.
