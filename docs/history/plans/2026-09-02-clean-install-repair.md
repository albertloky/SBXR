# Clean-install repair execution

Approved design: ADR-0018. Keep the current feature branch and unrelated files.

1. Test-first: add explicit empty-source `subscription-clean-install-repair`
   support to the existing Software Lifecycle index and GitHub Adapter. Refuse
   incoming update, missing/populated source lists, and reuse of ADR-0017.
2. Test-first: admit repair qualification only against the exact v3.1.0 baseline
   and complete history, with no previous published repair. Reuse all clean-install
   scenario obligations, signed attempt checks, clocks, and burn rules.
3. Extend existing bootstrap scope decoding and workflow admission, retaining
   exact asset/index validation. No alternate installer or evidence authority.
4. Run independent spec/security and code reviews, full tests, race checks, vet,
   builds, and diff checks. Commit only intended files and fast-forward main after
   checking remote ancestry; do not publish stable.
5. Gather fresh host/client/package identities, construct a canonical signed test
   attempt through the existing candidate workflow, and perform supported live
   scenarios. Stop and clean up at unexpected failure, fix the cause, then use a
   fresh identity. Do not wait for natural multi-day renewal or invent a pass.

## Execution status

Steps 1–3 are implemented. Step 4 passed local full tests, targeted race checks,
vet, dependency verification, both Linux cross-builds, and independent spec and
code-quality review. Step 5's read-only preflight found that the unchanged full
matrix exceeds the production certificate issuance budget within the existing
six-hour transport lifetime. No signed attempt or candidate was started. See
`docs/acceptance/clean-install-repair-2026-09-02.md` for exact evidence and limits.
