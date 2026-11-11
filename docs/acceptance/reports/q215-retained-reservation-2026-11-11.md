# Build 215 cancellation and retained reservation — 2026-11-11

The Owner approved cancelling run 42470439088 and reserving signed but unqualified
v3.1.141/215 while preserving its draft, assets and evidence. The run is now
completed/cancelled; acceptance-vps was cancelled without live steps. Signing
succeeded. cleanup-unqualified failed at its explicit Owner-decision stop; its
logs confirm no deletion, burn signing or failed-release publication.

The draft is release 438186606 at source
`84af948bc2a1d92607aa2e6b902512b648133c43`, with body `Qualification pending.`,
draft true and prerelease false. The manifest SHA-256 is
`8a9a38a86f2e12b92689c715021d02b51b7aab402a2735b3329231c1cad6f332`.
GitHub attestation verification passed for the exact candidate workflow, main
ref and source digest. All four downloaded assets match the manifest and their
GitHub size/digest metadata. The index SHA-256 is
`07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b`.

The fixed policy appends only this thirteenth reservation. The earlier twelve
records remain unchanged. Fresh authenticated GET-only replay accepts thirteen
exact drafts and twenty-six explicitly absent release/burn refs. No draft body,
asset, release tag or burn tag was changed. The new regression failed before
implementation because the exact reservation was missing.

Local evidence is `.scratch/acceptance/q215res/`: signed manifest, preserved
assets, terminal job state, finalizer log, workflow evidence, original and
canonical observations, and replay result. The first observation serialization
was refused for noncanonical Unicode encoding; canonical serialization of the
same observations passed. No remote mutation was retried for that refusal.

## Next candidate preparation

Prospective v3.1.142/216 uses the current main product source, after this
reservation change passes checks. Base main `4672c11955a2ccf45aa8236a64c659256b35b313`
is the exact successful Verify 43003091353 source. Latest remote release observed
was v3.1.118 (419829967); metadata alone does not establish authenticated baseline
acceptance. The next preflight must verify current public history independently.

The non-live handoff is `.scratch/acceptance/q215res/next-candidate.md`.
Do not reuse build 215's expired declaration, timestamps, host/package readiness,
client observations or signed manifest. No new candidate workflow, signing,
live VPS/client action, cleanup or stable publication has been dispatched.

## Local validation

The corrected reservation suite passed in 83.850s, including fresh full
qualification/publication fixtures, original historical replay, and thirteenth
missing/unavailable/present-ref shell-adapter cases. One initial fixture still
used 216 as a skipped sequence; it now checks 217 and passed the focused rerun.
Root integration passed in 142.636s; `go vet ./...`, shell syntax, Go formatting,
changed documentation links and whitespace checks passed. The prior twelve
reservation source records were independently compared byte-for-byte to HEAD.
Go 1.26.6 and workspace-scoped temporary files were used.

The prospective v3.1.142 release and burn refs were explicitly absent and the
latest candidate run remained the cancelled build 215 at preparation time.
This is not allocation or a substitute for fresh dispatch preflight.

The full release-tool run completed in 542.079s with one failure: the old
skipped-sequence fixture compiled before its correction. No other failure was
reported. The final corrected reservation suite passed separately as recorded
above; a clean rerun of the whole package is not claimed. Native CI remains the
next exact-source verification checkpoint. No local race or unchanged Rust rerun
is claimed, and no live qualification has been performed.
