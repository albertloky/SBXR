# Bounded supported cleanup preparation — 2026-11-06

This offline repair follows the build 213 failure and the next-attempt budget
review. It authorizes no VPS access, signing, live attempt, administrative deletion
or publication. Build 213's failed result and all retained candidate assets remain
unchanged. The current live details/five-journey criterion is still unverified.

## Confirmed caller gaps

Ordinary recorded menu operations correctly refuse while a Karing response is
pending. They therefore cannot themselves supply the existing requirement that
failure cleanup be available independently of a missing reply. The old generic
cleanup helper also has unbounded status/inventory reads, repeats details and may
loop through setup finishing actions. Its per-invocation 900-second cap is not a
whole-cleanup budget. Terminal failure/collector expiry tears down authentication;
cleanup cannot be deferred to the global final thirty minutes.

Build 212 supplied one successful supported-removal observation: 151.57 seconds
for the removal call, about 10m10s from failure return to final scoped verification,
without an imported Karing profile or enabled subscription. Build 213's later
administrative recovery used separate authority. Neither bounds future cleanup
of HTTP/Karing or interrupted identity/removal states.

## Bounded change

The existing recorder gains a read-only cleanup deadline. It retains all original
request/draft/handoff validation, rejects sealed or expired inputs, and credits
only completed waits. A pending response remains pending and adds no extra time.
Normal qualification operation deadlines are unchanged.

The shared driver gains an explicit safety-cleanup mode allowing only the current
Rust Complete removal or Finish removal action and their exact confirmation/result
contracts. It keeps real product authentication, ownership review and process
supervision, verifies the private existing runtime cutoff, and requires a full
action timeout plus explicit post-action reserve to fit original deadlines before
spawn. The thin packaged caller binds those arguments without loops or retries.
No product Rust, signed schema, workflow gate, transport expiry or trust rule is
changed. Secret-free errors do not label menu success as whole cleanup.

Independent review identified an inherited unbounded parent request read. Cleanup
now routes request loading through the verified bounded clock subprocess instead;
the strict loader uses nonblocking open before checking regular-file identity.
A FIFO regression checks that malformed input cannot hang before product launch.

## Verification

Initial new recorder and menu-mode regressions failed against the old source.
The FIFO regression also reproduced four blocking cases before the loader fix.
Final clock tests passed 20/20. The full root integration suite passed 289 tests
and subtests with three existing platform/opt-in skips in 125.069 seconds;
it includes the complete recorder and menu suites, the new cleanup FIFO case,
actual thin-caller execution, both confirmation contracts, expiry and cancellation.
Four focused HTTP/MVP/attended compatibility tests passed (14 with subtests,
zero skips) in 20.372 seconds. Go vet, Python parsing, shell syntax, changed local
links and whitespace checks passed. Independent final review found no remaining
blocking issue. Spec Kit Analyze/Converge retained the open live criterion.

Validation used the installed pinned Go 1.26.6 directly and cached modules offline.
The first toolchain-launch command refused before tests because checksum-database
lookup was disabled; using the already-installed exact binary resolved that local
launch issue without changing dependencies or test requirements. Private logs are
under `.scratch/acceptance/c4c/`, `c4d/`, `c4g/`, `c4p/` and `c4v/` in the Rust checkout.
Fixtures run local inert menu processes and actual clocks, files, confirmations,
signals and process supervision; they do not execute SBXR against a live machine.
Mac skips do not establish Linux root validation. Exact-source GitHub CI remains
pending at this pre-push documentation checkpoint.

## Remaining operational limits

Whole-cleanup durations and actual VPS/Karing readiness remain unproved. Prepare
source-bound callers and shared scenario-specific reserves; verify current
ownership and authentication before any separately approved live use. Failed,
missing or uncertain evidence remains failed/unknown. Late replies cannot revive
the attempt; no transport reconstruction or administrative fallback is included.

## Subsequent CI result

The repair reached main as `335769cc1b27694d10065fa88eccc09cdeeccd80`.
[Verify 42217521869](https://github.com/albertloky/SBXR/actions/runs/42217521869)
failed when the separate release-tool race package exhausted its cumulative
ten-minute timeout. Root checks containing these cleanup regressions passed;
arm64 completed the test step before later matrix cancellation. This is not a
successful full CI result. The separately authorized
[test-build investigation](release-test-build-reuse-2026-11-06.md) preserves the
original failure and records the follow-up; live cleanup remains unverified.
