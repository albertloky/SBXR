# Cleanup signal fixture repair — 2026-11-05

## Observed failure and limits

Verify [run 42003224687](https://github.com/albertloky/SBXR/actions/runs/42003224687)
at `a3d01a9286fd06b14dd3d48f16275ff1376284ac` failed its amd64 Go race phase:
`TestSharedPackagedMenuDrivers` reported exit `-9` instead of `0` in
`test_spawn_diagnostic_sink_failure_still_allows_full_protected_cleanup`.
The arm64 tests passed before its archive build was cancelled by matrix fail-fast;
assembly did not run. The reservation package passed both ordinary and race phases.
The failed test and production menu driver were unchanged by that source commit.

The original assertion recorded only SIGKILL termination. It did not establish
whether the signal handler ran, how much stderr drained, or who sent SIGKILL.
One hundred unchanged-test repetitions on local Python 3.9.6 passed, as did the
focused Go 1.26.6 race wrapper (16.779 seconds). A single unchanged-source Verify
retry was admitted as attempt 2 while the investigation continued. Its result is
separate from verification of the repair.

## Reproduced fixture defect

CPython can receive a signal in C before entering a blocking stdin read, leaving
its Python handler pending until the syscall returns or is interrupted. This is
consistent with [FileIO.readall](https://github.com/python/cpython/blob/v3.12.3/Modules/_io/fileio.c#L651-L731)
and [_Py_read](https://github.com/python/cpython/blob/v3.12.3/Python/fileutils.c#L1731-L1783),
which checks pending handlers after an interrupted read. It is a fixture-level
lost-wakeup window; no production driver defect was established.

An offline macOS/Python 3.13.18 experiment used a test-only dynamic-library read
interposer. It held the real SIGUSR1 until the child reached the C read boundary,
then delivered it immediately before the actual stdin read. The existing driver,
real process group, signal, pipes, stderr payload and 20-second cleanup budget
were retained. The unbounded idle child returned `-9` after 20.009 seconds, with
no Python-handler entry and zero stderr bytes. With periodic 10 ms sleeps as the
idle loop, the child returned `0` after 0.038 seconds, entered its handler, wrote
and drained all 196,608 stderr bytes, and completed cleanup.

This reproduces a concrete failure mechanism and the benefit of removing that
fixture dependency. It does **not** prove the precise scheduling of the original
Linux CI occurrence. No second signal, stdin write, timeout increase or production
change was used to make the repaired fixture pass.

## Bounded repair and checks

Only the five SIGUSR1 cleanup fixtures switch their otherwise unused stdin idle
read to periodic sleeps. They still use the real cleanup signal and large stderr
write. All exit, cleanup, secret-filter and timing assertions remain; the failing
case additionally records handler entry, completion, elapsed time and exact drained
byte count. Other stdin/EOF fixtures and the production driver remain unchanged.
The adjacent tests cover successful cleanup, failed diagnostic sinks, constructor
failure, high descriptors, and transient/persistent drainage errors.

The complete menu-driver suite passed on Python 3.9.6 (14.188 seconds) and 3.13.18
(14.004 seconds): 67 tests each, with four platform-specific skips each. The actual
Go race wrapper passed after the repair in 16.512 seconds. Exact-source Linux CI
is a separate post-push check; these local results do not imply that it passed.
Independent review and whitespace checks are recorded with the final diff.

Private reproducible experiment/source and logs: `.scratch/acceptance/cf1/`
through `cf4/`; original CI log and reservation observations remain under
`.scratch/acceptance/q212res/`. Test-owned temporary roots were removed empty.

## Unchanged release limitations

The approved build 212 reservation and its signed but unqualified draft, assets,
signature and failed result are preserved. This repair changes no product code,
release policy, workflow permissions, credential or security setting. It performs
no live VPS test, cleanup, signing or publication. The live 90-second details
criterion and the other exact-candidate journeys still need separate authorized
qualification and fresh readiness. Final-source CI remains an independent prerequisite.
