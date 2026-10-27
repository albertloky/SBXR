# DNS child fixture and supervisor review

This is a local diagnostic source/runbook, not authorization to execute it. Read
[the dated Linux report](../../docs/acceptance/reports/dns-child-diagnostic-linux-2026-10-27.md)
and [the tracer build assessment](../../docs/research/bpftrace-0.23-no-mount.md).
No new Library transfer is needed for repository documentation or source review.

## Sources and safe checks

`dns-child-fixture-supervisor.py` supervises one session; its adjacent
`test_dns_child_fixture_supervisor.py` exercises only inert decisions. The fixture
is `testdata/dns-child-fixture/main.rs`, importing the reviewed
`src/host/dns_observer.rs`. It does not link or run the product.

From the repository root with the prepared Rust 1.90.0 toolchain selected:

```sh
run="$PWD/.scratch/acceptance/dns-fixture-review"
mkdir -p "$run"
mkdir "$run/t" # Fresh, not reused.
export TMPDIR="$run/t"
python3 -B -m unittest discover -v -s .github/scripts -p test_dns_child_fixture_supervisor.py
rustc --edition 2024 -C opt-level=3 -C debuginfo=1 \
  --crate-name sbxr_dns_fixture .github/scripts/testdata/dns-child-fixture/main.rs \
  -o "$run/sbxr-dns-fixture"
nm --defined-only "$run/sbxr-dns-fixture" > "$run/symbols.txt"
objdump -d --demangle "$run/sbxr-dns-fixture" > "$run/disassembly.txt"
sha256sum "$run/sbxr-dns-fixture" > "$run/binary.sha256"
rmdir "$TMPDIR"
```

These commands build/inspect; they do not execute the fixture. Resolve the exact
mangled hook in that new binary and inspect every call site. Do not copy an old
address, symbol suffix or digest into a new session.

## Fixture cases

The fixture emits `GATED PID` and reads one `G` byte before work. Only the
supervisor releases that byte after executable/lifetime checks and the reviewed
wrapper's exact post-attachment receipt. `STARTING` and elapsed sleeps cannot
release observed work. A baseline session omits the observer.

- `immediate`: one same-executable child exits; parent reaps it before Spawned,
  deliberately testing EXIT-before-SPAWN correlation. This differs from product
  ordering and is not evidence that a product path has executed.
- `pipe-wait`: child waits for EOF on a private pipe. After `CHILD PID`, supervisor
  holds for 50 ms then sends `C`; parent closes the pipe and waits. Actual measured
  wait duration, not the requested delay, is evidence.
- `unrelated`: an unselected same-executable child is started before Begin and
  held across the selected child's lifetime. It must be excluded by the observer.

The fixture has at most two children, consumes at most two control bytes, emits
fewer than 128 normal output bytes, clears child environments and uses null child
stdout/stderr. It has no DNS, socket, credential, arbitrary-command or signal code.
On error, Finish can be emitted without successful reaping; such sessions are invalid and
require supervisor cleanup. Finish never proves cleanup.

## Supervisor contract and review checklist

The supervisor validates six file identities: fixture, wrapper, checker, template,
tracer and Python interpreter. The wrapper/checker/template must remain adjacent.
There is no working runtime manifest until the tracer launch artifact is selected.

To close the reviewed hash-to-execution race, all six inputs must already reside
on reviewed immutable local backing storage. The supervisor checks read-only
**superblock** status for each directory and final file (a read-only bind mount
over writable backing is insufficient), restricts filesystem types, retains
opened directories/files, and uses `/proc/SUPERVISOR_PID/fd/DIRFD/name` paths.
Those paths require descendants to retain permission to read the supervisor's
proc descriptors throughout execution and teardown. There is no fallback to
mutable original paths. The fixture self-spawns through literal `/proc/self/exe`.

The platform, dynamic loader/standard libraries and underlying backing storage
must be trusted; privileged remounts, ptrace, raw-storage writes and mutable remote
or overlay backing are outside that assumption. Existing checker `__pycache__`
or `.pyc` paths refuse: `-B` prevents cache writes, not reads. The observer Python
interpreter is launched with `-I -S -B`. These are source-level safeguards, not
proof of an available qualified deployment environment. The supervisor creates
no mounts and changes no filesystem permissions to satisfy the prerequisite.
`--execute-approved` is a guard, not a substitute for user approval.

Review ownership, race handling, completeness of descendant inventory, status
ownership, byte limits and actual deadline placement. Runtime design uses a
process-local subreaper, pidfds, parent/starttime checks, nonblocking streams and
no process-group or numeric-PID signal fallback. Direct children are reaped through
Popen; adopted descendants are reaped separately. PID reuse and uncertain ownership
must refuse. No source test proves those Linux adapters safe in a live run.

Limits: fixture stdout/stderr 1 KiB each; wrapper stdout/stderr 8 KiB each;
256-byte lines. The unchanged observer has 64 KiB capture, 8 KiB stderr, 32 queries,
128 WAIT rows, 4096 syscall entries/child, 64 keys/map and eight perf pages/CPU.
The supervisor's intended outer policy starts cleanup at 105 seconds, escalates
TERM to KILL after two seconds and stops cleanup by 110 seconds. Early failures
get at most five seconds of cleanup. OS-blocking operations remain a separate
runtime uncertainty. Evidence is written after process cleanup; file-write stalls
must not become success claims.

Implemented fault modes, still unexecuted: withhold the gate; terminate the owned
wrapper after release; pre-fill and stop draining wrapper stdout to block readiness.
All fault runs must report refusal. Output overflow, stderr, malformed/missing
records or unproved cleanup invalidate observations.

Process reaping is reported separately from kernel cleanup. Before/after inventory
must independently prove observer-owned probes/maps/perf resources are released.
`DONE`, `END` map clearing and process exit alone are not that proof.

## Smallest future approval scope

After the no-mount tracer and approved immutable input storage are ready,
request one `immediate` session, maximum 110 seconds, with exact input hashes and
symbol. Explicit scope must include fixture and observer launch, BPF load/perf
operations, exact fixture uprobe, five system-wide tracepoints with reviewed
predicates, process-local subreaping/pidfd ownership, wrapper SIGKILL and supervisor
TERM/KILL against precisely owned processes, plus read-only resource inventories.
No mounts, namespace creation, privilege/capability/seccomp/sysctl/service changes,
product operation, DNS, VPS/SSH, upload, publication or broad signals are included.

Only after that result and teardown are reviewed should additional cases be
approved. The later ceiling is 16 serial sessions/30 minutes: three functional
cases, five baseline/observed pairs and three faults. There is no automatic suite
runner. Overhead comparisons are preliminary, not timing-neutrality or DNS-root-
cause claims.
