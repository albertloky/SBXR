# Exact DNS-child diagnostic — prepared, not Linux-validated

This is a narrow diagnostic prototype for the unresolved public-IP DNS timeout.
It is not a root-cause fix, release gate, qualification result, or live-run authority.
Do not deploy it before independent review and isolated Linux validation.

## What changed

`src/host/dns_observer.rs` provides a no-I/O C-ABI hook with three numeric arguments:
`(event, native_query_id, child_pid)`. Event 1 precedes `Command::spawn`; event 2
confirms the returned `Child::id()`; event 3 follows the existing child guard's
cleanup. Only traced `DestinationDns` and `PublicIpDns` queries use it. Without
native tracing, or for other commands, the hook is not called. No timeout,
cancellation, pipe-drain, executable verification or admission rule changes.
The ordinary native-query/driver schema is unchanged.

The observer arms the exact calling TID at event 1, selects its child at the
kernel fork tracepoint, and checks event 2's PID. It deletes child tracking at
kernel exit, before PID reuse, while keeping the parent-side correlation until
event 3. A short child may exit before event 2; that still has an exact fork and
confirmed PID. A missing hook, extra fork/descendant, reused query ID, spawn
failure, lost lifecycle/wait record or inconsistent identity gives unknown.
No process-name or elapsed-time matching is accepted.

The observer reads only numeric hook arguments, fork/scheduler task IDs, syscall
numbers and kernel monotonic times. It never reads syscall arguments, paths,
buffers, packet data, argv, environment, names, stacks or raw return values.
Syscalls lasting at least 1 ms are reported individually. A syscall still entered
at child exit is explicitly unfinished, not a successful resolver response; a
normal exit_group can also be unfinished. Interpret the syscall number and duration.
The exit record also counts calls and total syscall/off-CPU time. Off-CPU and
syscall durations overlap: do not add them. Initial fork-to-first-scheduling delay
is not counted in off-CPU time. Other unaccounted time remains unknown. These
facts can distinguish a long poll/read/futex wait from time outside syscalls;
they do not themselves prove a network, NSS, upstream DNS or libc cause.

## Bounds and limitations

The template has a 90-second observer interval, 32 queries, 4096 syscall entries
per child, 128 individual wait rows globally, 64 entries per BPF map and eight
perf-ring pages per CPU. A valid capture has at most 291 rows and 64 KiB. Bounds
or unexpected activity invalidate the capture; they never affect product results.
There are no observer children or attachments created by the product, and no
observer writes or joins on its enforcement thread. Attaching uprobes still
adds synchronous kernel work to that thread. The Spawned hook runs before the
existing child-loop deadline begins, adding wall time outside it. System-wide
tracepoints also add work even when filters discard unrelated events. There is
no timing-neutrality claim; measure Linux baseline/observed overhead. The intended
first integration is serial: shared counter increments are not general atomic
concurrency bounds. FINISH alone does not prove successful kill/wait.

The template interval is not an independent watchdog for compilation, attachment,
a stalled output sink or teardown. The new wrapper has a 100-second collection
budget, bounded in-memory stdout/stderr and owned-process cleanup, but none of
its subprocess, watchdog or cleanup paths have been executed in this task. Its
readiness notification and final evidence writes can block on external sinks;
an independent outer supervisor remains required and unvalidated. `DONE` does
not prove resource release. Inspect termination and kernel resources separately.

## Post-attachment barrier

`BEGIN` now emits `STARTING`, which conveys no readiness. The checker refuses
legacy READY-only captures, missing/duplicate ATTACHED, pre-barrier query records
and captures exceeding the wrapper's 100-second clock budget. All kernel stamps
explicitly use `nsecs(monotonic)`, matching the wrapper's CLOCK_MONOTONIC.

`dns-child-observer-run.py` launches only an independently hash-pinned bpftrace
v0.23.0 binary with a fresh fixed environment. It sets missing_probes=error,
map/ring limits and `__BPFTRACE_NOTIFY_PROBES_ATTACHED=1`. In the pinned upstream
[source](https://github.com/bpftrace/bpftrace/blob/01e806d24c61f996f1809e1e991646311499db4f/src/bpftrace.cpp#L977-L1032),
that internal notification follows both attachment loops; an earlier failure
returns without it. The wrapper requires this exact token plus the matching
STARTING record, latches stderr/duplicate/malformed/premature-event failures, and
inserts an ATTACHED receipt timestamp into the bounded capture. Only then can it
emit `SBXR_DNS_OBSERVER_ATTACHED <pid>` to its caller. No elapsed sleep or early
"Attaching probes" message can open the barrier. A binary without this exact
reviewed notification contract never becomes ready. The internal interface must
be re-reviewed for any other bpftrace build/version.

The helper never sends product input. A future integration must hold the existing
menu input until this notification, retain the existing deadline and verify the
same target instance. This is implemented source with inert state-machine tests,
not a claim of a tested Linux launch barrier. Do not execute the wrapper under
the current no-tracing/no-process-signal-fixture scope. Its binary digest must
come from independently verified build provenance, not a conveniently supplied
hash. The standalone checker cannot authenticate a fabricated ATTACHED row.

## Isolated Linux handoff (not an authorized live command)

1. Review the patch. Use a disposable, already authorized Linux environment;
   do not change ptrace/BPF/security settings to make it work. Record kernel,
   architecture and bpftrace version. This template targets bpftrace 0.23 syntax.
   A missing capability is a blocker, not permission to relax a setting.
2. Build the exact patched source with the controlled native toolchain. Resolve
   the single `dns_child_observer_hook` mangled symbol with `nm`; inspect its
   disassembly to verify all three C register arguments and calls survive release
   optimization. No symbol wildcard or guessed offset. Confirm the actual target
   PID's executable inode/digest, process lifetime, PID namespace and matching
   kernel/userspace monotonic clock domain (no time-namespace offset); retain those
   independently with observer source hashes. Do not add `-p`: bpftrace 0.23
   applies it to kernel tracepoints too, excluding the resolver child. Use the
   template's explicit parent/child predicates and recheck target identity before
   any selected action. The hook changes product bytes: it cannot observe the
   old build 201 and requires normal future authenticated packaging/admission.
3. Render a program (this command itself does not attach):

   ```sh
   python3 -B .github/scripts/dns-child-observer.py render \
     --executable "$exact_binary" --symbol "$exact_mangled_symbol" \
     --pid "$exact_pid" > "$run/observer.bt"
   ```

   Compile/check that program against real tracepoint formats first. Validate
   bounded capture, an independent watchdog and teardown before trying any
   product operation. Keep stderr separate: any lost-event/error notice makes
   coverage unknown. Do not feed arbitrary bpftrace output into product stderr.
4. First perform offline native build/static symbol inspection in an already
   authorized builder with cached dependencies. The portable repair handoff
   describes an uncommitted patch; do not bypass the clean-commit packaging guard
   or stamp old source identity onto patched bytes. No product execution, BPF
   loading, `--dry-run` (which attaches probes), download or security change.
   Later, separately authorize **isolated diagnostic integration only**: prove
   selection before child execution; a short child that exits before spawn
   confirmation; wrong/unrelated same-name child exclusion; PID/query reuse;
   missing records; syscall/event limits; observer sink failure and shutdown.
   Measure overhead against an unobserved baseline. Timeout/cancellation and
   signal-based fixtures require explicit scope authorization; none were created
   or executed in this local task. Validate cleanup of probes/maps/descriptors
   on success, refusal, observer crash and watchdog expiry. Do not use a live
   candidate as the first integration test.
5. For a separately authorized future product observation, start only after the
   reviewed wrapper emits `SBXR_DNS_OBSERVER_ATTACHED` after its barrier. Use a safe
   menu-input wait before sending the selected action; do not stop a child or
   extend the operation deadline to attach. Then perform at most
   one existing bounded DNS-bearing operation. Keep its five-second query and
   existing operation deadline. Retain native phase/query records from that same
   exact process instance. Match the native query ID explicitly; never use timing
   or query ordinal alone. Check the saved observer capture:

   ```sh
   python3 -B .github/scripts/dns-child-observer.py check \
     --capture "$run/observer.stdout" --pid "$exact_pid"
   ```

   Accounting requires the unreported remainder to fit strictly sub-1-ms calls,
   at most one unfinished wait, and exclusive parent-TID query scopes.
   The checker validates record consistency, not genuine kernel provenance,
   successful attachment, native-query matching, loss-free stderr or cleanup.
   Those are separate required observations. Missing evidence is unknown.

No VPS, SSH, credential, BWH/Karing setting, publication or push operation is
part of this handoff. The historical failure remains unexplained.

Reference: bpftrace's [0.23 language](https://bpftrace.org/docs/release_023/language)
and [standard library](https://bpftrace.org/docs/release_023/stdlib) document the
probe filters, C-register arguments and asynchronous output/exit behavior.

Local build/static observations and supervisor review are recorded in the
[Linux preparation report](../../docs/acceptance/reports/dns-child-diagnostic-linux-2026-10-27.md).
Use the [fixture review runbook](dns-child-fixture-review.md) for the current
source layout and remaining runtime prerequisites.
