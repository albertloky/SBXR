# Bounded startup diagnostics

This is an offline-prepared diagnostic route, not qualification evidence or
permission to access a server. Build208's 15-second exit and 8.175s CPU observation
do not identify its failing stage. Its old null-output unit retained no internal
failure reason; installing new code cannot reconstruct that event.

New Rust fresh installations use the exact subscription unit with
`StandardError=journal` plus an anchored fixed-vocabulary `LogFilterPatterns`;
stdout remains null. Existing installed units are not
migrated or adopted. All other sandbox, ownership, authentication, lock, timeout,
listener and cancellation checks remain. No diagnostic value authorizes an action.
No startup deadline is increased.

The private runtime emits a fixed `SBXR_START_V1` record on admission/startup
failure or successful listener readiness. It includes only role, stage, typed
result, first rejected retry stage, elapsed milliseconds and current-stage
milliseconds. Durations saturate at1200000ms. There are no tokens, link IDs,
configuration fragments, addresses, paths, PIDs, environment values or arbitrary
error strings. The first rejection is a prior attempt's observation, not proof of
the terminal cause. The final stage is where failure was observed, not necessarily
where its underlying cause originated. A ready record does not prove outside
traffic, Karing success or continued service health.

Emission is one nonblocking `send(MSG_DONTWAIT|MSG_NOSIGNAL)` to the existing
stderr socket; no retries, log files, fd-mode changes or fallback output. A full,
closed or non-socket stderr loses the record without changing the runtime result.
The lender also attempts a fixed failure record, but ordinary Owner stderr is
usually a terminal or pipe, so that record is not guaranteed to be captured.
The current capture route collects only the subscription service; it does not
claim to retain the lender's full peer-validation outcome. No new protocol or
cross-process diagnostic channel is introduced.

## Capture during a separately approved attempt

Use the existing pinned SSH read route and its bounded query wrapper to run only:

```
journalctl --unit=sbxr-subscription.service --since=<approved-start-UTC> --until=<approved-end-UTC> --no-pager --output=json --output-fields=MESSAGE,_SYSTEMD_UNIT
```

Pipe stdout directly into `python3 .github/scripts/capture-startup-diagnostics.py
<private-evidence-directory>/startup.json` locally. Do not first save raw journal
output. The existing evidence directory must be owned by the current local user
and mode0700. Output is exclusive mode0600 at creation even under umask000; an
existing file or symlink refuses. No SSH, service command or other host action is
invoked by the filter. Bound the upstream command to five seconds and the exact
attempt interval; the filter accepts at most1MiB and32 diagnostic records. Input
EOF/transport success must also be verified by the operator; a filtered file is
not proof that the upstream command succeeded or that every record was delivered.
It drops unrelated messages and fields, rejects malformed diagnostic prefixes,
foreign units and out-of-range durations, and writes only canonical categories.
No diagnostic records is a refusal, not proof of successful startup.

## Security and validation limits

The source-controlled diagnostic formatter accepts only enums, booleans, result
categories and bounded durations. Local tests exercise genuine lock/socket retry
failures, cancellation, strict projection and private creation. Linux CI additionally
exercises delivery to a real Unix stream, a full socket, a closed socket and a
non-socket descriptor. These do not prove journald delivery under the native
systemd sandbox or native startup timing.

The exact unit includes an anchored positive journal filter admitting only the
fixed serving record grammar, so arbitrary application/panic lines are discarded.
The POSIX ERE is exercised locally against every stage/result and secret-bearing
negative examples. [Systemd255 documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#LogFilterPatterns=)
specifies positive filters and excludes normal system-manager messages about the
unit from this filtering. Filtering requires systemd253 or later (the supported
Ubuntu24.04 environment uses255); actual loaded filtering and journal delivery
remain future native validation, not a claim from a Mac fixture. No journal
permissions or retention settings are changed. Journal stderr also introduces
systemd's normal ordering after its journal socket. These logging effects must
be included in any future live approval.

A future specific approval must cover one new exact candidate and normal live
journeys, this journal stderr routing and bounded diagnostic read/capture, owned
cleanup, and fresh attendance/deadlines. It must not reuse failed208 or infer
permission for a new trial from these offline changes. Failed208 disposition,
new signing and publication remain separate from this implementation.
