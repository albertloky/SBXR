# ADR-0027: Attended Karing response timing

Accepted for future explicitly declared ordinary HTTP MVP attempts, 2026-10-02.

The Owner requested a full one-hour Karing response window beginning after a
link is prepared and readiness is communicated. r02 timed out because the
operator attempted to record the Owner's timely response after the existing
scenario deadline. The Owner's reply was not the late step. This decision does
not change that failure or authorize another attempt.

Use a signed opt-in `karing_response_limit_seconds: 3600` and actual
`attended_finish_by`. Preserve existing policy identifiers, immutable historical
manifests and requests without the opt-in. Keep technical preparation/check
budgets unchanged and exclude only sequential, explicitly recorded attended
wait intervals. Every wait records its allowed phase, preparation timestamp,
actual notification timestamp and actual response timestamp; no link or
credential belongs in that record. An expired request cannot open a new wait.

The recorder, collector, assembler and qualification validator must agree on the
same limits. Each wait is single-use, gives one hour after notification, requires
an actual response before sealing, and must fit the declared attendance and
existing six-hour session ceiling. Existing required checks, trust, cleanup,
five-minute submission limits and stop/burn rules remain. A new candidate is not
a rehearsal for this change.

Use [the HTTP procedure](../acceptance/http-subscription-live.md#attended-karing-response-windows)
for command ownership and the main-assistant/operator notification handshake.
