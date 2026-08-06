// Package systemchanges owns one read-only Inspect boundary and the only Apply
// path for installation-wide mutation. Apply consumes a reviewed Change Set,
// holds one kernel lock, reloads volatile facts, durably prepares one protected
// transaction, records ordered work, publishes State once after pre-publication
// proof, requires fresh active agreement, records Complete, and removes the
// transaction-only snapshot and journal. Before Complete, deterministic
// failure or explicit cancellation at a declared safe checkpoint restores the
// exact prior baseline through ordered automatic rollback; presentation loss
// is not cancellation. The private startup recovery path acquires the released
// lock before affected services, validates one durable unfinished transaction,
// inspects potentially applied steps, and rolls ordinary work back without
// resuming it forward. A later restart continues rollback only from durable
// reverse evidence; after durable Complete it removes transaction material
// without restoring the prior revision.
package systemchanges
