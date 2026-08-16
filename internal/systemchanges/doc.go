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
// without restoring the prior revision. When lineage or transaction safety is
// unprovable, Recovery Required blocks ordinary mutation and offers only
// secret-safe inspection, diagnostics, recheck, Back, separately confirmed
// Complete removal, an eligible rollback retry, or a fresh forward repair of
// valid current State drift.
// Network Policy steps additionally carry one exact inet sbxr candidate and
// detected SSH port. The Ubuntu Adapter validates it natively, arms rollback
// before atomic Apply, proves the current SSH session and admitted port before
// cancelling the watchdog, and records and removes only the approved temporary
// HTTP-01 rule. Certificate Lifecycle owns its one serial randomized scheduler;
// each due lineage still enters through the same one-use Apply and global lock.
// Complete removal additionally requires both exact Owner confirmations. Its
// reversible prefix removes only typed owned public exposure and immutable-ID
// Cloudflare resources while the token remains available, then durably stops at
// owned external deletion proof. It then durably crosses its irreversible
// checkpoint before asking for scoped-token revocation. Recovery verifies that
// revocation before deleting the local token copy, refuses rollback and restore,
// and continues only through the fixed deletion order until exact Not installed
// and final recovery-material absence are proven. Before that checkpoint,
// failure and restart still reverse to an exactly proven earlier baseline.
// Cloudflare Profile Setup uses the same transaction path with one final
// confirmation after durable preparation. Before durable Irreversible
// Cloudflare setup started it restores the exact Managed revision; afterward
// it proves Rollback Snapshot deletion and resumes only forward to the
// candidate revision or Recovery Required.
package systemchanges
