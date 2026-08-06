// Package systemchanges owns one read-only Inspect boundary and the only Apply
// path for installation-wide mutation. Apply consumes a reviewed Change Set,
// holds one kernel lock, reloads volatile facts, durably prepares one protected
// transaction, records ordered work, publishes State once after pre-publication
// proof, requires fresh active agreement, records Complete, and removes the
// transaction-only snapshot and journal. Failure and restart resolution are
// deliberately owned by later System Changes slices.
package systemchanges
