// Package systemchanges owns one read-only Inspect boundary and the only Apply
// admission path for installation-wide mutation. SC-01 consumes a reviewed
// Change Set on its first Apply attempt, holds one kernel file lock, reloads
// State lineage and volatile facts under that lock, and refuses unsafe work
// before any live step. Later System Changes slices deepen the admitted path;
// callers receive no capability to mutate outside Apply.
package systemchanges
