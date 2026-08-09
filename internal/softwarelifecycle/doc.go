// Package softwarelifecycle owns verified SBXR release identity and the
// review-first install, update, downgrade, repair, and Complete-removal
// lifecycle. The current implemented slice verifies one candidate through
// View; later slices add staging, Plan, and Apply behind the same Module.
package softwarelifecycle
