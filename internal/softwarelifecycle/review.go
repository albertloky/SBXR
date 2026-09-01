package softwarelifecycle

import (
	"context"
	"os"
)

type reviewKey struct{}

// ConfirmReview binds menu approval to the exact facts displayed by Check or
// Status. Update and Recover still perform their full admission under the lock.
func ConfirmReview(ctx context.Context, result Result) context.Context {
	if result.Installed != nil {
		identity := *result.Installed
		result.Installed = &identity
	}
	if result.Latest != nil {
		identity := *result.Latest
		result.Latest = &identity
	}
	return context.WithValue(ctx, reviewKey{}, result)
}

func reviewedUpdateMatches(ctx context.Context, prior ReleaseIdentity, candidate LatestRelease) bool {
	reviewed, bound := ctx.Value(reviewKey{}).(Result)
	return !bound || reviewed.Code == CheckUpdateAvailable && reviewed.Installed != nil && *reviewed.Installed == prior && reviewed.Latest != nil && *reviewed.Latest == candidate.Identity
}

func (inspector filesystemInspector) recoveryReview(result Result) Result {
	root, err := os.OpenRoot(inspector.root)
	if err != nil {
		return result
	}
	defer root.Close()
	record, err := readUpdateRecord(root)
	if err != nil {
		return result
	}
	proved := false
	if record.Checkpoint == committedCheckpoint {
		proved = proveCommittedRecovery(root, record) == nil
		result.RecoveryDirection = "Keep the committed release and finish forward"
	} else {
		_, err = provePreparedRecovery(root, record)
		proved = err == nil
		result.RecoveryDirection = "Restore the exact prior release"
	}
	held, valid := inspector.inspectLock()
	if !proved || held || !valid {
		result.RecoveryDirection = ""
		return result
	}
	result.recoveryBinding = digestBytes(updateRecordBytes(record))
	return result
}
