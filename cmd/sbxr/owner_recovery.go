package main

import (
	"context"

	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type ownerRecovery struct{ changeSet string }

func (recovery ownerRecovery) ViewRecovery(context.Context) ownerconsole.RecoveryPresentation {
	if recovery.changeSet != "" {
		return ownerconsole.RecoveryPresentation{Kind: ownerconsole.RecoveryRollbackAvailable, Proof: ownerconsole.ProvenUnfinishedRollback, CauseCode: "SYSTEM-CHANGES-UNFINISHED", Explanation: "A validated unfinished Change Set requires automatic recovery.", ChangeSet: recovery.changeSet, Material: "checksum-protected rollback material", Evidence: "DURABLE-TRANSACTION-PRESENT", Guidance: "Retry the exact automatic rollback before any new change."}
	}
	return ownerconsole.RecoveryPresentation{Kind: ownerconsole.RecoveryRebuildRequired, Proof: ownerconsole.ProvenRebuildRequired, CauseCode: "STATE-LINEAGE-UNPROVABLE", Explanation: "The installed State lineage could not be validated.", Evidence: "MANAGED-STATE-REFUSED", Guidance: "Use read-only diagnostics, complete removal, or rebuild from a fresh review."}
}

func (recovery ownerRecovery) RetryAutomaticRollback(ctx context.Context) ownerconsole.DurableChangeSet {
	operation := ownerconsole.OperationIdentity("automatic-recovery")
	if recovery.changeSet == "" {
		return ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, Checkpoint: "Recovery Required", Explanation: "Automatic recovery did not prove a safe terminal state."}
	}
	status, err := retryClientAccessRecovery(ctx, recovery.changeSet)
	if err != nil {
		return ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, Checkpoint: "Recovery Required", Explanation: "Automatic recovery did not prove a safe terminal state."}
	}
	checkpoint, explanation := "Managed", "Automatic recovery proved restored Managed State."
	if status == systemchanges.NotInstalled {
		checkpoint, explanation = "Not installed", "Automatic recovery proved restored Not installed State."
	}
	return ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRolledBack, OperationID: operation, Checkpoint: checkpoint, Explanation: explanation}
}

func (ownerRecovery) ReviewCurrentStateRepair(context.Context) ownerconsole.ChangeReview {
	return clientAccessCorrection("Current-State repair authority is unavailable")
}
