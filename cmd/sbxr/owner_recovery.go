package main

import (
	"context"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type ownerRecovery struct {
	changeSet             string
	forwardOnly           bool
	needsRunTokenRotation bool
	completeRemoval       bool
	currentStateRepair    bool
}

func (recovery ownerRecovery) ViewRecovery(context.Context) ownerconsole.RecoveryPresentation {
	if recovery.currentStateRepair {
		return ownerconsole.RecoveryPresentation{Kind: ownerconsole.RecoveryCurrentStateRepairAvailable, Proof: ownerconsole.ProvenCurrentState, CauseCode: "CURRENT-STATE-DRIFT", Explanation: "The current proven Desired State disagrees with one SBXR-owned Managed resource.", Evidence: "CURRENT-STATE-REPAIR-AVAILABLE", Guidance: "Review one forward repair of the current proven Desired State; do not adopt Observed State."}
	}
	if recovery.changeSet != "" {
		if recovery.forwardOnly {
			if recovery.completeRemoval {
				return ownerconsole.RecoveryPresentation{Kind: ownerconsole.RecoveryForwardOnly, Proof: ownerconsole.ProvenForwardOnlyRecovery, CauseCode: "SYSTEM-CHANGES-COMPLETE-REMOVAL-FORWARD", Explanation: "Irreversible Complete removal has started.", ChangeSet: recovery.changeSet, Material: "checksum-protected forward removal material", Evidence: "IRREVERSIBLE-REMOVAL-STARTED", Guidance: "Revoke the scoped Cloudflare token when requested, then continue the exact forward-only removal. Back, Cancel, and rollback are unavailable."}
			}
			guidance := "Continue the exact forward-only recovery; do not rotate the token again."
			if recovery.needsRunTokenRotation {
				guidance = "Follow the exact committed-Tunnel rotation Help, then continue the exact forward-only recovery."
			}
			presentation := ownerconsole.RecoveryPresentation{Kind: ownerconsole.RecoveryForwardOnly, Proof: ownerconsole.ProvenForwardOnlyRecovery, CauseCode: "SYSTEM-CHANGES-RUN-TOKEN-FORWARD", Explanation: "The old Tunnel run token was removed at the irreversible checkpoint.", ChangeSet: recovery.changeSet, Material: "checksum-protected forward recovery material", Evidence: "IRREVERSIBLE-RUN-TOKEN-ROTATION-STARTED", Guidance: guidance}
			if recovery.needsRunTokenRotation {
				presentation.ExternalGuidance = ownerCloudflareExternalGuidance(cloudflaretunnel.TunnelRunTokenRotation)
			}
			return presentation
		}
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
	return ownerRecoveryResult(recovery, status, err)
}

func ownerRecoveryResult(recovery ownerRecovery, status systemchanges.InstallationStatus, err error) ownerconsole.DurableChangeSet {
	operation := ownerconsole.OperationIdentity("automatic-recovery")
	if err != nil {
		return ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, Checkpoint: "Recovery Required", Explanation: "Automatic recovery did not prove a safe terminal state."}
	}
	if status == "" {
		return ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, Checkpoint: "Awaiting Owner token revocation", Explanation: "Provider deletion is complete. Revoke the scoped Cloudflare token, then continue the same forward-only removal."}
	}
	checkpoint, explanation := "Managed", "Automatic recovery proved restored Managed State."
	if status == systemchanges.NotInstalled {
		checkpoint, explanation = "Not installed", "Automatic recovery proved restored Not installed State."
	}
	kind := ownerconsole.ChangeSetRolledBack
	if recovery.forwardOnly {
		kind, checkpoint, explanation = ownerconsole.ChangeSetSucceeded, "Complete", "Forward-only Tunnel run-token recovery proved Managed State and both routes."
		if recovery.completeRemoval {
			checkpoint, explanation = "Not installed", "Forward-only Complete removal proved Not installed with no retained recovery material."
		}
	}
	return ownerconsole.DurableChangeSet{Kind: kind, OperationID: operation, Checkpoint: checkpoint, Explanation: explanation}
}
