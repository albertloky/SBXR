package installation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"sync"

	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

// PreparePrivilegedApply is process-startup wiring for the private Ubuntu handoff.
// It is not an Owner workflow action.
func PreparePrivilegedApply(module *Interface, ctx context.Context, request softwareubuntu.InstallHandoffRequest) (func() softwareubuntu.InstallApplyOutcome, error) {
	if module == nil {
		return nil, errors.New("Installation Module unavailable")
	}
	if pending, found, err := module.dependencies.Pending.PendingChangeSet(); err != nil {
		return nil, err
	} else if found {
		if pending.Kind != systemchanges.InstallationMutation {
			return nil, errors.New("another Module owns the pending Change Set recovery")
		}
		if err := module.Recover(ctx, pending); err != nil {
			return nil, err
		}
		return nil, errors.New("prior installation recovered; build a fresh Plan")
	}
	preflight := module.dependencies.Preflight()
	if preflight.Failure != nil || preflight.ActiveSSHPort != request.Draft.SSHPort {
		return nil, errors.New("fresh SSH Preservation Proof refused")
	}
	built, err := module.build(ctx, request, preflight.SSHPreservationProof())
	if err != nil || built.network == nil {
		return nil, errors.New("complete install composition refused")
	}
	stateModule := statefilesystem.New()
	prepared, err := built.prepareState(stateModule)
	if err != nil {
		return nil, err
	}
	staged, _, _, valid := built.candidate.SoftwareLifecyclePreparedArchive()
	if !valid {
		return nil, errors.New("prepared release unavailable")
	}
	certificateExecutor, err := certificateubuntu.NewFreshTransactionExecutor(filepath.Join(filepath.Dir(staged.InstallPath), "certbot/bin/certbot"))
	if err != nil {
		return nil, err
	}
	subscriptionExecutor, err := subscriptionfilesystem.NewForFreshInstallation(func(proofContext context.Context, address string) error {
		return module.dependencies.ProveSubscription(proofContext, address, built.desired.Subscription.ListenPort)
	})
	if err != nil {
		return nil, err
	}
	softwareExecutor, err := softwareubuntu.NewInstaller(built.candidate)
	if err != nil {
		return nil, err
	}
	installHost, err := systemubuntu.NewFreshInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return nil, err
	}

	var observationMu sync.RWMutex
	volatileSHA256 := built.plan.VolatileSHA256()
	observation := func() (systemchanges.Observation, error) {
		observationMu.RLock()
		volatile := volatileSHA256
		observationMu.RUnlock()
		return observeInstallApply(module.installApplyStateObservation, module.dependencies.Pending, string(requestChangeSet(request)), built.totalSteps, volatile)
	}

	approval := softwareubuntu.NewApproval(func(recheckContext context.Context) (softwarelifecycle.InstallRecheck, error) {
		recheck, freshVolatileSHA256, err := recheckInstall(recheckContext, request, built)
		if err != nil {
			return softwarelifecycle.InstallRecheck{}, err
		}
		observationMu.Lock()
		volatileSHA256 = freshVolatileSHA256
		observationMu.Unlock()
		return recheck, nil
	})

	adapter := systemubuntu.NewAtForInstall("/", observation, installHost, systemchanges.NewFreshInstallationAuthority(built.wiring.network.FreshInstallationProof()), systemubuntu.NewNativeFirewall(), nil, certificateExecutor, profilesubuntu.NewRuntimeExecutor(), subscriptionExecutor, softwareExecutor, stateModule)
	changes := systemchanges.New(adapter)
	cancellation := systemchanges.NewCancellation()
	go func() {
		<-ctx.Done()
		cancellation.Request()
	}()
	return func() softwareubuntu.InstallApplyOutcome {
		if err := module.dependencies.WriteReceipt(string(requestChangeSet(request)), staged.Identity, staged.Build.PayloadSHA256); err != nil {
			return softwareubuntu.InstallRecoveryRequired
		}
		result := built.plan.Apply(ctx, softwarelifecycle.InstallApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: changes, Cancellation: cancellation})
		switch result.Outcome {
		case systemchanges.Completed:
			if module.dependencies.RemoveReceipt() != nil {
				return softwareubuntu.InstallRecoveryRequired
			}
			return softwareubuntu.InstallCompleted
		case systemchanges.RollbackSucceeded:
			if module.dependencies.RemoveReceipt() != nil {
				return softwareubuntu.InstallRecoveryRequired
			}
			return softwareubuntu.InstallRolledBack
		default:
			return softwareubuntu.InstallRecoveryRequired
		}
	}, nil
}

func recheckInstall(ctx context.Context, request softwareubuntu.InstallHandoffRequest, built *builtInstall) (softwarelifecycle.InstallRecheck, string, error) {
	fresh := built.network(networkpolicy.Request{Intent: built.networkIntent, Stage: networkpolicy.PostApproval, ReclamationReview: request.ReviewedReclamationSHA256 != "", ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	if fresh.Outcome == networkpolicy.Failed || fresh.Outcome == networkpolicy.Unknown {
		return softwarelifecycle.InstallRecheck{}, "", errors.New("privileged Network Policy recheck failed")
	}
	contributions := append([]softwarelifecycle.InstallContribution(nil), built.contributions...)
	for index, contribution := range contributions {
		if contribution.SoftwareLifecycleInstallContribution().Name == string(softwarelifecycle.NetworkInstallContribution) {
			contributions[index] = softwarelifecycle.NewNetworkInstallContribution(fresh, string(requestChangeSet(request)), built.desiredSHA256)
		}
	}
	freshDigest := sha256.New()
	for _, contribution := range contributions {
		_, _ = io.WriteString(freshDigest, contribution.SoftwareLifecycleInstallContribution().SHA256)
	}
	recheck := softwarelifecycle.InstallRecheck{Candidate: built.candidate, Contributions: contributions, PrivilegedNetworkHealthy: true}
	if request.ReviewedReclamationSHA256 != "" {
		recheck.Reclamation = fresh.ReclamationAuthority()
	}
	return recheck, hex.EncodeToString(freshDigest.Sum(nil)), nil
}

func (module *Interface) installApplyStateObservation() (systemchanges.Observation, error) {
	observed, err := module.dependencies.ObserveState()
	if err != nil || observed.Status != systemchanges.Managed {
		return observed, err
	}
	lineage, release, err := module.dependencies.LoadManaged()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	stateModule := statefilesystem.New()
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: lineage.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(lineage.LastChangeSet), ReleaseIdentity: release}})
	if err != nil {
		return systemchanges.Observation{}, err
	}
	revision, sha256, lastChangeSet, loadedRelease, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid || loadedRelease != release {
		return systemchanges.Observation{}, errors.New("install State lineage is unprovable")
	}
	lineage.StateRevision, lineage.StateSHA256, lineage.LastChangeSet = revision, sha256, string(lastChangeSet)
	return lineage, nil
}

func observeInstallApply(stateSource systemubuntu.ObservationSource, reader systemchanges.PendingChangeSetReader, changeSet string, totalSteps int, volatileSHA256 string) (systemchanges.Observation, error) {
	observed, err := stateSource()
	if err != nil || observed.Status != systemchanges.NotInstalled && observed.Status != systemchanges.Managed {
		return systemchanges.Observation{}, errors.New("install State lineage is unprovable")
	}
	observed.VolatileSHA256 = volatileSHA256
	pending, found, err := reader.PendingChangeSet()
	if err == nil && !found {
		return observed, nil
	}
	if err != nil || pending.Identity != changeSet {
		return systemchanges.Observation{}, errors.New("install transaction lineage is unprovable")
	}
	observed.Status, observed.CurrentChangeSet = systemchanges.ChangeInProgress, changeSet
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, totalSteps, !pending.ForwardOnly
	return observed, nil
}

func requestChangeSet(request softwareubuntu.InstallHandoffRequest) state.ChangeSetIdentity {
	return state.ChangeSetIdentity("install-" + request.Session[:16])
}
