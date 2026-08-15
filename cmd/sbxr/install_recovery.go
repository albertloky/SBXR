package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	networkubuntu "github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func pendingStartupRecovery() (bool, error) {
	_, pending, err := productionPendingChangeSetReader().PendingChangeSet()
	return pending, err
}

type recoveryHandler func(systemchanges.PendingChangeSet) error

func productionPendingChangeSetReader() systemchanges.PendingChangeSetReader {
	return systemubuntu.NewAt("/", nil, nil)
}

func recoveryRoutes(handler recoveryHandler) map[systemchanges.MutationClass]recoveryHandler {
	return map[systemchanges.MutationClass]recoveryHandler{
		systemchanges.InstallationMutation:       handler,
		systemchanges.RepairMutation:             handler,
		systemchanges.SettingChangeMutation:      handler,
		systemchanges.RotationMutation:           handler,
		systemchanges.CertificateChangeMutation:  handler,
		systemchanges.UpdateMutation:             handler,
		systemchanges.CertificateRenewalMutation: handler,
		systemchanges.CompleteRemovalMutation:    handler,
	}
}

func dispatchPendingChangeSet(pending systemchanges.PendingChangeSet, routes map[systemchanges.MutationClass]recoveryHandler) error {
	handler := routes[pending.Kind]
	if handler == nil {
		return errors.New("pending Change Set kind is unsupported")
	}
	return handler(pending)
}

func runStartupRecovery() (resultErr error) {
	pending, found, err := productionPendingChangeSetReader().PendingChangeSet()
	if err != nil {
		return err
	}
	if !found {
		if orphanedCompleteRemoval() {
			return runOrphanedCompleteRemovalRecovery()
		}
		if err := removeInstallRecoveryReceipt(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if pending.Kind == systemchanges.InstallationMutation {
		installationModule, err := newInstallationModule()
		if err != nil {
			return err
		}
		return installationModule.Recover(context.Background(), pending)
	}
	return dispatchPendingChangeSet(pending, recoveryRoutes(runProvenRecovery))
}

func orphanedCompleteRemoval() bool {
	observed, err := installRecoveryObservation()
	return err == nil && validOrphanedCompleteRemoval(observed.Status, installedClientAccessMarker())
}

func validOrphanedCompleteRemoval(status systemchanges.InstallationStatus, installed bool) bool {
	return status == systemchanges.NotInstalled && installed
}

func runProvenRecovery(transaction systemchanges.PendingChangeSet) (resultErr error) {
	defer func() {
		if resultErr == nil {
			resultErr = removeInstallRecoveryReceipt()
			if errors.Is(resultErr, os.ErrNotExist) {
				resultErr = nil
			}
		}
	}()
	if transaction.Identity == systemubuntu.FinalizingRemovalChangeSet {
		return runOrphanedCompleteRemovalRecovery()
	}
	starting, release, forwardOnly := transaction.StartingStatus, transaction.StartingRelease, transaction.ForwardOnly
	if release == (systemchanges.ReleaseBinding{}) {
		release = transaction.CandidateRelease
	}
	stateModule := statefilesystem.New()
	api := cloudflaretunnel.NewProductionAPI()
	if transaction.Kind == systemchanges.CompleteRemovalMutation {
		var base systemubuntu.InstallHost
		var err error
		if forwardOnly {
			base, err = systemubuntu.NewFreshInstallHost("/", softwarelifecycle.ManagedUnitNames())
		} else {
			base, err = systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
		}
		if err != nil {
			return err
		}
		host := newCompleteRemovalHost(base, state.DesiredState{}, api, cloudflaretunnel.ManagementToken{})
		result := systemchanges.New(systemubuntu.NewAt("/", installRecoveryObservation, host, stateModule)).Recover()
		if result.Outcome != systemchanges.Completed && result.Outcome != systemchanges.RollbackSucceeded && result.Outcome != systemchanges.AwaitingTokenRevocation {
			return errors.New("Complete removal restart recovery requires inspection")
		}
		return nil
	}
	cloudflareExecutor, err := cloudflaretunnel.NewRecoveryExecutor(api)
	if forwardOnly {
		observed, currentRelease, loadErr := managedLoadEvidence()
		if loadErr != nil {
			return loadErr
		}
		loaded, loadErr := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: currentRelease, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: currentRelease}})
		if loadErr != nil {
			return loadErr
		}
		err = stateModule.WithManagedCloudflareSecrets(loaded, func(snapshot state.Snapshot, secrets state.InfrastructureSecretReader) error {
			token, tokenErr := cloudflaretunnel.NewManagementToken(secrets.ReadInfrastructureSecret(snapshot.DesiredState.Cloudflare.ManagementToken))
			if tokenErr != nil {
				return tokenErr
			}
			cloudflareExecutor, tokenErr = cloudflaretunnel.NewRunTokenRotationExecutor(api, token)
			return tokenErr
		})
	}
	if err != nil {
		return err
	}
	certificateExecutor, err := certificateubuntu.NewFreshTransactionExecutor(filepath.Join("/opt/sbxr/releases", release.Tag, "certbot/bin/certbot"))
	if err != nil {
		return err
	}
	port := uint16(10443)
	if observed, release, loadErr := managedLoadEvidence(); loadErr == nil {
		loaded, stateErr := statefilesystem.New().Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
		if stateErr == nil && loaded.Snapshot != nil {
			port = loaded.Snapshot.DesiredState.Subscription.ListenPort
		}
	}
	servingProof := func(ctx context.Context, address string) error {
		return proveInstalledSubscription(ctx, address, port)
	}
	managed := starting == systemchanges.Managed
	var subscriptionExecutor subscriptionfilesystem.Executor
	if managed {
		subscriptionExecutor, err = subscriptionfilesystem.New(servingProof)
	} else {
		subscriptionExecutor, err = subscriptionfilesystem.NewForFreshInstallation(servingProof)
	}
	if err != nil {
		return err
	}
	var host systemubuntu.InstallHost
	if managed {
		host, err = systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	} else {
		host, err = systemubuntu.NewFreshInstallHost("/", softwarelifecycle.ManagedUnitNames())
	}
	if err != nil {
		return err
	}
	var software systemubuntu.SoftwareLifecycleExecutor = softwareubuntu.NewRecoveryInstaller()
	if transaction.Kind == systemchanges.UpdateMutation {
		software, err = recoverySoftwareUpdater(transaction)
		if err != nil {
			return err
		}
	}
	adapter := systemubuntu.NewAtForInstallRecovery("/", installRecoveryObservation, host, systemubuntu.NewNativeFirewall(), cloudflareExecutor, certificateExecutor, profilesubuntu.NewRuntimeExecutor(), subscriptionExecutor, software, stateModule)
	authority := systemchanges.SSHPreservationAuthority{}
	recoveryIdentity := systemchanges.RecoverySSHIdentityAuthority{}
	var sshFailure *networkpolicy.SSHPreservationFailure
	if transaction.SSHPreservationTracked {
		identity := os.Getenv("SBXR_SSH_CONNECTION")
		captured, captureFailure := networkpolicy.New(nil).CaptureSSHRecoveryIdentity(identity)
		if captureFailure == nil {
			recoveryIdentity = systemchanges.NewRecoverySSHIdentityAuthority(captured)
		}
		proof, failure := networkpolicy.New(networkubuntu.New()).ProveSSHPreservation(identity)
		sshFailure = failure
		if captureFailure != nil {
			sshFailure = captureFailure
		}
		if failure == nil {
			authority = systemchanges.NewSSHPreservationAuthority(proof)
		}
	}
	result := systemchanges.New(adapter).RecoverWithSSHRecovery(recoveryIdentity, authority)
	if transaction.ForwardFirewallPending && sshFailure != nil {
		return &sshPreservationFailureError{Cause: sshFailure.Cause}
	}
	if result.Outcome != systemchanges.Completed && result.Outcome != systemchanges.RollbackSucceeded {
		return errors.New("install restart recovery requires inspection")
	}
	return nil
}

func runOrphanedCompleteRemovalRecovery() error {
	base, err := systemubuntu.NewFreshInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return err
	}
	host := newCompleteRemovalHost(base, state.DesiredState{}, cloudflaretunnel.NewProductionAPI(), cloudflaretunnel.ManagementToken{})
	result := systemchanges.New(systemubuntu.NewAt("/", installRecoveryObservation, host, statefilesystem.New())).Recover()
	if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled {
		return errors.New("orphaned Complete removal recovery requires inspection")
	}
	return nil
}

type recoveryReleaseSource struct {
	evidence softwarelifecycle.ReleaseEvidence
}

func (source recoveryReleaseSource) Verify(_ context.Context, tag string) (softwarelifecycle.ReleaseEvidence, error) {
	if tag != source.evidence.Tag {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("recovery candidate tag changed")
	}
	return source.evidence, nil
}

func recoverySoftwareUpdater(transaction systemchanges.PendingChangeSet) (softwareubuntu.Updater, error) {
	if transaction.StartingRelease == (systemchanges.ReleaseBinding{}) || transaction.CandidateRelease == (systemchanges.ReleaseBinding{}) {
		return softwareubuntu.Updater{}, errors.New("update recovery release binding is incomplete")
	}
	installed := softwarelifecycle.ReleaseIdentity{Repository: transaction.StartingRelease.Repository, Tag: transaction.StartingRelease.Tag, Commit: transaction.StartingRelease.Commit, IndexSHA256: transaction.StartingRelease.ReleaseIndexSHA256}
	candidate := softwarelifecycle.ReleaseIdentity{Repository: transaction.CandidateRelease.Repository, Tag: transaction.CandidateRelease.Tag, Commit: transaction.CandidateRelease.Commit, IndexSHA256: transaction.CandidateRelease.ReleaseIndexSHA256}
	return softwareubuntu.NewSnapshotRecoveryUpdater(installed, candidate)
}

func installRecoveryObservation() (systemchanges.Observation, error) {
	result := systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	info, statErr := os.Lstat(statefilesystem.StatePath)
	if errors.Is(statErr, os.ErrNotExist) {
		return result, nil
	}
	if statErr != nil {
		return systemchanges.Observation{}, errors.New("managed State lineage is unprovable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Nlink != 1 {
		return systemchanges.Observation{}, errors.New("managed State lineage is unprovable")
	}
	body, err := os.ReadFile(statefilesystem.StatePath)
	var document struct {
		Revision               uint64          `json:"revision"`
		LastCompletedChangeSet string          `json:"last_completed_change_set"`
		Payload                json.RawMessage `json:"payload"`
		Checksum               string          `json:"checksum"`
	}
	if err != nil || json.Unmarshal(body, &document) != nil || document.Revision == 0 || document.LastCompletedChangeSet == "" {
		return systemchanges.Observation{}, errors.New("managed State lineage is unprovable")
	}
	digest := sha256.Sum256(document.Payload)
	if hex.EncodeToString(digest[:]) != document.Checksum {
		return systemchanges.Observation{}, errors.New("managed State lineage is unprovable")
	}
	result.Status, result.StateRevision = systemchanges.Managed, document.Revision
	result.StateSHA256, result.LastChangeSet = document.Checksum, document.LastCompletedChangeSet
	return result, nil
}

func managedLoadEvidence() (systemchanges.Observation, state.ReleaseIdentity, error) {
	observed, err := installRecoveryObservation()
	if err != nil || observed.Status != systemchanges.Managed {
		return systemchanges.Observation{}, state.ReleaseIdentity{}, errors.New("Managed State lineage is unavailable")
	}
	body, err := os.ReadFile(statefilesystem.StatePath)
	var envelope struct {
		ReleaseIdentity state.ReleaseIdentity `json:"release_identity"`
	}
	if err != nil || json.Unmarshal(body, &envelope) != nil || envelope.ReleaseIdentity.Repository == "" || envelope.ReleaseIdentity.Tag == "" || envelope.ReleaseIdentity.Commit == "" || envelope.ReleaseIdentity.ReleaseIndexSHA256 == "" {
		return systemchanges.Observation{}, state.ReleaseIdentity{}, errors.New("Managed Release Identity is unavailable")
	}
	return observed, envelope.ReleaseIdentity, nil
}
