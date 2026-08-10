package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"

	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

const (
	installTransactions = "/var/lib/sbxr/transactions"
	recoveryCertbotPath = "/opt/sbxr/releases/recovery/certbot/bin/certbot"
)

func pendingInstallRecovery() (bool, error) {
	info, statErr := os.Lstat(installTransactions)
	if errors.Is(statErr, os.ErrNotExist) {
		return false, nil
	}
	if statErr != nil {
		return false, errors.New("install recovery transaction is unprovable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || stat.Uid != 0 {
		return false, errors.New("install recovery transaction is unprovable")
	}
	entries, err := os.ReadDir(installTransactions)
	if err != nil || len(entries) > 1 || len(entries) == 1 && !entries[0].IsDir() {
		return false, errors.New("install recovery transaction is unprovable")
	}
	return len(entries) == 1, nil
}

func runInstallRecovery(certbot string) error {
	pending, err := pendingInstallRecovery()
	if err != nil || !pending {
		return err
	}
	cloudflareExecutor, err := cloudflaretunnel.NewRecoveryExecutor(cloudflaretunnel.NewProductionAPI())
	if err != nil {
		return err
	}
	certificateExecutor, err := certificateubuntu.NewFreshTransactionExecutor(certbot)
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
	starting, startingErr := systemubuntu.RecoveryStartingStatus("/")
	if startingErr != nil {
		return startingErr
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
	stateModule := statefilesystem.New()
	var host systemubuntu.InstallHost
	if managed {
		host, err = systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	} else {
		host, err = systemubuntu.NewFreshInstallHost("/", softwarelifecycle.ManagedUnitNames())
	}
	if err != nil {
		return err
	}
	adapter := systemubuntu.NewAtForInstallRecovery("/", installRecoveryObservation, host, systemubuntu.NewNativeFirewall(), cloudflareExecutor, certificateExecutor, profilesubuntu.NewDirectTLSExecutor(), subscriptionExecutor, softwareubuntu.NewRecoveryInstaller(), stateModule)
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed && result.Outcome != systemchanges.RollbackSucceeded {
		return errors.New("install restart recovery requires inspection")
	}
	return nil
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
