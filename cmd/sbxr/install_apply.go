package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

func prepareInstallApply(ctx context.Context, request softwareubuntu.InstallHandoffRequest) (func() softwareubuntu.InstallApplyOutcome, error) {
	if pending, err := pendingInstallRecovery(); err != nil {
		return nil, err
	} else if pending {
		if err := runInstallRecovery(); err != nil {
			return nil, err
		}
		return nil, errors.New("prior installation recovered; build a fresh Plan")
	}
	built, err := buildInstall(ctx, request)
	if err != nil || built.cloudflareAPI == nil || built.network == nil {
		return nil, errors.New("complete install composition refused")
	}
	stateModule := statefilesystem.New()
	prepared, err := built.prepareState(stateModule)
	if err != nil {
		return nil, err
	}
	cloudflareExecutor, err := built.cloudflare.Executor(built.cloudflareAPI)
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
		return proveInstalledSubscription(proofContext, address, built.desired.Subscription.ListenPort)
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
		return observeInstallApply(installApplyStateObservation, os.ReadDir, string(requestChangeSet(request)), built.totalSteps, volatile)
	}

	approval := softwareubuntu.NewApproval(func(recheckContext context.Context) (softwarelifecycle.InstallRecheck, error) {
		fresh := built.network(networkpolicy.Request{Intent: built.networkIntent, Stage: networkpolicy.PostApproval})
		if fresh.Outcome == networkpolicy.Failed || fresh.Outcome == networkpolicy.Unknown {
			return softwarelifecycle.InstallRecheck{}, errors.New("privileged Network Policy recheck failed")
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
		observationMu.Lock()
		volatileSHA256 = hex.EncodeToString(freshDigest.Sum(nil))
		observationMu.Unlock()
		return softwarelifecycle.InstallRecheck{Candidate: built.candidate, Contributions: contributions, PrivilegedNetworkHealthy: true}, nil
	})

	adapter := systemubuntu.NewAtForInstall("/", observation, installHost, systemchanges.NewFreshInstallationAuthority(built.wiring.network.FreshInstallationProof()), systemubuntu.NewNativeFirewall(), cloudflareExecutor, certificateExecutor, profilesubuntu.NewDirectTLSExecutor(), subscriptionExecutor, softwareExecutor, stateModule)
	changes := systemchanges.New(adapter)
	cancellation := systemchanges.NewCancellation()
	go func() {
		<-ctx.Done()
		cancellation.Request()
	}()
	return func() softwareubuntu.InstallApplyOutcome {
		result := built.plan.Apply(ctx, softwarelifecycle.InstallApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: changes, Cancellation: cancellation})
		switch result.Outcome {
		case systemchanges.Completed:
			return softwareubuntu.InstallCompleted
		case systemchanges.RollbackSucceeded:
			return softwareubuntu.InstallRolledBack
		default:
			return softwareubuntu.InstallRecoveryRequired
		}
	}, nil
}

func installApplyStateObservation() (systemchanges.Observation, error) {
	observed, err := installRecoveryObservation()
	if err != nil || observed.Status != systemchanges.Managed {
		return observed, err
	}
	lineage, release, err := managedLoadEvidence()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: lineage.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(lineage.LastChangeSet), ReleaseIdentity: release}})
	if err != nil {
		return systemchanges.Observation{}, err
	}
	revision, sha256, lastChangeSet, loadedRelease, valid := module.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid || loadedRelease != release {
		return systemchanges.Observation{}, errors.New("install State lineage is unprovable")
	}
	lineage.StateRevision, lineage.StateSHA256, lineage.LastChangeSet = revision, sha256, string(lastChangeSet)
	return lineage, nil
}

func observeInstallApply(stateSource systemubuntu.ObservationSource, readDir func(string) ([]os.DirEntry, error), changeSet string, totalSteps int, volatileSHA256 string) (systemchanges.Observation, error) {
	observed, err := stateSource()
	if err != nil || observed.Status != systemchanges.NotInstalled && observed.Status != systemchanges.Managed {
		return systemchanges.Observation{}, errors.New("install State lineage is unprovable")
	}
	observed.VolatileSHA256 = volatileSHA256
	entries, err := readDir(installTransactions)
	if errors.Is(err, os.ErrNotExist) {
		return observed, nil
	}
	if err != nil || len(entries) > 1 || len(entries) == 1 && (!entries[0].IsDir() || entries[0].Name() != changeSet) {
		return systemchanges.Observation{}, errors.New("install transaction lineage is unprovable")
	}
	if len(entries) == 1 {
		observed.Status, observed.CurrentChangeSet = systemchanges.ChangeInProgress, changeSet
		observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, totalSteps, true
	}
	return observed, nil
}

func requestChangeSet(request softwareubuntu.InstallHandoffRequest) state.ChangeSetIdentity {
	return state.ChangeSetIdentity("install-" + request.Session[:16])
}

func proveInstalledSubscription(ctx context.Context, address string, port uint16) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(address, formatPort(port))+"/", nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func formatPort(port uint16) string {
	return fmt.Sprint(port)
}
