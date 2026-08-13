package main

import (
	"context"
	"errors"

	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func applyManagedProvider(ctx context.Context, built *builtManagedProvider, module state.Interface) systemchanges.ApplyResult {
	if ctx == nil || built == nil || built.plan == nil || built.prepared == nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	host, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	subscription, err := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
		return proveInstalledSubscription(proofContext, address, built.subscriptionPort)
	})
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	observation := func() (systemchanges.Observation, error) { return managedProviderObservation(built) }
	adapter := systemubuntu.NewAtForManagedProvider("/", observation, host, systemubuntu.NewNativeFirewall(), built.cloudflare, built.certificate, profilesubuntu.NewDirectTLSExecutor(), subscription, module)
	changes := systemchanges.New(adapter)
	if built.cloudflarePlan != nil {
		return built.cloudflarePlan.Apply(changes, built.prepared, built.starting, built.volatileSHA, built.disk)
	}
	return built.certificatePlan.Apply(changes, built.prepared, built.starting, built.volatileSHA, built.disk)
}

func managedProviderObservation(built *builtManagedProvider) (systemchanges.Observation, error) {
	if built == nil || built.plan == nil {
		return systemchanges.Observation{}, errors.New("managed provider observation unavailable")
	}
	observed, err := installRecoveryObservation()
	if err != nil || observed.Status != systemchanges.Managed {
		return observed, err
	}
	observed.VolatileSHA256, err = clientAccessVolatileSHA("/")
	if err != nil {
		return systemchanges.Observation{}, err
	}
	pending, found, readErr := productionPendingChangeSetReader().PendingChangeSet()
	if readErr != nil || found && pending.Identity != built.changeSet {
		return systemchanges.Observation{}, errors.New("managed provider transaction lineage is unprovable")
	}
	if found {
		observed.Status, observed.CurrentChangeSet = systemchanges.ChangeInProgress, built.changeSet
		observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, built.totalSteps, !pending.ForwardOnly
	}
	return observed, nil
}
