package main

import (
	"context"
	"errors"
	"io"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func applyClientAccess(ctx context.Context, built *builtClientAccess, module state.Interface) systemchanges.ApplyResult {
	if ctx == nil || built == nil || built.plan == nil || built.prepared == nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	host, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	subscription, err := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
		return proveInstalledSubscription(proofContext, address, built.candidate.Subscription.ListenPort)
	})
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	observation := func() (systemchanges.Observation, error) { return clientAccessObservation(built) }
	adapter := systemubuntu.NewAtForClientAccess("/", observation, host, systemubuntu.NewNativeFirewall(), built.cloudflare, profilesubuntu.NewDirectTLSExecutor(), subscription, module)
	changeSet, err := built.plan.changeSet(built.prepared, built.starting, built.volatileSHA, built.disk)
	if err != nil {
		return systemchanges.New(adapter).Apply(nil)
	}
	cancellation := systemchanges.NewCancellation()
	go func() {
		<-ctx.Done()
		cancellation.Request()
	}()
	return systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
}

func clientAccessObservation(built *builtClientAccess) (systemchanges.Observation, error) {
	if built == nil || built.plan == nil {
		return systemchanges.Observation{}, errors.New("Client Access observation unavailable")
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
	if readErr != nil || found && pending.Identity != built.plan.changeSetID {
		return systemchanges.Observation{}, errors.New("Client Access transaction lineage is unprovable")
	}
	if found {
		observed.Status, observed.CurrentChangeSet = systemchanges.ChangeInProgress, built.plan.changeSetID
		observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, built.totalSteps, !pending.ForwardOnly
	}
	return observed, nil
}

func prepareManagedClientAccess(ctx context.Context, request clientAccessBuildRequest) (*builtClientAccess, state.Interface, error) {
	if pending, err := pendingStartupRecovery(); err != nil {
		return nil, state.Interface{}, err
	} else if pending {
		return nil, state.Interface{}, errors.New("an unfinished Change Set must recover before a new Client Access Plan")
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return nil, state.Interface{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{
		Baseline:         state.ManagedEvidence,
		SupportedRelease: release,
		Lineage: &state.LineageProof{
			Revision:               observed.StateRevision,
			LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet),
			ReleaseIdentity:        release,
		},
	})
	if err != nil {
		return nil, state.Interface{}, err
	}
	host := profilesubuntu.NewRealityHost("/")
	built, err := buildClientAccess(ctx, module, loaded, request, clientAccessBuildDependencies{Profiles: connectionprofiles.New(host), Publication: subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: host, version: trimVersion(loaded.Snapshot.DesiredState.Software.SingBoxVersion)}), Cloudflare: cloudflaretunnel.NewProductionAPI(), Observe: observeManagedClientAccess})
	if err == nil {
		built.volatileSHA, err = clientAccessVolatileSHA("/")
	}
	return built, module, err
}

type installedSingBoxValidator struct {
	host    profilesubuntu.RealityHost
	version string
}

func (validator installedSingBoxValidator) ValidateSingBox(ctx context.Context, document io.Reader) error {
	return validator.host.ValidateSingBox(ctx, validator.version, document)
}
