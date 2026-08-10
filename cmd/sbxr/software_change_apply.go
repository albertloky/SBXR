package main

import (
	"context"
	"errors"

	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	softwarelifecycle "github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type softwareChangeApproval struct {
	built *builtSoftwareChange
	fresh string
}

func (approval *softwareChangeApproval) AuthorizeAndRecheck(ctx context.Context) (softwarelifecycle.UpdateRecheck, error) {
	if approval == nil || approval.built == nil {
		return softwarelifecycle.UpdateRecheck{}, errors.New("Software Lifecycle approval unavailable")
	}
	rebuilt, err := prepareSoftwareChange(ctx, approval.built.action, approval.built.candidate.Identity.Tag, approval.built.changeSet)
	if err != nil {
		return softwarelifecycle.UpdateRecheck{}, err
	}
	approval.fresh = rebuilt.plan.VolatileSHA256()
	return softwarelifecycle.UpdateRecheck{Installed: rebuilt.installed, InstalledCandidate: rebuilt.installedCandidate, Candidate: rebuilt.next, StartingRevision: rebuilt.starting.Revision, StartingStateSHA256: rebuilt.starting.SHA256, Contributions: rebuilt.contributions}, nil
}

func applySoftwareChange(ctx context.Context, built *builtSoftwareChange, cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
	if ctx == nil || built == nil || built.plan == nil || built.prepared == nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	host, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	subscription, err := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
		return proveInstalledSubscription(proofContext, address, built.desired.Subscription.ListenPort)
	})
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	var software softwareubuntu.Updater
	if built.action == softwareDowngrade {
		software, err = softwareubuntu.NewDowngrader(built.next, built.installedCandidate)
	} else {
		software, err = softwareubuntu.NewUpdater(built.next, built.installedCandidate)
	}
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	approval := &softwareChangeApproval{built: built}
	observation := func() (systemchanges.Observation, error) {
		observed, err := installRecoveryObservation()
		if err != nil {
			return systemchanges.Observation{}, err
		}
		observed.VolatileSHA256 = approval.fresh
		return observed, nil
	}
	adapter := systemubuntu.NewAtForSoftwareChange("/", observation, host, built.cloudflare, profilesubuntu.NewDirectTLSExecutor(), subscription, software, built.module)
	return built.plan.Apply(ctx, softwarelifecycle.UpdateApplyRequest{Approval: approval, PreparedState: built.prepared, SystemChanges: systemchanges.New(adapter), Cancellation: cancellation})
}
