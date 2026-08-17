package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type productionRenewalPlanner struct {
	ctx     context.Context
	disk    systemchanges.DiskRequirement
	adapter *systemubuntu.Adapter
}

func (planner productionRenewalPlanner) BuildFresh(lineage certificatelifecycle.Lineage) (certificatelifecycle.ChangeSet, error) {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return nil, err
	}
	action := managedCertificateIP
	if lineage == certificatelifecycle.DomainLineage {
		action = managedCertificateDomain
	} else if lineage != certificatelifecycle.IPLineage {
		return nil, errors.New("unsupported certificate renewal lineage")
	}
	built, stateModule, err := prepareManagedProvider(planner.ctx, managedProviderBuildRequest{Action: action, ChangeSet: "renewal-" + hex.EncodeToString(identity), StandingRenewal: true, Disk: planner.disk})
	if err != nil {
		return nil, err
	}
	host, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return nil, err
	}
	subscription, err := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
		return proveInstalledSubscription(proofContext, address, built.subscriptionPort)
	})
	if err != nil || planner.adapter == nil {
		return nil, errors.New("certificate renewal transaction Adapter unavailable")
	}
	observation := func() (systemchanges.Observation, error) { return managedProviderObservation(built) }
	*planner.adapter = systemubuntu.NewAtForManagedProvider("/", observation, host, systemubuntu.NewNativeFirewall(), nil, built.certificate, profilesubuntu.NewRuntimeExecutor(), subscription, stateModule)
	return built.certificatePlan.RenewalChangeSet(built.prepared, built.starting, built.volatileSHA, built.disk)
}

func runCertificateRenewal(ctx context.Context) error {
	if ctx == nil {
		return errors.New("certificate renewal context unavailable")
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return err
	}
	stateModule := statefilesystem.New()
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return errors.New("Managed certificate renewal State unavailable")
	}
	desired := loaded.Snapshot.DesiredState
	observation, err := certificateubuntu.New().Observe(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	policy := certificatelifecycle.NewStandingPolicy(
		certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: desired.Certificates.RenewalPolicy, Now: now, NotAfter: observation.IP.NotAfter},
		certificatelifecycle.DomainRenewalFacts{LineageExists: desired.Certificates.DomainCertificateID != "", StandingPolicyApproved: desired.Certificates.RenewalPolicy, Now: now, NotAfter: observation.Domain.NotAfter, RenewalInformation: observation.Domain.RenewalInformation},
		certificateubuntu.NewRenewalAttemptStore(),
	)
	adapter := systemubuntu.NewAt("/", installRecoveryObservation, nil)
	disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
	results := certificatelifecycle.NewScheduler(policy, productionRenewalPlanner{ctx: ctx, disk: disk, adapter: &adapter}, renewalSystemChanges{changes: systemchanges.New(&adapter)}).Run()
	for _, result := range results {
		if result.Error != nil || result.Apply.Outcome == certificatelifecycle.Refused {
			return errors.New("certificate renewal evaluation failed")
		}
	}
	return nil
}
