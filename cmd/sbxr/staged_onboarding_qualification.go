package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflareprofilesetup"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

// RunControlled continues one exact controlled revision 1 through the public
// Cloudflare Profile Setup Plan and real State and System Changes interfaces.
func runControlledCloudflareProfileSetup(ctx context.Context, root string, load state.LoadRequest) error {
	return runControlledCloudflareProfileSetupWithOptions(ctx, root, load, controlledSetupOptions{confirm: true})
}

func qualifyControlledCloudflareProfileSetupFailure(ctx context.Context, root string, load state.LoadRequest, options controlledSetupOptions, wantJournal bool) error {
	setupErr := runControlledCloudflareProfileSetupWithOptions(ctx, root, load, options)
	if setupErr == nil {
		return errors.New("controlled setup failure was not reported")
	}
	if wantJournal {
		var applyErr *controlledSetupApplyError
		if !errors.As(setupErr, &applyErr) || applyErr.transaction.Outcome != systemchanges.RecoveryRequiredOutcome {
			return errors.New("controlled post-checkpoint outcome was not Recovery Required")
		}
	}
	loaded, err := statefilesystem.NewAt(root).Load(load)
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 {
		return errors.New("controlled setup did not preserve revision 1")
	}
	_, journalErr := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/cloudflare-profile-setup-0002/journal.jsonl"))
	if wantJournal == errors.Is(journalErr, os.ErrNotExist) {
		return errors.New("controlled setup journal state disagrees")
	}
	if wantJournal && options.scanSurface != nil {
		journalRoot := filepath.Join(root, "var/lib/sbxr/transactions/cloudflare-profile-setup-0002")
		if err := filepath.Walk(journalRoot, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return walkErr
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return options.scanSurface("journal", body)
		}); err != nil {
			return err
		}
		stateModule := statefilesystem.NewAt(root)
		recoveryLoaded, err := stateModule.Load(load)
		if err != nil || recoveryLoaded.Snapshot == nil {
			return errors.New("controlled recovery State unavailable")
		}
		_, stateSHA, _, _, valid := stateModule.SystemChangesLineageInspection(recoveryLoaded).SystemChangesStateLineageFacts()
		if !valid {
			return errors.New("controlled recovery lineage unavailable")
		}
		base := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 1, StateSHA256: stateSHA, LastChangeSet: string(recoveryLoaded.Snapshot.LastCompletedChangeSet), Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
		observed, err := systemubuntu.RecoveryHealthObservation(root, func() (systemchanges.Observation, error) { return base, nil })
		if err != nil {
			return err
		}
		recoveryAdapter, err := systemubuntu.NewControlledManagedProviderAdapter(root, observed, stateModule, func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error) {
			return systemchanges.StepEvidence{}, errors.New("controlled recovery provider refusal")
		})
		if err != nil {
			return err
		}
		recovery := systemchanges.New(recoveryAdapter)
		if err := options.scanSurface("inspect", []byte(fmt.Sprintf("%+v", recovery.Inspect()))); err != nil {
			return err
		}
		if err := options.scanSurface("recovery", []byte(fmt.Sprintf("%+v", recovery.Recover()))); err != nil {
			return err
		}
	}
	return nil
}

func qualifyControlledCloudflareProfileSetupRestart(ctx context.Context, root string, load state.LoadRequest) error {
	func() {
		defer func() { _ = recover() }()
		_ = runControlledCloudflareProfileSetupWithOptions(ctx, root, load, controlledSetupOptions{confirm: true, crashAt: systemchanges.StatePublished, crashAfter: true})
	}()
	stateModule := statefilesystem.NewAt(root)
	finalLoad := state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: load.SupportedRelease, Lineage: &state.LineageProof{Revision: 2, LastCompletedChangeSet: "cloudflare-profile-setup-0002", ReleaseIdentity: load.SupportedRelease}}
	loaded, err := stateModule.Load(finalLoad)
	if err != nil || loaded.Snapshot == nil {
		return errors.New("controlled setup published revision 2 unavailable")
	}
	_, finalSHA, _, _, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid {
		return errors.New("controlled setup revision 2 lineage unavailable")
	}
	observation := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 2, StateSHA256: finalSHA, LastChangeSet: "cloudflare-profile-setup-0002", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter, err := systemubuntu.NewControlledManagedProviderAdapter(root, observation, stateModule, func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error) {
		return systemchanges.StepEvidence{}, errors.New("provider effect must not repeat after restart")
	})
	if err != nil {
		return err
	}
	if result := systemchanges.New(adapter).Recover(); result.Outcome != systemchanges.Completed {
		return errors.New("controlled setup fresh recovery refused")
	}
	return nil
}

type controlledSetupOptions struct {
	confirm          bool
	failAction       systemchanges.CloudflareAction
	crashAt          systemchanges.DurableCheckpoint
	crashAfter       bool
	singBoxValidator subscriptionpublication.SingBoxValidator
	scanSurface      func(string, []byte) error
}

type controlledSetupApplyError struct {
	correction  *cloudflareprofilesetup.Correction
	transaction systemchanges.ApplyResult
}

func (failure *controlledSetupApplyError) Error() string {
	return fmt.Sprintf("controlled Cloudflare Profile Setup did not complete: %+v: %+v", failure.correction, failure.transaction)
}

func runControlledCloudflareProfileSetupWithOptions(ctx context.Context, root string, load state.LoadRequest, options controlledSetupOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stateModule := statefilesystem.NewAt(root)
	singBoxValidator := options.singBoxValidator
	if singBoxValidator == nil {
		singBoxValidator = controlledPublicationValidator{}
	}
	loaded, err := stateModule.Load(load)
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 || !controlledAllDeferred(loaded.Snapshot.DesiredState.ConnectionProfiles) {
		return errors.New("controlled Managed revision 1 unavailable")
	}
	revision, startingSHA, _, release, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid || revision != 1 {
		return errors.New("controlled revision 1 lineage unavailable")
	}
	var current, candidate connectionprofiles.RegistryViewRequest
	var profileSecrets connectionprofiles.QualificationFixture
	_, preliminaryNetwork := controlledSetupNetwork(loaded.Snapshot.DesiredState, strings.Repeat("0", 64), "preliminary-setup")
	preliminaryExposure := networkpolicy.NewCloudflareProfileSetupListenerContribution(preliminaryNetwork)
	profileLoaded, err := stateModule.Load(load)
	if err != nil {
		return err
	}
	if err := stateModule.WithManagedConnectionProfileSecrets(profileLoaded, func(snapshot state.Snapshot, reader state.ConnectionProfileSecretReader) error {
		var buildErr error
		current, candidate, profileSecrets, buildErr = connectionprofiles.ControlledCloudflareProfileSetup(snapshot, reader, preliminaryExposure)
		return buildErr
	}); err != nil {
		return err
	}
	candidateProfiles, ok := connectionprofiles.DesiredProfiles(candidate)
	if !ok {
		return errors.New("controlled profile candidate unavailable")
	}
	desired := loaded.Snapshot.DesiredState
	desired.Installation.Domain = "example.com"
	desired.ConnectionProfiles = candidateProfiles
	desired.Cloudflare = state.CloudflareSettings{AccountID: strings.Repeat("1", 32), ZoneID: strings.Repeat("2", 32), ZoneName: "example.com", TunnelName: "sbxr-main", ManagementToken: state.NewInfrastructureSecret("sbxr_CONTROLLED-MANAGEMENT-TOKEN-000000000000000000"), DedicatedBroadPolicyConfirmed: true, XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com"}
	desired.Certificates.DomainCertificateID = "sbxr-domain"
	desired.Certificates.DomainServingPointer = "/var/lib/sbxr/certificates/domain/current"
	desired.Certificates.DomainHostname = "direct.example.com"
	desiredSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return err
	}
	const changeSet = "cloudflare-profile-setup-0002"
	networkRequest, networkResult := controlledSetupNetwork(loaded.Snapshot.DesiredState, desiredSHA, changeSet)
	if networkResult.Outcome != networkpolicy.Healthy {
		return errors.New("controlled Network Policy refused setup")
	}
	current.Exposure = networkpolicy.NewListenerContribution(networkResult)
	candidate.Exposure = networkpolicy.NewCloudflareProfileSetupListenerContribution(networkResult)
	profiles := connectionprofiles.ControlledCloudflareProfileSetupModule().PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: changeSet, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA})
	if profiles.Plan == nil {
		return errors.New("controlled Connection Profiles refused setup")
	}
	api := &controlledSetupAPI{}
	cloudflareRequest, cloudflare := controlledSetupCloudflare(ctx, loaded.Snapshot.DesiredState, desiredSHA, startingSHA, changeSet, networkResult.CloudflareTunnelPath, api)
	if cloudflare.Plan == nil {
		return errors.New("controlled Cloudflare Tunnel refused setup")
	}
	certificateRequest, certificate := controlledSetupCertificate(ctx, loaded.Snapshot.DesiredState, desiredSHA, startingSHA, changeSet, networkResult, cloudflare.Plan, candidate)
	if certificate.Plan == nil {
		return errors.New("controlled Certificate Lifecycle refused setup")
	}
	publicationRequest := subscriptionpublication.PlanRequest{Source: profileSecrets.PublicationSource(), Subscription: desired.Subscription, ChangeSet: changeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: startingSHA}, DesiredStateRevision: 2, DesiredStateSHA256: desiredSHA, ManagedInputsSHA256: strings.Repeat("d", 64), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profiles.Plan.SHA256(), Subscription: strings.Repeat("e", 64)}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: desired.NetworkPolicy.PrimarySubscriptionAddress, ReleaseIdentity: release}
	var publication subscriptionpublication.PlanResult
	connectionLoaded, loadErr := stateModule.Load(load)
	if loadErr != nil {
		return loadErr
	}
	subscriptionLoaded, loadErr := stateModule.Load(load)
	if loadErr != nil {
		return loadErr
	}
	if err := stateModule.WithManagedConnectionProfileSecrets(connectionLoaded, func(_ state.Snapshot, connectionReader state.ConnectionProfileSecretReader) error {
		return stateModule.WithManagedSubscriptionSecrets(subscriptionLoaded, func(_ state.Snapshot, subscriptionReader state.ClientAccessReader) error {
			publicationRequest.Secrets = controlledSetupSecrets{profiles: profileSecrets, connection: connectionReader, subscription: subscriptionReader}
			publication = subscriptionpublication.NewIntegrated(singBoxValidator).Plan(ctx, publicationRequest)
			return nil
		})
	}); err != nil {
		return err
	}
	publicationRequest.Secrets = nil
	if publication.Plan == nil {
		return errors.New("controlled Subscription Publication refused setup")
	}
	observation := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 1, StateSHA256: startingSHA, LastChangeSet: string(loaded.Snapshot.LastCompletedChangeSet), Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	cloudflareExecutor, err := cloudflare.Plan.Executor(api)
	if err != nil {
		return err
	}
	adapter, err := systemubuntu.NewControlledManagedProviderAdapter(root, observation, stateModule, func(step systemchanges.Step, tunnelID string, _ time.Duration) (systemchanges.StepEvidence, error) {
		change, ok := step.CloudflareChange()
		if !ok {
			return systemchanges.StepEvidence{}, errors.New("controlled Cloudflare effect is untyped")
		}
		if change.Action == options.failAction {
			return systemchanges.StepEvidence{}, errors.New("controlled post-checkpoint failure")
		}
		evidence := systemchanges.StepEvidence{Code: "controlled-cloudflare-applied", SHA256: strings.Repeat("a", 64)}
		switch change.Action {
		case systemchanges.CloudflareTunnelCreate:
			return cloudflareExecutor.Execute(step, tunnelID, time.Second)
		case systemchanges.CloudflareDNSCreate, systemchanges.CloudflareDNSRepair:
			evidence.ResourceType, evidence.ResourceID = string(systemchanges.CloudflareDNSRecordResource), fmt.Sprintf("%032x", api.dns.Add(1))
		case systemchanges.CloudflareRoutesPut:
			evidence.ResourceType, evidence.ResourceID = string(systemchanges.CloudflareRouteResource), tunnelID
		case systemchanges.CloudflareManagementTokenActivate:
			evidence.ResourceID = change.ManagementTokenID
		}
		return evidence, nil
	})
	if err != nil {
		return err
	}
	qualifiedCurrent := current
	qualifiedCurrent.Exposure = controlledRevisionOneExposure(networkRequest.Intent)
	if err := qualifyControlledManagedCapability(ctx, stateModule, loaded, qualifiedCurrent, false, singBoxValidator, options.scanSurface); err != nil {
		return fmt.Errorf("controlled revision 1 capability: %w", err)
	}
	var transactionAdapter systemchanges.Adapter = adapter
	if options.crashAt != "" {
		transactionAdapter = &controlledCheckpointCrash{Adapter: adapter, checkpoint: options.crashAt, after: options.crashAfter}
	}
	sshProof, err := networkpolicy.ControlledInstallationSSHPreservationProof()
	if err != nil {
		return err
	}
	var prepareErr error
	var transaction systemchanges.ApplyResult
	module, err := cloudflareprofilesetup.New(cloudflareprofilesetup.Dependencies{
		NetworkPolicy:    func(networkpolicy.Request) networkpolicy.Result { return networkResult },
		CloudflareTunnel: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult { return cloudflare },
		CertificateLifecycle: func(context.Context, certificatelifecycle.PlanRequest) certificatelifecycle.PlanResult {
			return certificate
		},
		ConnectionProfiles: func(context.Context, connectionprofiles.RegistryPlanRequest) connectionprofiles.PlanResult {
			return profiles
		},
		SubscriptionPublication: func(context.Context, subscriptionpublication.PlanRequest) subscriptionpublication.PlanResult {
			return publication
		},
		State: cloudflareprofilesetup.StateDependency{Load: stateModule.Load, Prepare: func(request state.PrepareRequest, authority state.DeferredCloudflareAuthority) (*state.PreparedCommit, error) {
			prepared, err := stateModule.PrepareDeferredCloudflareCommit(request, authority)
			prepareErr = err
			return prepared, err
		}},
		SystemChanges: cloudflareprofilesetup.SystemChangesDependency{Inspect: func() systemchanges.Inspection {
			return systemchanges.Inspection{Status: systemchanges.Managed, Lock: systemchanges.LockReleased}
		}, Apply: func(change *systemchanges.ChangeSet, _ cloudflareprofilesetup.Execution) systemchanges.ApplyResult {
			transaction = systemchanges.New(transactionAdapter).Apply(change)
			return transaction
		}},
	})
	if err != nil {
		return err
	}
	result := module.Plan(ctx, cloudflareprofilesetup.PlanRequest{StateLoad: load, NetworkPolicy: networkRequest, CloudflareTunnel: cloudflareRequest, CertificateLifecycle: certificateRequest, ConnectionProfiles: connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: changeSet, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA}, SubscriptionPublication: publicationRequest, StatePrepare: state.PrepareRequest{ChangeSet: changeSet, CandidateReleaseIdentity: release, Candidate: desired}, SoftwareLifecycleSHA256: strings.Repeat("f", 64), VolatileSHA256: observation.VolatileSHA256, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}, Confirmation: func(systemchanges.CloudflareSetupConfirmationRequest) bool { return options.confirm }, SSHPreservation: systemchanges.NewSSHPreservationAuthority(sshProof)})
	if result.Plan == nil {
		return fmt.Errorf("controlled Cloudflare Profile Setup Plan refused: %+v: %v", result.Correction, prepareErr)
	}
	if options.scanSurface != nil {
		transactionSurface := []byte(result.Plan.String() + strings.Join(result.Plan.Review(), "\n"))
		if err := options.scanSurface("transaction", transactionSurface); err != nil {
			return err
		}
	}
	applied := module.Apply(result.Approval)
	if options.scanSurface != nil {
		body := []byte(fmt.Sprintf("%+v %+v", applied, transaction))
		if err := options.scanSurface("apply", body); err != nil {
			return err
		}
	}
	if applied.Kind != cloudflareprofilesetup.ApplyComplete {
		failure := &controlledSetupApplyError{correction: applied.Correction, transaction: transaction}
		if options.scanSurface != nil {
			if err := options.scanSurface("typed-error", []byte(failure.Error())); err != nil {
				return err
			}
		}
		return failure
	}
	finalLoad := state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 2, LastCompletedChangeSet: changeSet, ReleaseIdentity: release}}
	final, err := stateModule.Load(finalLoad)
	if err != nil || final.Snapshot == nil || !controlledAllEnabled(final.Snapshot.DesiredState.ConnectionProfiles) {
		return errors.New("controlled Managed revision 2 unavailable")
	}
	qualifiedCandidate := candidate
	qualifiedCandidate.XHTTP.RouteHealth, qualifiedCandidate.WebSocket.RouteHealth = controlledRouteHealth(final.Snapshot.DesiredState)
	qualifiedCandidate.Hysteria2.Network = qualifiedCandidate.Exposure
	qualifiedCandidate.TUIC.Network = qualifiedCandidate.Exposure
	qualifiedCandidate.AnyTLS.Network = qualifiedCandidate.Exposure
	if err := qualifyControlledManagedCapability(ctx, stateModule, final, qualifiedCandidate, true, singBoxValidator, options.scanSurface); err != nil {
		return fmt.Errorf("controlled revision 2 capability: %w", err)
	}
	return nil
}

func controlledRouteHealth(desired state.DesiredState) (cloudflaretunnel.XHTTPRouteHealth, cloudflaretunnel.WebSocketRouteHealth) {
	expected := managedTunnelExpected(desired)
	observed := cloudflaretunnel.WholeTunnelObservation{TunnelID: expected.TunnelID, Connected: true, Routes: append([]cloudflaretunnel.Route(nil), expected.Routes...), XHTTPOriginReachable: true, WebSocketOriginReachable: true}
	for _, record := range expected.DNSRecords {
		observed.DNSRecords = append(observed.DNSRecords, cloudflaretunnel.DNSObservation{ID: record.ID, Name: record.Name, Type: record.Type, Content: record.Content, Proxied: record.Proxied})
	}
	return cloudflaretunnel.EvaluateXHTTPRouteHealth(observed, expected), cloudflaretunnel.EvaluateWebSocketRouteHealth(observed, expected)
}

type controlledManagedObservation struct{ observation systemchanges.Observation }

func (adapter controlledManagedObservation) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (controlledManagedObservation) TryLock() (systemchanges.Lock, bool, error) {
	return nil, false, nil
}

func qualifyControlledManagedCapability(ctx context.Context, stateModule state.Interface, loaded state.Result, registry connectionprofiles.RegistryViewRequest, cloudflareProfilesSetUp bool, singBoxValidator subscriptionpublication.SingBoxValidator, scanSurface func(string, []byte) error) error {
	if loaded.Snapshot == nil {
		return errors.New("controlled Managed capability unavailable")
	}
	revision, stateSHA, changeSet, _, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	capabilityRevision, capabilitySHA, capabilitySetUp, capabilityValid := stateModule.SoftwareLifecycleCapability(loaded).SoftwareLifecycleManagedCapability()
	if !valid || !capabilityValid || capabilityRevision != revision || capabilitySHA != stateSHA || capabilitySetUp != cloudflareProfilesSetUp {
		return errors.New("controlled Software Lifecycle capability disagrees")
	}
	observation := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: revision, StateSHA256: stateSHA, LastChangeSet: string(changeSet), Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	changes := systemchanges.New(controlledManagedObservation{observation: observation})
	update, downgrade, err := softwarelifecycle.ControlledReleaseChangeSummaries(stateModule.SoftwareLifecycleCapability(loaded))
	wantServices := []string{"sbxr-subscription.service", "xray.service"}
	if cloudflareProfilesSetUp {
		wantServices = []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"}
	}
	if err != nil || !slices.Equal(update.AffectedServices, wantServices) || !slices.Equal(downgrade.AffectedServices, wantServices) {
		return errors.New("controlled update or downgrade capability disagrees")
	}
	capabilities := healthCapabilities(revision, loaded.Snapshot.DesiredState.ConnectionProfiles)
	diagnostics := healthdiagnostics.New(nil).Check(ctx, healthdiagnostics.InstallationSummaryFrom(changes.InstallationHealthInspection()), connectionProfileHealthInspection(map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{healthdiagnostics.ConnectionProfilesModule: healthdiagnostics.Healthy}, capabilities))
	if scanSurface != nil {
		body, err := json.Marshal(diagnostics)
		if err != nil || scanSurface("diagnostic", body) != nil {
			return errors.New("controlled diagnostic secret scan failed")
		}
	}
	if len(diagnostics.Modules) != 1 || diagnostics.Modules[0].Capability == nil || diagnostics.Modules[0].Capability.CommittedRevision != revision || len(diagnostics.Modules[0].Capability.CapabilityRows) != 6 {
		return errors.New("controlled diagnostics capability disagrees")
	}
	for index, profile := range diagnostics.Modules[0].Capability.CapabilityRows {
		if cloudflareProfilesSetUp {
			if profile.Lifecycle != healthdiagnostics.ProfileEnabled || profile.HealthResultOmitted || profile.PublicationOmitted || profile.Explanation != "Set up and Enabled." {
				return errors.New("controlled completed diagnostics capability disagrees")
			}
			continue
		}
		if index == 0 {
			if profile.Lifecycle != healthdiagnostics.ProfileEnabled || profile.HealthResultOmitted || profile.PublicationOmitted || profile.Explanation != "Set up and Enabled." {
				return errors.New("controlled revision 1 diagnostics REALITY capability disagrees")
			}
			continue
		}
		if profile.Lifecycle != healthdiagnostics.ProfileNotSetUp || !profile.HealthResultOmitted || !profile.PublicationOmitted || profile.Explanation != "No individual Health Result; Cloudflare Profile Setup is required." {
			return errors.New("controlled revision 1 diagnostics deferred capability disagrees")
		}
	}
	return stateModule.WithManagedConnectionProfileSecrets(loaded, func(_ state.Snapshot, connection state.ConnectionProfileSecretReader) error {
		subscriptionLoaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: loaded.Snapshot.ReleaseIdentity, Lineage: &state.LineageProof{Revision: revision, LastCompletedChangeSet: changeSet, ReleaseIdentity: loaded.Snapshot.ReleaseIdentity}})
		if err != nil {
			return err
		}
		return stateModule.WithManagedSubscriptionSecrets(subscriptionLoaded, func(_ state.Snapshot, subscription state.ClientAccessReader) error {
			secrets := controlledSetupSecrets{connection: connection, subscription: subscription}
			view := connectionprofiles.ControlledCloudflareProfileSetupModule().ViewRegistry(ctx, registry)
			if view.Health.Outcome != connectionprofiles.Healthy {
				return fmt.Errorf("controlled Access registry health disagrees: %s", view.Health.Code)
			}
			if !connectionprofiles.PublicationInputsMatch(view.Publication, loaded.Snapshot.DesiredState.ConnectionProfiles) {
				return errors.New("controlled Access registry publication disagrees")
			}
			repairContribution, err := connectionprofiles.ControlledRepairPlan(ctx, registry, "controlled-repair-capability", stateSHA)
			if err != nil {
				return err
			}
			repairProof := repairContribution.SoftwareLifecycleRepairContribution()
			repairObservation := observation
			repairObservation.Status, repairObservation.RecoveryCause, repairObservation.ForwardRepairAvailable, repairObservation.VolatileSHA256 = systemchanges.RecoveryRequired, systemchanges.CurrentStateDrift, true, repairProof.StableSHA256
			repairChanges := systemchanges.New(controlledManagedObservation{observation: repairObservation})
			repairView := (softwarelifecycle.FullProductModule{}).ViewRepair(repairChanges)
			repair, finding := softwarelifecycle.PlanRepair(softwarelifecycle.RepairPlanRequest{Candidate: repairView.RepairCandidate(), Contribution: repairContribution, ChangeSet: repairProof.ChangeSet, Capability: stateModule.SoftwareLifecycleCapability(loaded), Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
			if finding != nil || repair == nil || repair.Summary().OwningModule != systemchanges.ConnectionProfilesModule || repair.Summary().CurrentRevision != revision {
				return errors.New("controlled repair capability disagrees")
			}
			const removalReviewID = "controlled-complete-removal"
			removalView := (softwarelifecycle.FullProductModule{}).ViewCompleteRemoval(changes)
			removalReview, err := ownerconsole.ControlledRemovalReview(removalReviewID)
			if err != nil {
				return err
			}
			publicProofs, err := networkpolicy.ControlledRemovalAuthorities(removalReviewID)
			if err != nil {
				return err
			}
			publicRemoval := make([]systemchanges.PublicRemovalAuthority, len(publicProofs))
			for index := range publicProofs {
				publicRemoval[index] = publicProofs[index]
			}
			var providerRemoval []systemchanges.CloudflareRemovalAuthority
			if cloudflareProfilesSetUp {
				providerRemoval, err = cloudflaretunnel.ControlledRemovalAuthorities(removalReviewID)
				if err != nil {
					return err
				}
			}
			removal, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: removalView.Candidate(), Review: removalReview, ChangeSet: removalReviewID, Capability: stateModule.SoftwareLifecycleCapability(loaded), PublicAuthorities: publicRemoval, CloudflareAuthorities: providerRemoval, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
			if finding != nil || removal == nil || cloudflareProfilesSetUp != (len(removal.Summary().CloudflareCategories) > 0) || cloudflareProfilesSetUp != (removal.Summary().TokenRevocationResponsibility != "") {
				return errors.New("controlled Complete removal capability disagrees")
			}
			mutation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RotateSubscriptionToken, loaded.Snapshot.DesiredState.NetworkPolicy.PrimarySubscriptionAddress, loaded.Snapshot.DesiredState.Subscription, loaded.Snapshot.DesiredState.ConnectionProfiles, view.Publication)
			if err != nil {
				return err
			}
			universal, err := mutation.Route("")
			if err != nil || !strings.HasPrefix(universal, "https://") || strings.HasSuffix(universal, "/sing-box") {
				return errors.New("controlled universal Access route unavailable")
			}
			singBoxRoute, err := mutation.Route(string(subscriptionpublication.SingBoxRepresentation))
			if err != nil || !strings.HasSuffix(singBoxRoute, "/sing-box") {
				return errors.New("controlled /sing-box Access route unavailable")
			}
			artifacts, err := subscriptionpublication.NewIntegrated(singBoxValidator).Render(ctx, view.Publication, secrets)
			if err != nil {
				return err
			}
			if scanSurface != nil {
				body := append(append([]byte(nil), artifacts.Raw...), artifacts.SingBox.Body...)
				if err := scanSurface("http", body); err != nil {
					return err
				}
			}
			decoded, decodeErr := base64.StdEncoding.DecodeString(string(artifacts.Base64))
			wantProfiles, wantSingBox := 1, 1
			if cloudflareProfilesSetUp {
				wantProfiles, wantSingBox = 6, 5
			}
			var singBox struct {
				Outbounds []json.RawMessage `json:"outbounds"`
			}
			if decodeErr != nil || !bytes.Equal(decoded, artifacts.Raw) || artifacts.ProfileCount != wantProfiles || artifacts.SingBox.ProfileCount != wantSingBox || json.Unmarshal(artifacts.SingBox.Body, &singBox) != nil || len(singBox.Outbounds) != wantSingBox+1 {
				return errors.New("controlled client output disagrees")
			}
			if cloudflareProfilesSetUp && (len(artifacts.SingBox.Omissions) != 1 || artifacts.SingBox.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || artifacts.SingBox.Omissions[0].Status != subscriptionpublication.NotOffered || artifacts.SingBox.Omissions[0].Reason != "VLESS XHTTP is unsupported by the sing-box transport contract") {
				return errors.New("controlled /sing-box XHTTP omission disagrees")
			}
			liveSubscription, err := connectionprofiles.NewLiveProfileSubscription(universal)
			if err != nil {
				return err
			}
			live := connectionprofiles.ControlledCloudflareProfileSetupModule().RunLiveProfileCheck(ctx, connectionprofiles.LiveProfileCheckRequest{Registry: registry, Managed: changes.ManagedAuthority(), StateSHA256: stateSHA, Subscription: liveSubscription})
			if live.Health.Outcome != connectionprofiles.Healthy || len(live.Evidence()) != wantProfiles || len(live.Skips()) != 6-wantProfiles {
				return errors.New("controlled Live Profile Check capability disagrees")
			}
			for _, skipped := range live.Skips() {
				if skipped.Reason != "The Connection Profile is not set up" && skipped.Reason != "The Connection Profile is deliberately disabled" {
					return errors.New("controlled Live Profile Check skip reason disagrees")
				}
			}
			return nil
		})
	})
}

func controlledAllEnabled(profiles state.ConnectionProfiles) bool {
	for _, lifecycle := range controlledProfileLifecycles(profiles) {
		if lifecycle != state.ProfileEnabled {
			return false
		}
	}
	return true
}

func controlledAllDeferred(profiles state.ConnectionProfiles) bool {
	lifecycles := controlledProfileLifecycles(profiles)
	if lifecycles[0] != state.ProfileEnabled {
		return false
	}
	for _, lifecycle := range lifecycles[1:] {
		if lifecycle != state.ProfileNotSetUp {
			return false
		}
	}
	return true
}

func controlledProfileLifecycles(profiles state.ConnectionProfiles) [6]state.ProfileLifecycle {
	return [6]state.ProfileLifecycle{profiles.VLESSRealityVision.Lifecycle, profiles.VLESSXHTTP.Lifecycle, profiles.VLESSWebSocket.Lifecycle, profiles.Hysteria2.Lifecycle, profiles.TUIC.Lifecycle, profiles.AnyTLS.Lifecycle}
}

type controlledSetupSecrets struct {
	profiles     connectionprofiles.QualificationFixture
	connection   state.ConnectionProfileSecretReader
	subscription state.ClientAccessReader
}

func (s controlledSetupSecrets) ReadClientAccessValue(value state.ClientAccessValue) string {
	if raw := s.subscription.ReadClientAccessValue(value); raw != "" {
		return raw
	}
	if raw := s.connection.ReadClientAccessValue(value); raw != "" {
		return raw
	}
	return s.profiles.ReadClientAccessValue(value)
}

type controlledPublicationValidator struct{}

func (controlledPublicationValidator) ValidateSingBox(_ context.Context, document io.Reader) error {
	body, err := io.ReadAll(io.LimitReader(document, 1<<20+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 || !json.Valid(body) || !bytes.Contains(body, []byte(`"outbounds"`)) {
		return errors.New("controlled sing-box document validation failed")
	}
	return nil
}

type controlledSetupAPI struct{ dns atomic.Uint32 }

func (*controlledSetupAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: strings.Repeat("1", 32)}, Zone: cloudflaretunnel.ZoneObservation{ID: strings.Repeat("2", 32), AccountID: strings.Repeat("1", 32), Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("4", 32), Status: "active"}, DNSListProven: true, TunnelListProven: true}, nil
}
func (*controlledSetupAPI) ObserveMutation(context.Context, cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Digest: strings.Repeat("5", 64)}, nil
}
func (*controlledSetupAPI) CreateTunnel(_ context.Context, request cloudflaretunnel.CreateTunnelRequest) (cloudflaretunnel.CreatedTunnel, error) {
	return cloudflaretunnel.NewCreatedTunnelResult("11111111-1111-4111-8111-111111111111", request.Name, "controlled-tunnel-run-token")
}
func (*controlledSetupAPI) PutConfiguration(_ context.Context, request cloudflaretunnel.PutConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{TunnelID: request.TunnelID, Version: 1, Routes: request.Routes}, nil
}
func (*controlledSetupAPI) GetConfiguration(_ context.Context, request cloudflaretunnel.GetConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{TunnelID: request.TunnelID, Version: 1}, nil
}
func (*controlledSetupAPI) GetTunnel(_ context.Context, request cloudflaretunnel.GetTunnelRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{ID: request.ID, Name: "sbxr-main"}, nil
}
func (api *controlledSetupAPI) CreateDNSRecord(_ context.Context, request cloudflaretunnel.CreateDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{ID: fmt.Sprintf("%032x", api.dns.Add(1)), Name: request.Name}, nil
}
func (*controlledSetupAPI) GetDNSRecord(_ context.Context, request cloudflaretunnel.GetDNSRecordRequest) (cloudflaretunnel.DNSObservation, error) {
	return cloudflaretunnel.DNSObservation{ID: request.ID}, nil
}
func (*controlledSetupAPI) PutDNSRecord(_ context.Context, request cloudflaretunnel.PutDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{ID: request.ID, Name: request.Name}, nil
}
func (*controlledSetupAPI) ObserveWholeTunnel(context.Context, cloudflaretunnel.WholeTunnelRequest) (cloudflaretunnel.WholeTunnelObservation, error) {
	return cloudflaretunnel.WholeTunnelObservation{}, nil
}
func (*controlledSetupAPI) ObserveCertificateDNS(_ context.Context, request cloudflaretunnel.CertificateDNSRequest) (cloudflaretunnel.CertificateDNSFacts, error) {
	return cloudflaretunnel.CertificateDNSFacts{Hostname: request.Hostname}, nil
}
func (*controlledSetupAPI) DeleteDNSRecord(context.Context, cloudflaretunnel.DeleteDNSRecordRequest) error {
	return nil
}
func (*controlledSetupAPI) DeleteTunnel(context.Context, cloudflaretunnel.DeleteTunnelRequest) error {
	return nil
}

type controlledSetupClock struct{}

func (controlledSetupClock) Now() time.Time                             { return time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC) }
func (controlledSetupClock) Sleep(context.Context, time.Duration) error { return nil }

type controlledCheckpointCrash struct {
	systemubuntu.Adapter
	checkpoint systemchanges.DurableCheckpoint
	after      bool
	crashed    bool
	lock       systemchanges.Lock
}

func (adapter *controlledCheckpointCrash) TryLock() (systemchanges.Lock, bool, error) {
	lock, acquired, err := adapter.Adapter.TryLock()
	adapter.lock = lock
	return lock, acquired, err
}

func (adapter *controlledCheckpointCrash) die() {
	adapter.crashed = true
	if adapter.lock != nil {
		_ = adapter.lock.Close()
	}
	panic("controlled worker death")
}

func (adapter *controlledCheckpointCrash) Record(lease systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if !adapter.crashed && record.Checkpoint == adapter.checkpoint && !adapter.after {
		adapter.die()
	}
	err := adapter.Adapter.Record(lease, record)
	if err == nil && !adapter.crashed && record.Checkpoint == adapter.checkpoint {
		adapter.die()
	}
	return err
}

type controlledCertificateAdapter struct{}

func (controlledCertificateAdapter) Observe(context.Context) (certificatelifecycle.Observation, error) {
	return certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "pip-venv", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true}, Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, ExactUnitPair: true, Randomized: true, NoCompetingScheduler: true, RunsPerDay: 2}}, nil
}

func controlledSetupNetwork(current state.DesiredState, desiredSHA, changeSet string) (networkpolicy.Request, networkpolicy.Result) {
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Managed, PublicIPv4: current.NetworkPolicy.PublicIPv4, PrimarySubscriptionAddress: current.NetworkPolicy.PrimarySubscriptionAddress, SSHPort: current.NetworkPolicy.SSHPort, SubscriptionPort: current.Subscription.ListenPort, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: current.ConnectionProfiles.VLESSRealityVision.Port}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	candidate := intent
	candidate.Revision, candidate.CertificateHostname = 2, "direct.example.com"
	candidate.Profiles.VLESSXHTTP = networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}
	candidate.Profiles.VLESSWebSocket = networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}
	candidate.Profiles.Hysteria2, candidate.Profiles.TUIC, candidate.Profiles.AnyTLS = networkpolicy.Profile{Enabled: true, Port: 443}, networkpolicy.Profile{Enabled: true, Port: 8443}, networkpolicy.Profile{Enabled: true, Port: 9443}
	request := networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval, CloudflareProfileSetup: &networkpolicy.CloudflareProfileSetupRequest{Candidate: candidate, Binding: networkpolicy.ChangeSetBinding{StartingRevision: 1, CandidateRevision: 2, ChangeSetID: changeSet, DesiredStateSHA256: desiredSHA}}}
	return request, networkpolicy.New(networkpolicy.ControlledCloudflareProfileSetupAdapter()).Evaluate(request)
}

func controlledRevisionOneExposure(intent networkpolicy.Intent) connectionprofiles.RegistryExposureAuthority {
	result := networkpolicy.New(networkpolicy.ControlledCloudflareProfileSetupAdapter()).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	return networkpolicy.NewListenerContribution(result)
}

func controlledSetupCloudflare(ctx context.Context, current state.DesiredState, desiredSHA, startingSHA, changeSet string, path networkpolicy.CloudflareTunnelPath, api *controlledSetupAPI) (cloudflaretunnel.PlanRequest, cloudflaretunnel.PlanResult) {
	token, _ := cloudflaretunnel.NewManagementToken("sbxr_CONTROLLED-MANAGEMENT-TOKEN-000000000000000000")
	request := cloudflaretunnel.PlanRequest{Authority: cloudflaretunnel.ViewRequest{AccountID: strings.Repeat("1", 32), ZoneID: strings.Repeat("2", 32), ZoneName: "example.com", Token: token, NetworkPath: path, DedicatedBroadPolicyConfirmed: true}, ChangeSet: changeSet, StartingRevision: 1, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA, TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com", PublicIPv4: current.NetworkPolicy.PublicIPv4, CloudflaredVersion: current.Software.CloudflaredVersion}
	return request, cloudflaretunnel.New(api, controlledSetupClock{}, func(context.Context, []byte) error { return nil }).Plan(ctx, request)
}

func controlledSetupCertificate(ctx context.Context, current state.DesiredState, desiredSHA, startingSHA, changeSet string, network networkpolicy.Result, cloudflare *cloudflaretunnel.Plan, candidate connectionprofiles.RegistryViewRequest) (certificatelifecycle.PlanRequest, certificatelifecycle.PlanResult) {
	http01, _ := network.CloudflareProfileSetup.HTTP01Contribution()
	request := certificatelifecycle.PlanRequest{View: certificatelifecycle.ViewRequest{SelectedIP: current.NetworkPolicy.PublicIPv4, DirectHostname: "direct.example.com", QualifiedAddresses: []string{current.NetworkPolicy.PublicIPv4}, HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true}}, Lineage: certificatelifecycle.DomainLineage, ChangeSet: changeSet, StartingRevision: 1, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA, HTTP01: http01, DirectTLS: candidate.Hysteria2.DirectTLS, OwnerEmail: current.Certificates.OwnerEmail, SubscriberAgreementReviewed: true, RenewalPolicyApproved: true, FreshDNS: certificatelifecycle.NewFreshDNSAuthority(network, cloudflare)}
	return request, certificatelifecycle.New(controlledCertificateAdapter{}, controlledSetupClock{}).Plan(ctx, request)
}
