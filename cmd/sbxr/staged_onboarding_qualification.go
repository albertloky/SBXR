package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflareprofilesetup"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
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

type controlledSetupOptions struct {
	confirm    bool
	failAction systemchanges.CloudflareAction
	crashAt    systemchanges.DurableCheckpoint
	crashAfter bool
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
			publication = subscriptionpublication.NewIntegrated(controlledPublicationValidator{}).Plan(ctx, publicationRequest)
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
	applied := module.Apply(result.Approval)
	if applied.Kind != cloudflareprofilesetup.ApplyComplete {
		return &controlledSetupApplyError{correction: applied.Correction, transaction: transaction}
	}
	finalLoad := state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 2, LastCompletedChangeSet: changeSet, ReleaseIdentity: release}}
	final, err := stateModule.Load(finalLoad)
	if err != nil || final.Snapshot == nil || !controlledAllEnabled(final.Snapshot.DesiredState.ConnectionProfiles) {
		return errors.New("controlled Managed revision 2 unavailable")
	}
	return nil
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

func (controlledPublicationValidator) ValidateSingBox(context.Context, io.Reader) error { return nil }

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
