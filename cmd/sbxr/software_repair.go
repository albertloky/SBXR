package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type builtSoftwareRepair struct {
	changeSet     string
	lastChangeSet string
	plan          *softwarelifecycle.RepairPlan
	prepared      *state.PreparedCommit
	contribution  softwarelifecycle.RepairContribution
	candidate     softwarelifecycle.RepairCandidate
	starting      systemchanges.StateLineage
	desired       state.DesiredState
	disk          systemchanges.DiskRequirement
	module        state.Interface
	profiles      *connectionprofiles.Plan
	publication   *subscriptionpublication.Plan
	cloudflare    cloudflaretunnel.Executor
	inspection    systemchanges.Observation
}

func inspectSoftwareRepair(ctx context.Context) (systemchanges.Observation, error) {
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return systemchanges.Observation{}, errors.New("current proven State is unavailable")
	}
	var proofs []string
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader) error {
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				desired := snapshot.DesiredState
				disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 32 << 20, OverheadBytes: 256 << 20}
				network, xhttp, websocket, err := observeManagedClientAccess(ctx, snapshot, cloudflareSecrets, disk)
				if err != nil {
					return err
				}
				request, err := clientAccessRegistryRequest(desired, snapshot.Revision, profileSecrets, networkpolicy.NewListenerContribution(network), xhttp, websocket)
				if err != nil {
					return err
				}
				registry := connectionprofiles.New(profilesubuntu.NewRealityHost("/")).ViewRegistry(ctx, request)
				if registry.Repairable {
					proofs = append(proofs, registry.VolatileSHA256)
				}
				token, tokenErr := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
				if tokenErr != nil {
					return tokenErr
				}
				stateSHA, err := state.CandidateSHA256(desired)
				if err != nil {
					return err
				}
				cloudflareView := cloudflaretunnel.New(cloudflaretunnel.NewProductionAPI(), cloudflaretunnel.SystemClock{}).ViewManagedRepair(ctx, managedCloudflareRepairRequest(desired, network, token, snapshot.Revision, stateSHA, "repair-inspection"))
				if cloudflareView.Repairable {
					proofs = append(proofs, cloudflareView.StableSHA256)
				}
				source, err := connectionprofiles.PublicationSourceFor(desired.NetworkPolicy.PrimarySubscriptionAddress, desired.ConnectionProfiles)
				if err != nil {
					return err
				}
				storage, err := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
					return proveInstalledSubscription(proofContext, address, desired.Subscription.ListenPort)
				})
				if err != nil {
					return err
				}
				published, err := storage.ObserveCurrent("/", 30*time.Second)
				if err != nil {
					return err
				}
				view := subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: profilesubuntu.NewRealityHost("/"), version: trimVersion(desired.Software.SingBoxVersion)}).View(subscriptionpublication.ViewRequest{Source: source, SubscriptionAddress: net.JoinHostPort(desired.NetworkPolicy.PrimarySubscriptionAddress, strconv.Itoa(int(desired.Subscription.ListenPort))), DesiredStateRevision: snapshot.Revision, PublishedRevision: published.Revision, DesiredStateSHA256: stateSHA, PublishedStateSHA256: published.StateSHA256, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, PublishedCompatibility: published.Compatibility})
				if view.Status != subscriptionpublication.PublicationCurrent || published.Serving != systemchanges.Healthy {
					proofs = append(proofs, repairDigest(fmt.Sprintf("publication:%+v:%+v", view.Status, published)))
				}
				return nil
			})
		})
	})
	if err != nil || len(proofs) != 1 {
		return systemchanges.Observation{}, errors.New("exactly one proven owning-Module drift is required for repair")
	}
	return systemchanges.CurrentStateDriftObservation(systemchanges.StateLineage{Status: systemchanges.Managed, Revision: observed.StateRevision, SHA256: observed.StateSHA256}, observed.LastChangeSet, proofs[0], 1)
}

func managedCloudflareRepairRequest(desired state.DesiredState, network networkpolicy.Result, token cloudflaretunnel.ManagementToken, revision uint64, stateSHA, changeSet string) cloudflaretunnel.PlanRequest {
	return cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Token: token, NetworkPath: network.CloudflareTunnelPath},
		ChangeSet: changeSet, StartingRevision: revision, StartingStateSHA256: stateSHA, DesiredStateSHA256: stateSHA,
		TunnelName: desired.Cloudflare.TunnelName, XHTTPHostname: desired.Cloudflare.XHTTPHostname, WebSocketHostname: desired.Cloudflare.WebSocketHostname, DirectHostname: desired.Cloudflare.DirectHostname,
		PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6, CloudflaredVersion: trimVersion(desired.Software.CloudflaredVersion),
		ManagedRepair: cloudflaretunnel.OwnedTunnelBinding{TunnelID: desired.Cloudflare.TunnelID, XHTTPDNSRecordID: desired.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: desired.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, DirectIPv6RecordID: desired.Cloudflare.DirectIPv6RecordID},
	}
}

func prepareSoftwareRepair(ctx context.Context, changeSet string) (*builtSoftwareRepair, error) {
	return prepareSoftwareRepairBuild(ctx, changeSet, true)
}

func recheckSoftwareRepair(ctx context.Context, changeSet string) (*builtSoftwareRepair, error) {
	return prepareSoftwareRepairBuild(ctx, changeSet, false)
}

func prepareSoftwareRepairBuild(ctx context.Context, changeSet string, prepareState bool) (*builtSoftwareRepair, error) {
	if ctx == nil || !validClientAccessChangeSet(changeSet) {
		return nil, errors.New("complete current-State repair inputs are required")
	}
	if pending, err := pendingStartupRecovery(); err != nil || pending {
		return nil, errors.New("an unfinished Change Set must recover before current-State repair")
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return nil, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return nil, errors.New("current proven State is unavailable")
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 32 << 20, OverheadBytes: 256 << 20}
	var built *builtSoftwareRepair
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader) error {
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				var buildErr error
				built, buildErr = buildSoftwareRepair(ctx, module, loaded, snapshot, profileSecrets, publicationSecrets, cloudflareSecrets, changeSet, disk, prepareState)
				return buildErr
			})
		})
	})
	return built, err
}

func buildSoftwareRepair(ctx context.Context, module state.Interface, loaded state.Result, snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader, publicationSecrets state.ClientAccessReader, cloudflareSecrets state.InfrastructureSecretReader, changeSet string, disk systemchanges.DiskRequirement, prepareState bool) (*builtSoftwareRepair, error) {
	desired := snapshot.DesiredState
	stateSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, err
	}
	network, xhttp, websocket, err := observeManagedClientAccess(ctx, snapshot, cloudflareSecrets, disk)
	if err != nil {
		return nil, err
	}
	host := profilesubuntu.NewRealityHost("/")
	registryRequest, err := clientAccessRegistryRequest(desired, snapshot.Revision, profileSecrets, networkpolicy.NewListenerContribution(network), xhttp, websocket)
	if err != nil {
		return nil, err
	}
	profileModule := connectionprofiles.New(host)
	registryView := profileModule.ViewRegistry(ctx, registryRequest)
	source, err := connectionprofiles.PublicationSourceFor(desired.NetworkPolicy.PrimarySubscriptionAddress, desired.ConnectionProfiles)
	if err != nil {
		return nil, err
	}
	publicationModule := subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: host, version: trimVersion(desired.Software.SingBoxVersion)})

	var candidates []softwarelifecycle.RepairContribution
	var profilePlan *connectionprofiles.Plan
	if registryView.Repairable && registryView.VolatileSHA256 != "" {
		inspection, inspectionErr := systemchanges.CurrentStateDriftObservation(systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: stateSHA}, string(snapshot.LastCompletedChangeSet), registryView.VolatileSHA256, 1)
		if inspectionErr == nil {
			result := profileModule.PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: registryRequest, Candidate: registryRequest, ChangeSet: changeSet, StartingStateSHA256: stateSHA, DesiredStateSHA256: stateSHA, Repair: repairChanges(inspection).ForwardRepairAuthority()})
			if result.Plan != nil {
				profilePlan = result.Plan
				candidates = append(candidates, result.Plan)
			}
		}
	}

	token, tokenErr := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
	api := cloudflaretunnel.NewProductionAPI()
	cloudflareModule := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{})
	cloudflareResult := cloudflaretunnel.PlanResult{}
	if tokenErr == nil {
		cloudflareResult = cloudflareModule.Plan(ctx, managedCloudflareRepairRequest(desired, network, token, snapshot.Revision, stateSHA, changeSet))
		if cloudflareResult.Plan != nil {
			candidates = append(candidates, cloudflareResult.Plan)
		}
	}

	publicationDigest := sha256.Sum256([]byte(fmt.Sprintf("publication-repair:%d:%s:%s", desired.Subscription.ListenPort, desired.Subscription.CertificateID, stateSHA)))
	publicationInputs := hex.EncodeToString(publicationDigest[:])
	publicationRequest := subscriptionpublication.PlanRequest{Source: source, Secrets: publicationSecrets, Subscription: desired.Subscription, ChangeSet: changeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: stateSHA}, DesiredStateRevision: snapshot.Revision + 1, DesiredStateSHA256: stateSHA, ManagedInputsSHA256: publicationInputs, RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: repairDigest("profiles:" + stateSHA), Subscription: repairDigest("subscription:" + stateSHA)}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: desired.NetworkPolicy.PrimarySubscriptionAddress, ReleaseIdentity: snapshot.ReleaseIdentity}
	publicationRepair := false
	if storage, storageErr := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
		return proveInstalledSubscription(proofContext, address, desired.Subscription.ListenPort)
	}); storageErr == nil {
		if published, observeErr := storage.ObserveCurrent("/", 30*time.Second); observeErr == nil {
			view := publicationModule.View(subscriptionpublication.ViewRequest{Source: source, SubscriptionAddress: net.JoinHostPort(desired.NetworkPolicy.PrimarySubscriptionAddress, strconv.Itoa(int(desired.Subscription.ListenPort))), DesiredStateRevision: snapshot.Revision, PublishedRevision: published.Revision, DesiredStateSHA256: stateSHA, PublishedStateSHA256: published.StateSHA256, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, PublishedCompatibility: published.Compatibility})
			publicationRepair = view.Status != subscriptionpublication.PublicationCurrent || published.Serving != systemchanges.Healthy
		}
	}
	var publicationPlan *subscriptionpublication.Plan
	if publicationRepair {
		publicationRequest.Repair = true
		publicationPlan = publicationModule.Plan(ctx, publicationRequest).Plan
		if publicationPlan != nil {
			candidates = append(candidates, publicationPlan)
		}
	}
	if len(candidates) != 1 {
		return nil, errors.New("exactly one proven owning-Module drift is required for repair")
	}
	contribution := candidates[0]
	proof := contribution.SoftwareLifecycleRepairContribution()
	inspection, err := systemchanges.CurrentStateDriftObservation(systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: stateSHA}, string(snapshot.LastCompletedChangeSet), proof.StableSHA256, len(candidates))
	if err != nil {
		return nil, err
	}
	changes := repairChanges(inspection)
	repairView := (softwarelifecycle.Interface{}).ViewRepair(changes)
	plan, finding := softwarelifecycle.PlanRepair(softwarelifecycle.RepairPlanRequest{Candidate: repairView.RepairCandidate(), Contribution: contribution, ChangeSet: changeSet, Disk: disk})
	if finding != nil || plan == nil {
		return nil, errors.New("Software Lifecycle current-State repair Plan refused")
	}
	if profilePlan == nil {
		unchanged := profileModule.PlanUnchangedRegistry(ctx, registryRequest, changeSet, stateSHA)
		if _, cloudflareRepair := contribution.(*cloudflaretunnel.Plan); cloudflareRepair {
			unchanged = profileModule.PlanUnchangedCoreRegistry(ctx, registryRequest, changeSet, stateSHA)
		}
		profilePlan = unchanged.Plan
	}
	if profilePlan == nil {
		return nil, errors.New("unchanged Connection Profiles preparation refused")
	}
	if publicationPlan == nil {
		publicationRequest.Repair = false
		publicationRequest.ManagedInputsSHA256 = repairDigest(profilePlan.SHA256() + plan.SHA256())
		publicationPlan = publicationModule.Plan(ctx, publicationRequest).Plan
	}
	if publicationPlan == nil {
		return nil, errors.New("Subscription Publication preparation refused")
	}
	var cloudflarePlan *cloudflaretunnel.Plan
	var cloudflareExecutor cloudflaretunnel.Executor
	if selected, ok := contribution.(*cloudflaretunnel.Plan); ok {
		cloudflarePlan = selected
		cloudflareExecutor, err = selected.Executor(api)
		if err != nil {
			return nil, err
		}
	}
	freshCandidate := (softwarelifecycle.Interface{}).ViewRepair(changes).RepairCandidate()
	built := &builtSoftwareRepair{changeSet: changeSet, lastChangeSet: string(snapshot.LastCompletedChangeSet), plan: plan, contribution: contribution, candidate: freshCandidate, starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: stateSHA}, desired: desired, disk: disk, module: module, profiles: profilePlan, publication: publicationPlan, cloudflare: cloudflareExecutor, inspection: inspection}
	if !prepareState {
		return built, nil
	}
	wiring := &softwareRepairWiring{plan: plan, profiles: profilePlan, publication: publicationPlan, cloudflare: cloudflarePlan, current: desired, network: network}
	cloudflareSHA := repairDigest("unchanged-cloudflare:" + plan.SHA256())
	if cloudflarePlan != nil {
		cloudflareSHA = cloudflarePlan.SHA256()
	}
	checksums, err := state.NewManagedInputChecksums(profilePlan.SHA256(), publicationPlan.SHA256(), cloudflareSHA, repairDigest("unchanged-certificates:"+plan.SHA256()), repairDigest("unchanged-network:"+plan.SHA256()), repairDigest("unchanged-software:"+plan.SHA256()))
	if err != nil {
		return nil, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(plan.Identity()), plan.SHA256(), checksums)
	if err != nil {
		return nil, err
	}
	prepared, err := module.PrepareSoftwareRepairCommit(state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: snapshot.ReleaseIdentity, ChangeSet: state.ChangeSetIdentity(changeSet), Candidate: desired, SemanticValidators: state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring}, ServiceMaterials: state.ServiceMaterialsFor(desired), SubscriptionPublication: wiring, ReviewedInputs: reviewed}, plan)
	if err != nil {
		return nil, err
	}
	built.prepared = prepared
	return built, nil
}

func repairChanges(observation systemchanges.Observation) systemchanges.Interface {
	return systemchanges.New(systemubuntu.NewAt("/", func() (systemchanges.Observation, error) { return observation, nil }, nil))
}

type softwareRepairWiring struct {
	plan        *softwarelifecycle.RepairPlan
	profiles    *connectionprofiles.Plan
	publication *subscriptionpublication.Plan
	cloudflare  *cloudflaretunnel.Plan
	current     state.DesiredState
	network     networkpolicy.Result
}

func (w *softwareRepairWiring) Identity() string { return w.plan.Identity() }
func (w *softwareRepairWiring) SHA256() string   { return w.plan.SHA256() }
func (w *softwareRepairWiring) ValidateConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	return w.profiles.ValidateConnectionProfiles(value, secrets)
}
func (w *softwareRepairWiring) PrepareConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return w.profiles.PrepareConnectionProfiles(value, secrets)
}
func (w *softwareRepairWiring) ValidateSubscription(value state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	return w.publication.ValidateSubscription(value, secrets)
}
func (w *softwareRepairWiring) PrepareSubscriptionPublication() ([]byte, error) {
	return w.publication.PrepareSubscriptionPublication()
}
func (w *softwareRepairWiring) ValidateCloudflare(value state.CloudflareSettings, secrets state.InfrastructureSecretReader) error {
	if value != w.current.Cloudflare || w.cloudflare != nil && !w.cloudflare.MatchesDesiredState(value.AccountID, value.ZoneID, value.ZoneName, value.TunnelName, value.XHTTPHostname, value.WebSocketHostname, value.DirectHostname, w.current.NetworkPolicy.PublicIPv4, w.current.NetworkPolicy.PublicIPv6, secrets.ReadInfrastructureSecret(value.ManagementToken)) || w.cloudflare == nil && secrets.ReadInfrastructureSecret(value.ManagementToken) == "" {
		return errors.New("repair changed Cloudflare Desired State")
	}
	return nil
}
func (w *softwareRepairWiring) ValidateCertificates(value state.CertificateSettings) error {
	if value != w.current.Certificates {
		return errors.New("repair changed Certificate Desired State")
	}
	return nil
}
func (w *softwareRepairWiring) ValidateNetworkPolicy(value state.NetworkPolicyInputs) error {
	if value != w.current.NetworkPolicy || !w.network.MatchesDesiredState(value.SSHPort, value.PublicIPv4, value.PublicIPv6, value.PrimarySubscriptionAddress) {
		return errors.New("repair changed Network Policy Desired State")
	}
	return nil
}
func (w *softwareRepairWiring) ValidateSoftwareLifecycle(value state.SoftwareLifecycleIntent) error {
	if value != (state.SoftwareLifecycleIntent{Installation: w.current.Installation, Software: w.current.Software}) {
		return errors.New("repair changed Software Lifecycle Desired State")
	}
	return nil
}

func repairDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type softwareRepairApproval struct {
	built *builtSoftwareRepair
	fresh systemchanges.Observation
}

func (approval *softwareRepairApproval) AuthorizeAndRecheck(ctx context.Context) (softwarelifecycle.RepairRecheck, error) {
	rebuilt, err := recheckSoftwareRepair(ctx, approval.built.changeSet)
	if err != nil {
		return softwarelifecycle.RepairRecheck{}, err
	}
	approval.fresh = rebuilt.inspection
	return softwarelifecycle.RepairRecheck{Candidate: rebuilt.candidate, Contribution: rebuilt.contribution}, nil
}

func applySoftwareRepair(ctx context.Context, built *builtSoftwareRepair, cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
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
	approval := &softwareRepairApproval{built: built}
	observation := func() (systemchanges.Observation, error) {
		if approval.fresh == (systemchanges.Observation{}) {
			return built.inspection, nil
		}
		return approval.fresh, nil
	}
	adapter := systemubuntu.NewAtForClientAccess("/", observation, host, systemubuntu.NewNativeFirewall(), built.cloudflare, profilesubuntu.NewDirectTLSExecutor(), subscription, built.module)
	return built.plan.Apply(ctx, softwarelifecycle.RepairApplyRequest{Approval: approval, PreparedState: built.prepared, SystemChanges: systemchanges.New(adapter), Cancellation: cancellation})
}
