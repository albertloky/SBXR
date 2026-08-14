package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type clientAccessBuildRequest struct {
	Action           clientAccessAction
	Profile          connectionprofiles.ProfileID
	ChangeSet        string
	CurrentNetwork   networkpolicy.Result
	CurrentXHTTP     cloudflaretunnel.XHTTPRouteHealth
	CurrentWebSocket cloudflaretunnel.WebSocketRouteHealth
	Disk             systemchanges.DiskRequirement
}

type clientAccessBuildDependencies struct {
	Profiles    connectionprofiles.Interface
	Publication subscriptionpublication.Interface
	Cloudflare  cloudflaretunnel.MutationAPI
	Observe     func(context.Context, state.Snapshot, state.InfrastructureSecretReader, systemchanges.DiskRequirement) (networkpolicy.Result, cloudflaretunnel.XHTTPRouteHealth, cloudflaretunnel.WebSocketRouteHealth, error)
}

type builtClientAccess struct {
	plan         *clientAccessPlan
	prepared     *state.PreparedCommit
	candidate    state.DesiredState
	candidateSHA string
	starting     systemchanges.StateLineage
	disk         systemchanges.DiskRequirement
	totalSteps   int
	cloudflare   cloudflaretunnel.Executor
	volatileSHA  string
}

func buildClientAccess(ctx context.Context, module state.Interface, loaded state.Result, request clientAccessBuildRequest, dependencies clientAccessBuildDependencies) (*builtClientAccess, error) {
	if ctx == nil || loaded.Status != state.Managed || loaded.Snapshot == nil || request.ChangeSet == "" {
		return nil, errors.New("complete Managed Client Access inputs are required")
	}
	var built *builtClientAccess
	err := module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, secrets state.ConnectionProfileSecretReader) error {
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				currentNetwork, currentXHTTP, currentWebSocket := request.CurrentNetwork, request.CurrentXHTTP, request.CurrentWebSocket
				if currentNetwork.Outcome != networkpolicy.Healthy && dependencies.Observe != nil {
					var observeErr error
					currentNetwork, currentXHTTP, currentWebSocket, observeErr = dependencies.Observe(ctx, snapshot, cloudflareSecrets, request.Disk)
					if observeErr != nil {
						return observeErr
					}
				}
				if currentNetwork.Outcome != networkpolicy.Healthy {
					return errors.New("current Managed Network Policy is not healthy")
				}
				startingSHA, err := state.CandidateSHA256(snapshot.DesiredState)
				if err != nil {
					return err
				}
				currentSource, err := connectionprofiles.PublicationSourceFor(snapshot.DesiredState.NetworkPolicy.PrimarySubscriptionAddress, snapshot.DesiredState.ConnectionProfiles)
				if err != nil {
					return err
				}
				candidate := snapshot.DesiredState
				candidateSource := currentSource
				var accessMutation *subscriptionpublication.ClientAccessMutation
				switch request.Action {
				case clientAccessEnableProfile, clientAccessDisableProfile, clientAccessRotateProfile, clientAccessRotateAllProfiles:
					action := map[clientAccessAction]connectionprofiles.RegistryMutationAction{
						clientAccessEnableProfile: connectionprofiles.EnableProfile, clientAccessDisableProfile: connectionprofiles.DisableProfile,
						clientAccessRotateProfile: connectionprofiles.RotateProfileCredential, clientAccessRotateAllProfiles: connectionprofiles.RotateEveryProfileCredential,
					}[request.Action]
					mutation, mutationErr := connectionprofiles.PrepareRegistryMutation(action, request.Profile, candidate.NetworkPolicy.PrimarySubscriptionAddress, candidate.ConnectionProfiles, currentSource)
					if mutationErr != nil {
						return mutationErr
					}
					candidate.ConnectionProfiles, candidateSource = mutation.ConnectionProfiles(), mutation.PublicationSource()
				case clientAccessRotateSubscription, clientAccessRevokeAll:
					action := subscriptionpublication.RotateSubscriptionToken
					if request.Action == clientAccessRevokeAll {
						action = subscriptionpublication.RevokeAllClientAccess
					}
					accessMutation, err = subscriptionpublication.PrepareClientAccessMutation(action, candidate.NetworkPolicy.PrimarySubscriptionAddress, candidate.Subscription, candidate.ConnectionProfiles, currentSource)
					if err != nil {
						return err
					}
					candidate.Subscription, candidate.ConnectionProfiles, candidateSource = accessMutation.Subscription(), accessMutation.ConnectionProfiles(), accessMutation.PublicationSource()
				default:
					return errors.New("Client Access action is invalid")
				}
				candidateSHA, err := state.CandidateSHA256(candidate)
				if err != nil || candidateSHA == startingSHA {
					return errors.New("Client Access candidate is unchanged")
				}

				currentIntent := clientAccessNetworkIntent(snapshot.DesiredState, snapshot.Revision, request.Disk)
				candidateIntent := clientAccessNetworkIntent(candidate, snapshot.Revision, request.Disk)
				currentExposure := networkpolicy.NewListenerContribution(currentNetwork)
				candidateExposure := connectionprofiles.RegistryExposureAuthority(currentExposure)
				var effect clientAccessPlanEffects
				if request.Action == clientAccessEnableProfile || request.Action == clientAccessDisableProfile {
					planned, nftables, planErr := networkpolicy.PrepareProfileEnablement(currentNetwork, currentIntent, candidateIntent)
					if planErr != nil {
						return planErr
					}
					candidateExposure = planned
					step, stepErr := systemchanges.NewFirewallPolicyStep(nftables, candidate.NetworkPolicy.SSHPort)
					if stepErr != nil {
						return stepErr
					}
					digest := sha256.Sum256([]byte(nftables))
					effect = clientAccessPlanEffects{SHA256: hex.EncodeToString(digest[:]), Steps: []systemchanges.Step{step}, Checks: []systemchanges.Check{
						{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-CLIENT-ACCESS-CANDIDATE"},
						{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-CLIENT-ACCESS-ACTIVE"},
					}}
				}

				var cloudflareExecutor cloudflaretunnel.Executor
				if (request.Action == clientAccessEnableProfile || request.Action == clientAccessDisableProfile) && (request.Profile == connectionprofiles.VLESSXHTTPProfileID || request.Profile == connectionprofiles.VLESSWebSocketProfileID) {
					routes, routeErr := cloudflaretunnel.PrepareClientAccessRoutes(cloudflaretunnel.ClientAccessRoutesRequest{
						ChangeSet: request.ChangeSet, AccountID: candidate.Cloudflare.AccountID, ZoneID: candidate.Cloudflare.ZoneID, TunnelID: candidate.Cloudflare.TunnelID,
						XHTTPHostname: candidate.Cloudflare.XHTTPHostname, WebSocketHostname: candidate.Cloudflare.WebSocketHostname, XHTTPDNSRecordID: candidate.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: candidate.Cloudflare.WebSocketDNSRecordID,
						CurrentXHTTP: snapshot.DesiredState.ConnectionProfiles.VLESSXHTTP.Enabled, CurrentWebSocket: snapshot.DesiredState.ConnectionProfiles.VLESSWebSocket.Enabled,
						CandidateXHTTP: candidate.ConnectionProfiles.VLESSXHTTP.Enabled, CandidateWebSocket: candidate.ConnectionProfiles.VLESSWebSocket.Enabled,
					})
					if routeErr != nil {
						return routeErr
					}
					token, tokenErr := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(candidate.Cloudflare.ManagementToken))
					if tokenErr != nil {
						return tokenErr
					}
					cloudflareExecutor, routeErr = routes.Executor(dependencies.Cloudflare, token)
					if routeErr != nil {
						return routeErr
					}
					effect.Steps = append(effect.Steps, routes.Steps()...)
					effect.Checks = append(effect.Checks, routes.Checks()...)
					digest := sha256.Sum256([]byte(effect.SHA256 + routes.SHA256()))
					effect.SHA256 = hex.EncodeToString(digest[:])
				}

				currentRegistry, err := clientAccessRegistryRequest(snapshot.DesiredState, snapshot.Revision, secrets, currentExposure, currentXHTTP, currentWebSocket)
				if err != nil {
					return err
				}
				candidateRegistry, err := clientAccessRegistryRequest(candidate, snapshot.Revision, secrets, candidateExposure, currentXHTTP, currentWebSocket)
				if err != nil {
					return err
				}
				var profilePlan clientAccessProfilePlan
				if request.Action == clientAccessRotateSubscription {
					unchanged := dependencies.Profiles.PlanUnchangedRegistry(ctx, currentRegistry, request.ChangeSet, startingSHA)
					if unchanged.Plan == nil {
						return fmt.Errorf("unchanged Connection Profiles preparation refused: %s", unchanged.Health.Code)
					}
					profilePlan = unchanged.Plan
				} else {
					profileResult := dependencies.Profiles.PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: currentRegistry, Candidate: candidateRegistry, ChangeSet: request.ChangeSet, StartingStateSHA256: startingSHA, DesiredStateSHA256: candidateSHA})
					if profileResult.Plan == nil {
						return fmt.Errorf("Connection Profiles Plan refused: %s", profileResult.Health.Code)
					}
					profilePlan = profileResult.Plan
				}

				profileSHA := profilePlan.SHA256()
				managedDigest := sha256.Sum256([]byte(profileSHA + candidateSHA))
				subscriptionDigest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", request.Action, candidate.Subscription.ListenPort, candidate.Subscription.CertificateID)))
				publicationResult := dependencies.Publication.Plan(ctx, subscriptionpublication.PlanRequest{
					Source: candidateSource, Secrets: publicationSecrets, Subscription: candidate.Subscription, ClientAccessMutation: accessMutation,
					ChangeSet: request.ChangeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: startingSHA},
					DesiredStateRevision: snapshot.Revision + 1, DesiredStateSHA256: candidateSHA, ManagedInputsSHA256: hex.EncodeToString(managedDigest[:]),
					RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: profileSHA, Subscription: hex.EncodeToString(subscriptionDigest[:])},
					CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: candidate.NetworkPolicy.PrimarySubscriptionAddress, ReleaseIdentity: snapshot.ReleaseIdentity,
				})
				if publicationResult.Plan == nil {
					return errors.New("Subscription Publication Plan refused")
				}
				var effects []clientAccessPlanEffects
				if len(effect.Steps) > 0 {
					effects = []clientAccessPlanEffects{effect}
				}
				plan, err := newClientAccessPlan(request.ChangeSet, request.Action, profilePlan, publicationResult.Plan, effects...)
				if err != nil {
					return err
				}
				wiring := &clientAccessWiring{clientAccessPlan: plan, current: snapshot.DesiredState, network: currentNetwork}
				checksums, err := clientAccessManagedChecksums(plan, profilePlan, publicationResult.Plan)
				if err != nil {
					return err
				}
				reviewed, err := state.NewReviewedInputs(state.PlanIdentity(plan.Identity()), plan.SHA256(), checksums)
				if err != nil {
					return err
				}
				profileRuntime, ok := profilePlan.(state.RuntimeArtifactContribution)
				if !ok {
					return errors.New("Connection Profiles runtime contribution unavailable")
				}
				prepared, err := module.PrepareCommit(state.PrepareRequest{
					Loaded: loaded, CandidateReleaseIdentity: snapshot.ReleaseIdentity, ChangeSet: state.ChangeSetIdentity(request.ChangeSet), Candidate: candidate,
					SemanticValidators: state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring},
					ServiceMaterials:   state.ServiceMaterialsFor(candidate), RuntimeArtifacts: state.RuntimeArtifactContributions{profileRuntime, publicationResult.Plan},
					SubscriptionPublication: wiring, ReviewedInputs: reviewed,
				})
				if err != nil {
					return err
				}
				built = &builtClientAccess{plan: plan, prepared: prepared, candidate: candidate, candidateSHA: candidateSHA, starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: startingSHA}, disk: request.Disk, totalSteps: len(plan.Steps()), cloudflare: cloudflareExecutor}
				return nil
			})
		})
	})
	return built, err
}

func clientAccessNetworkIntent(desired state.DesiredState, revision uint64, disk systemchanges.DiskRequirement) networkpolicy.Intent {
	profiles := desired.ConnectionProfiles
	return networkpolicy.Intent{
		Revision: revision, Baseline: networkpolicy.Managed, PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6,
		PrimarySubscriptionAddress: desired.NetworkPolicy.PrimarySubscriptionAddress, CertificateHostname: desired.Certificates.DomainHostname, SSHPort: desired.NetworkPolicy.SSHPort,
		Profiles: networkpolicy.Profiles{
			VLESSRealityVision: networkpolicy.Profile{Enabled: profiles.VLESSRealityVision.Enabled, Port: profiles.VLESSRealityVision.Port},
			VLESSXHTTP:         networkpolicy.Profile{Enabled: profiles.VLESSXHTTP.Enabled, Address: profiles.VLESSXHTTP.OriginAddress, Port: profiles.VLESSXHTTP.OriginPort},
			VLESSWebSocket:     networkpolicy.Profile{Enabled: profiles.VLESSWebSocket.Enabled, Address: profiles.VLESSWebSocket.OriginAddress, Port: profiles.VLESSWebSocket.OriginPort},
			Hysteria2:          networkpolicy.Profile{Enabled: profiles.Hysteria2.Enabled, Port: profiles.Hysteria2.Port}, TUIC: networkpolicy.Profile{Enabled: profiles.TUIC.Enabled, Port: profiles.TUIC.Port}, AnyTLS: networkpolicy.Profile{Enabled: profiles.AnyTLS.Enabled, Port: profiles.AnyTLS.Port},
		},
		SubscriptionPort: desired.Subscription.ListenPort,
		Disk:             networkpolicy.DiskRequirement{PreparationBytes: disk.PreparationBytes, TemporaryBytes: disk.TemporaryBytes, SnapshotBytes: disk.SnapshotBytes, JournalBytes: disk.JournalBytes, RollbackBytes: disk.RollbackBytes, OverheadBytes: disk.OverheadBytes},
	}
}

func clientAccessManagedChecksums(plan *clientAccessPlan, profiles clientAccessProfilePlan, publication clientAccessPublicationPlan) (state.ManagedInputChecksums, error) {
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	return state.NewManagedInputChecksums(profiles.SHA256(), publication.SHA256(), digest("unchanged-cloudflare:"+plan.SHA256()), digest("unchanged-certificates:"+plan.SHA256()), digest("network-policy:"+plan.SHA256()), digest("unchanged-software:"+plan.SHA256()))
}

type clientAccessWiring struct {
	*clientAccessPlan
	current state.DesiredState
	network networkpolicy.Result
}

func (w *clientAccessWiring) StateRuntimeArtifactOwner() any { return w.profile }
func (w *clientAccessWiring) StateSubscriptionRuntimeArtifactOwner() any {
	return w.publication
}

func (w *clientAccessWiring) ValidateCloudflare(candidate state.CloudflareSettings, _ state.InfrastructureSecretReader) error {
	if w == nil || candidate != w.current.Cloudflare {
		return errors.New("Client Access change altered Cloudflare State")
	}
	return nil
}
func (w *clientAccessWiring) ValidateCertificates(candidate state.CertificateSettings) error {
	if w == nil || candidate != w.current.Certificates {
		return errors.New("Client Access change altered certificate State")
	}
	return nil
}
func (w *clientAccessWiring) ValidateNetworkPolicy(candidate state.NetworkPolicyInputs) error {
	if w == nil || candidate != w.current.NetworkPolicy || !w.network.MatchesDesiredState(candidate.SSHPort, candidate.PublicIPv4, candidate.PublicIPv6, candidate.PrimarySubscriptionAddress) {
		return errors.New("Client Access change altered Network Policy State")
	}
	return nil
}
func (w *clientAccessWiring) ValidateSoftwareLifecycle(candidate state.SoftwareLifecycleIntent) error {
	if w == nil || candidate.Installation != w.current.Installation || candidate.Software != w.current.Software {
		return errors.New("Client Access change altered Software Lifecycle State")
	}
	return nil
}
