package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type clientAccessPresentation struct {
	Installation  ownerconsole.InstallationStatus
	Release       state.ReleaseIdentity
	StateRevision uint64
	StateSHA256   string
	Repair        systemchanges.Observation
	Profiles      ownerconsole.ProfilesPresentation
	Access        ownerconsole.AccessPresentation
	Cloudflare    ownerconsole.CloudflarePresentation
	Certificates  ownerconsole.CertificatesPresentation
	Lifecycle     ownerconsole.LifecyclePresentation
	Recovery      ownerconsole.RecoveryPresentation
	health        map[healthdiagnostics.Module]healthdiagnostics.HealthStatus
}

func managedClientAccessPresentation(ctx context.Context) (clientAccessPresentation, error) {
	pending, pendingErr := pendingInstallRecovery()
	if pendingErr == nil && pending {
		if _, _, forwardOnly, checkpoint, err := systemubuntu.RecoveryStartingRelease("/"); err == nil {
			entries, readErr := os.ReadDir(installTransactions)
			if readErr == nil && len(entries) == 1 {
				recovery := ownerRecovery{changeSet: entries[0].Name(), forwardOnly: forwardOnly, needsRunTokenRotation: checkpoint == systemchanges.IrreversibleRunTokenRotationStarted}
				return clientAccessPresentation{Installation: ownerconsole.InstallationRecoveryRequired, Recovery: recovery.ViewRecovery(ctx)}, nil
			}
		}
		return clientAccessPresentation{Installation: ownerconsole.InstallationRecoveryRequired, Recovery: ownerRecovery{}.ViewRecovery(ctx)}, nil
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return clientAccessPresentation{Installation: ownerconsole.InstallationRecoveryRequired, Recovery: ownerRecovery{}.ViewRecovery(ctx)}, nil
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil {
		return clientAccessPresentation{}, err
	}
	presentation := clientAccessPresentation{Installation: ownerconsole.InstallationManaged, Release: release, StateRevision: observed.StateRevision, StateSHA256: observed.StateSHA256, health: map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{healthdiagnostics.StateModule: healthdiagnostics.Healthy}}
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, secrets state.ConnectionProfileSecretReader) error {
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				if snapshot.DesiredState.Cloudflare.ManagementTokenRemoved {
					provider := managedProviderPresentations(ctx, snapshot, cloudflareSecrets, networkpolicy.Result{})
					presentation.Cloudflare, presentation.Certificates = provider.cloudflare, provider.certificates
					presentation.health[healthdiagnostics.CloudflareTunnelModule] = healthdiagnostics.HealthStatus(provider.cloudflareHealth)
					return nil
				}
				disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
				network, xhttp, websocket, err := observeManagedClientAccess(ctx, snapshot, cloudflareSecrets, disk)
				if err != nil {
					return err
				}
				presentation.health[healthdiagnostics.NetworkPolicyModule] = healthdiagnostics.HealthStatus(network.Outcome)
				request, err := clientAccessRegistryRequest(snapshot.DesiredState, snapshot.Revision, secrets, connectionprofiles.RegistryExposureAuthority(networkpolicy.NewListenerContribution(network)), xhttp, websocket)
				if err != nil {
					return err
				}
				host := profilesubuntu.NewRealityHost("/")
				registry := connectionprofiles.New(host).ViewRegistry(ctx, request)
				if len(registry.Profiles) != 6 {
					return errors.New("Managed Connection Profiles presentation unavailable")
				}
				presentation.health[healthdiagnostics.ConnectionProfilesModule] = healthdiagnostics.HealthStatus(registry.Health.Outcome)
				source, err := connectionprofiles.PublicationSourceFor(snapshot.DesiredState.NetworkPolicy.PrimarySubscriptionAddress, snapshot.DesiredState.ConnectionProfiles)
				if err != nil {
					return err
				}
				publication := subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: host, version: trimVersion(snapshot.DesiredState.Software.SingBoxVersion)})
				artifacts, err := publication.Render(ctx, source, publicationSecrets)
				if err != nil {
					return err
				}
				allProfiles := snapshot.DesiredState.ConnectionProfiles
				allProfiles.VLESSRealityVision.Enabled, allProfiles.VLESSXHTTP.Enabled, allProfiles.VLESSWebSocket.Enabled = true, true, true
				allProfiles.Hysteria2.Enabled, allProfiles.TUIC.Enabled, allProfiles.AnyTLS.Enabled = true, true, true
				fullSource, err := connectionprofiles.PublicationSourceFor(snapshot.DesiredState.NetworkPolicy.PrimarySubscriptionAddress, allProfiles)
				if err != nil {
					return err
				}
				fullArtifacts, err := publication.Render(ctx, fullSource, publicationSecrets)
				if err != nil {
					return err
				}
				presentation.Profiles = ownerProfilesPresentation(snapshot.DesiredState, registry.Profiles)
				presentation.Access = ownerAccessPresentation(snapshot.DesiredState, source, artifacts, fullSource, fullArtifacts, publicationSecrets)
				provider := managedProviderPresentations(ctx, snapshot, cloudflareSecrets, network)
				presentation.Cloudflare, presentation.Certificates = provider.cloudflare, provider.certificates
				presentation.health[healthdiagnostics.CloudflareTunnelModule] = healthdiagnostics.HealthStatus(provider.cloudflareHealth)
				presentation.health[healthdiagnostics.CertificateLifecycleModule] = healthdiagnostics.HealthStatus(provider.certificateHealth)
				publicationStorage, storageErr := subscriptionfilesystem.New(func(proofContext context.Context, address string) error {
					return proveInstalledSubscription(proofContext, address, snapshot.DesiredState.Subscription.ListenPort)
				})
				if storageErr == nil {
					if published, observeErr := publicationStorage.ObserveCurrent("/", 30*time.Second); observeErr == nil {
						view := publication.View(subscriptionpublication.ViewRequest{Source: source, SubscriptionAddress: net.JoinHostPort(snapshot.DesiredState.NetworkPolicy.PrimarySubscriptionAddress, strconv.Itoa(int(snapshot.DesiredState.Subscription.ListenPort))), DesiredStateRevision: snapshot.Revision, PublishedRevision: published.Revision, DesiredStateSHA256: observed.StateSHA256, PublishedStateSHA256: published.StateSHA256, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, PublishedCompatibility: published.Compatibility})
						presentation.health[healthdiagnostics.SubscriptionPublicationModule] = publicationHealth(view.Status, published.Serving)
					}
				}
				return nil
			})
		})
	})
	if err == nil && loaded.Snapshot != nil {
		presentation.health[healthdiagnostics.SubscriptionServingModule] = healthdiagnostics.HealthStatus(subscriptionserving.Inspect().Status)
		if repair, repairErr := inspectSoftwareRepair(ctx); repairErr == nil && repair.ForwardRepairAvailable {
			presentation.Recovery = (ownerRecovery{currentStateRepair: true}).ViewRecovery(ctx)
			presentation.Repair = repair
		}
	}
	if err == nil {
		if lifecycle, _, _, lifecycleErr := managedSoftwareLifecyclePresentation(ctx, release); lifecycleErr == nil {
			presentation.Lifecycle = lifecycle
		}
	}
	return presentation, err
}

func publicationHealth(status subscriptionpublication.PublicationStatus, serving systemchanges.HealthStatus) healthdiagnostics.HealthStatus {
	if status == subscriptionpublication.PublicationCurrent && serving == systemchanges.Healthy {
		return healthdiagnostics.Healthy
	}
	if status == subscriptionpublication.PublicationNeedsRegeneration || status == subscriptionpublication.PublicationNotPublished {
		return healthdiagnostics.NeedsAttention
	}
	if serving == systemchanges.Failed {
		return healthdiagnostics.Failed
	}
	return healthdiagnostics.Unknown
}

func ownerProfilesPresentation(desired state.DesiredState, observed []connectionprofiles.RegistryProfile) ownerconsole.ProfilesPresentation {
	type profilePresentation struct {
		id                 connectionprofiles.ProfileID
		address, transport string
		port               uint16
		settings           string
	}
	profiles := [...]profilePresentation{
		{connectionprofiles.VLESSRealityVisionProfileID, desired.NetworkPolicy.PrimarySubscriptionAddress, "VLESS REALITY Vision", desired.ConnectionProfiles.VLESSRealityVision.Port, desired.ConnectionProfiles.VLESSRealityVision.Fingerprint},
		{connectionprofiles.VLESSXHTTPProfileID, desired.Cloudflare.XHTTPHostname, "VLESS XHTTP", 443, string(desired.ConnectionProfiles.VLESSXHTTP.Mode)},
		{connectionprofiles.VLESSWebSocketProfileID, desired.Cloudflare.WebSocketHostname, "VLESS WebSocket", 443, "TLS WebSocket"},
		{connectionprofiles.Hysteria2ProfileID, desired.NetworkPolicy.PrimarySubscriptionAddress, "Hysteria2", desired.ConnectionProfiles.Hysteria2.Port, "QUIC"},
		{connectionprofiles.TUICProfileID, desired.NetworkPolicy.PrimarySubscriptionAddress, "TUIC v5", desired.ConnectionProfiles.TUIC.Port, string(desired.ConnectionProfiles.TUIC.CongestionControl)},
		{connectionprofiles.AnyTLSProfileID, desired.NetworkPolicy.PrimarySubscriptionAddress, "AnyTLS", desired.ConnectionProfiles.AnyTLS.Port, desired.ConnectionProfiles.AnyTLS.PaddingScheme},
	}
	result := ownerconsole.ProfilesPresentation{Managed: true}
	for index, expected := range profiles {
		profile := observed[index]
		health := ownerProfileHealth(profile.Health.Outcome)
		result.Profiles[index] = ownerconsole.ProfilePresentation{ID: ownerconsole.AccessProfileID(index + 1), Enabled: profile.Enabled, Service: health, Listener: health, Address: expected.address, Port: expected.port, Transport: expected.transport, Settings: expected.settings, Exposed: profile.Enabled && profile.SelectedListener.Port != 0, Published: profile.Enabled, CredentialRetained: !profile.Enabled}
		if profile.ID != expected.id {
			return ownerconsole.ProfilesPresentation{}
		}
	}
	return result
}

func ownerProfileHealth(outcome connectionprofiles.Outcome) ownerconsole.ProfileHealth {
	switch outcome {
	case connectionprofiles.Healthy:
		return ownerconsole.ProfileHealthy
	case connectionprofiles.Disabled:
		return ownerconsole.ProfileDisabled
	case connectionprofiles.NeedsAttention:
		return ownerconsole.ProfileNeedsAttention
	case connectionprofiles.Failed:
		return ownerconsole.ProfileFailed
	default:
		return ownerconsole.ProfileUnknown
	}
}

func ownerAccessPresentation(desired state.DesiredState, source connectionprofiles.PublicationSource, artifacts subscriptionpublication.Artifacts, fullSource connectionprofiles.PublicationSource, full subscriptionpublication.Artifacts, secrets state.ClientAccessReader) ownerconsole.AccessPresentation {
	var result ownerconsole.AccessPresentation
	lines := strings.Split(string(full.Raw), "\n")
	for index, profile := range fullSource.Profiles() {
		if index < len(lines) {
			result.Profiles[profileIndex(profile.ID)] = ownerconsole.AccessProfile{ShareURI: lines[index]}
		}
	}
	token := secrets.ReadClientAccessValue(desired.Subscription.Token)
	base := "https://" + net.JoinHostPort(desired.NetworkPolicy.PrimarySubscriptionAddress, strconv.Itoa(int(desired.Subscription.ListenPort))) + "/s/" + token
	disabled := ownerOmissions(source.Omissions())
	supported := append([]ownerconsole.AccessOmission(nil), disabled...)
	if desired.ConnectionProfiles.VLESSXHTTP.Enabled {
		supported = append(supported, ownerconsole.AccessOmission{Profile: ownerconsole.XHTTPProfile, Status: ownerconsole.NotOffered})
	}
	sort.Slice(supported, func(i, j int) bool { return supported[i].Profile < supported[j].Profile })
	result.Links = [6]ownerconsole.AccessLink{
		{URL: base, ProfileCount: artifacts.ProfileCount, Omissions: disabled},
		{URL: base + string(subscriptionpublication.V2RayNRepresentation), ProfileCount: artifacts.ProfileCount, Omissions: disabled},
		{URL: base + string(subscriptionpublication.ShadowrocketRepresentation), ProfileCount: artifacts.ProfileCount, Omissions: disabled, OwnerAcceptancePending: enabledOwnerProfiles(source)},
		{URL: base + string(subscriptionpublication.KaringRepresentation), ProfileCount: artifacts.Karing.ProfileCount, Omissions: supported},
		{URL: base + string(subscriptionpublication.MihomoRepresentation), ProfileCount: artifacts.ProfileCount, Omissions: disabled},
		{URL: base + string(subscriptionpublication.SingBoxRepresentation), ProfileCount: artifacts.SingBox.ProfileCount, Omissions: supported},
	}
	return result
}

func ownerOmissions(omissions []connectionprofiles.PublicationOmission) []ownerconsole.AccessOmission {
	result := make([]ownerconsole.AccessOmission, 0, len(omissions))
	for _, omission := range omissions {
		result = append(result, ownerconsole.AccessOmission{Profile: ownerconsole.AccessProfileID(profileIndex(omission.ID) + 1), Status: ownerconsole.Disabled})
	}
	return result
}

func enabledOwnerProfiles(source connectionprofiles.PublicationSource) []ownerconsole.AccessProfileID {
	result := make([]ownerconsole.AccessProfileID, 0, len(source.Profiles()))
	for _, profile := range source.Profiles() {
		result = append(result, ownerconsole.AccessProfileID(profileIndex(profile.ID)+1))
	}
	return result
}

func profileIndex(id connectionprofiles.ProfileID) int {
	return map[connectionprofiles.ProfileID]int{connectionprofiles.VLESSRealityVisionProfileID: 0, connectionprofiles.VLESSXHTTPProfileID: 1, connectionprofiles.VLESSWebSocketProfileID: 2, connectionprofiles.Hysteria2ProfileID: 3, connectionprofiles.TUICProfileID: 4, connectionprofiles.AnyTLSProfileID: 5}[id]
}
