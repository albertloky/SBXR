package installation

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type builtInstall struct {
	candidate     softwarelifecycle.InstallCandidate
	desired       state.DesiredState
	desiredSHA256 string
	plan          *softwarelifecycle.InstallPlan
	wiring        *installWiring
	cloudflare    *cloudflaretunnel.Plan
	cloudflareAPI cloudflaretunnel.MutationAPI
	inventory     cloudflaretunnel.MutationPlanner
	contributions []softwarelifecycle.InstallContribution
	networkIntent networkpolicy.Intent
	network       func(networkpolicy.Request) networkpolicy.Result
	disk          systemchanges.DiskRequirement
	totalSteps    int
	health        healthdiagnostics.InstallationSummary
}

func (built *builtInstall) prepareState(module state.Interface) (*state.PreparedCommit, error) {
	if built == nil || built.plan == nil || built.wiring == nil || built.cloudflare == nil {
		return nil, errors.New("complete install Plan unavailable")
	}
	loaded, err := module.Load(state.LoadRequest{Baseline: state.CleanVPS})
	if err != nil {
		return nil, err
	}
	proofs := make(map[softwarelifecycle.InstallContributionName]softwarelifecycle.InstallContributionProof, len(built.contributions))
	for _, contribution := range built.contributions {
		proof := contribution.SoftwareLifecycleInstallContribution()
		proofs[softwarelifecycle.InstallContributionName(proof.Name)] = proof
	}
	certificateDigest := sha256.Sum256([]byte(proofs[softwarelifecycle.IPCertificateInstallContribution].SHA256 + proofs[softwarelifecycle.DomainCertificateInstallContribution].SHA256))
	checksums, err := state.NewManagedInputChecksums(
		proofs[softwarelifecycle.ProfilesInstallContribution].SHA256,
		proofs[softwarelifecycle.SubscriptionInstallContribution].SHA256,
		proofs[softwarelifecycle.CloudflareInstallContribution].SHA256,
		hex.EncodeToString(certificateDigest[:]),
		proofs[softwarelifecycle.NetworkInstallContribution].SHA256,
		built.plan.SHA256(),
	)
	if err != nil {
		return nil, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(built.plan.Identity()), built.plan.SHA256(), checksums)
	if err != nil {
		return nil, err
	}
	release := candidateRelease(built.candidate)
	request := state.PrepareRequest{
		Loaded:                   loaded,
		CandidateReleaseIdentity: state.ReleaseIdentity{Repository: release.Repository, Tag: release.Tag, Commit: release.Commit, ReleaseIndexSHA256: release.IndexSHA256},
		ChangeSet:                state.ChangeSetIdentity("install-" + built.desired.Installation.ID[:16]),
		Candidate:                built.desired,
		SemanticValidators:       state.SemanticValidators{ConnectionProfiles: built.wiring, Subscription: built.wiring, Cloudflare: built.wiring, Certificates: built.wiring, NetworkPolicy: built.wiring, SoftwareLifecycle: built.wiring},
		ServiceMaterials:         state.ServiceMaterialsFor(built.desired),
		RuntimeArtifacts:         state.RuntimeArtifactContributions{built.wiring.profiles, built.wiring.cloudflare, built.wiring.subscription},
		SubscriptionPublication:  built.wiring,
		ReviewedInputs:           reviewed,
	}
	return module.PrepareDeferredCloudflareCommit(request, built.cloudflare)
}

type installClientReader struct {
	profiles state.ClientAccessReader
	token    state.ClientAccessValue
	rawToken string
}

func (reader installClientReader) ReadClientAccessValue(value state.ClientAccessValue) string {
	if value == reader.token {
		return reader.rawToken
	}
	return reader.profiles.ReadClientAccessValue(value)
}

type installSingBoxValidator struct{ host profilesubuntu.CandidateHost }

func (validator installSingBoxValidator) ValidateSingBox(ctx context.Context, document io.Reader) error {
	return validator.host.ValidateSingBox(ctx, "1.13.16", document)
}

type buildDependencies struct {
	stage         func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
	network       func(networkpolicy.Request) networkpolicy.Result
	cloudflare    func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult
	random        io.Reader
	cloudflareAPI cloudflaretunnel.MutationAPI
	inventory     cloudflaretunnel.MutationPlanner
}

type reclamationReviewError struct {
	plan *networkpolicy.ReclamationPlan
}

func (err *reclamationReviewError) Error() string { return "Reclaimable VPS review is required" }

func observeReclamationCloudflare(ctx context.Context, api cloudflaretunnel.MutationPlanner, account, zone string, token cloudflaretunnel.ManagementToken, tunnel string, hostnames []string) (networkpolicy.OwnerFacts, []cloudflaretunnel.ReclamationConflict, error) {
	facts := networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"}
	if api == nil {
		return networkpolicy.OwnerFacts{}, nil, errors.New("Cloudflare inventory unavailable")
	}
	var conflicts []cloudflaretunnel.ReclamationConflict
	seen := map[string]bool{}
	for _, hostname := range hostnames {
		observed, err := api.ObserveMutation(ctx, cloudflaretunnel.MutationRequest{AccountID: account, ZoneID: zone, Tunnel: tunnel, Hostname: hostname, Token: token})
		if err != nil {
			return networkpolicy.OwnerFacts{}, nil, err
		}
		for _, resource := range observed.Tunnels {
			key := "Tunnel\x00" + resource.ID + "\x00" + resource.Name
			if !seen[key] {
				routes := make([]networkpolicy.CloudflareRoute, len(observed.Routes))
				for index, route := range observed.Routes {
					routes[index] = networkpolicy.CloudflareRoute{Profile: route.Hostname, Origin: route.Service}
				}
				facts.Conflicts = append(facts.Conflicts, networkpolicy.CloudflareConflict{Kind: "Tunnel routes", ID: resource.ID, Name: resource.Name, Routes: routes}, networkpolicy.CloudflareConflict{Kind: "Tunnel", ID: resource.ID, Name: resource.Name})
				conflicts = append(conflicts, cloudflaretunnel.ReclamationConflict{Kind: cloudflaretunnel.ReclamationRoutes, ID: resource.ID, Name: resource.Name, Routes: append([]cloudflaretunnel.Route(nil), observed.Routes...)}, cloudflaretunnel.ReclamationConflict{Kind: cloudflaretunnel.ReclamationTunnel, ID: resource.ID, Name: resource.Name})
				seen[key] = true
			}
		}
		for _, resource := range observed.DNSRecords {
			facts.Conflicts = append(facts.Conflicts, networkpolicy.CloudflareConflict{Kind: "DNS record", ID: resource.ID, Name: resource.Name})
			conflicts = append(conflicts, cloudflaretunnel.ReclamationConflict{Kind: cloudflaretunnel.ReclamationDNS, ID: resource.ID, Name: resource.Name})
		}
	}
	order := func(kind cloudflaretunnel.ReclamationKind) int {
		if kind == cloudflaretunnel.ReclamationDNS {
			return 0
		}
		if kind == cloudflaretunnel.ReclamationRoutes {
			return 1
		}
		return 2
	}
	slices.SortStableFunc(conflicts, func(a, b cloudflaretunnel.ReclamationConflict) int {
		if result := cmp.Compare(order(a.Kind), order(b.Kind)); result != 0 {
			return result
		}
		return cmp.Compare(a.Name+a.ID, b.Name+b.ID)
	})
	slices.SortStableFunc(facts.Conflicts, func(a, b networkpolicy.CloudflareConflict) int {
		return cmp.Compare(a.Kind+a.Name+a.ID, b.Kind+b.Name+b.ID)
	})
	return facts, conflicts, nil
}

type installReleaseStager struct {
	stage func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
}

func (stager installReleaseStager) Stage(ctx context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	return stager.stage(ctx, request)
}

func buildInstallWith(ctx context.Context, request softwareubuntu.InstallHandoffRequest, dependencies buildDependencies) (*builtInstall, error) {
	if dependencies.stage == nil || dependencies.network == nil || dependencies.cloudflare == nil || dependencies.random == nil {
		return nil, errors.New("install composition dependencies unavailable")
	}
	candidate, err := softwarelifecycle.RebuildInstallCandidate(ctx, request.Candidate, installReleaseStager{dependencies.stage})
	if err != nil {
		return nil, errors.New("verified install candidate could not be rebuilt")
	}
	xrayVersion, singBoxVersion, cloudflaredVersion, certbotVersion, valid := candidate.ManagedComponentVersions()
	if !valid {
		return nil, errors.New("managed component versions are unavailable")
	}
	_, archive, components, valid := candidate.SoftwareLifecyclePreparedArchive()
	if !valid {
		return nil, errors.New("prepared release is unavailable")
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: uint64(len(archive) + len(components)), TemporaryBytes: uint64(len(archive) + len(components)), SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: uint64(len(archive) + len(components)), OverheadBytes: 256 << 20}
	networkDisk := networkpolicy.DiskRequirement{PreparationBytes: disk.PreparationBytes, TemporaryBytes: disk.TemporaryBytes, SnapshotBytes: disk.SnapshotBytes, JournalBytes: disk.JournalBytes, RollbackBytes: disk.RollbackBytes, OverheadBytes: disk.OverheadBytes}
	draft := request.Draft
	directHostname := "direct." + draft.Domain
	token, err := cloudflaretunnel.NewManagementToken(request.CloudflareToken)
	if err != nil {
		return nil, errors.New("Cloudflare management token refused")
	}
	ownerFacts, cloudflareConflicts, err := observeReclamationCloudflare(ctx, dependencies.inventory, request.CloudflareAccountID, request.CloudflareZoneID, token, "sbxr-main", []string{"xhttp." + draft.Domain, "ws." + draft.Domain, directHostname})
	if err != nil {
		return nil, errors.New("Cloudflare conflict inventory failed")
	}
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: draft.PublicIPv4, PublicIPv6: draft.PublicIPv6, PrimarySubscriptionAddress: draft.PrimaryAddress, CertificateHostname: directHostname, SSHPort: draft.SSHPort, SubscriptionPort: draft.SubscriptionPort, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: draft.RealityPort}, VLESSXHTTP: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}, VLESSWebSocket: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}, Hysteria2: networkpolicy.Profile{Enabled: true, Port: draft.Hysteria2Port}, TUIC: networkpolicy.Profile{Enabled: true, Port: draft.TUICPort}, AnyTLS: networkpolicy.Profile{Enabled: true, Port: draft.AnyTLSPort}}, Disk: networkDisk}
	baseNetwork := dependencies.network(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval, OwnerFacts: ownerFacts, ReclamationReview: true, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	if baseNetwork.Reclamation != nil && request.ReviewedReclamationSHA256 == "" {
		return nil, &reclamationReviewError{plan: baseNetwork.Reclamation}
	}
	httpIntent := intent
	httpIntent.TemporaryHTTP = true
	httpNetwork := dependencies.network(networkpolicy.Request{Intent: httpIntent, Stage: networkpolicy.PreApproval, OwnerFacts: ownerFacts, ReclamationReview: true, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	http01, postFirewallHTTP := networkpolicy.PrepareHTTP01AfterFirewallReclamation(baseNetwork, intent, httpIntent)
	if baseNetwork.Outcome == networkpolicy.Failed || httpNetwork.Outcome == networkpolicy.Failed && !postFirewallHTTP {
		return nil, errors.New("Clean VPS Network Policy refused the installation")
	}
	if !postFirewallHTTP {
		http01, postFirewallHTTP = httpNetwork.HTTP01Contribution()
	}
	if !postFirewallHTTP {
		return nil, errors.New("temporary HTTP-01 authority is unavailable")
	}

	credentials, err := connectionprofiles.GenerateRegistryCredentialsFrom(dependencies.random)
	if err != nil {
		return nil, err
	}
	directTLS := connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{Revision: 1, DestinationIP: draft.PrimaryAddress, Hostname: directHostname, Hysteria2: connectionprofiles.DirectTLSConsumer{Port: draft.Hysteria2Port, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, TUIC: connectionprofiles.DirectTLSConsumer{Port: draft.TUICPort, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, AnyTLS: connectionprofiles.DirectTLSConsumer{Port: draft.AnyTLSPort, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}})
	registry, err := connectionprofiles.NewFreshRegistry(connectionprofiles.RegistryViewRequest{ClientAddress: draft.PrimaryAddress, Reality: connectionprofiles.ViewRequest{Revision: 1, Port: draft.RealityPort, Target: connectionprofiles.RealityTarget{Address: request.RealityTarget, ServerName: request.RealityServerName}, Fingerprint: "chrome", XrayVersion: xrayVersion}, XHTTP: connectionprofiles.XHTTPViewRequest{Revision: 1, Hostname: "xhttp." + draft.Domain, OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp, XrayVersion: xrayVersion}, WebSocket: connectionprofiles.WebSocketViewRequest{Revision: 1, Hostname: "ws." + draft.Domain, TLSName: "ws." + draft.Domain, HTTPHost: "ws." + draft.Domain, OriginAddress: "127.0.0.1", OriginPort: 11081, XrayVersion: xrayVersion}, Hysteria2: connectionprofiles.Hysteria2ViewRequest{Revision: 1, DestinationIP: draft.PrimaryAddress, Port: draft.Hysteria2Port, ServerName: directHostname, CertificateID: "sbxr-domain", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: trimVersion(singBoxVersion), DirectTLS: directTLS}, TUIC: connectionprofiles.TUICViewRequest{Revision: 1, DestinationIP: draft.PrimaryAddress, Port: draft.TUICPort, ServerName: directHostname, CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: trimVersion(singBoxVersion), CongestionControl: state.CongestionCubic, DirectTLS: directTLS}, AnyTLS: connectionprofiles.AnyTLSViewRequest{Revision: 1, DestinationIP: draft.PrimaryAddress, Port: draft.AnyTLSPort, ServerName: directHostname, CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: trimVersion(singBoxVersion), UseCorePadding: true, DirectTLS: directTLS}, Exposure: networkpolicy.NewListenerContribution(baseNetwork)}, credentials)
	if err != nil {
		return nil, err
	}
	registryInputs, err := connectionprofiles.NewFreshRegistryInputs(registry)
	if err != nil {
		return nil, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(dependencies.random, tokenBytes); err != nil {
		return nil, errors.New("subscription token generation failed")
	}
	rawSubscriptionToken := hex.EncodeToString(tokenBytes)
	subscriptionToken := state.NewClientAccessValue(rawSubscriptionToken)
	networkState := state.NetworkPolicyInputs{SSHPort: draft.SSHPort, PublicIPv4: draft.PublicIPv4, PublicIPv6: draft.PublicIPv6, PrimarySubscriptionAddress: draft.PrimaryAddress}
	desired := state.DesiredState{Installation: state.InstallationIdentity{ID: request.Session, Domain: draft.Domain}, ConnectionProfiles: registryInputs.Profiles(), Subscription: state.SubscriptionSettings{Token: subscriptionToken, ListenPort: draft.SubscriptionPort, CertificateID: "sbxr-ip"}, Cloudflare: state.CloudflareSettings{AccountID: request.CloudflareAccountID, ZoneID: request.CloudflareZoneID, ZoneName: draft.Domain, TunnelName: "sbxr-main", ManagementToken: state.NewInfrastructureSecret(request.CloudflareToken), XHTTPHostname: "xhttp." + draft.Domain, WebSocketHostname: "ws." + draft.Domain, DirectHostname: directHostname}, Certificates: state.CertificateSettings{RenewalPolicy: true, OwnerEmail: draft.OwnerEmail, ACMEAccountID: "letsencrypt", IPCertificateID: "sbxr-ip", IPServingPointer: "/var/lib/sbxr/certificates/ip/current", DomainCertificateID: "sbxr-domain", DomainServingPointer: "/var/lib/sbxr/certificates/domain/current", DomainHostname: directHostname}, NetworkPolicy: networkState, Software: state.SoftwareSettings{XrayVersion: xrayVersion, SingBoxVersion: singBoxVersion, CloudflaredVersion: cloudflaredVersion, CertbotVersion: certbotVersion, AutomaticUpdateDiscovery: true}}
	if policy, ok := baseNetwork.ReclamationPolicy(); ok && policy.Held != nil {
		desired.Reclamation = state.ReclamationPolicy{Version: policy.Version, Held: state.HeldPackagePolicy{Name: policy.Held.Name, Version: policy.Held.Version, DeletedExecutable: policy.Path, SHA256: policy.SHA256}}
	}
	desiredSHA256, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, fmt.Errorf("Desired State candidate refused: %w", err)
	}
	changeSet := "install-" + request.Session[:16]
	cloudflareResult := dependencies.cloudflare(ctx, cloudflaretunnel.PlanRequest{Authority: cloudflaretunnel.ViewRequest{AccountID: request.CloudflareAccountID, ZoneID: request.CloudflareZoneID, ZoneName: draft.Domain, Token: token, NetworkPath: baseNetwork.CloudflareTunnelPath}, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA256, TunnelName: "sbxr-main", XHTTPHostname: "xhttp." + draft.Domain, WebSocketHostname: "ws." + draft.Domain, DirectHostname: directHostname, PublicIPv4: draft.PublicIPv4, PublicIPv6: draft.PublicIPv6, CloudflaredVersion: cloudflaredVersion, Reclamation: cloudflareConflicts})
	if cloudflareResult.Plan == nil {
		return nil, errors.New("Cloudflare install Plan refused")
	}

	certificateModule := certificatelifecycle.NewForFreshInstallation(candidate, installClock{})
	freshDNS := certificatelifecycle.NewFreshDNSAuthority(baseNetwork, cloudflareResult.Plan)
	certificateRequest := certificatelifecycle.PlanRequest{View: certificatelifecycle.ViewRequest{SelectedIP: draft.PrimaryAddress, DirectHostname: directHostname, QualifiedAddresses: selectedAddresses(draft), HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true}}, ChangeSet: changeSet, StartingRevision: 1, DesiredStateSHA256: desiredSHA256, HTTP01: http01, OwnerEmail: draft.OwnerEmail, SubscriberAgreementReviewed: true, FreshDNS: freshDNS}
	certificateRequest.Lineage = certificatelifecycle.IPLineage
	certificateRequest.FreshInstallation = systemchanges.NewFreshInstallationAuthority(baseNetwork.FreshInstallationProof())
	ipPlan := certificateModule.Plan(ctx, certificateRequest).Plan
	certificateRequest.Lineage = certificatelifecycle.DomainLineage
	certificateRequest.DirectTLS = directTLS
	certificateRequest.FreshInstallation = systemchanges.NewFreshInstallationAuthority(baseNetwork.FreshInstallationProof())
	domainPlan := certificateModule.Plan(ctx, certificateRequest).Plan
	if ipPlan == nil || domainPlan == nil {
		return nil, errors.New("both Certificate Lifecycle install Plans are required")
	}

	candidateHost, err := profilesubuntu.NewCandidateHost(candidate)
	if err != nil {
		return nil, err
	}
	startingRegistry := registry
	startingRegistry.Reality.Revision, startingRegistry.XHTTP.Revision, startingRegistry.WebSocket.Revision = 0, 0, 0
	startingRegistry.Hysteria2.Revision, startingRegistry.TUIC.Revision, startingRegistry.AnyTLS.Revision = 0, 0, 0
	startingRegistry.Reality.Port, startingRegistry.XHTTP.OriginPort, startingRegistry.WebSocket.OriginPort = 0, 0, 0
	startingRegistry.Hysteria2.Port, startingRegistry.TUIC.Port, startingRegistry.AnyTLS.Port = 0, 0, 0
	profileResult := connectionprofiles.New(candidateHost).PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: startingRegistry, Candidate: registry, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA256, FreshInstallation: systemchanges.NewFreshInstallationAuthority(baseNetwork.FreshInstallationProof())})
	if profileResult.Plan == nil {
		return nil, errors.New("Connection Profiles install Plan refused")
	}

	var subscriptionPlan *subscriptionpublication.Plan
	if err := registryInputs.WithClientAccessReader(func(profileReader state.ClientAccessReader) error {
		reader := installClientReader{profiles: profileReader, token: subscriptionToken, rawToken: rawSubscriptionToken}
		managedDigest := sha256.Sum256([]byte(profileResult.Plan.SHA256() + desiredSHA256))
		subscriptionDigest := sha256.Sum256([]byte(rawSubscriptionToken + fmt.Sprint(draft.SubscriptionPort)))
		module := subscriptionpublication.NewIntegrated(installSingBoxValidator{candidateHost})
		result := module.Plan(ctx, subscriptionpublication.PlanRequest{Source: registryInputs.PublicationSource(), Secrets: reader, Subscription: desired.Subscription, ChangeSet: changeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled}, DesiredStateRevision: 1, DesiredStateSHA256: desiredSHA256, ManagedInputsSHA256: hex.EncodeToString(managedDigest[:]), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profileResult.Plan.SHA256(), Subscription: hex.EncodeToString(subscriptionDigest[:])}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: draft.PrimaryAddress, ReleaseIdentity: state.ReleaseIdentity{Repository: candidateRelease(candidate).Repository, Tag: candidateRelease(candidate).Tag, Commit: candidateRelease(candidate).Commit, ReleaseIndexSHA256: candidateRelease(candidate).IndexSHA256}})
		subscriptionPlan = result.Plan
		if subscriptionPlan == nil {
			return errors.New("Subscription Publication install Plan refused")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	contributions := []softwarelifecycle.InstallContribution{softwarelifecycle.NewReviewedNetworkInstallContribution(baseNetwork, changeSet, desiredSHA256), profileResult.Plan, cloudflareResult.Plan, ipPlan, domainPlan, subscriptionPlan}
	installPlan, finding := softwarelifecycle.PlanInstall(softwarelifecycle.InstallPlanRequest{Candidate: candidate, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA256, Contributions: contributions, Disk: disk, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	if finding != nil || installPlan == nil || request.ReviewedPlanSHA256 != "" && installPlan.SHA256() != request.ReviewedPlanSHA256 {
		return nil, errors.New("reviewed install Plan changed")
	}
	wiring := &installWiring{install: installPlan, profiles: profileResult.Plan, subscription: subscriptionPlan, cloudflare: cloudflareResult.Plan, ip: ipPlan, domain: domainPlan, network: baseNetwork, networkState: networkState}
	totalSteps := 1
	for _, contribution := range contributions {
		totalSteps += len(contribution.SoftwareLifecycleInstallContribution().Steps)
	}
	health := healthdiagnostics.InstallationSummaryFrom(systemchanges.NewNotInstalledHealthInspection(baseNetwork.FreshInstallationProof()))
	return &builtInstall{candidate: candidate, desired: desired, desiredSHA256: desiredSHA256, plan: installPlan, wiring: wiring, cloudflare: cloudflareResult.Plan, cloudflareAPI: dependencies.cloudflareAPI, inventory: dependencies.inventory, contributions: contributions, networkIntent: intent, network: dependencies.network, disk: disk, totalSteps: totalSteps, health: health}, nil
}

type installEntropyReader struct {
	key     []byte
	counter uint64
	buffer  []byte
}

func newInstallEntropyReader(key []byte) io.Reader {
	return &installEntropyReader{key: append([]byte(nil), key...)}
}

func (reader *installEntropyReader) Read(destination []byte) (int, error) {
	written := 0
	for written < len(destination) {
		if len(reader.buffer) == 0 {
			reader.counter++
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, reader.counter)
			digest := hmac.New(sha256.New, reader.key)
			_, _ = digest.Write([]byte("SBXR revision 1 install entropy"))
			_, _ = digest.Write(counter)
			reader.buffer = digest.Sum(nil)
		}
		count := copy(destination[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}

type installClock struct{}

func (installClock) Now() time.Time { return time.Now() }

func trimVersion(version string) string {
	if len(version) > 0 && version[0] == 'v' {
		return version[1:]
	}
	return version
}

func selectedAddresses(draft softwarelifecycle.InstallationDraft) []string {
	result := []string{}
	if draft.PublicIPv4 != "" {
		result = append(result, draft.PublicIPv4)
	}
	if draft.PublicIPv6 != "" {
		result = append(result, draft.PublicIPv6)
	}
	return result
}

func candidateRelease(candidate softwarelifecycle.InstallCandidate) softwarelifecycle.ReleaseIdentity {
	staged, _, _, _ := candidate.SoftwareLifecyclePreparedArchive()
	return staged.Identity
}
