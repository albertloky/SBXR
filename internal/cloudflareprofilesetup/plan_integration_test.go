package cloudflareprofilesetup

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestPlanComposesSevenFreshOwningModuleResults(t *testing.T) {
	fixture := newPlanFixture(t)
	calls := 0
	module, err := New(Dependencies{
		NetworkPolicy: func(networkpolicy.Request) networkpolicy.Result { calls++; return fixture.network },
		CloudflareTunnel: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult {
			calls++
			return fixture.cloudflare
		},
		CertificateLifecycle: func(context.Context, certificatelifecycle.PlanRequest) certificatelifecycle.PlanResult {
			calls++
			return fixture.certificate
		},
		ConnectionProfiles: func(context.Context, connectionprofiles.RegistryPlanRequest) connectionprofiles.PlanResult {
			calls++
			return fixture.profiles
		},
		SubscriptionPublication: func(context.Context, subscriptionpublication.PlanRequest) subscriptionpublication.PlanResult {
			calls++
			return fixture.publication
		},
		State: StateDependency{
			Load: func(state.LoadRequest) (state.Result, error) { calls++; return fixture.loaded, nil },
			Prepare: func(state.PrepareRequest, state.DeferredCloudflareAuthority) (*state.PreparedCommit, error) {
				calls++
				return &state.PreparedCommit{}, nil
			},
		},
		SystemChanges: SystemChangesDependency{
			Inspect: func() systemchanges.Inspection {
				return systemchanges.Inspection{Status: systemchanges.Managed, Lock: systemchanges.LockReleased}
			},
			Apply: func(*systemchanges.ChangeSet, Execution) systemchanges.ApplyResult {
				return systemchanges.ApplyResult{}
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := module.Plan(t.Context(), fixture.request)
	if result.Plan == nil || result.Correction != nil || calls != 7 || len(result.Plan.steps) < 10 || len(result.Plan.Review()) != 8 {
		t.Fatalf("Plan = %+v calls=%d", result, calls)
	}
	if result.Plan.steps[0].Owner() != systemchanges.CloudflareModule || result.Plan.steps[1].Forward() != systemchanges.ActivatePreparedOrigins {
		t.Fatalf("ordered setup steps = %+v", result.Plan.steps[:2])
	}
	for _, marker := range []string{"PLAN-SECRET-MARKER", "profile-secret-marker", "subscription-secret-marker"} {
		if strings.Contains(result.Plan.String()+strings.Join(result.Plan.Review(), " "), marker) {
			t.Fatalf("Plan leaked %q", marker)
		}
	}
	t.Log("RELEASE-STAGED-ONBOARDING-MARKER-PROFILE-CREDENTIALS")
	t.Log("RELEASE-STAGED-ONBOARDING-MARKER-SUBSCRIPTION-TOKEN")
	reused := module.Plan(t.Context(), fixture.request)
	if reused.Plan != nil || reused.Correction == nil || reused.Correction.Code != "CLOUDFLARE-SETUP-CONTRIBUTION" {
		t.Fatalf("reused owning contribution = %+v", reused)
	}
}

type planFixture struct {
	request     PlanRequest
	loaded      state.Result
	network     networkpolicy.Result
	cloudflare  cloudflaretunnel.PlanResult
	certificate certificatelifecycle.PlanResult
	profiles    connectionprofiles.PlanResult
	publication subscriptionpublication.PlanResult
}

func newPlanFixture(t *testing.T) planFixture {
	t.Helper()
	current, candidate := registryRequests(t)
	_, preliminaryNetwork := setupNetwork(t, strings.Repeat("0", 64), "preliminary-setup")
	current.Exposure = networkpolicy.NewListenerContribution(preliminaryNetwork)
	candidate.Exposure = networkpolicy.NewCloudflareProfileSetupListenerContribution(preliminaryNetwork)
	currentProfiles, ok := connectionprofiles.DesiredProfiles(current)
	if !ok {
		t.Fatal("current profiles unavailable")
	}
	candidateProfiles, ok := connectionprofiles.DesiredProfiles(candidate)
	if !ok {
		view := connectionprofiles.New(setupProfileHost{}).ViewRegistry(t.Context(), candidate)
		t.Fatalf("candidate profiles unavailable: %+v", view.Health)
	}
	subscriptionToken := state.NewClientAccessValue("subscription-secret-marker")
	candidateState := state.DesiredState{
		Installation:       state.InstallationIdentity{ID: "550e8400-e29b-41d4-a716-446655440000", Domain: "example.com"},
		ConnectionProfiles: candidateProfiles,
		NetworkPolicy:      state.NetworkPolicyInputs{SSHPort: 2222, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10"},
		Subscription:       state.SubscriptionSettings{Token: subscriptionToken, ListenPort: 10443, CertificateID: "sbxr-ip"},
		Cloudflare:         state.CloudflareSettings{AccountID: strings.Repeat("1", 32), ZoneID: strings.Repeat("2", 32), ZoneName: "example.com", TunnelName: "sbxr-main", ManagementToken: state.NewInfrastructureSecret("sbxr_PLAN-SECRET-MARKER-000000000000000000000"), DedicatedBroadPolicyConfirmed: true, XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com"},
		Certificates:       state.CertificateSettings{RenewalPolicy: true, OwnerEmail: "owner@example.com", ACMEAccountID: "acme-account", IPCertificateID: "sbxr-ip", IPServingPointer: "/var/lib/sbxr/certificates/ip/current", DomainCertificateID: "sbxr-domain", DomainServingPointer: "/var/lib/sbxr/certificates/domain/current", DomainHostname: "direct.example.com"},
		Software:           state.SoftwareSettings{XrayVersion: "v26.3.27", SingBoxVersion: "1.13.16", CloudflaredVersion: "2026.7.3", CertbotVersion: "5.4.0", AutomaticUpdateDiscovery: true},
	}
	desiredSHA, err := state.CandidateSHA256(candidateState)
	if err != nil {
		t.Fatal(err)
	}
	const changeSet = "cloudflare-profile-setup-0008"
	startingSHA := strings.Repeat("a", 64)

	networkRequest, networkResult := setupNetwork(t, desiredSHA, changeSet)
	candidate.Exposure = networkpolicy.NewCloudflareProfileSetupListenerContribution(networkResult)
	if revision, digest, valid := candidate.Exposure.ConnectionProfilesRegistryBinding(); !valid || revision != 8 || len(digest) != 64 {
		t.Fatalf("candidate exposure = revision %d digest %q valid %t", revision, digest, valid)
	}
	profiles := connectionprofiles.New(setupProfileHost{}).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: changeSet, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA})
	if profiles.Plan == nil {
		t.Fatalf("profiles = %+v", profiles.Health)
	}

	cloudflareRequest, cloudflare := setupCloudflare(t, desiredSHA, startingSHA, changeSet, networkResult.CloudflareTunnelPath)
	if cloudflare.Plan == nil {
		t.Fatalf("cloudflare = %+v", cloudflare.Health)
	}
	certificateRequest, certificate := setupCertificate(t, desiredSHA, startingSHA, changeSet, networkResult, cloudflare.Plan, candidate)
	if certificate.Plan == nil {
		t.Fatalf("certificate = %+v", certificate.Health)
	}

	source, err := connectionprofiles.PublicationSourceFor("192.0.2.10", candidateProfiles)
	if err != nil {
		t.Fatal(err)
	}
	secrets := setupSecrets{values: map[state.ClientAccessValue]string{subscriptionToken: "subscription-secret-marker"}}
	addProfileSecrets(secrets.values, candidateProfiles)
	release := state.ReleaseIdentity{Repository: "albertloky/SBXR", Tag: "v1.13.20", Commit: strings.Repeat("b", 40), ReleaseIndexSHA256: strings.Repeat("c", 64)}
	publicationRequest := subscriptionpublication.PlanRequest{Source: source, Secrets: secrets, Subscription: candidateState.Subscription, ChangeSet: changeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: startingSHA}, DesiredStateRevision: 8, DesiredStateSHA256: desiredSHA, ManagedInputsSHA256: strings.Repeat("d", 64), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profiles.Plan.SHA256(), Subscription: strings.Repeat("e", 64)}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "192.0.2.10", ReleaseIdentity: release}
	publication := subscriptionpublication.NewIntegrated(setupPublicationValidator{}).Plan(t.Context(), publicationRequest)
	if publication.Plan == nil {
		t.Fatalf("publication = %+v", publication.Finding)
	}

	loaded := state.Result{Status: state.Managed, Snapshot: &state.Snapshot{Revision: 7, ReleaseIdentity: release, DesiredState: state.DesiredState{ConnectionProfiles: currentProfiles}}}
	request := PlanRequest{
		NetworkPolicy: networkRequest, CloudflareTunnel: cloudflareRequest, CertificateLifecycle: certificateRequest,
		ConnectionProfiles:      connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: changeSet, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA},
		SubscriptionPublication: publicationRequest,
		StatePrepare:            state.PrepareRequest{ChangeSet: state.ChangeSetIdentity(changeSet), CandidateReleaseIdentity: release, Candidate: candidateState},
		SoftwareLifecycleSHA256: strings.Repeat("f", 64), VolatileSHA256: strings.Repeat("9", 64),
		Disk:         systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
		Confirmation: func(systemchanges.CloudflareSetupConfirmationRequest) bool { return true },
	}
	return planFixture{request: request, loaded: loaded, network: networkResult, cloudflare: cloudflare, certificate: certificate, profiles: profiles, publication: publication}
}

type setupNetworkAdapter struct{ observed networkpolicy.Observations }

func (a setupNetworkAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return a.observed, nil
}

func setupNetwork(t *testing.T, desiredSHA, changeSet string) (networkpolicy.Request, networkpolicy.Result) {
	t.Helper()
	current := networkpolicy.Intent{Revision: 7, Baseline: networkpolicy.Managed, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", SSHPort: 2222, SubscriptionPort: 10443, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	candidate := current
	candidate.Revision, candidate.CertificateHostname = 8, "direct.example.com"
	candidate.Profiles.VLESSXHTTP = networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}
	candidate.Profiles.VLESSWebSocket = networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}
	candidate.Profiles.Hysteria2, candidate.Profiles.TUIC, candidate.Profiles.AnyTLS = networkpolicy.Profile{Enabled: true, Port: 443}, networkpolicy.Profile{Enabled: true, Port: 8443}, networkpolicy.Profile{Enabled: true, Port: 9443}
	observed := networkpolicy.Observations{Host: networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20}, PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "matches Desired State", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"}, Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true}, Disk: networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, Lineage: networkpolicy.ProvenLineage, OwnerFacts: networkpolicy.OwnerFacts{DNS: "absent", Tunnel: "absent"}, Listeners: []networkpolicy.Listener{{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned}, {Address: "0.0.0.0", Port: 10443, Protocol: networkpolicy.TCP, Service: "sbxr-subscription.service", Ownership: networkpolicy.SBXROwned}}, LocalProofs: []networkpolicy.LocalProof{{Purpose: "VLESS REALITY Vision", Address: "192.0.2.10", Port: 443, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}}
	request := networkpolicy.Request{Intent: current, Stage: networkpolicy.PostApproval, CloudflareProfileSetup: &networkpolicy.CloudflareProfileSetupRequest{Candidate: candidate, Binding: networkpolicy.ChangeSetBinding{StartingRevision: 7, CandidateRevision: 8, ChangeSetID: changeSet, DesiredStateSHA256: desiredSHA}}}
	result := networkpolicy.New(setupNetworkAdapter{observed}).Evaluate(request)
	if result.Outcome != networkpolicy.Healthy {
		t.Fatalf("network = %+v", result.Findings)
	}
	return request, result
}

type setupCloudflareAPI struct{}

func (setupCloudflareAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: strings.Repeat("1", 32)}, Zone: cloudflaretunnel.ZoneObservation{ID: strings.Repeat("2", 32), AccountID: strings.Repeat("1", 32), Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("4", 32), Status: "active"}, DNSListProven: true, TunnelListProven: true}, nil
}
func (setupCloudflareAPI) ObserveMutation(context.Context, cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Digest: strings.Repeat("5", 64)}, nil
}

type setupClock struct{}

func (setupClock) Now() time.Time                             { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }
func (setupClock) Sleep(context.Context, time.Duration) error { return nil }

func setupCloudflare(t *testing.T, desiredSHA, startingSHA, changeSet string, path networkpolicy.CloudflareTunnelPath) (cloudflaretunnel.PlanRequest, cloudflaretunnel.PlanResult) {
	t.Helper()
	token, err := cloudflaretunnel.NewManagementToken("sbxr_PLAN-SECRET-MARKER-000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	request := cloudflaretunnel.PlanRequest{Authority: cloudflaretunnel.ViewRequest{AccountID: strings.Repeat("1", 32), ZoneID: strings.Repeat("2", 32), ZoneName: "example.com", Token: token, NetworkPath: path, DedicatedBroadPolicyConfirmed: true}, ChangeSet: changeSet, StartingRevision: 7, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA, TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com", PublicIPv4: "192.0.2.10", CloudflaredVersion: "2026.7.3"}
	module := cloudflaretunnel.New(setupCloudflareAPI{}, setupClock{}, func(context.Context, []byte) error { return nil })
	return request, module.Plan(t.Context(), request)
}

type setupCertificateAdapter struct{}

func (setupCertificateAdapter) Observe(context.Context) (certificatelifecycle.Observation, error) {
	return certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "pip-venv", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true}, Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, ExactUnitPair: true, Randomized: true, NoCompetingScheduler: true, RunsPerDay: 2}}, nil
}

func setupCertificate(t *testing.T, desiredSHA, startingSHA, changeSet string, network networkpolicy.Result, cloudflare *cloudflaretunnel.Plan, candidate connectionprofiles.RegistryViewRequest) (certificatelifecycle.PlanRequest, certificatelifecycle.PlanResult) {
	t.Helper()
	http01, ok := network.CloudflareProfileSetup.HTTP01Contribution()
	if !ok {
		t.Fatal("HTTP-01 unavailable")
	}
	request := certificatelifecycle.PlanRequest{View: certificatelifecycle.ViewRequest{SelectedIP: "192.0.2.10", DirectHostname: "direct.example.com", QualifiedAddresses: []string{"192.0.2.10"}, HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true}}, Lineage: certificatelifecycle.DomainLineage, ChangeSet: changeSet, StartingRevision: 7, StartingStateSHA256: startingSHA, DesiredStateSHA256: desiredSHA, HTTP01: http01, DirectTLS: candidate.Hysteria2.DirectTLS, OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true, RenewalPolicyApproved: true, FreshDNS: certificatelifecycle.NewFreshDNSAuthority(network, cloudflare)}
	return request, certificatelifecycle.New(setupCertificateAdapter{}, setupClock{}).Plan(t.Context(), request)
}

type setupPublicationValidator struct{}

func (setupPublicationValidator) ValidateSingBox(context.Context, io.Reader) error { return nil }

type setupSecrets struct {
	values map[state.ClientAccessValue]string
}

func (s setupSecrets) ReadClientAccessValue(value state.ClientAccessValue) string {
	return s.values[value]
}

func addProfileSecrets(values map[state.ClientAccessValue]string, profiles state.ConnectionProfiles) {
	for value, secret := range map[state.ClientAccessValue]string{profiles.VLESSRealityVision.UUID: "profile-secret-marker", profiles.VLESSRealityVision.ShortID: "short-secret", profiles.VLESSXHTTP.UUID: "xhttp-uuid", profiles.VLESSXHTTP.Path: "xhttp-path", profiles.VLESSWebSocket.UUID: "ws-uuid", profiles.VLESSWebSocket.Path: "ws-path", profiles.Hysteria2.Password: "hysteria-password", profiles.Hysteria2.ObfuscationSecret: "hysteria-obfs", profiles.TUIC.UUID: "5f8f3e85-65d5-4fa4-8b4f-1f5ddfb52e0e", profiles.TUIC.Password: strings.Repeat("a", 32), profiles.AnyTLS.Password: strings.Repeat("b", 64)} {
		values[value] = secret
	}
}

type setupProfileHost struct{}

func (setupProfileHost) ValidateReality(context.Context, string, io.Reader) error { return nil }
func (setupProfileHost) ValidateSingBox(context.Context, string, io.Reader) error { return nil }
func (setupProfileHost) ObserveReality(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	return connectionprofiles.RealityObservation{CheckedAt: time.Now(), Probe: connectionprofiles.ProbePassed, Class: connectionprofiles.OrdinaryTarget, AcceptedNames: []string{"edge.example.net"}, RouteVerified: true, ServiceInstalled: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, ConfigurationSafe: true, Listener: connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "tcp"}, NetBindService: true, ProviderNetwork: true}
}
func (setupProfileHost) ObserveXHTTP(context.Context, uint16) connectionprofiles.XHTTPObservation {
	return connectionprofiles.XHTTPObservation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: connectionprofiles.Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}}
}
func (setupProfileHost) ObserveWebSocket(context.Context, uint16, string, string) connectionprofiles.WebSocketObservation {
	return connectionprofiles.WebSocketObservation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: connectionprofiles.Listener{Address: "127.0.0.1", Port: 11081, Protocol: "tcp"}, HostMatches: true, PathMatches: true}
}
func setupSingBoxObservation(port uint16, protocol string) connectionprofiles.Hysteria2Observation {
	return connectionprofiles.Hysteria2Observation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ConfigurationMatches: true, ServiceUnit: "sing-box.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: connectionprofiles.Listener{Address: "0.0.0.0", Port: port, Protocol: protocol}, NetBindService: true, ServerFunction: connectionprofiles.ProbePassed}
}
func (setupProfileHost) ObserveHysteria2(context.Context, connectionprofiles.Hysteria2ViewRequest) connectionprofiles.Hysteria2Observation {
	return setupSingBoxObservation(443, "udp")
}
func (setupProfileHost) ObserveTUIC(context.Context, connectionprofiles.Hysteria2ViewRequest, connectionprofiles.TUICViewRequest) connectionprofiles.TUICObservation {
	return setupSingBoxObservation(8443, "udp")
}
func (setupProfileHost) ObserveAnyTLS(context.Context, connectionprofiles.Hysteria2ViewRequest, connectionprofiles.TUICViewRequest, connectionprofiles.AnyTLSViewRequest) connectionprofiles.AnyTLSObservation {
	return setupSingBoxObservation(9443, "tcp")
}
func (setupProfileHost) ObserveCoreCapabilities(context.Context) connectionprofiles.CoreCapabilityObservation {
	return connectionprofiles.CoreCapabilityObservation{CheckedAt: time.Now()}
}
func (setupProfileHost) ObserveDeferredRegistry(context.Context) connectionprofiles.DeferredRegistryObservation {
	return connectionprofiles.DeferredRegistryObservation{CheckedAt: time.Now(), XrayRealityOnly: true, SingBoxConfigurationAbsent: true, SingBoxServiceDisabled: true, SingBoxServiceInactive: true}
}

func registryRequests(t *testing.T) (connectionprofiles.RegistryViewRequest, connectionprofiles.RegistryViewRequest) {
	t.Helper()
	reality, err := connectionprofiles.GenerateRealityCredentials()
	if err != nil {
		t.Fatal(err)
	}
	base := connectionprofiles.RegistryViewRequest{ClientAddress: "192.0.2.10", Reality: connectionprofiles.ViewRequest{Revision: 7, Enabled: true, Port: 443, Target: connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net"}, Fingerprint: "chrome", XrayVersion: "v26.3.27", Credentials: reality}, XHTTP: connectionprofiles.XHTTPViewRequest{Revision: 7, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp, XrayVersion: "v26.3.27", RouteHealth: cloudflaretunnel.XHTTPRouteHealth{Hostname: "xhttp.example.com", Origin: "http://127.0.0.1:11080", Health: cloudflaretunnel.Health{Module: "Cloudflare Tunnel", Outcome: cloudflaretunnel.Healthy, Code: "CLOUDFLARE-XHTTP-ROUTE-HEALTHY"}}}, WebSocket: connectionprofiles.WebSocketViewRequest{Revision: 7, Hostname: "ws.example.com", TLSName: "ws.example.com", HTTPHost: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081, XrayVersion: "v26.3.27", RouteHealth: cloudflaretunnel.WebSocketRouteHealth{Hostname: "ws.example.com", Origin: "http://127.0.0.1:11081", Health: cloudflaretunnel.Health{Module: "Cloudflare Tunnel", Outcome: cloudflaretunnel.Healthy, Code: "CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY"}}}, Hysteria2: connectionprofiles.Hysteria2ViewRequest{Revision: 7, DestinationIP: "192.0.2.10", Port: 443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16"}, TUIC: connectionprofiles.TUICViewRequest{Revision: 7, DestinationIP: "192.0.2.10", Port: 8443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", CongestionControl: state.CongestionCubic}, AnyTLS: connectionprofiles.AnyTLSViewRequest{Revision: 7, DestinationIP: "192.0.2.10", Port: 9443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: "1.13.16", UseCorePadding: true}}
	current, err := connectionprofiles.NewRevisionOneRegistry(base, reality)
	if err != nil {
		t.Fatal(err)
	}
	candidate := base
	candidate.Reality = current.Reality
	candidate.Reality.Revision, candidate.XHTTP.Revision, candidate.WebSocket.Revision, candidate.Hysteria2.Revision, candidate.TUIC.Revision, candidate.AnyTLS.Revision = 8, 8, 8, 8, 8, 8
	direct := connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{Revision: 8, DestinationIP: "192.0.2.10", Hostname: "direct.example.com", Hysteria2: connectionprofiles.DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, TUIC: connectionprofiles.DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, AnyTLS: connectionprofiles.DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}})
	candidate.Hysteria2.DirectTLS, candidate.TUIC.DirectTLS, candidate.AnyTLS.DirectTLS = direct, direct, direct
	credentials, err := connectionprofiles.GenerateDeferredRegistryCredentials()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = connectionprofiles.NewDeferredRegistry(candidate, credentials)
	if err != nil {
		t.Fatal(err)
	}
	return current, candidate
}
