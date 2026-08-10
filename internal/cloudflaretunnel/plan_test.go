package cloudflaretunnel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type freshDNSNetworkAdapter struct{ observed networkpolicy.Observations }

func (adapter freshDNSNetworkAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return adapter.observed, nil
}

type freshDNSCertificateAdapter struct{}

func (freshDNSCertificateAdapter) Observe(context.Context) (certificatelifecycle.Observation, error) {
	return certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "pip-venv", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true}, Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, ExactUnitPair: true, Randomized: true, NoCompetingScheduler: true, RunsPerDay: 2}}, nil
}

type freshDNSClock struct{}

func (freshDNSClock) Now() time.Time { return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) }

func TestFreshCloudflarePlanSuppliesOnlyTheExactPendingCertificateDNS(t *testing.T) {
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", CertificateHostname: "direct.example.com", SSHPort: 2222, SubscriptionPort: 10443, TemporaryHTTP: true, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443}, VLESSXHTTP: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}, VLESSWebSocket: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}, Hysteria2: networkpolicy.Profile{Enabled: true, Port: 443}, TUIC: networkpolicy.Profile{Enabled: true, Port: 8443}, AnyTLS: networkpolicy.Profile{Enabled: true, Port: 9443}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	observed := networkpolicy.Observations{Host: networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20}, PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"}, Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true}, Disk: networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"}, Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: intent.CertificateHostname}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}}
	network := networkpolicy.New(freshDNSNetworkAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval})
	cloudflare := &Plan{identity: "fresh-cloudflare-plan", sha256: strings.Repeat("a", 64), request: PlanRequest{Authority: ViewRequest{ZoneName: "example.com"}, ChangeSet: "fresh-cloudflare", DesiredStateSHA256: strings.Repeat("b", 64), TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: intent.CertificateHostname, PublicIPv4: intent.PublicIPv4, CloudflaredVersion: qualifiedCloudflaredVersion}}
	authority := certificatelifecycle.NewFreshDNSAuthority(network, cloudflare)
	http01, ok := network.HTTP01Contribution()
	if !ok {
		t.Fatal("pending DNS Network Policy omitted HTTP-01 authority")
	}
	module := certificatelifecycle.New(freshDNSCertificateAdapter{}, freshDNSClock{})
	result := module.Plan(t.Context(), certificatelifecycle.PlanRequest{View: certificatelifecycle.ViewRequest{SelectedIP: intent.PrimarySubscriptionAddress, DirectHostname: intent.CertificateHostname, QualifiedAddresses: []string{intent.PublicIPv4}, HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true}}, Lineage: certificatelifecycle.IPLineage, ChangeSet: "fresh-certificate-ip", StartingRevision: 1, DesiredStateSHA256: strings.Repeat("b", 64), HTTP01: http01, OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true, FreshInstallation: systemchanges.NewFreshInstallationAuthority(network.FreshInstallationProof()), FreshDNS: authority})
	if result.Plan == nil || result.Health.Outcome != certificatelifecycle.Healthy {
		t.Fatalf("fresh certificate Plan = %+v", result)
	}

	cloudflare.request.DirectHostname = "other.example.com"
	stale := certificatelifecycle.NewFreshDNSAuthority(network, cloudflare)
	if rendered := fmt.Sprintf("%+v", stale); !strings.Contains(rendered, "redacted") {
		t.Fatalf("stale fresh DNS authority rendered unexpectedly: %s", rendered)
	}
}

const (
	testAccountID = "11111111111111111111111111111111"
	testZoneID    = "22222222222222222222222222222222"
	testTunnelID  = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	testDNSID     = "33333333333333333333333333333333"
)

func TestPlanBindsCompleteSecretSafeCloudflareInstallation(t *testing.T) {
	module, request := plannedModule(t)
	first, second := module.Plan(context.Background(), request), module.Plan(context.Background(), request)
	if first.Plan == nil || second.Plan == nil || first.Health.Outcome != Healthy || first.Plan.Identity() != second.Plan.Identity() || first.Plan.SHA256() != second.Plan.SHA256() {
		t.Fatalf("deterministic Plan = first %+v second %+v", first, second)
	}
	preview := fmt.Sprintf("%+v %#v %s", first, first.Plan, first.Plan)
	for _, required := range []string{xhttpOrigin, webSocketOrigin, "HTTP 404 fallback", "cloudflared.service", "--token-file " + cloudflaredTokenPath} {
		if !strings.Contains(preview, required) {
			t.Fatalf("Plan omitted %q: %s", required, preview)
		}
	}
	if strings.Contains(preview, "PLAN-SECRET-MARKER") {
		t.Fatalf("Plan leaked token: %s", preview)
	}
	steps := first.Plan.Steps()
	if len(steps) != 7 {
		t.Fatalf("steps = %d, want Tunnel, routes, three DNS records, and service", len(steps))
	}
	for index, step := range steps {
		change, ok := step.CloudflareChange()
		if index == len(steps)-1 {
			if ok || step.Owner() != systemchanges.CloudflareModule || step.Forward() != systemchanges.ActivatePreparedConfiguration {
				t.Fatalf("last step is not protected cloudflared activation: %#v", step)
			}
			continue
		}
		if !ok {
			t.Fatalf("step %d has no typed Cloudflare contract", index+1)
		}
		if change.TunnelIDFromStep > 0 && change.TunnelIDFromStep >= index+1 {
			t.Fatalf("step %d references non-durable evidence", index+1)
		}
	}
	routes, _ := steps[1].CloudflareChange()
	if len(routes.Routes) != 3 || routes.Routes[2].Origin != "http_status:404" {
		t.Fatalf("routes = %#v", routes.Routes)
	}
	if _, _, _, ok := first.Plan.StateDeferredCloudflare(); !ok {
		t.Fatal("State finalization authority unavailable")
	}
}

func TestPlanReleaseUpdateRestartsOnlyTheVerifiedOwnedCloudflaredService(t *testing.T) {
	module, request := plannedModule(t)
	request.StartingRevision = 7
	request.StartingStateSHA256 = strings.Repeat("c", 64)
	request.ReleaseUpdate = true
	request.CandidateServiceUnit = strings.Replace(CloudflaredServiceUnit(), "/usr/bin/cloudflared", "/opt/sbxr/releases/v1.1.0-candidate/cloudflared", 1)
	request.ManagedRepair = OwnedTunnelBinding{TunnelID: testTunnelID, XHTTPDNSRecordID: testDNSID, WebSocketDNSRecordID: strings.Repeat("5", 32), DirectIPv4RecordID: strings.Repeat("6", 32), DirectIPv6RecordID: strings.Repeat("7", 32)}
	module.api.(*planningAPI).wholeTunnel = healthyWholeTunnel(request)
	result := module.Plan(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != Healthy {
		t.Fatalf("Plan(release update) = %+v", result)
	}
	contribution := result.Plan.SoftwareLifecycleUpdateContribution()
	if contribution.Name != "Cloudflare Tunnel" || contribution.Owner != systemchanges.CloudflareModule || len(contribution.Steps) != 1 || contribution.Steps[0].Forward() != systemchanges.ActivatePreparedConfiguration || len(contribution.Checks) != 2 {
		t.Fatalf("update contribution = %+v", contribution)
	}
	if repair := result.Plan.SoftwareLifecycleRepairContribution(); repair.Name != "" {
		t.Fatalf("release update also exposed repair authority = %+v", repair)
	}
}

func TestPlanNamesOwnerAssistedRunTokenRotationAndBindsOwnedIdentifiers(t *testing.T) {
	module, request := plannedModule(t)
	request.StartingRevision = 7
	request.StartingStateSHA256 = strings.Repeat("c", 64)
	request.ChangeSet = "cloudflare-run-token-rotation"
	request.RunTokenRotation = RunTokenRotation{
		TunnelID: testTunnelID, XHTTPDNSRecordID: testDNSID,
		WebSocketDNSRecordID: "44444444444444444444444444444444",
		DirectIPv4RecordID:   "55555555555555555555555555555555",
		DirectIPv6RecordID:   "66666666666666666666666666666666",
	}
	api := module.api.(*planningAPI)
	api.wholeTunnel = healthyWholeTunnel(request)
	result := module.Plan(context.Background(), request)
	if result.Plan == nil || result.Health.Outcome != Healthy || result.Health.Code != "CLOUDFLARE-RUN-TOKEN-ROTATION-READY" {
		t.Fatalf("rotation Plan = %+v", result)
	}
	steps := result.Plan.Steps()
	change, ok := steps[0].CloudflareChange()
	if len(steps) != 1 || !ok || change.Action != systemchanges.CloudflareRunTokenActivate || change.TunnelID != testTunnelID {
		t.Fatalf("rotation steps = %#v", steps)
	}
	preview := fmt.Sprintf("%+v %#v %s", result, result.Plan, result.Plan)
	for _, required := range []string{"Owner selects Rotate token", "forward-only recovery", testTunnelID} {
		if !strings.Contains(preview, required) {
			t.Fatalf("rotation preview omitted %q: %s", required, preview)
		}
	}
	if strings.Contains(preview, "PLAN-SECRET-MARKER") {
		t.Fatalf("rotation Plan leaked management token: %s", preview)
	}
	if source, _, templateSHA, valid := result.Plan.StateRunTokenRotation(); source == nil || templateSHA != request.DesiredStateSHA256 || !valid {
		t.Fatal("rotation Plan omitted its protected State handoff")
	}
	if !result.Plan.MatchesDesiredState(request.Authority.AccountID, request.Authority.ZoneID, request.Authority.ZoneName, request.TunnelName, request.XHTTPHostname, request.WebSocketHostname, request.DirectHostname, request.PublicIPv4, request.PublicIPv6, request.Authority.Token.value) {
		t.Fatal("managed rotation Plan did not match its Desired State authority")
	}
}

func TestManagedRepairPlansOnlyCommittedOwnedDriftAndBlocksConflicts(t *testing.T) {
	module, request := managedRepairRequest(t)
	api := module.api.(*planningAPI)
	api.wholeTunnel = healthyWholeTunnel(request)
	api.wholeTunnel.Connected = false
	api.wholeTunnel.Routes = []Route{{Hostname: request.XHTTPHostname, Service: "https://wrong.example"}}
	api.wholeTunnel.DNSRecords[0].Content = "wrong.example"
	result := module.Plan(t.Context(), request)
	if result.Plan == nil || result.Health.Code != "CLOUDFLARE-REPAIR-READY" {
		t.Fatalf("repair Plan = %+v", result)
	}
	steps := result.Plan.Steps()
	if len(steps) != 3 {
		t.Fatalf("repair steps = %#v", steps)
	}
	routes, _ := steps[0].CloudflareChange()
	dns, _ := steps[1].CloudflareChange()
	if routes.Action != systemchanges.CloudflareRoutesPut || routes.TunnelID != testTunnelID || dns.Action != systemchanges.CloudflareDNSRepair || dns.DNSRecordID != testDNSID || steps[2].Forward() != systemchanges.ActivatePreparedConfiguration {
		t.Fatalf("typed repair steps = %#v", steps)
	}
	if _, binding, templateSHA, valid := result.Plan.StateCloudflareRepair(); len(binding) == 0 || templateSHA != request.DesiredStateSHA256 || !valid {
		t.Fatal("repair omitted its State ownership binding")
	}
	if contribution := result.Plan.SoftwareLifecycleRepairContribution(); contribution.Name != "Cloudflare Tunnel" || contribution.Owner != systemchanges.CloudflareModule || contribution.CurrentRevision != 7 || contribution.CurrentStateSHA256 != request.StartingStateSHA256 || len(contribution.Steps) != 3 || len(contribution.Checks) == 0 {
		t.Fatalf("Software Lifecycle repair contribution = %+v", contribution)
	}
	api.mutations[request.XHTTPHostname] = MutationObservation{Digest: strings.Repeat("d", 64), Tunnels: []OwnedResource{{ID: testTunnelID, Name: request.TunnelName}}, DNSRecords: []OwnedResource{{ID: strings.Repeat("9", 32), Name: request.XHTTPHostname}}}
	blocked := module.Plan(t.Context(), request)
	if blocked.Plan != nil || blocked.Health.Code != "CLOUDFLARE-REPAIR-OWNERSHIP" || blocked.Health.Problem == "" || blocked.Health.Found == "" || blocked.Health.Required == "" || blocked.Health.WhyStopped == "" || fmt.Sprint(blocked.Health.NextActions) != "[Check again Back]" {
		t.Fatalf("unowned conflict = %+v", blocked)
	}
}

func TestManagedRepairStopsDeterministicProviderFailureAndBoundsTemporaryRetries(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		calls int
		wait  time.Duration
	}{
		{name: "deterministic", err: APIError{Kind: APIPermanent}, calls: 1},
		{name: "temporary", err: APIError{Kind: APITemporary}, calls: 3, wait: time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			module, request := managedRepairRequest(t)
			api := module.api.(*planningAPI)
			api.mutationErr = test.err
			result := module.Plan(t.Context(), request)
			if result.Plan != nil || result.Health.Problem == "" || result.Health.Evidence == "" || api.mutationCalls != test.calls || module.clock.(*planClock).elapsed != test.wait {
				t.Fatalf("provider failure = %+v calls=%d wait=%s", result, api.mutationCalls, module.clock.(*planClock).elapsed)
			}
		})
	}
}

func managedRepairRequest(t *testing.T) (Interface, PlanRequest) {
	t.Helper()
	module, request := plannedModule(t)
	request.StartingRevision = 7
	request.StartingStateSHA256 = strings.Repeat("c", 64)
	request.ChangeSet = "cloudflare-managed-repair"
	request.ManagedRepair = RunTokenRotation{TunnelID: testTunnelID, XHTTPDNSRecordID: testDNSID, WebSocketDNSRecordID: strings.Repeat("4", 32), DirectIPv4RecordID: strings.Repeat("5", 32), DirectIPv6RecordID: strings.Repeat("6", 32)}
	api := module.api.(*planningAPI)
	tunnel := []OwnedResource{{ID: testTunnelID, Name: request.TunnelName}}
	api.mutations = map[string]MutationObservation{
		request.XHTTPHostname:     {Digest: strings.Repeat("a", 64), Tunnels: tunnel, DNSRecords: []OwnedResource{{ID: testDNSID, Name: request.XHTTPHostname}}},
		request.WebSocketHostname: {Digest: strings.Repeat("b", 64), Tunnels: tunnel, DNSRecords: []OwnedResource{{ID: strings.Repeat("4", 32), Name: request.WebSocketHostname}}},
		request.DirectHostname:    {Digest: strings.Repeat("c", 64), Tunnels: tunnel, DNSRecords: []OwnedResource{{ID: strings.Repeat("5", 32), Name: request.DirectHostname}, {ID: strings.Repeat("6", 32), Name: request.DirectHostname}}},
	}
	return module, request
}

func TestPlanRefusesUnownedConflictAndUnqualifiedCloudflared(t *testing.T) {
	module, request := plannedModule(t)
	api := module.api.(*planningAPI)
	api.suffixFree = true
	api.conflictHostname = request.XHTTPHostname
	api.mutation = MutationObservation{Digest: strings.Repeat("a", 64), DNSRecords: []OwnedResource{{ID: testDNSID, Name: request.XHTTPHostname}}}
	if result := module.Plan(context.Background(), request); result.Plan != nil || result.Health.Code != "CLOUDFLARE-UNOWNED-CONFLICT" || len(result.SuggestedHostnames) != 1 || result.SuggestedHostnames[0] == request.XHTTPHostname || !strings.HasSuffix(result.SuggestedHostnames[0], ".example.com") {
		t.Fatalf("conflict Plan = %+v", result)
	}
	request.CloudflaredVersion = "2026.7.2"
	if result := module.Plan(context.Background(), request); result.Plan != nil {
		t.Fatalf("unqualified cloudflared Plan = %+v", result)
	}
}

func TestPlanRechecksEveryConflictingOwnedHostname(t *testing.T) {
	for _, selectHostname := range []func(*PlanRequest) *string{
		func(request *PlanRequest) *string { return &request.XHTTPHostname },
		func(request *PlanRequest) *string { return &request.WebSocketHostname },
		func(request *PlanRequest) *string { return &request.DirectHostname },
	} {
		module, request := plannedModule(t)
		hostname := selectHostname(&request)
		api := module.api.(*planningAPI)
		api.suffixFree, api.conflictHostname = true, *hostname
		api.mutation = MutationObservation{Digest: strings.Repeat("a", 64), DNSRecords: []OwnedResource{{ID: testDNSID, Name: *hostname}}}
		conflict := module.Plan(context.Background(), request)
		if conflict.Health.Code != "CLOUDFLARE-UNOWNED-CONFLICT" || len(conflict.SuggestedHostnames) != 1 {
			t.Fatalf("conflict = %+v", conflict)
		}
		*hostname = conflict.SuggestedHostnames[0]
		if approved := module.Plan(context.Background(), request); approved.Plan == nil || approved.Health.Outcome != Healthy {
			t.Fatalf("approved suffix Plan = %+v", approved)
		}
	}
}

func TestHostnameSuggestionReplacesAnEarlierReviewedSuffix(t *testing.T) {
	for _, label := range []string{"xhttp", "ws", "direct"} {
		first := suggestHostname(label+".example.com", strings.Repeat("a", 64))
		second := suggestHostname(first, strings.Repeat("b", 64))
		if !validOwnedHostname(second, "example.com", label) || strings.Count(strings.Split(second, ".")[0], "-") != 1 {
			t.Fatalf("second %s suggestion = %q", label, second)
		}
	}
}

func TestPlanPublishesDirectDNSOnlyForQualifiedAddressFamilies(t *testing.T) {
	for _, test := range []struct {
		name, ipv4, ipv6 string
		wantType         string
	}{
		{name: "IPv4", ipv4: "192.0.2.10", wantType: "A"},
		{name: "IPv6", ipv6: "2001:db8::10", wantType: "AAAA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			module, request := plannedModule(t)
			request.PublicIPv4, request.PublicIPv6 = test.ipv4, test.ipv6
			result := module.Plan(context.Background(), request)
			if result.Plan == nil || result.Health.Outcome != Healthy {
				t.Fatalf("Plan = %+v", result)
			}
			steps := result.Plan.Steps()
			if len(steps) != 6 {
				t.Fatalf("steps = %d, want five provider changes and service activation", len(steps))
			}
			direct, ok := steps[4].CloudflareChange()
			if !ok || direct.Hostname != request.DirectHostname || direct.RecordType != test.wantType || direct.Content != test.ipv4+test.ipv6 {
				t.Fatalf("Direct DNS step = %#v", direct)
			}
		})
	}
}

func TestPlanRefusesUnqualifiedAddressesAndHostnames(t *testing.T) {
	for _, change := range []func(*PlanRequest){
		func(request *PlanRequest) { request.PublicIPv4 = "2001:db8::10" },
		func(request *PlanRequest) { request.PublicIPv6 = "192.0.2.10" },
		func(request *PlanRequest) { request.XHTTPHostname = "other.example.com" },
		func(request *PlanRequest) { request.DirectHostname = "direct.example.net" },
	} {
		module, request := plannedModule(t)
		change(&request)
		if result := module.Plan(context.Background(), request); result.Plan != nil || result.Health.Code != "CLOUDFLARE-PLAN-REFUSED" {
			t.Fatalf("unqualified Plan = %+v", result)
		}
	}
}

func TestPlanApplyRefusesDifferentStartingRevision(t *testing.T) {
	module, request := plannedModule(t)
	plan := module.Plan(context.Background(), request).Plan
	result := plan.Apply(systemchanges.Interface{}, &fakePreparedState{}, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: strings.Repeat("a", 64)}, strings.Repeat("b", 64), systemchanges.DiskRequirement{})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("changed revision Apply = %+v", result)
	}
	rebuilt := module.Plan(context.Background(), request).Plan
	if rebuilt == nil || rebuilt.used == nil || !rebuilt.used.Load() {
		t.Fatal("rebuilt identical Plan did not share consumed authority")
	}
	second := rebuilt.Apply(systemchanges.Interface{}, &fakePreparedState{}, systemchanges.StateLineage{Status: systemchanges.NotInstalled}, strings.Repeat("b", 64), systemchanges.DiskRequirement{})
	if second.Finding == nil || second.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("reused Plan Apply = %+v", second)
	}
}

func TestPlanReviewsManagementTokenReplacementWithoutChangingProviderAuthority(t *testing.T) {
	module, request := managedTokenPlanRequest(t, ManagementTokenReplace)
	result := module.Plan(context.Background(), request)
	if result.Plan == nil || result.Health.Outcome != Healthy || result.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-READY" || result.WritesProven {
		t.Fatalf("replacement Plan = %+v", result)
	}
	if len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 2 || result.Plan.Steps()[0].Forward() != systemchanges.RecordManagementTokenChange {
		t.Fatalf("replacement transaction = steps %#v checks %#v", result.Plan.Steps(), result.Plan.Checks())
	}
	preview := fmt.Sprintf("%+v %#v %s", result, result.Plan, result.Plan)
	for _, required := range []string{"stored management token changes only at State publication", "old token remains active", "resources remain unchanged"} {
		if !strings.Contains(preview, required) {
			t.Fatalf("replacement preview omitted %q: %s", required, preview)
		}
	}
	if strings.Contains(preview, "PLAN-SECRET-MARKER") {
		t.Fatalf("replacement preview leaked token: %s", preview)
	}
	source, _, templateSHA, valid := result.Plan.StateManagementTokenChange()
	if source == nil || templateSHA != request.DesiredStateSHA256 || !valid {
		t.Fatal("replacement Plan omitted the one-use State handoff")
	}
	if !result.Plan.MatchesDesiredState(request.Authority.AccountID, request.Authority.ZoneID, request.Authority.ZoneName, request.TunnelName, request.XHTTPHostname, request.WebSocketHostname, request.DirectHostname, request.PublicIPv4, request.PublicIPv6, request.Authority.Token.value) {
		t.Fatal("managed replacement Plan did not match its Desired State authority")
	}
	request.ManagementToken.CurrentTokenID = healthyAuthorityObservation().Token.ID
	if same := module.Plan(context.Background(), request); same.Plan != nil || same.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-UNCHANGED" {
		t.Fatalf("same-token replacement = %+v", same)
	}
}

func TestPlanReplacesADeliberatelyRemovedManagementToken(t *testing.T) {
	module, request := managedTokenPlanRequest(t, ManagementTokenReplace)
	request.ManagementToken.CurrentTokenID = ""
	request.ManagementToken.StartingTokenRemoved = true
	result := module.Plan(t.Context(), request)
	if result.Plan == nil || result.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-READY" {
		t.Fatalf("removed-token replacement Plan = %+v", result)
	}
}

func TestManagementTokenPlanApplyBindsManagedLineageAndBurnsEveryOutcome(t *testing.T) {
	module, request := managedTokenPlanRequest(t, ManagementTokenReplace)
	plan := module.Plan(context.Background(), request).Plan
	prepared := &tokenPreparedState{changeSet: request.ChangeSet, revision: 8, starting: request.StartingStateSHA256, candidate: strings.Repeat("d", 64), planIdentity: plan.Identity(), planSHA: plan.SHA256()}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: request.StartingStateSHA256}
	result := plan.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("e", 64), disk)
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !result.PlanConsumed {
		t.Fatalf("valid token Apply = %+v", result)
	}
	identical := module.Plan(context.Background(), request).Plan
	if reused := identical.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("e", 64), disk); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("reused token Apply = %+v", reused)
	}
	freshModule, freshRequest := managedTokenPlanRequest(t, ManagementTokenReplace)
	freshRequest.ChangeSet = "cloudflare-token-change-2"
	fresh := freshModule.Plan(context.Background(), freshRequest).Plan
	prepared.changeSet, prepared.planIdentity, prepared.planSHA = freshRequest.ChangeSet, fresh.Identity(), fresh.SHA256()
	if stale := fresh.Apply(systemchanges.Interface{}, prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("f", 64)}, strings.Repeat("e", 64), disk); stale.Finding == nil || stale.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("stale token Apply = %+v", stale)
	}
}

type tokenPreparedState struct {
	changeSet, starting, candidate, planIdentity, planSHA string
	revision                                              uint64
}

func (prepared *tokenPreparedState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.planIdentity, prepared.planSHA, true
}

func (*tokenPreparedState) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }

func managedTokenPlanRequest(t *testing.T, action ManagementTokenAction) (Interface, PlanRequest) {
	t.Helper()
	module, request := plannedModule(t)
	request.StartingRevision = 7
	request.StartingStateSHA256 = strings.Repeat("c", 64)
	request.ManagementToken = ManagementTokenChange{Action: action, CurrentTokenID: strings.Repeat("5", 32)}
	if action == ManagementTokenRemove {
		request.Authority.Token = ManagementToken{}
	}
	return module, request
}

func plannedModule(t *testing.T) (Interface, PlanRequest) {
	t.Helper()
	token, err := NewManagementToken("cfat_PLAN-SECRET-MARKER-000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	api := &planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}
	request := PlanRequest{Authority: ViewRequest{AccountID: testAccountID, ZoneID: testZoneID, ZoneName: "example.com", Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}}, ChangeSet: "cloudflare-change-0001", DesiredStateSHA256: strings.Repeat("b", 64), TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com", PublicIPv4: "192.0.2.10", PublicIPv6: "2001:db8::10", CloudflaredVersion: qualifiedCloudflaredVersion}
	return New(api, &planClock{}), request
}

type planningAPI struct {
	observation      Observation
	mutation         MutationObservation
	suffixFree       bool
	conflictHostname string
	wholeTunnel      WholeTunnelObservation
	mutations        map[string]MutationObservation
	mutationErr      error
	mutationCalls    int
}

func (api *planningAPI) ObserveWholeTunnel(context.Context, WholeTunnelRequest) (WholeTunnelObservation, error) {
	return api.wholeTunnel, nil
}

func healthyWholeTunnel(request PlanRequest) WholeTunnelObservation {
	rotation := request.RunTokenRotation
	if rotation.TunnelID == "" {
		rotation = request.ManagedRepair
	}
	return WholeTunnelObservation{
		TunnelID: rotation.TunnelID, Connected: true,
		Routes: []Route{{Hostname: request.XHTTPHostname, Service: xhttpOrigin}, {Hostname: request.WebSocketHostname, Service: webSocketOrigin}, {Service: "http_status:404"}},
		DNSRecords: []DNSObservation{
			{ID: rotation.XHTTPDNSRecordID, Name: request.XHTTPHostname, Type: "CNAME", Content: rotation.TunnelID + ".cfargotunnel.com", Proxied: true},
			{ID: rotation.WebSocketDNSRecordID, Name: request.WebSocketHostname, Type: "CNAME", Content: rotation.TunnelID + ".cfargotunnel.com", Proxied: true},
			{ID: rotation.DirectIPv4RecordID, Name: request.DirectHostname, Type: "A", Content: request.PublicIPv4},
			{ID: rotation.DirectIPv6RecordID, Name: request.DirectHostname, Type: "AAAA", Content: request.PublicIPv6},
		},
		XHTTPOriginReachable: true, WebSocketOriginReachable: true,
	}
}

func (api *planningAPI) Observe(context.Context, ObservationRequest) (Observation, error) {
	return api.observation, nil
}

func (api *planningAPI) ObserveMutation(_ context.Context, request MutationRequest) (MutationObservation, error) {
	api.mutationCalls++
	if api.mutationErr != nil {
		return MutationObservation{}, api.mutationErr
	}
	if observed, ok := api.mutations[request.Hostname]; ok {
		return observed, nil
	}
	if api.suffixFree && strings.Contains(strings.Split(request.Hostname, ".")[0], "-") {
		return MutationObservation{Digest: strings.Repeat("c", 64)}, nil
	}
	if api.conflictHostname != "" && request.Hostname != api.conflictHostname {
		return MutationObservation{Digest: strings.Repeat("a", 64)}, nil
	}
	return api.mutation, nil
}

type planClock struct{ elapsed time.Duration }

func (clock *planClock) Now() time.Time {
	return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC).Add(clock.elapsed)
}
func (clock *planClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.elapsed += duration
	return nil
}

func healthyAuthorityObservation() Observation {
	return Observation{Account: AccountObservation{ID: testAccountID}, Zone: ZoneObservation{ID: testZoneID, AccountID: testAccountID, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: TokenObservation{ID: "44444444444444444444444444444444", Status: "active"}, Policies: []TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + testAccountID: "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + testZoneID: "*"}}}}
}

var _ systemchanges.PreparedStateCommit = (*fakePreparedState)(nil)

type fakePreparedState struct{}

func (*fakePreparedState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return "", 0, "", "", "", "", false
}
func (*fakePreparedState) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }
