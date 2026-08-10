package connectionprofiles_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRegistryUsesEveryReviewedAlternativePort(t *testing.T) {
	request := validRegistryRequest(t)
	request.Reality.Port = 20000
	request.XHTTP.OriginPort = 20001
	request.WebSocket.OriginPort = 20002
	request.Hysteria2.Port = 20003
	request.TUIC.Port = 20004
	request.AnyTLS.Port = 20005
	directTLSForSelectedPorts(&request)
	request.XHTTP.RouteHealth = healthyXHTTPRoute(request.XHTTP.Hostname, request.XHTTP.OriginPort)
	request.WebSocket.RouteHealth = healthyWebSocketRoute(request.WebSocket.Hostname, request.WebSocket.OriginPort)
	request.Exposure = registryPolicyContribution(request)

	host := healthyRegistryHost(request)
	host.webSocketHost.xhttpHost.realityHost.observation.Listener.Port = request.Reality.Port
	host.webSocketHost.xhttpHost.observation.Listener.Port = request.XHTTP.OriginPort
	host.webSocketHost.observation.Listener.Port = request.WebSocket.OriginPort
	host.tuicHost.hysteria2Host.observation.Listener.Port = request.Hysteria2.Port
	host.tuicHost.observation.Listener.Port = request.TUIC.Port
	host.observation.Listener.Port = request.AnyTLS.Port
	result := connectionprofiles.New(host).ViewRegistry(t.Context(), request)

	if result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("alternative-port registry = %+v", result)
	}
	want := []uint16{20000, 20001, 20002, 20003, 20004, 20005}
	for index, profile := range result.Profiles {
		if profile.SelectedListener.Port != want[index] || profile.Listener.Port != want[index] {
			t.Fatalf("profile %s listeners = selected %+v active %+v", profile.ID, profile.SelectedListener, profile.Listener)
		}
	}
	for index, profile := range result.Publication.Profiles() {
		if profile.Port != want[index] && profile.ID != connectionprofiles.VLESSXHTTPProfileID && profile.ID != connectionprofiles.VLESSWebSocketProfileID {
			t.Fatalf("publication %s port = %d, want %d", profile.ID, profile.Port, want[index])
		}
	}
}

func TestBlockedProfileAlwaysOffersOneRedactedCorrectionFlow(t *testing.T) {
	health := connectionprofiles.New(healthyRegistryHost(validRegistryRequest(t))).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{}).Health
	flow := health.CorrectionFlow()
	if flow.FixWithSBXR == "" || flow.OwnerWork != "" || flow.CheckAgain != "Check again" || flow.Back != "Back" || flow.Evidence == "" || strings.Contains(flow.Evidence, anyTLSPasswordMarker) {
		t.Fatalf("Correction Flow = %+v", flow)
	}
	externalRequest := validRealityRequest(t)
	externalRequest.Target.Address = "other.example.net:443"
	external := connectionprofiles.New(&realityHost{observation: healthyRealityObservation()}).View(t.Context(), externalRequest).Health.CorrectionFlow()
	if external.FixWithSBXR != "" || external.OwnerWork == "" {
		t.Fatalf("external Correction Flow = %+v", external)
	}
	hysteria2 := validHysteria2Request(t)
	hysteria2.Network = nil
	ownedNetwork := connectionprofiles.New(healthyHysteria2Host()).ViewHysteria2(t.Context(), hysteria2).Health.CorrectionFlow()
	if ownedNetwork.FixWithSBXR == "" || ownedNetwork.OwnerWork != "" {
		t.Fatalf("SBXR-owned Network Policy Correction Flow = %+v", ownedNetwork)
	}
}

type updateQualificationHost struct {
	*anyTLSHost
	xrayVersion, singBoxVersion string
	xray, singBox               []byte
}

func (host *updateQualificationHost) ValidateReality(_ context.Context, version string, configuration io.Reader) error {
	host.xrayVersion, host.xray = version, mustRead(configuration)
	return nil
}

func (host *updateQualificationHost) ValidateSingBox(_ context.Context, version string, configuration io.Reader) error {
	host.singBoxVersion, host.singBox = version, mustRead(configuration)
	return nil
}

func mustRead(reader io.Reader) []byte {
	value, _ := io.ReadAll(reader)
	return value
}

func TestCoreUpdateRequalificationValidatesCompleteCandidateAndResetsAcceptance(t *testing.T) {
	request := validRegistryRequest(t)
	host := &updateQualificationHost{anyTLSHost: healthyRegistryHost(request)}
	result := connectionprofiles.New(host).RequalifyCoreUpdate(t.Context(), connectionprofiles.CoreUpdateRequalificationRequest{Registry: request, XrayVersion: "v27.0.0", SingBoxVersion: "1.14.0"})
	if !result.NativeConfigurationPassed || result.ReplacementAllowed || result.AutomatedAcceptance != connectionprofiles.AcceptancePending || result.LiveAcceptance != connectionprofiles.AcceptancePending || result.OwnerAcceptance != connectionprofiles.AcceptancePending || result.Health.Outcome != connectionprofiles.NeedsAttention {
		t.Fatalf("core update requalification = %+v", result)
	}
	if host.xrayVersion != "v27.0.0" || host.singBoxVersion != "1.14.0" {
		t.Fatalf("native versions = %q %q", host.xrayVersion, host.singBoxVersion)
	}
	for _, tag := range []string{"vless-reality-vision", "vless-xhttp", "vless-websocket"} {
		if !bytes.Contains(host.xray, []byte(tag)) {
			t.Fatalf("candidate Xray omitted %q: %s", tag, host.xray)
		}
	}
	for _, tag := range []string{"hysteria2", "tuic", "anytls"} {
		if !bytes.Contains(host.singBox, []byte(tag)) {
			t.Fatalf("candidate sing-box omitted %q: %s", tag, host.singBox)
		}
	}
}

func TestRegistryPlanPropagatesReviewedAlternativePortsIntoNativeConfigurations(t *testing.T) {
	current, candidate := validRegistryRequest(t), validRegistryRequest(t)
	setRegistryRevision(&current, 0)
	setRegistryRevision(&candidate, 1)
	candidate.Reality.Port, candidate.XHTTP.OriginPort, candidate.WebSocket.OriginPort = 20000, 20001, 20002
	candidate.Hysteria2.Port, candidate.TUIC.Port, candidate.AnyTLS.Port = 20003, 20004, 20005
	directTLSForSelectedPorts(&candidate)
	candidate.XHTTP.RouteHealth = healthyXHTTPRoute(candidate.XHTTP.Hostname, candidate.XHTTP.OriginPort)
	candidate.WebSocket.RouteHealth = healthyWebSocketRoute(candidate.WebSocket.Hostname, candidate.WebSocket.OriginPort)
	candidate.Exposure = registryPolicyContribution(candidate)
	cleanHost := healthyRegistryHost(candidate)
	cleanHost.webSocketHost.xhttpHost.realityHost.observation = connectionprofiles.RealityObservation{}
	blocked := connectionprofiles.New(cleanHost).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-unapproved-ports", DesiredStateSHA256: strings.Repeat("b", 64)})
	if blocked.Plan != nil || blocked.Health.Outcome == connectionprofiles.Healthy {
		t.Fatalf("committed ports moved without fresh-install authority: %+v", blocked)
	}
	fresh := systemchanges.New(managedStatusAdapter{observation: systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased}}).FreshInstallationAuthority()
	result := connectionprofiles.New(cleanHost).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-reviewed-ports", DesiredStateSHA256: strings.Repeat("b", 64), FreshInstallation: fresh})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || !registryPlanIsReversible(result.Plan) {
		t.Fatalf("alternative-port Plan = %+v", result)
	}
	profiles, secrets := completeProfileStateForAnyTLS()
	profiles.VLESSRealityVision.Port, profiles.VLESSXHTTP.OriginPort, profiles.VLESSWebSocket.OriginPort = 20000, 20001, 20002
	profiles.Hysteria2.Port, profiles.TUIC.Port, profiles.AnyTLS.Port = 20003, 20004, 20005
	xray, singBox, err := result.Plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`"port":20000`, `"port":20001`, `"port":20002`} {
		if !bytes.Contains(xray, []byte(marker)) {
			t.Fatalf("Xray configuration omitted %s: %s", marker, xray)
		}
	}
	for _, marker := range []string{`"listen_port":20003`, `"listen_port":20004`, `"listen_port":20005`} {
		if !bytes.Contains(singBox, []byte(marker)) {
			t.Fatalf("sing-box configuration omitted %s: %s", marker, singBox)
		}
	}
	prepared := &realityPreparedState{changeSet: "profiles-reviewed-ports", revision: 1, candidate: strings.Repeat("b", 64), planIdentity: result.Plan.Identity(), planSHA: result.Plan.SHA256()}
	applied := result.Plan.Apply(systemchanges.Interface{}, prepared, systemchanges.StateLineage{Status: systemchanges.NotInstalled}, result.Plan.VolatileSHA256(), systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1})
	if applied.Finding == nil || applied.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" {
		t.Fatalf("fresh alternative-port Apply = %+v", applied)
	}
}

func TestRegistryPlansSingleAndCoordinatedCredentialReplacement(t *testing.T) {
	current := validRegistryRequest(t)
	for name, replace := range map[string]func(*connectionprofiles.RegistryViewRequest) error{
		"single profile": func(candidate *connectionprofiles.RegistryViewRequest) error {
			credentials, err := connectionprofiles.NewAnyTLSCredentials(strings.Repeat("d", 64))
			candidate.AnyTLS.Credentials = credentials
			return err
		},
		"all profiles": func(candidate *connectionprofiles.RegistryViewRequest) error {
			credentials, err := connectionprofiles.GenerateRegistryCredentials()
			if err == nil {
				candidate.Reality, candidate.XHTTP, candidate.WebSocket = withRegistryCredentials(*candidate, credentials)
				candidate.Hysteria2.Credentials, candidate.TUIC.Credentials, candidate.AnyTLS.Credentials = credentials.Hysteria2, credentials.TUIC, credentials.AnyTLS
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := current
			if err := replace(&candidate); err != nil {
				t.Fatal(err)
			}
			result := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-credential-rotation", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
			if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || !registryPlanIsReversible(result.Plan) {
				t.Fatalf("rotation Plan = %+v", result)
			}
		})
	}
}

func TestManagedPortConflictRequiresExactOneUseCorrectionAuthority(t *testing.T) {
	current := validRegistryRequest(t)
	current.Exposure = networkpolicy.NewListenerContribution(managedRegistryPolicyResult(current, false))
	candidate := current
	candidate.AnyTLS.Port = 19443
	directTLSForSelectedPorts(&candidate)
	request := connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-managed-port-correction", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	if blocked := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), request); blocked.Plan != nil || blocked.Health.Outcome == connectionprofiles.Healthy {
		t.Fatalf("unreviewed Managed port move = %+v", blocked)
	}
	conflict := managedRegistryPolicyResult(current, true)
	if len(conflict.Findings) != 1 || conflict.Findings[0].Fix.SBXROption != "Change the SBXR port" || fmt.Sprint(conflict.Findings[0].Fix.OwnerChecklist) != "[Stop the other service]" || conflict.Findings[0].Back == "" {
		t.Fatalf("Managed port Correction Flow = %+v", conflict.Findings)
	}
	request.Candidate.Exposure = conflict.PortCorrectionCandidate()
	request.PortCorrection = conflict.PortCorrectionAuthority()
	conflictedHost := healthyRegistryHost(current)
	conflictedHost.observation.Listener = connectionprofiles.Listener{Address: "0.0.0.0", Port: current.AnyTLS.Port, Protocol: "tcp-other-owner"}
	result := connectionprofiles.New(conflictedHost).PlanRegistry(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("reviewed Managed port correction = %+v conflict=%+v", result, conflict.Findings)
	}
	emptyBinding := fmt.Sprintf("%x", sha256.Sum256(nil))
	if result.Plan.SHA256() == emptyBinding {
		t.Fatalf("registry Plan used an empty binding: %s", result.Plan.SHA256())
	}
	if replay := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), request); replay.Plan != nil || replay.Health.Outcome == connectionprofiles.Healthy {
		t.Fatalf("replayed Managed port correction = %+v", replay)
	}
	secondConflict := managedRegistryPolicyResult(current, true)
	request.ChangeSet = "profiles-managed-port-correction-reviewed-again"
	request.Candidate.Exposure, request.PortCorrection = secondConflict.PortCorrectionCandidate(), secondConflict.PortCorrectionAuthority()
	second := connectionprofiles.New(conflictedHost).PlanRegistry(t.Context(), request)
	if second.Plan == nil || second.Plan.SHA256() == result.Plan.SHA256() {
		t.Fatalf("materially different registry binding = first %v second %+v", result.Plan.SHA256(), second)
	}
	mixed := managedRegistryPolicyResult(current, true, true)
	if _, _, _, _, valid := mixed.PortCorrectionAuthority().ConnectionProfilesPortCorrection(); valid {
		t.Fatal("mixed Managed drift issued port-correction authority")
	}
	failedFunction := managedRegistryPolicyResult(current, true)
	request.Candidate.Exposure, request.PortCorrection = failedFunction.PortCorrectionCandidate(), failedFunction.PortCorrectionAuthority()
	conflictedHost.observation.ServerFunction = connectionprofiles.ProbeFailed
	if failed := connectionprofiles.New(conflictedHost).PlanRegistry(t.Context(), request); failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-ANYTLS-FUNCTION" {
		t.Fatalf("port correction bypassed unrelated current failure = %+v", failed)
	}
}

func TestRegistryPlansOnlyAuthorizedForwardRepairOfCurrentLineage(t *testing.T) {
	request := validRegistryRequest(t)
	host := healthyRegistryHost(request)
	host.webSocketHost.xhttpHost.realityHost.observation.ServiceRunning = false
	stateSHA := strings.Repeat("a", 64)
	base := connectionprofiles.RegistryPlanRequest{Current: request, Candidate: request, ChangeSet: "profiles-forward-repair", StartingStateSHA256: stateSHA, DesiredStateSHA256: stateSHA}
	if result := connectionprofiles.New(host).PlanRegistry(t.Context(), base); result.Plan != nil || result.Health.Outcome == connectionprofiles.Healthy {
		t.Fatalf("unapproved repair = %+v", result)
	}
	base.Repair = systemchanges.New(managedStatusAdapter{observation: systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, LastChangeSet: "profiles-complete", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
		ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift, StateRevision: 7, StateSHA256: stateSHA,
	}}).ForwardRepairAuthority()
	result := connectionprofiles.New(host).PlanRegistry(t.Context(), base)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || !registryPlanIsReversible(result.Plan) {
		t.Fatalf("authorized repair Plan = %+v", result)
	}
	if revision, sha, valid := result.Plan.StateConnectionProfilesRepair(); !valid || revision != 7 || sha != stateSHA {
		t.Fatalf("State repair authority = revision %d sha %q valid %t", revision, sha, valid)
	}
	if contribution := result.Plan.SoftwareLifecycleRepairContribution(); contribution.Name != "Connection Profiles" || contribution.Owner != systemchanges.ConnectionProfilesModule || contribution.CurrentRevision != 7 || contribution.CurrentStateSHA256 != stateSHA || len(contribution.Steps) == 0 || len(contribution.Checks) == 0 {
		t.Fatalf("Software Lifecycle repair contribution = %+v", contribution)
	}
	if replay := connectionprofiles.New(host).PlanRegistry(t.Context(), base); replay.Plan != nil || replay.Health.Outcome == connectionprofiles.Healthy {
		t.Fatalf("replayed repair authority = %+v", replay)
	}
}

func TestUnchangedCoreRegistryExcludesOnlySeparatelyOwnedRouteDrift(t *testing.T) {
	request := validRegistryRequest(t)
	request.XHTTP.RouteHealth.Origin = "http://127.0.0.1:1"
	module := connectionprofiles.New(healthyRegistryHost(request))
	if result := module.PlanUnchangedRegistry(t.Context(), request, "repair-0001", strings.Repeat("a", 64)); result.Plan != nil {
		t.Fatal("ordinary unchanged proof ignored route drift")
	}
	if result := module.PlanUnchangedCoreRegistry(t.Context(), request, "repair-0001", strings.Repeat("a", 64)); result.Plan == nil {
		t.Fatalf("core-only proof rejected separately owned route drift: %+v", result.Health)
	}
	request.Reality.XrayVersion = "changed"
	if result := module.PlanUnchangedCoreRegistry(t.Context(), request, "repair-0001", strings.Repeat("a", 64)); result.Plan != nil {
		t.Fatal("core-only proof ignored local core drift")
	}
}

func withRegistryCredentials(request connectionprofiles.RegistryViewRequest, credentials connectionprofiles.RegistryCredentials) (connectionprofiles.ViewRequest, connectionprofiles.XHTTPViewRequest, connectionprofiles.WebSocketViewRequest) {
	request.Reality.Credentials, request.XHTTP.Credentials, request.WebSocket.Credentials = credentials.Reality, credentials.XHTTP, credentials.WebSocket
	return request.Reality, request.XHTTP, request.WebSocket
}

type liveCheckHost struct {
	*anyTLSHost
	calls int
	seen  bool
}

func (host *liveCheckHost) CheckLiveProfiles(_ context.Context, subscription *connectionprofiles.LiveProfileSubscription, profiles []connectionprofiles.ProfileID) []connectionprofiles.LiveProfileEvidence {
	host.calls++
	value, ok := subscription.Consume()
	host.seen = ok && value == "https://profiles.example.com/u/LIVE-SUBSCRIPTION-TOKEN-MARKER"
	result := make([]connectionprofiles.LiveProfileEvidence, len(profiles))
	for index, profile := range profiles {
		result[index] = connectionprofiles.LiveProfileEvidence{Profile: profile, Authenticated: true, Uplink: true, Downlink: true}
	}
	return result
}

type managedStatusAdapter struct{ observation systemchanges.Observation }

func (adapter managedStatusAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (managedStatusAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

func TestLiveProfileCheckIsManagedOnlyOneUseAndLeavesNoRenderableHistory(t *testing.T) {
	request := validRegistryRequest(t)
	host := &liveCheckHost{anyTLSHost: healthyRegistryHost(request)}
	module := connectionprofiles.New(host)
	managed := systemchanges.New(managedStatusAdapter{observation: systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "profiles-complete", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: strings.Repeat("a", 64)}}).ManagedAuthority()
	const subscriptionMarker = "https://profiles.example.com/u/LIVE-SUBSCRIPTION-TOKEN-MARKER"
	subscription, err := connectionprofiles.NewLiveProfileSubscription(subscriptionMarker)
	if err != nil {
		t.Fatal(err)
	}
	result := module.RunLiveProfileCheck(t.Context(), connectionprofiles.LiveProfileCheckRequest{Registry: request, Managed: managed, StateSHA256: strings.Repeat("a", 64), Subscription: subscription})
	if result.Health.Outcome != connectionprofiles.Healthy || len(result.Evidence()) != 6 || host.calls != 1 || !host.seen {
		t.Fatalf("Live Profile Check health = %+v evidence=%+v calls=%d", result.Health, result.Evidence(), host.calls)
	}
	for _, evidence := range result.Evidence() {
		if !evidence.Authenticated || !evidence.Uplink || !evidence.Downlink {
			t.Fatalf("incomplete one-time evidence: %+v", evidence)
		}
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, "LIVE-SUBSCRIPTION-TOKEN-MARKER") {
		t.Fatalf("Live Profile Check retained the token: %s", rendered)
	}
	if _, err := json.Marshal(result); err == nil {
		t.Fatal("Live Profile Check allowed persistent rendering")
	}
	freshManaged := systemchanges.New(managedStatusAdapter{observation: systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "profiles-complete", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: strings.Repeat("a", 64)}}).ManagedAuthority()
	reused := module.RunLiveProfileCheck(t.Context(), connectionprofiles.LiveProfileCheckRequest{Registry: request, Managed: freshManaged, StateSHA256: strings.Repeat("a", 64), Subscription: subscription})
	if reused.Health.Code != "CONNECTION-PROFILES-LIVE-CHECK-SUBSCRIPTION" || host.calls != 1 {
		t.Fatalf("reused Live Profile Check = %+v calls=%d", reused, host.calls)
	}
}

func directTLSForSelectedPorts(request *connectionprofiles.RegistryViewRequest) {
	request.Hysteria2.DirectTLS = connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{
		Revision: request.Hysteria2.Revision, DestinationIP: request.ClientAddress, Hostname: request.Hysteria2.ServerName,
		Hysteria2: connectionprofiles.DirectTLSConsumer{Port: request.Hysteria2.Port, CertificatePointer: request.Hysteria2.CertificatePointer},
		TUIC:      connectionprofiles.DirectTLSConsumer{Port: request.TUIC.Port, CertificatePointer: request.TUIC.CertificatePointer},
		AnyTLS:    connectionprofiles.DirectTLSConsumer{Port: request.AnyTLS.Port, CertificatePointer: request.AnyTLS.CertificatePointer},
	})
	request.TUIC.DirectTLS, request.AnyTLS.DirectTLS = request.Hysteria2.DirectTLS, request.Hysteria2.DirectTLS
}

func setRegistryRevision(request *connectionprofiles.RegistryViewRequest, revision uint64) {
	request.Reality.Revision, request.XHTTP.Revision, request.WebSocket.Revision = revision, revision, revision
	request.Hysteria2.Revision, request.TUIC.Revision, request.AnyTLS.Revision = revision, revision, revision
	directTLSForSelectedPorts(request)
}

func healthyXHTTPRoute(hostname string, port uint16) cloudflaretunnel.XHTTPRouteHealth {
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)
	want := cloudflaretunnel.WholeTunnelExpected{TunnelID: "11111111-1111-4111-8111-111111111111", Routes: []cloudflaretunnel.Route{{Hostname: hostname, Service: origin}, {Service: "http_status:404"}}, DNSRecords: []cloudflaretunnel.DNSExpected{{ID: "dns-x", Name: hostname, Type: "CNAME", Content: "11111111-1111-4111-8111-111111111111.cfargotunnel.com", Proxied: true}}}
	observed := cloudflaretunnel.WholeTunnelObservation{TunnelID: want.TunnelID, Connected: true, Routes: want.Routes, DNSRecords: []cloudflaretunnel.DNSObservation{{ID: "dns-x", Name: hostname, Type: "CNAME", Content: want.TunnelID + ".cfargotunnel.com", Proxied: true}}, XHTTPOriginReachable: true}
	return cloudflaretunnel.EvaluateXHTTPRouteHealth(observed, want)
}

func healthyWebSocketRoute(hostname string, port uint16) cloudflaretunnel.WebSocketRouteHealth {
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)
	want := cloudflaretunnel.WholeTunnelExpected{TunnelID: "11111111-1111-4111-8111-111111111111", Routes: []cloudflaretunnel.Route{{Hostname: hostname, Service: origin}, {Service: "http_status:404"}}, DNSRecords: []cloudflaretunnel.DNSExpected{{ID: "dns-w", Name: hostname, Type: "CNAME", Content: "11111111-1111-4111-8111-111111111111.cfargotunnel.com", Proxied: true}}}
	observed := cloudflaretunnel.WholeTunnelObservation{TunnelID: want.TunnelID, Connected: true, Routes: want.Routes, DNSRecords: []cloudflaretunnel.DNSObservation{{ID: "dns-w", Name: hostname, Type: "CNAME", Content: want.TunnelID + ".cfargotunnel.com", Proxied: true}}, WebSocketOriginReachable: true}
	return cloudflaretunnel.EvaluateWebSocketRouteHealth(observed, want)
}

func managedRegistryPolicyResult(request connectionprofiles.RegistryViewRequest, conflict bool, extraDrift ...bool) networkpolicy.Result {
	intent := networkpolicy.Intent{Revision: request.Reality.Revision, Baseline: networkpolicy.Managed, PublicIPv4: request.ClientAddress, PrimarySubscriptionAddress: request.ClientAddress, CertificateHostname: request.Hysteria2.ServerName, SSHPort: 2222, SubscriptionPort: 10443, Disk: networkpolicy.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100}, Profiles: networkpolicy.Profiles{
		VLESSRealityVision: networkpolicy.Profile{Enabled: request.Reality.Enabled, Port: request.Reality.Port}, VLESSXHTTP: networkpolicy.Profile{Enabled: request.XHTTP.Enabled, Address: request.XHTTP.OriginAddress, Port: request.XHTTP.OriginPort}, VLESSWebSocket: networkpolicy.Profile{Enabled: request.WebSocket.Enabled, Address: request.WebSocket.OriginAddress, Port: request.WebSocket.OriginPort}, Hysteria2: networkpolicy.Profile{Enabled: request.Hysteria2.Enabled, Port: request.Hysteria2.Port}, TUIC: networkpolicy.Profile{Enabled: request.TUIC.Enabled, Port: request.TUIC.Port}, AnyTLS: networkpolicy.Profile{Enabled: request.AnyTLS.Enabled, Port: request.AnyTLS.Port},
	}}
	listeners := []networkpolicy.Listener{{Address: "0.0.0.0", Port: request.Reality.Port, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned}, {Address: "0.0.0.0", Port: request.Hysteria2.Port, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned}, {Address: "0.0.0.0", Port: request.TUIC.Port, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned}, {Address: "0.0.0.0", Port: request.AnyTLS.Port, Protocol: networkpolicy.TCP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned}, {Address: "0.0.0.0", Port: 10443, Protocol: networkpolicy.TCP, Service: "sbxr-subscription.service", Ownership: networkpolicy.SBXROwned}, {Address: "127.0.0.1", Port: request.XHTTP.OriginPort, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned}, {Address: "127.0.0.1", Port: request.WebSocket.OriginPort, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned}}
	if conflict {
		listeners[3].Service, listeners[3].Ownership = "other.service", networkpolicy.Unproved
	}
	observed := networkpolicy.Observations{Host: networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20}, Lineage: networkpolicy.ProvenLineage, PublicIPv4: []string{request.ClientAddress}, Listeners: listeners, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: request.ClientAddress, CurrentSessions: []string{"session-1"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "matches Desired State", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"}, Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true}, Disk: networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State", Routes: []networkpolicy.CloudflareRoute{{Profile: "VLESS XHTTP", OriginAddress: request.XHTTP.OriginAddress, OriginPort: request.XHTTP.OriginPort, Protocol: networkpolicy.TCP, Connected: true}, {Profile: "VLESS WebSocket", OriginAddress: request.WebSocket.OriginAddress, OriginPort: request.WebSocket.OriginPort, Protocol: networkpolicy.TCP, Connected: true}}}, Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: request.Hysteria2.ServerName, IPv4: []string{request.ClientAddress}}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}, PortCandidates: []networkpolicy.PortCandidate{{Port: 19443, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true}}, LocalProofs: []networkpolicy.LocalProof{{Purpose: "VLESS REALITY Vision", Address: request.ClientAddress, Port: request.Reality.Port, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true}, {Purpose: "Hysteria2", Address: request.ClientAddress, Port: request.Hysteria2.Port, Protocol: networkpolicy.UDP, RouteMatches: true, ConfigurationMatches: true}, {Purpose: "TUIC", Address: request.ClientAddress, Port: request.TUIC.Port, Protocol: networkpolicy.UDP, RouteMatches: true, ConfigurationMatches: true}, {Purpose: "AnyTLS", Address: request.ClientAddress, Port: request.AnyTLS.Port, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true}, {Purpose: "VLESS XHTTP", Address: request.XHTTP.OriginAddress, Port: request.XHTTP.OriginPort, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true}, {Purpose: "VLESS WebSocket", Address: request.WebSocket.OriginAddress, Port: request.WebSocket.OriginPort, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true}}}
	if len(extraDrift) > 0 && extraDrift[0] {
		observed.Firewall.SBXRTableState = "different from Desired State"
	}
	return networkpolicy.New(registryPolicyAdapter{observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
}
