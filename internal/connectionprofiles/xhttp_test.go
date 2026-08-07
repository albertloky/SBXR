package connectionprofiles_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	xhttpUUIDMarker = "22222222-2222-4222-8222-222222222222"
	xhttpPathMarker = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type xhttpHost struct {
	*realityHost
	observation connectionprofiles.XHTTPObservation
}

func (host *xhttpHost) ObserveXHTTP(context.Context, uint16) connectionprofiles.XHTTPObservation {
	return host.observation
}

func TestXHTTPViewRequiresExactLoopbackRouteAndService(t *testing.T) {
	request := validXHTTPRequest(t)
	host := &xhttpHost{realityHost: &realityHost{}, observation: healthyXHTTPObservation()}
	result := connectionprofiles.New(host).ViewXHTTP(t.Context(), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Profile.Name != "VLESS XHTTP" || result.Profile.Mode != "packet-up" || result.Profile.Origin != "127.0.0.1:11080" || result.Profile.Listener != (connectionprofiles.Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}) {
		t.Fatalf("ViewXHTTP() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, xhttpPathMarker) {
		t.Fatalf("ViewXHTTP() leaked protected material: %s", rendered)
	}

	for _, test := range []struct {
		name string
		edit func(*connectionprofiles.XHTTPViewRequest, *connectionprofiles.XHTTPObservation)
		code string
	}{
		{"public origin", func(request *connectionprofiles.XHTTPViewRequest, _ *connectionprofiles.XHTTPObservation) {
			request.OriginAddress = "0.0.0.0"
		}, "CONNECTION-PROFILES-XHTTP-ORIGIN"},
		{"wrong listener", func(_ *connectionprofiles.XHTTPViewRequest, observation *connectionprofiles.XHTTPObservation) {
			observation.Listener.Address = "0.0.0.0"
		}, "CONNECTION-PROFILES-XHTTP-LISTENER"},
		{"native configuration failure", func(_ *connectionprofiles.XHTTPViewRequest, observation *connectionprofiles.XHTTPObservation) {
			observation.ConfigurationValid = false
		}, "CONNECTION-PROFILES-XHTTP-CONFIGURATION"},
		{"route mismatch", func(request *connectionprofiles.XHTTPViewRequest, _ *connectionprofiles.XHTTPObservation) {
			request.RouteHealth.Origin = "http://203.0.113.1:11080"
		}, "CONNECTION-PROFILES-XHTTP-ROUTE"},
		{"service failure", func(_ *connectionprofiles.XHTTPViewRequest, observation *connectionprofiles.XHTTPObservation) {
			observation.ServiceRunning = false
		}, "CONNECTION-PROFILES-XHTTP-SERVICE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validXHTTPRequest(t)
			observation := healthyXHTTPObservation()
			test.edit(&request, &observation)
			got := connectionprofiles.New(&xhttpHost{realityHost: &realityHost{}, observation: observation}).ViewXHTTP(t.Context(), request)
			if got.Health.Outcome == connectionprofiles.Healthy || got.Health.Code != test.code {
				t.Fatalf("ViewXHTTP() = %+v", got)
			}
		})
	}
}

func TestXHTTPPlanValidatesOneCompletePacketUpConfiguration(t *testing.T) {
	host := &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}
	request := connectionprofiles.XHTTPPlanRequest{
		Reality: validRealityRequest(t), View: validXHTTPRequest(t), ChangeSet: "profiles-xhttp-0001",
		StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64),
	}
	result := connectionprofiles.New(host).PlanXHTTP(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 4 {
		t.Fatalf("PlanXHTTP() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, xhttpPathMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("PlanXHTTP() leaked protected material: %s", rendered)
	}
	for _, protected := range []string{xhttpUUIDMarker, xhttpPathMarker, string(host.validated)} {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(protected)))
		if strings.Contains(fmt.Sprintf("%+v", result), digest) || result.Plan.SHA256() == digest {
			t.Fatalf("PlanXHTTP() exposed a protected-value digest: %s", digest)
		}
	}
	var configuration struct {
		Inbounds []struct {
			Tag, Listen, Protocol string
			Port                  uint16
			Settings              struct {
				Clients    []struct{ ID string }
				Decryption string
			}
			StreamSettings struct {
				Method, Security string
				XHTTPSettings    struct{ Mode, Path string }
			}
		}
	}
	if err := json.Unmarshal(host.validated, &configuration); err != nil || len(configuration.Inbounds) != 2 {
		t.Fatalf("complete Xray configuration = %s, %v", host.validated, err)
	}
	var xhttp any
	for _, inbound := range configuration.Inbounds {
		if inbound.Tag == "vless-xhttp" {
			xhttp = inbound
			if inbound.Listen != "127.0.0.1" || inbound.Port != 11080 || inbound.Protocol != "vless" || len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != xhttpUUIDMarker || inbound.Settings.Decryption != "none" || inbound.StreamSettings.Method != "xhttp" || inbound.StreamSettings.Security != "none" || inbound.StreamSettings.XHTTPSettings.Mode != "packet-up" || inbound.StreamSettings.XHTTPSettings.Path != xhttpPathMarker {
				t.Fatalf("XHTTP inbound = %+v", inbound)
			}
		}
	}
	if xhttp == nil || bytes.Contains(host.validated, []byte(`"mode":"auto"`)) || bytes.Contains(host.validated, []byte("stream-up")) || bytes.Contains(host.validated, []byte("stream-one")) || bytes.Contains(host.validated, []byte("tlsSettings")) {
		t.Fatalf("unsafe XHTTP server configuration = %s", host.validated)
	}
	failedHost := &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation(), validation: fmt.Errorf("XHTTP-SECRET-MARKER")}, observation: healthyXHTTPObservation()}
	failed := connectionprofiles.New(failedHost).PlanXHTTP(t.Context(), request)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-XHTTP-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "XHTTP-SECRET-MARKER") {
		t.Fatalf("native XHTTP refusal = %+v", failed)
	}
}

func TestXHTTPPlanBindsIndependentPathAndCredentialForState(t *testing.T) {
	host := &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}
	request := connectionprofiles.XHTTPPlanRequest{Reality: validRealityRequest(t), View: validXHTTPRequest(t), ChangeSet: "profiles-xhttp-state", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	plan := connectionprofiles.New(host).PlanXHTTP(t.Context(), request).Plan
	realityUUID := state.NewClientAccessValue("reality-uuid")
	privateKey := state.NewInfrastructureSecret("private")
	shortID := state.NewClientAccessValue("short-id")
	xhttpUUID := state.NewClientAccessValue("xhttp-uuid")
	xhttpPath := state.NewClientAccessValue("xhttp-path")
	profiles := state.ConnectionProfiles{
		VLESSRealityVision: state.VLESSRealityVision{Enabled: true, Port: 443, UUID: realityUUID, PrivateKey: privateKey, PublicKey: publicKeyMarker, ShortID: shortID, Target: "edge.example.net:443", ServerName: "edge.example.net", Fingerprint: "chrome"},
		VLESSXHTTP:         state.VLESSXHTTP{Enabled: true, UUID: xhttpUUID, Path: xhttpPath, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp},
	}
	secrets := profileSecrets{
		clients:        map[state.ClientAccessValue]string{realityUUID: uuidMarker, shortID: shortIDMarker, xhttpUUID: xhttpUUIDMarker, xhttpPath: xhttpPathMarker},
		infrastructure: map[state.InfrastructureSecret]string{privateKey: privateKeyMarker},
	}
	xray, singBox, err := plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || singBox != nil || !bytes.Equal(xray, host.validated) {
		t.Fatalf("reviewed XHTTP State configuration = (%s, %s, %v)", xray, singBox, err)
	}
	secrets.clients[xhttpPath] = "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("changed XHTTP path accepted by reviewed Plan")
	}
}

func TestXHTTPApplyRejectsStaleAndReusedPlans(t *testing.T) {
	host := &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}
	request := connectionprofiles.XHTTPPlanRequest{Reality: validRealityRequest(t), View: validXHTTPRequest(t), ChangeSet: "profiles-xhttp-apply", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	plan := connectionprofiles.New(host).PlanXHTTP(t.Context(), request).Plan
	prepared := &realityPreparedState{changeSet: request.ChangeSet, revision: 8, starting: request.StartingStateSHA256, candidate: request.DesiredStateSHA256, planIdentity: plan.Identity(), planSHA: plan.SHA256()}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: request.StartingStateSHA256}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	if result := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk); result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !result.PlanConsumed {
		t.Fatalf("valid XHTTP Apply = %+v", result)
	}
	if reused := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("reused XHTTP Apply = %+v", reused)
	}
	stale := connectionprofiles.New(host).PlanXHTTP(t.Context(), request).Plan
	prepared.planIdentity, prepared.planSHA = stale.Identity(), stale.SHA256()
	if result := stale.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("c", 64), disk); result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("stale XHTTP Apply = %+v", result)
	}
}

func TestGenerateXHTTPCredentialsProducesIndependentUUIDAndPath(t *testing.T) {
	first, err := connectionprofiles.GenerateXHTTPCredentials()
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectionprofiles.GenerateXHTTPCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%#v", first) != "XHTTP credentials: ready" || fmt.Sprintf("%#v", second) != "XHTTP credentials: ready" {
		t.Fatalf("generated credential rendering is unsafe: first %#v second %#v", first, second)
	}
	request := connectionprofiles.XHTTPPlanRequest{Reality: validRealityRequest(t), View: validXHTTPRequest(t), ChangeSet: "profiles-xhttp-random", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	request.View.Credentials = first
	firstPlan := connectionprofiles.New(&xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}).PlanXHTTP(t.Context(), request)
	request.View.Credentials = second
	secondPlan := connectionprofiles.New(&xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}).PlanXHTTP(t.Context(), request)
	if firstPlan.Plan == nil || secondPlan.Plan == nil || firstPlan.Plan.SHA256() == secondPlan.Plan.SHA256() {
		t.Fatalf("independent generated XHTTP credentials produced one Plan: first %+v second %+v", firstPlan, secondPlan)
	}
	if _, err := connectionprofiles.NewXHTTPCredentials(xhttpUUIDMarker, "/"+strings.Repeat("a", 63)); err == nil {
		t.Fatal("short XHTTP path accepted")
	}
}

type nativeXHTTPHost struct {
	*nativeRealityHost
	xhttp connectionprofiles.XHTTPObservation
}

func (host *nativeXHTTPHost) ObserveXHTTP(context.Context, uint16) connectionprofiles.XHTTPObservation {
	return host.xhttp
}

func TestPinnedNativeXrayAcceptsCompleteXHTTPConfiguration(t *testing.T) {
	binary := os.Getenv("SBXR_XRAY_BIN")
	if binary == "" {
		t.Skip("set SBXR_XRAY_BIN to the pinned v26.3.27 executable for Seam Verification")
	}
	host := &nativeXHTTPHost{nativeRealityHost: &nativeRealityHost{observation: healthyRealityObservation(), binary: binary}, xhttp: healthyXHTTPObservation()}
	result := connectionprofiles.New(host).PlanXHTTP(t.Context(), connectionprofiles.XHTTPPlanRequest{Reality: validRealityRequest(t), View: validXHTTPRequest(t), ChangeSet: "profiles-xhttp-native", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("pinned native XHTTP validation = %+v", result)
	}
}

func validXHTTPRequest(t *testing.T) connectionprofiles.XHTTPViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewXHTTPCredentials(xhttpUUIDMarker, xhttpPathMarker)
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.XHTTPViewRequest{
		Revision: 7, Enabled: true, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080,
		Mode: "packet-up", XrayVersion: "v26.3.27", Credentials: credentials,
		RouteHealth: cloudflaretunnel.XHTTPRouteHealth{Hostname: "xhttp.example.com", Origin: "http://127.0.0.1:11080", Health: cloudflaretunnel.Health{Module: "Cloudflare Tunnel", Outcome: cloudflaretunnel.Healthy, Code: "CLOUDFLARE-XHTTP-ROUTE-HEALTHY"}},
	}
}

func healthyXHTTPObservation() connectionprofiles.XHTTPObservation {
	return connectionprofiles.XHTTPObservation{
		CheckedAt: healthyRealityObservation().CheckedAt, ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "xray", ServiceRunning: true,
		Listener: connectionprofiles.Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"},
	}
}
