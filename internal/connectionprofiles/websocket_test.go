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
	webSocketUUIDMarker = "44444444-4444-4444-8444-444444444444"
	webSocketPathMarker = "/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type webSocketHost struct {
	*xhttpHost
	observation connectionprofiles.WebSocketObservation
}

func (host *webSocketHost) ObserveWebSocket(context.Context, uint16, string, string) connectionprofiles.WebSocketObservation {
	return host.observation
}

func TestWebSocketViewRequiresIndependentCompatibilityOriginAndRoute(t *testing.T) {
	request := validWebSocketRequest(t)
	host := &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}
	result := connectionprofiles.New(host).ViewWebSocket(t.Context(), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-WEBSOCKET-HEALTHY" || result.Profile.Name != "VLESS WebSocket" || result.Profile.Compatibility != "WebSocket" {
		t.Fatalf("ViewWebSocket() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, webSocketUUIDMarker) || strings.Contains(rendered, webSocketPathMarker) {
		t.Fatalf("ViewWebSocket() leaked protected material: %s", rendered)
	}

	for _, test := range []struct {
		name, code string
		edit       func(*connectionprofiles.WebSocketViewRequest, *connectionprofiles.WebSocketObservation)
	}{
		{"wrong TLS name", "CONNECTION-PROFILES-WEBSOCKET-HOST", func(request *connectionprofiles.WebSocketViewRequest, _ *connectionprofiles.WebSocketObservation) {
			request.TLSName = "other.example.com"
		}},
		{"wrong HTTP Host", "CONNECTION-PROFILES-WEBSOCKET-HOST", func(request *connectionprofiles.WebSocketViewRequest, _ *connectionprofiles.WebSocketObservation) {
			request.HTTPHost = "other.example.com"
		}},
		{"active Host mismatch", "CONNECTION-PROFILES-WEBSOCKET-HOST", func(_ *connectionprofiles.WebSocketViewRequest, observation *connectionprofiles.WebSocketObservation) {
			observation.HostMatches = false
		}},
		{"active path mismatch", "CONNECTION-PROFILES-WEBSOCKET-PATH", func(_ *connectionprofiles.WebSocketViewRequest, observation *connectionprofiles.WebSocketObservation) {
			observation.PathMatches = false
		}},
		{"public listener", "CONNECTION-PROFILES-WEBSOCKET-LISTENER", func(_ *connectionprofiles.WebSocketViewRequest, observation *connectionprofiles.WebSocketObservation) {
			observation.Listener.Address = "0.0.0.0"
		}},
		{"route mismatch", "CONNECTION-PROFILES-WEBSOCKET-ROUTE", func(request *connectionprofiles.WebSocketViewRequest, _ *connectionprofiles.WebSocketObservation) {
			request.RouteHealth.Origin = "http://127.0.0.1:11080"
		}},
		{"service failure", "CONNECTION-PROFILES-WEBSOCKET-SERVICE", func(_ *connectionprofiles.WebSocketViewRequest, observation *connectionprofiles.WebSocketObservation) {
			observation.ServiceRunning = false
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validWebSocketRequest(t)
			observation := healthyWebSocketObservation()
			test.edit(&request, &observation)
			got := connectionprofiles.New(&webSocketHost{xhttpHost: host.xhttpHost, observation: observation}).ViewWebSocket(t.Context(), request)
			if got.Health.Outcome == connectionprofiles.Healthy || got.Health.Code != test.code {
				t.Fatalf("ViewWebSocket() = %+v", got)
			}
		})
	}
}

func TestGenerateWebSocketCredentialsRequiresA32BytePath(t *testing.T) {
	credentials, err := connectionprofiles.GenerateWebSocketCredentials()
	if err != nil || fmt.Sprintf("%#v", credentials) != "WebSocket credentials: ready" {
		t.Fatalf("GenerateWebSocketCredentials() = (%#v, %v)", credentials, err)
	}
	if _, err := connectionprofiles.NewWebSocketCredentials(webSocketUUIDMarker, "/"+strings.Repeat("a", 63)); err == nil {
		t.Fatal("short WebSocket path accepted")
	}
}

func TestWebSocketPlanValidatesOneCompleteThreeProfileXrayConfiguration(t *testing.T) {
	host := &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}
	request := connectionprofiles.WebSocketPlanRequest{
		Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), View: validWebSocketRequest(t), ChangeSet: "profiles-websocket-0001",
		StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64),
	}
	result := connectionprofiles.New(host).PlanWebSocket(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 4 {
		t.Fatalf("PlanWebSocket() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, webSocketUUIDMarker) || strings.Contains(rendered, webSocketPathMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("PlanWebSocket() leaked protected material: %s", rendered)
	}
	for _, protected := range []string{webSocketUUIDMarker, webSocketPathMarker, string(host.validated)} {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(protected)))
		if strings.Contains(fmt.Sprintf("%+v", result), digest) || result.Plan.SHA256() == digest {
			t.Fatalf("PlanWebSocket() exposed a protected-value digest: %s", digest)
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
				WSSettings       struct{ Host, Path string }
			}
		}
	}
	if err := json.Unmarshal(host.validated, &configuration); err != nil || len(configuration.Inbounds) != 3 {
		t.Fatalf("complete Xray configuration = %s, %v", host.validated, err)
	}
	found := false
	for _, inbound := range configuration.Inbounds {
		if inbound.Tag == "vless-websocket" {
			found = true
			if inbound.Listen != "127.0.0.1" || inbound.Port != 11081 || inbound.Protocol != "vless" || len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != webSocketUUIDMarker || inbound.Settings.Decryption != "none" || inbound.StreamSettings.Method != "websocket" || inbound.StreamSettings.Security != "none" || inbound.StreamSettings.WSSettings.Host != "ws.example.com" || inbound.StreamSettings.WSSettings.Path != webSocketPathMarker {
				t.Fatalf("WebSocket inbound = %+v", inbound)
			}
		}
	}
	if !found || bytes.Contains(host.validated, []byte("tlsSettings")) {
		t.Fatalf("unsafe WebSocket server configuration = %s", host.validated)
	}
	failedHost := &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation(), validation: fmt.Errorf("WEBSOCKET-SECRET-MARKER")}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}
	failed := connectionprofiles.New(failedHost).PlanWebSocket(t.Context(), request)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-WEBSOCKET-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "WEBSOCKET-SECRET-MARKER") {
		t.Fatalf("native WebSocket refusal = %+v", failed)
	}
}

func TestWebSocketPlanBindsIndependentCredentialsPathAndHostForState(t *testing.T) {
	host := &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}
	request := connectionprofiles.WebSocketPlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), View: validWebSocketRequest(t), ChangeSet: "profiles-websocket-state", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	plan := connectionprofiles.New(host).PlanWebSocket(t.Context(), request).Plan
	realityUUID := state.NewClientAccessValue("reality-uuid")
	privateKey := state.NewInfrastructureSecret("private")
	shortID := state.NewClientAccessValue("short-id")
	xhttpUUID := state.NewClientAccessValue("xhttp-uuid")
	xhttpPath := state.NewClientAccessValue("xhttp-path")
	websocketUUID := state.NewClientAccessValue("websocket-uuid")
	websocketPath := state.NewClientAccessValue("websocket-path")
	profiles := state.ConnectionProfiles{
		VLESSRealityVision: state.VLESSRealityVision{Enabled: true, Port: 443, UUID: realityUUID, PrivateKey: privateKey, PublicKey: publicKeyMarker, ShortID: shortID, Target: "edge.example.net:443", ServerName: "edge.example.net", Fingerprint: "chrome"},
		VLESSXHTTP:         state.VLESSXHTTP{Enabled: true, UUID: xhttpUUID, Path: xhttpPath, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp},
		VLESSWebSocket:     state.VLESSWebSocket{Enabled: true, UUID: websocketUUID, Path: websocketPath, Hostname: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081},
	}
	secrets := profileSecrets{
		clients:        map[state.ClientAccessValue]string{realityUUID: uuidMarker, shortID: shortIDMarker, xhttpUUID: xhttpUUIDMarker, xhttpPath: xhttpPathMarker, websocketUUID: webSocketUUIDMarker, websocketPath: webSocketPathMarker},
		infrastructure: map[state.InfrastructureSecret]string{privateKey: privateKeyMarker},
	}
	xray, singBox, err := plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || singBox != nil || !bytes.Equal(xray, host.validated) {
		t.Fatalf("reviewed WebSocket State configuration = (%s, %s, %v)", xray, singBox, err)
	}
	secrets.clients[websocketPath] = xhttpPathMarker
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("WebSocket path shared with XHTTP accepted by reviewed Plan")
	}
	secrets.clients[websocketPath] = "/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("changed WebSocket path accepted by reviewed Plan")
	}
}

func TestWebSocketApplyRejectsStaleAndReusedPlans(t *testing.T) {
	host := &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}
	request := connectionprofiles.WebSocketPlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), View: validWebSocketRequest(t), ChangeSet: "profiles-websocket-apply", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	plan := connectionprofiles.New(host).PlanWebSocket(t.Context(), request).Plan
	prepared := &realityPreparedState{changeSet: request.ChangeSet, revision: 8, starting: request.StartingStateSHA256, candidate: request.DesiredStateSHA256, planIdentity: plan.Identity(), planSHA: plan.SHA256()}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: request.StartingStateSHA256}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	if result := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk); result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !result.PlanConsumed {
		t.Fatalf("valid WebSocket Apply = %+v", result)
	}
	if reused := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("reused WebSocket Apply = %+v", reused)
	}
	stale := connectionprofiles.New(host).PlanWebSocket(t.Context(), request).Plan
	prepared.planIdentity, prepared.planSHA = stale.Identity(), stale.SHA256()
	if result := stale.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("c", 64), disk); result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("stale WebSocket Apply = %+v", result)
	}
}

func validWebSocketRequest(t *testing.T) connectionprofiles.WebSocketViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewWebSocketCredentials(webSocketUUIDMarker, webSocketPathMarker)
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.WebSocketViewRequest{
		Revision: 7, Enabled: true, Hostname: "ws.example.com", TLSName: "ws.example.com", HTTPHost: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081, XrayVersion: "v26.3.27", Credentials: credentials,
		RouteHealth: cloudflaretunnel.WebSocketRouteHealth{Hostname: "ws.example.com", Origin: "http://127.0.0.1:11081", Health: cloudflaretunnel.Health{Module: "Cloudflare Tunnel", Outcome: cloudflaretunnel.Healthy, Code: "CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY"}},
	}
}

func healthyWebSocketObservation() connectionprofiles.WebSocketObservation {
	return connectionprofiles.WebSocketObservation{
		CheckedAt: healthyRealityObservation().CheckedAt, ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "xray", ServiceRunning: true,
		Listener: connectionprofiles.Listener{Address: "127.0.0.1", Port: 11081, Protocol: "tcp"}, HostMatches: true, PathMatches: true,
	}
}

type nativeWebSocketHost struct {
	*nativeXHTTPHost
	websocket connectionprofiles.WebSocketObservation
}

func (host *nativeWebSocketHost) ObserveWebSocket(context.Context, uint16, string, string) connectionprofiles.WebSocketObservation {
	return host.websocket
}

func TestPinnedNativeXrayAcceptsCompleteWebSocketConfiguration(t *testing.T) {
	binary := os.Getenv("SBXR_XRAY_BIN")
	if binary == "" {
		t.Skip("set SBXR_XRAY_BIN to the pinned v26.3.27 executable for Seam Verification")
	}
	host := &nativeWebSocketHost{
		nativeXHTTPHost: &nativeXHTTPHost{nativeRealityHost: &nativeRealityHost{observation: healthyRealityObservation(), binary: binary}, xhttp: healthyXHTTPObservation()},
		websocket:       healthyWebSocketObservation(),
	}
	result := connectionprofiles.New(host).PlanWebSocket(t.Context(), connectionprofiles.WebSocketPlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), View: validWebSocketRequest(t), ChangeSet: "profiles-websocket-native", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("pinned native WebSocket validation = %+v", result)
	}
}
