package connectionprofiles

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
)

type WebSocketCredentials struct{ uuid, path secretText }

func (WebSocketCredentials) String() string   { return "WebSocket credentials: ready" }
func (WebSocketCredentials) GoString() string { return "WebSocket credentials: ready" }

func NewWebSocketCredentials(uuid, path string) (WebSocketCredentials, error) {
	credentials := WebSocketCredentials{secretText{uuid}, secretText{path}}
	if !credentials.valid() {
		return WebSocketCredentials{}, errors.New("WebSocket credentials are invalid")
	}
	return credentials, nil
}

func GenerateWebSocketCredentials() (WebSocketCredentials, error) {
	return generateWebSocketCredentials(rand.Reader)
}

func generateWebSocketCredentials(random io.Reader) (WebSocketCredentials, error) {
	uuid, err := generateUUIDFrom(random)
	if err != nil {
		return WebSocketCredentials{}, errors.New("WebSocket UUID generation failed")
	}
	path, err := generateHighEntropyPathFrom(random)
	if err != nil {
		return WebSocketCredentials{}, errors.New("WebSocket path generation failed")
	}
	return NewWebSocketCredentials(uuid, path)
}

func (credentials WebSocketCredentials) valid() bool {
	return uuidV4.MatchString(credentials.uuid.value) && highEntropyPath.MatchString(credentials.path.value)
}

type WebSocketObservation struct {
	CheckedAt          time.Time
	ConfigurationSafe  bool
	ConfigurationValid bool
	ServiceUnit        string
	ServiceIdentity    string
	ServiceRunning     bool
	ServiceContained   bool
	NoCapabilities     bool
	Listener           Listener
	HostMatches        bool
	PathMatches        bool
}

type WebSocketHost interface {
	ObserveWebSocket(context.Context, uint16, string, string) WebSocketObservation
}

type WebSocketViewRequest struct {
	Revision                                   uint64
	Enabled                                    bool
	Hostname, TLSName, HTTPHost, OriginAddress string
	OriginPort                                 uint16
	XrayVersion                                string
	Credentials                                WebSocketCredentials
	RouteHealth                                cloudflaretunnel.WebSocketRouteHealth
	reviewedAlternative                        bool
}

type WebSocketProfile struct {
	Name, Compatibility, Hostname, TLSName, HTTPHost, Origin, XrayVersion string
	Enabled, CredentialsReady, ServiceRunning                             bool
	ServiceUnit                                                           string
	Listener                                                              Listener
}

type WebSocketViewResult struct {
	Profile        WebSocketProfile
	Health         Health
	VolatileSHA256 string

	observation WebSocketObservation
}

func (module Interface) ViewWebSocket(ctx context.Context, request WebSocketViewRequest) WebSocketViewResult {
	return module.viewWebSocket(ctx, request, true)
}

func (module Interface) viewWebSocketCore(ctx context.Context, request WebSocketViewRequest) WebSocketViewResult {
	return module.viewWebSocket(ctx, request, false)
}

func (module Interface) viewWebSocket(ctx context.Context, request WebSocketViewRequest, includeRoute bool) WebSocketViewResult {
	profile := WebSocketProfile{Name: "VLESS WebSocket", Compatibility: "WebSocket", Hostname: request.Hostname, TLSName: request.TLSName, HTTPHost: request.HTTPHost, Origin: fmt.Sprintf("%s:%d", request.OriginAddress, request.OriginPort), XrayVersion: request.XrayVersion, Enabled: request.Enabled, CredentialsReady: request.Credentials.valid()}
	host, ok := module.host.(WebSocketHost)
	if !ok {
		return WebSocketViewResult{Profile: profile, Health: blockedWebSocket(time.Time{}, Unknown, "CONNECTION-PROFILES-WEBSOCKET-HOST", "The Ubuntu WebSocket observation is unavailable", "no local host boundary", "one typed Ubuntu WebSocket observation")}
	}
	observation := host.ObserveWebSocket(ctx, request.OriginPort, request.HTTPHost, request.Credentials.path.value)
	profile.ServiceUnit, profile.ServiceRunning, profile.Listener = observation.ServiceUnit, observation.ServiceRunning, observation.Listener
	result := WebSocketViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = webSocketObservationSHA256(request, observation)
	if !request.Enabled || request.OriginAddress != "127.0.0.1" || !selectedPort(request.OriginPort, 11081, request.reviewedAlternative) || request.XrayVersion != qualifiedXrayVersion || !validHostname(request.Hostname) || !request.Credentials.valid() {
		result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-ORIGIN", "The VLESS WebSocket inputs are invalid", "the origin, hostname, credential, enabled state, or qualified release is wrong", "one enabled compatibility profile on 127.0.0.1:11081/TCP")
		return result
	}
	if request.TLSName != request.Hostname || request.HTTPHost != request.Hostname {
		result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-HOST", "The WebSocket public names do not agree", "the TLS name or HTTP Host differs from the selected hostname", "one selected hostname used as destination, TLS name, and HTTP Host")
		return result
	}
	expectedOrigin := fmt.Sprintf("http://%s:%d", request.OriginAddress, request.OriginPort)
	if includeRoute && (request.RouteHealth.Hostname != request.Hostname || request.RouteHealth.Origin != expectedOrigin || request.RouteHealth.Health.Module != "Cloudflare Tunnel" || request.RouteHealth.Health.Outcome != cloudflaretunnel.Healthy || request.RouteHealth.Health.Code != "CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY") {
		result.Health = externalBlockedHealth(blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-ROUTE", "The typed Cloudflare WebSocket route is not healthy or does not match", request.RouteHealth.Health.Code, "the selected hostname mapped to the reviewed loopback WebSocket origin with CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY"), "Use Cloudflare Tunnel repair to restore the selected WebSocket hostname to its exact reviewed loopback origin, then Check again.")
		return result
	}
	if request.Revision > 0 {
		if !observation.ConfigurationSafe || !observation.ConfigurationValid {
			result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-CONFIGURATION", "The root-runtime Xray configuration is unsafe or invalid", "ownership, mode, path, symbolic-link, or native validation proof failed", "root:root 0755/0644 material under /etc/sbxr accepted by Xray")
			return result
		}
		if !observation.HostMatches {
			result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-HOST", "The active WebSocket HTTP Host does not agree", "the protected active configuration has a different Host", request.Hostname)
			return result
		}
		if !observation.PathMatches {
			result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-PATH", "The active WebSocket path does not agree", "the protected active configuration has a different path", "the exact reviewed high-entropy path")
			return result
		}
		if !rootServiceHealthy(observation.ServiceUnit, observation.ServiceIdentity, observation.ServiceRunning, observation.ServiceContained, "xray.service") {
			result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-SERVICE", "The fixed Xray service is not running safely", "xray.service root identity, state, or containment disagrees", "running contained xray.service as root")
			return result
		}
		if observation.Listener != (Listener{Address: "127.0.0.1", Port: request.OriginPort, Protocol: "tcp"}) {
			result.Health = blockedWebSocket(observation.CheckedAt, Failed, "CONNECTION-PROFILES-WEBSOCKET-LISTENER", "The WebSocket listener is not loopback-only", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), "127.0.0.1/11081/tcp")
			return result
		}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-WEBSOCKET-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
	return result
}

func webSocketObservationSHA256(request WebSocketViewRequest, observation WebSocketObservation) string {
	encoded, _ := json.Marshal(struct {
		Request     WebSocketViewRequest
		Observation WebSocketObservation
	}{request, observation})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blockedWebSocket(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return blockedHealth(Health{Time: at, Module: "Connection Profiles", Profile: "VLESS WebSocket", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}})
}

type WebSocketPlanRequest struct {
	Reality             ViewRequest
	XHTTP               XHTTPViewRequest
	View                WebSocketViewRequest
	ChangeSet           string
	StartingStateSHA256 string
	DesiredStateSHA256  string
}

func (module Interface) PlanWebSocket(ctx context.Context, request WebSocketPlanRequest) PlanResult {
	reality := module.View(ctx, request.Reality)
	if reality.Health.Outcome != Healthy {
		return PlanResult{Health: reality.Health}
	}
	xhttp := module.ViewXHTTP(ctx, request.XHTTP)
	if xhttp.Health.Outcome != Healthy {
		return PlanResult{Health: xhttp.Health}
	}
	websocket := module.ViewWebSocket(ctx, request.View)
	if websocket.Health.Outcome != Healthy {
		return PlanResult{Health: websocket.Health}
	}
	if request.Reality.Revision != request.XHTTP.Revision || request.XHTTP.Revision != request.View.Revision || request.XHTTP.Credentials.uuid.value == request.View.Credentials.uuid.value || request.XHTTP.Credentials.path.value == request.View.Credentials.path.value || request.XHTTP.Hostname == request.View.Hostname || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blockedWebSocket(websocket.Health.Time, Failed, "CONNECTION-PROFILES-WEBSOCKET-PLAN-STATE", "The reviewed State or independent-profile binding is invalid", "a Change Set, revision, checksum, independent credential, path, or hostname is missing or contradictory", "one exact current and candidate State binding with independent XHTTP and WebSocket facts")}
	}
	configuration, err := xrayConfiguration(&request.Reality, &request.XHTTP, &request.View)
	if err != nil {
		return PlanResult{Health: blockedWebSocket(websocket.Health.Time, Failed, "CONNECTION-PROFILES-WEBSOCKET-CONFIGURATION", "The complete Xray configuration could not be prepared", "the typed REALITY, XHTTP, or WebSocket inputs are incomplete", "one complete protected three-profile Xray configuration")}
	}
	volatile := sha256.Sum256([]byte(reality.VolatileSHA256 + xhttp.VolatileSHA256 + websocket.VolatileSHA256))
	volatileSHA256 := hex.EncodeToString(volatile[:])
	plan, failure := module.buildXrayPlan(ctx, xrayPlanSpec{
		identityPrefix: "profiles-websocket-", description: "validate and activate independent VLESS WebSocket on 127.0.0.1:11081/TCP through xray.service and its typed Cloudflare route; rollback restores the prior configuration",
		profile: websocket.Profile.Name, codePrefix: "CONNECTION-PROFILES-WEBSOCKET", version: request.View.XrayVersion,
		revision: request.View.Revision, changeSet: request.ChangeSet, startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256,
		volatileSHA256: volatileSHA256, configuration: configuration, request: request, reality: request.Reality, xhttp: &request.XHTTP, websocket: &request.View, checkedAt: websocket.Health.Time,
	})
	if failure != nil {
		return PlanResult{Health: *failure}
	}
	return PlanResult{Plan: plan, Health: Health{Time: websocket.Health.Time, Module: "Connection Profiles", Profile: websocket.Profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-WEBSOCKET-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}
