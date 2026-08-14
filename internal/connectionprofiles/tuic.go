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
	"net/netip"
	"reflect"
	"time"

	"github.com/albertloky/SBXR/internal/state"
)

type TUICCredentials struct{ uuid, password secretText }

func (TUICCredentials) String() string   { return "TUIC credentials: ready" }
func (TUICCredentials) GoString() string { return "TUIC credentials: ready" }

func NewTUICCredentials(uuid, password string) (TUICCredentials, error) {
	credentials := TUICCredentials{uuid: secretText{value: uuid}, password: secretText{value: password}}
	if !credentials.valid() {
		return TUICCredentials{}, errors.New("TUIC credentials are invalid")
	}
	return credentials, nil
}

func GenerateTUICCredentials() (TUICCredentials, error) {
	return generateTUICCredentials(rand.Reader)
}

func generateTUICCredentials(random io.Reader) (TUICCredentials, error) {
	uuid, err := generateUUIDFrom(random)
	if err != nil {
		return TUICCredentials{}, errors.New("TUIC UUID generation failed")
	}
	password, err := generateHexSecretFrom(random)
	if err != nil {
		return TUICCredentials{}, errors.New("TUIC password generation failed")
	}
	return NewTUICCredentials(uuid, password)
}

func (credentials TUICCredentials) valid() bool {
	password, err := hex.DecodeString(credentials.password.value)
	return uuidV4.MatchString(credentials.uuid.value) && err == nil && len(password) == 32
}

type TUICObservation = Hysteria2Observation

type TUICHost interface {
	ObserveTUIC(context.Context, Hysteria2ViewRequest, TUICViewRequest) TUICObservation
}

type TUICViewRequest struct {
	Revision                           uint64
	Port                               uint16
	Enabled                            bool
	DestinationIP, ServerName          string
	CertificatePointer, SingBoxVersion string
	CertificateID                      string
	CongestionControl                  state.CongestionControl
	ZeroRTT                            bool
	Credentials                        TUICCredentials
	DirectTLS                          DirectTLSContribution
	Network                            TUICListenerPolicyAuthority
	reviewedAlternative                bool
}

type TUICListenerPolicyAuthority interface {
	ConnectionProfilesTUICListener() (port uint16, protocol string, valid bool)
}

type TUICProfile struct {
	Name, DestinationIP, ServerName, SingBoxVersion string
	ServiceUnit                                     string
	Enabled, CredentialsReady, ServiceRunning       bool
	Port                                            uint16
	Listener                                        Listener
}

type TUICViewResult struct {
	Profile        TUICProfile
	Health         Health
	VolatileSHA256 string
	observation    TUICObservation
}

func (module Interface) ViewTUIC(ctx context.Context, hysteria2 Hysteria2ViewRequest, request TUICViewRequest) TUICViewResult {
	return module.viewTUIC(ctx, hysteria2, request, true)
}

func (module Interface) viewTUIC(ctx context.Context, hysteria2 Hysteria2ViewRequest, request TUICViewRequest, checkActive bool) TUICViewResult {
	profiles := SingBoxProfileSet{TUIC: &request}
	if hysteria2.Profiles != nil {
		profiles.AnyTLS = hysteria2.Profiles.AnyTLS
	}
	hysteria2.Profiles = &profiles
	profile := TUICProfile{Name: "TUIC", DestinationIP: request.DestinationIP, ServerName: request.ServerName, SingBoxVersion: request.SingBoxVersion, Enabled: request.Enabled, Port: request.Port, CredentialsReady: request.Credentials.valid()}
	host, ok := module.host.(TUICHost)
	if !ok {
		return TUICViewResult{Profile: profile, Health: blockedTUIC(time.Time{}, Unknown, "CONNECTION-PROFILES-TUIC-HOST", "The Ubuntu TUIC observation is unavailable", "no local host boundary", "one typed Ubuntu observation")}
	}
	observation := host.ObserveTUIC(ctx, hysteria2, request)
	profile.ServiceUnit, profile.ServiceRunning, profile.Listener = observation.ServiceUnit, observation.ServiceRunning, observation.Listener
	result := TUICViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = tuicObservationSHA256(request, observation)
	address, addressErr := netip.ParseAddr(request.DestinationIP)
	if !request.Enabled || !selectedPort(request.Port, 8443, request.reviewedAlternative) || addressErr != nil || !address.IsGlobalUnicast() || !validHostname(request.ServerName) || request.CertificateID == "" || request.CertificatePointer != directCertificatePointer || request.SingBoxVersion != qualifiedSingBoxVersion || request.CongestionControl != state.CongestionCubic || request.ZeroRTT || !request.Credentials.valid() || !hysteria2.Credentials.valid() || request.Credentials.password.value == hysteria2.Credentials.password.value {
		result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-INPUT", "The TUIC inputs are invalid", "the destination, listener, TLS name, credential, replay, congestion, or release setting is wrong", "one enabled TUIC profile on public 8443/UDP using cubic and zero-RTT disabled")
		return result
	}
	revision, destination, hostname, _, directValid := request.DirectTLS.SystemChangesDirectTLS()
	if !directValid || revision != request.Revision || destination != request.DestinationIP || hostname != request.ServerName {
		result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-CERTIFICATE", "The reviewed Direct TLS identity does not agree", "the destination, hostname, revision, or shared certificate consumers differ", "one exact Direct TLS Hostname and shared active certificate pair with normal verification")
		return result
	}
	if !protocolAwareTUIC(request.Network, request.Port) {
		result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-NETWORK", "The reviewed TUIC listener policy does not agree", "public 8443/UDP was not proved", "one public TUIC listener on 8443/UDP")
		return result
	}
	if checkActive && request.Revision > 0 {
		switch {
		case !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches:
			result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-CONFIGURATION", "The protected sing-box configuration is unsafe, invalid, or different", "ownership, native validity, or exact active agreement failed", "the reviewed complete Hysteria2 and TUIC configuration")
		case !rootServiceHealthy(observation.ServiceUnit, observation.ServiceIdentity, observation.ServiceRunning, observation.ServiceContained, "sing-box.service"):
			result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-SERVICE", "The fixed sing-box service is not running safely", "sing-box.service root identity, state, or containment disagrees", "running contained sing-box.service as root")
		case !publicUDPListener(observation.Listener, request.Port):
			result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-LISTENER", "The TUIC listener disagrees", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), "public 8443/UDP")
		case observation.NetBindService != singBoxNeedsCapability(hysteria2, request, AnyTLSViewRequest{}) || !singBoxNeedsCapability(hysteria2, request, AnyTLSViewRequest{}) && !observation.NoCapabilities:
			result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-CAPABILITY", "The shared sing-box service capability is wrong", "CAP_NET_BIND_SERVICE is absent or broader", "only CAP_NET_BIND_SERVICE for the shared privileged Hysteria2 listener")
		case observation.ServerFunction != ProbePassed:
			result.Health = blockedTUIC(observation.CheckedAt, Failed, "CONNECTION-PROFILES-TUIC-FUNCTION", "The bounded authenticated TUIC check did not pass", string(observation.ServerFunction), "one safe authenticated TUIC server-side function proof")
		default:
			result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: "TUIC", Outcome: Healthy, Code: "CONNECTION-PROFILES-TUIC-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
		}
		if result.Health.Outcome != Healthy {
			return result
		}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: "TUIC", Outcome: Healthy, Code: "CONNECTION-PROFILES-TUIC-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
	return result
}

func protocolAwareTUIC(authority TUICListenerPolicyAuthority, selected uint16) bool {
	if authority == nil {
		return false
	}
	typeName := reflect.TypeOf(authority)
	if typeName.Kind() == reflect.Pointer {
		if reflect.ValueOf(authority).IsNil() {
			return false
		}
		typeName = typeName.Elem()
	}
	if typeName.PkgPath() != "github.com/albertloky/SBXR/internal/networkpolicy" || typeName.Name() != "ListenerContribution" {
		return false
	}
	port, protocol, valid := authority.ConnectionProfilesTUICListener()
	return valid && port == selected && protocol == "UDP"
}

func tuicObservationSHA256(request TUICViewRequest, observation TUICObservation) string {
	port, protocol, valid := uint16(0), "", false
	if protocolAwareTUIC(request.Network, request.Port) {
		port, protocol, valid = request.Network.ConnectionProfilesTUICListener()
	}
	encoded, _ := json.Marshal(struct {
		Request     TUICViewRequest
		Port        uint16
		Protocol    string
		Valid       bool
		Observation TUICObservation
	}{request, port, protocol, valid, observation})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blockedTUIC(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return blockedHealth(Health{Time: at, Module: "Connection Profiles", Profile: "TUIC", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}})
}

type TUICPlanRequest struct {
	Reality                                            ViewRequest
	XHTTP                                              XHTTPViewRequest
	WebSocket                                          WebSocketViewRequest
	Hysteria2                                          Hysteria2ViewRequest
	View                                               TUICViewRequest
	ChangeSet, StartingStateSHA256, DesiredStateSHA256 string
}

func (module Interface) PlanTUIC(ctx context.Context, request TUICPlanRequest) PlanResult {
	reality, xhttp, websocket := module.View(ctx, request.Reality), module.ViewXHTTP(ctx, request.XHTTP), module.ViewWebSocket(ctx, request.WebSocket)
	for _, health := range []Health{reality.Health, xhttp.Health, websocket.Health} {
		if health.Outcome != Healthy {
			return PlanResult{Health: health}
		}
	}
	hysteria2Request := request.Hysteria2
	hysteria2Request.Profiles = &SingBoxProfileSet{TUIC: &request.View}
	hysteria2 := module.viewHysteria2(ctx, hysteria2Request, false)
	if hysteria2.Health.Outcome != Healthy {
		return PlanResult{Health: hysteria2.Health}
	}
	view := module.viewTUIC(ctx, hysteria2Request, request.View, false)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if request.Reality.Revision != request.View.Revision || request.XHTTP.Revision != request.View.Revision || request.WebSocket.Revision != request.View.Revision || request.Hysteria2.Revision != request.View.Revision || request.View.Credentials.uuid.value == request.Reality.Credentials.uuid.value || request.View.Credentials.uuid.value == request.XHTTP.Credentials.uuid.value || request.View.Credentials.uuid.value == request.WebSocket.Credentials.uuid.value || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blockedTUIC(view.Health.Time, Failed, "CONNECTION-PROFILES-TUIC-PLAN-STATE", "The reviewed State binding is invalid", "a Change Set, revision, or State checksum is missing or contradictory", "one exact current and candidate State binding")}
	}
	xray, err := xrayConfiguration(&request.Reality, &request.XHTTP, &request.WebSocket)
	if err != nil {
		return PlanResult{Health: blockedTUIC(view.Health.Time, Failed, "CONNECTION-PROFILES-TUIC-CONFIGURATION", "The complete Xray configuration could not be prepared", "the reviewed Xray profiles are incomplete", "one complete protected Xray configuration")}
	}
	singBox, err := singBoxConfiguration(&hysteria2Request, hysteria2Request.Profiles)
	if err != nil {
		return PlanResult{Health: blockedTUIC(view.Health.Time, Failed, "CONNECTION-PROFILES-TUIC-CONFIGURATION", "The complete sing-box configuration could not be prepared", "the reviewed Hysteria2 or TUIC inputs are incomplete", "one complete protected sing-box configuration")}
	}
	plan, failure := module.buildSingBoxPlan(ctx, singBoxPlanSpec{profile: "TUIC", description: "validate and activate TUIC on public 8443/UDP with replay-safe cubic defaults; rollback restores both prior configurations", xrayVersion: request.Reality.XrayVersion, singBoxVersion: request.View.SingBoxVersion, revision: request.View.Revision, changeSet: request.ChangeSet, startingState: request.StartingStateSHA256, desiredState: request.DesiredStateSHA256, xray: xray, singBox: singBox, volatileInputs: reality.VolatileSHA256 + xhttp.VolatileSHA256 + websocket.VolatileSHA256 + hysteria2.VolatileSHA256 + view.VolatileSHA256, binding: request, reality: request.Reality, xhttp: &request.XHTTP, websocket: &request.WebSocket, hysteria2: &hysteria2Request, tuic: &request.View})
	if failure != "" {
		return PlanResult{Health: blockedTUIC(view.Health.Time, Failed, "CONNECTION-PROFILES-TUIC-"+failure, "The complete protected Plan could not be finalized", "native validation, binding, or transaction preparation failed", "one validated and reversible TUIC Plan")}
	}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: "TUIC", Outcome: Healthy, Code: "CONNECTION-PROFILES-TUIC-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func tuicProfileInput(profile state.TUIC, secrets state.ConnectionProfileSecretReader) (*TUICViewRequest, error) {
	if !profile.Enabled && profile == (state.TUIC{}) {
		return nil, nil
	}
	credentials, err := NewTUICCredentials(secrets.ReadClientAccessValue(profile.UUID), secrets.ReadClientAccessValue(profile.Password))
	if err != nil || profile.Port == 0 || !validHostname(profile.ServerName) || profile.CertificateID == "" || profile.CongestionControl != state.CongestionCubic || profile.ZeroRTT {
		return nil, errors.New("TUIC intent is invalid")
	}
	return &TUICViewRequest{Enabled: profile.Enabled, Port: profile.Port, ServerName: profile.ServerName, CertificateID: profile.CertificateID, CertificatePointer: directCertificatePointer, SingBoxVersion: qualifiedSingBoxVersion, CongestionControl: profile.CongestionControl, ZeroRTT: profile.ZeroRTT, Credentials: credentials, reviewedAlternative: profile.Port != 8443}, nil
}

func reviewedTUICMatches(reviewed *TUICViewRequest, profile state.TUIC, secrets state.ConnectionProfileSecretReader) bool {
	if reviewed == nil {
		return !profile.Enabled
	}
	return profile.Enabled == reviewed.Enabled && profile.Port == reviewed.Port && profile.ServerName == reviewed.ServerName && profile.CertificateID == reviewed.CertificateID && profile.CongestionControl == reviewed.CongestionControl && profile.ZeroRTT == reviewed.ZeroRTT && secrets.ReadClientAccessValue(profile.UUID) == reviewed.Credentials.uuid.value && secrets.ReadClientAccessValue(profile.Password) == reviewed.Credentials.password.value
}

func singBoxConfiguration(hysteria2 *Hysteria2ViewRequest, profiles *SingBoxProfileSet) ([]byte, error) {
	inbounds := make([]any, 0, 3)
	var tuic *TUICViewRequest
	var anyTLS *AnyTLSViewRequest
	if profiles != nil {
		tuic, anyTLS = profiles.TUIC, profiles.AnyTLS
	}
	if hysteria2 != nil && hysteria2.Enabled {
		if !selectedPort(hysteria2.Port, 443, hysteria2.reviewedAlternative) || !hysteria2.Credentials.valid() || !validHostname(hysteria2.ServerName) || hysteria2.MasqueradeResponse != "Not Found\n" || hysteria2.CertificatePointer != directCertificatePointer {
			return nil, errors.New("Hysteria2 inputs invalid")
		}
		inbound := map[string]any{"type": "hysteria2", "tag": "hysteria2-in", "listen": "0.0.0.0", "listen_port": hysteria2.Port, "users": []any{map[string]any{"password": hysteria2.Credentials.password.value}}, "tls": map[string]any{"enabled": true, "server_name": hysteria2.ServerName, "certificate_path": hysteria2.CertificatePointer + "/fullchain.pem", "key_path": hysteria2.CertificatePointer + "/privkey.pem"}, "masquerade": map[string]any{"type": "string", "status_code": 404, "headers": map[string][]string{"content-type": {"text/plain; charset=utf-8"}}, "content": hysteria2.MasqueradeResponse}}
		if hysteria2.Credentials.obfuscation {
			inbound["obfs"] = map[string]any{"type": "salamander", "password": hysteria2.Credentials.obfuscationSecret.value}
		}
		inbounds = append(inbounds, inbound)
	}
	if tuic != nil && tuic.Enabled {
		if !selectedPort(tuic.Port, 8443, tuic.reviewedAlternative) || !tuic.Credentials.valid() || !validHostname(tuic.ServerName) || tuic.CertificatePointer != directCertificatePointer || tuic.CongestionControl != state.CongestionCubic || tuic.ZeroRTT || hysteria2 == nil || tuic.Credentials.password.value == hysteria2.Credentials.password.value {
			return nil, errors.New("TUIC inputs invalid")
		}
		inbounds = append(inbounds, map[string]any{"type": "tuic", "tag": "tuic-in", "listen": "0.0.0.0", "listen_port": tuic.Port, "users": []any{map[string]any{"uuid": tuic.Credentials.uuid.value, "password": tuic.Credentials.password.value}}, "congestion_control": "cubic", "zero_rtt_handshake": false, "tls": map[string]any{"enabled": true, "server_name": tuic.ServerName, "certificate_path": tuic.CertificatePointer + "/fullchain.pem", "key_path": tuic.CertificatePointer + "/privkey.pem"}})
	}
	if anyTLS != nil && anyTLS.Enabled {
		if !selectedPort(anyTLS.Port, 9443, anyTLS.reviewedAlternative) || !anyTLS.Credentials.valid() || !validHostname(anyTLS.ServerName) || anyTLS.CertificatePointer != directCertificatePointer || anyTLS.MinimumSingBoxVersion != anyTLSMinimumSingBoxVersion || anyTLS.SingBoxVersion != qualifiedSingBoxVersion || !anyTLS.UseCorePadding || hysteria2 == nil || tuic == nil || anyTLS.Credentials.password.value == hysteria2.Credentials.password.value || anyTLS.Credentials.password.value == tuic.Credentials.password.value {
			return nil, errors.New("AnyTLS inputs invalid")
		}
		inbounds = append(inbounds, map[string]any{"type": "anytls", "tag": "anytls-in", "listen": "0.0.0.0", "listen_port": anyTLS.Port, "users": []any{map[string]any{"password": anyTLS.Credentials.password.value}}, "tls": map[string]any{"enabled": true, "server_name": anyTLS.ServerName, "certificate_path": anyTLS.CertificatePointer + "/fullchain.pem", "key_path": anyTLS.CertificatePointer + "/privkey.pem"}})
	}
	if len(inbounds) == 0 {
		inbounds = []any{}
	}
	return json.Marshal(map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": inbounds, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}})
}

func TUICConfigurationAgreement(content []byte, hysteria2 Hysteria2ViewRequest) bool {
	expected, err := singBoxConfiguration(&hysteria2, hysteria2.Profiles)
	if err != nil {
		return false
	}
	var activeValue, expectedValue any
	return json.Unmarshal(content, &activeValue) == nil && json.Unmarshal(expected, &expectedValue) == nil && reflect.DeepEqual(activeValue, expectedValue)
}
