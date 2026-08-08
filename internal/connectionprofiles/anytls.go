package connectionprofiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/albertloky/SBXR/internal/state"
)

const anyTLSMinimumSingBoxVersion = "1.12.0"

type AnyTLSCredentials struct{ password secretText }

func (AnyTLSCredentials) String() string   { return "AnyTLS credentials: ready" }
func (AnyTLSCredentials) GoString() string { return "AnyTLS credentials: ready" }

func NewAnyTLSCredentials(password string) (AnyTLSCredentials, error) {
	credentials := AnyTLSCredentials{password: secretText{value: password}}
	if !credentials.valid() {
		return AnyTLSCredentials{}, errors.New("AnyTLS credentials are invalid")
	}
	return credentials, nil
}

func GenerateAnyTLSCredentials() (AnyTLSCredentials, error) {
	password, err := generateHexSecret()
	if err != nil {
		return AnyTLSCredentials{}, errors.New("AnyTLS password generation failed")
	}
	return NewAnyTLSCredentials(password)
}

func (credentials AnyTLSCredentials) valid() bool {
	password, err := hex.DecodeString(credentials.password.value)
	return err == nil && len(password) == 32
}

type AnyTLSObservation = Hysteria2Observation

type AnyTLSHost interface {
	ObserveAnyTLS(context.Context, Hysteria2ViewRequest, TUICViewRequest, AnyTLSViewRequest) AnyTLSObservation
}

type AnyTLSViewRequest struct {
	Revision                             uint64
	Port                                 uint16
	Enabled, UseCorePadding              bool
	DestinationIP, ServerName            string
	CertificatePointer, SingBoxVersion   string
	MinimumSingBoxVersion, CertificateID string
	Credentials                          AnyTLSCredentials
	DirectTLS                            DirectTLSContribution
	Network                              AnyTLSListenerPolicyAuthority
	reviewedAlternative                  bool
}

type AnyTLSListenerPolicyAuthority interface {
	ConnectionProfilesAnyTLSListener() (port uint16, protocol string, valid bool)
}

type AnyTLSProfile struct {
	Name, DestinationIP, ServerName, SingBoxVersion, MinimumSingBoxVersion string
	ServiceUnit                                                            string
	Enabled, CredentialsReady, ServiceRunning, UsesCorePadding             bool
	Port                                                                   uint16
	Listener                                                               Listener
}

type AnyTLSViewResult struct {
	Profile        AnyTLSProfile
	Health         Health
	VolatileSHA256 string
	observation    AnyTLSObservation
}

func (module Interface) ViewAnyTLS(ctx context.Context, hysteria2 Hysteria2ViewRequest, tuic TUICViewRequest, request AnyTLSViewRequest) AnyTLSViewResult {
	return module.viewAnyTLS(ctx, hysteria2, tuic, request, true)
}

func (module Interface) viewAnyTLS(ctx context.Context, hysteria2 Hysteria2ViewRequest, tuic TUICViewRequest, request AnyTLSViewRequest, checkActive bool) AnyTLSViewResult {
	profiles := SingBoxProfileSet{TUIC: &tuic, AnyTLS: &request}
	hysteria2.Profiles = &profiles
	profile := AnyTLSProfile{Name: "AnyTLS", DestinationIP: request.DestinationIP, ServerName: request.ServerName, SingBoxVersion: request.SingBoxVersion, MinimumSingBoxVersion: request.MinimumSingBoxVersion, Enabled: request.Enabled, Port: request.Port, CredentialsReady: request.Credentials.valid(), UsesCorePadding: request.UseCorePadding}
	host, ok := module.host.(AnyTLSHost)
	if !ok {
		return AnyTLSViewResult{Profile: profile, Health: blockedAnyTLS(time.Time{}, Unknown, "CONNECTION-PROFILES-ANYTLS-HOST", "The Ubuntu AnyTLS observation is unavailable", "no local host boundary", "one typed Ubuntu observation")}
	}
	observation := host.ObserveAnyTLS(ctx, hysteria2, tuic, request)
	profile.ServiceUnit, profile.ServiceRunning, profile.Listener = observation.ServiceUnit, observation.ServiceRunning, observation.Listener
	result := AnyTLSViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = anyTLSObservationSHA256(request, observation)
	address, addressErr := netip.ParseAddr(request.DestinationIP)
	if !request.Enabled || !selectedPort(request.Port, 9443, request.reviewedAlternative) || addressErr != nil || !address.IsGlobalUnicast() || !validHostname(request.ServerName) || request.CertificateID == "" || request.CertificatePointer != directCertificatePointer || request.MinimumSingBoxVersion != anyTLSMinimumSingBoxVersion || request.SingBoxVersion != qualifiedSingBoxVersion || !request.UseCorePadding || !request.Credentials.valid() || !hysteria2.Credentials.valid() || !tuic.Credentials.valid() || request.Credentials.password.value == hysteria2.Credentials.password.value || request.Credentials.password.value == tuic.Credentials.password.value {
		result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-INPUT", "The AnyTLS inputs are invalid", "the destination, listener, TLS name, credential, version floor, qualified release, or padding ownership is wrong", "one enabled AnyTLS profile on public 9443/TCP using sing-box 1.12.0 or newer, qualified at 1.13.16, with core-owned padding")
		return result
	}
	revision, destination, hostname, _, directValid := request.DirectTLS.SystemChangesDirectTLS()
	if !directValid || revision != request.Revision || destination != request.DestinationIP || hostname != request.ServerName {
		result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-CERTIFICATE", "The reviewed Direct TLS identity does not agree", "the destination, hostname, revision, or shared certificate consumers differ", "one exact Direct TLS Hostname and shared active certificate pair with normal verification")
		return result
	}
	if !protocolAwareAnyTLS(request.Network, request.Port) {
		result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-NETWORK", "The reviewed AnyTLS listener policy does not agree", "public 9443/TCP was not proved", "one public AnyTLS listener on 9443/TCP")
		return result
	}
	if checkActive && request.Revision > 0 {
		switch {
		case observation.ConfigurationSafe && observation.ConfigurationValid && !observation.CertificateMatches:
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-CERTIFICATE", "The active certificate binding does not agree", "the shared certificate protection or identity differs", request.ServerName+" through the shared active Direct TLS pair")
		case !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches:
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-CONFIGURATION", "The protected sing-box configuration is unsafe, invalid, or different", "ownership, native validity, exact active agreement, or core padding ownership failed", "the reviewed complete Hysteria2, TUIC, and AnyTLS configuration without copied padding")
		case observation.ServiceUnit != "sing-box.service" || observation.ServiceIdentity != "sing-box" || !observation.ServiceRunning:
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-SERVICE", "The fixed sing-box service is not running safely", "sing-box.service or its non-root identity disagrees", "running sing-box.service as sing-box")
		case !publicTCPListener(observation.Listener, request.Port):
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-LISTENER", "The AnyTLS listener disagrees", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), "public 9443/TCP")
		case observation.NetBindService != singBoxNeedsCapability(hysteria2, tuic, request) || !singBoxNeedsCapability(hysteria2, tuic, request) && !observation.NoCapabilities:
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-CAPABILITY", "The shared sing-box service capability is wrong", "CAP_NET_BIND_SERVICE is absent or broader", "only CAP_NET_BIND_SERVICE for the shared privileged Hysteria2 listener")
		case observation.ServerFunction != ProbePassed:
			result.Health = blockedAnyTLS(observation.CheckedAt, Failed, "CONNECTION-PROFILES-ANYTLS-FUNCTION", "The bounded authenticated AnyTLS check did not pass", string(observation.ServerFunction), "one safe authenticated AnyTLS server-side function proof")
		default:
			result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: "AnyTLS", Outcome: Healthy, Code: "CONNECTION-PROFILES-ANYTLS-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
		}
		if result.Health.Outcome != Healthy {
			return result
		}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: "AnyTLS", Outcome: Healthy, Code: "CONNECTION-PROFILES-ANYTLS-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
	return result
}

func protocolAwareAnyTLS(authority AnyTLSListenerPolicyAuthority, selected uint16) bool {
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
	port, protocol, valid := authority.ConnectionProfilesAnyTLSListener()
	return valid && port == selected && protocol == "TCP"
}

func anyTLSObservationSHA256(request AnyTLSViewRequest, observation AnyTLSObservation) string {
	port, protocol, valid := uint16(0), "", false
	if protocolAwareAnyTLS(request.Network, request.Port) {
		port, protocol, valid = request.Network.ConnectionProfilesAnyTLSListener()
	}
	encoded, _ := json.Marshal(struct {
		Request     AnyTLSViewRequest
		Port        uint16
		Protocol    string
		Valid       bool
		Observation AnyTLSObservation
	}{request, port, protocol, valid, observation})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blockedAnyTLS(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return blockedHealth(Health{Time: at, Module: "Connection Profiles", Profile: "AnyTLS", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}})
}

type AnyTLSPlanRequest struct {
	Reality                                            ViewRequest
	XHTTP                                              XHTTPViewRequest
	WebSocket                                          WebSocketViewRequest
	Hysteria2                                          Hysteria2ViewRequest
	TUIC                                               TUICViewRequest
	View                                               AnyTLSViewRequest
	ChangeSet, StartingStateSHA256, DesiredStateSHA256 string
}

func (module Interface) PlanAnyTLS(ctx context.Context, request AnyTLSPlanRequest) PlanResult {
	reality, xhttp, websocket := module.View(ctx, request.Reality), module.ViewXHTTP(ctx, request.XHTTP), module.ViewWebSocket(ctx, request.WebSocket)
	for _, health := range []Health{reality.Health, xhttp.Health, websocket.Health} {
		if health.Outcome != Healthy {
			return PlanResult{Health: health}
		}
	}
	hysteria2Request, tuicRequest := request.Hysteria2, request.TUIC
	profiles := &SingBoxProfileSet{TUIC: &tuicRequest, AnyTLS: &request.View}
	hysteria2Request.Profiles = profiles
	hysteria2 := module.viewHysteria2(ctx, hysteria2Request, false)
	if hysteria2.Health.Outcome != Healthy {
		return PlanResult{Health: hysteria2.Health}
	}
	tuic := module.viewTUIC(ctx, hysteria2Request, tuicRequest, false)
	if tuic.Health.Outcome != Healthy {
		return PlanResult{Health: tuic.Health}
	}
	view := module.viewAnyTLS(ctx, hysteria2Request, tuicRequest, request.View, false)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if request.Reality.Revision != request.View.Revision || request.XHTTP.Revision != request.View.Revision || request.WebSocket.Revision != request.View.Revision || request.Hysteria2.Revision != request.View.Revision || request.TUIC.Revision != request.View.Revision || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blockedAnyTLS(view.Health.Time, Failed, "CONNECTION-PROFILES-ANYTLS-PLAN-STATE", "The reviewed State binding is invalid", "a Change Set, revision, or State checksum is missing or contradictory", "one exact current and candidate State binding")}
	}
	xray, err := xrayConfiguration(&request.Reality, &request.XHTTP, &request.WebSocket)
	if err != nil {
		return PlanResult{Health: blockedAnyTLS(view.Health.Time, Failed, "CONNECTION-PROFILES-ANYTLS-CONFIGURATION", "The complete Xray configuration could not be prepared", "the reviewed Xray profiles are incomplete", "one complete protected Xray configuration")}
	}
	singBox, err := singBoxConfiguration(&hysteria2Request, profiles)
	if err != nil {
		return PlanResult{Health: blockedAnyTLS(view.Health.Time, Failed, "CONNECTION-PROFILES-ANYTLS-CONFIGURATION", "The complete sing-box configuration could not be prepared", "the reviewed direct profiles are incomplete", "one complete protected sing-box configuration")}
	}
	plan, failure := module.buildSingBoxPlan(ctx, singBoxPlanSpec{profile: "ANYTLS", description: "validate and activate AnyTLS on public 9443/TCP with core-owned padding; rollback restores both prior configurations", xrayVersion: request.Reality.XrayVersion, singBoxVersion: request.View.SingBoxVersion, revision: request.View.Revision, changeSet: request.ChangeSet, startingState: request.StartingStateSHA256, desiredState: request.DesiredStateSHA256, xray: xray, singBox: singBox, volatileInputs: reality.VolatileSHA256 + xhttp.VolatileSHA256 + websocket.VolatileSHA256 + hysteria2.VolatileSHA256 + tuic.VolatileSHA256 + view.VolatileSHA256, binding: request, reality: request.Reality, xhttp: &request.XHTTP, websocket: &request.WebSocket, hysteria2: &hysteria2Request, tuic: &tuicRequest, anyTLS: &request.View})
	if failure != "" {
		return PlanResult{Health: blockedAnyTLS(view.Health.Time, Failed, "CONNECTION-PROFILES-ANYTLS-"+failure, "The complete protected Plan could not be finalized", "native validation, binding, or transaction preparation failed", "one validated and reversible AnyTLS Plan")}
	}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: "AnyTLS", Outcome: Healthy, Code: "CONNECTION-PROFILES-ANYTLS-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func anyTLSProfileInput(profile state.AnyTLS, secrets state.ConnectionProfileSecretReader) (*AnyTLSViewRequest, error) {
	if !profile.Enabled && profile == (state.AnyTLS{}) {
		return nil, nil
	}
	credentials, err := NewAnyTLSCredentials(secrets.ReadClientAccessValue(profile.Password))
	if err != nil || profile.Port == 0 || !validHostname(profile.ServerName) || profile.CertificateID == "" || profile.PaddingScheme != "upstream-default" {
		return nil, errors.New("AnyTLS intent is invalid")
	}
	return &AnyTLSViewRequest{Enabled: profile.Enabled, Port: profile.Port, ServerName: profile.ServerName, CertificateID: profile.CertificateID, CertificatePointer: directCertificatePointer, MinimumSingBoxVersion: anyTLSMinimumSingBoxVersion, SingBoxVersion: qualifiedSingBoxVersion, UseCorePadding: true, Credentials: credentials, reviewedAlternative: profile.Port != 9443}, nil
}

func reviewedAnyTLSMatches(reviewed *AnyTLSViewRequest, profile state.AnyTLS, secrets state.ConnectionProfileSecretReader) bool {
	if reviewed == nil {
		return !profile.Enabled
	}
	return profile.Enabled == reviewed.Enabled && profile.Port == reviewed.Port && profile.ServerName == reviewed.ServerName && profile.CertificateID == reviewed.CertificateID && profile.PaddingScheme == "upstream-default" && reviewed.UseCorePadding && secrets.ReadClientAccessValue(profile.Password) == reviewed.Credentials.password.value
}

func AnyTLSConfigurationAgreement(content []byte, hysteria2 Hysteria2ViewRequest) bool {
	expected, err := singBoxConfiguration(&hysteria2, hysteria2.Profiles)
	if err != nil {
		return false
	}
	var activeValue, expectedValue any
	return json.Unmarshal(content, &activeValue) == nil && json.Unmarshal(expected, &expectedValue) == nil && reflect.DeepEqual(activeValue, expectedValue)
}
