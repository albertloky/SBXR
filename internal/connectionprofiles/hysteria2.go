package connectionprofiles

import (
	"bytes"
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
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	qualifiedSingBoxVersion  = "1.13.16"
	directCertificatePointer = "/var/lib/sbxr/certificates/domain/current"
)

type Hysteria2Credentials struct{ password secretText }

func (Hysteria2Credentials) String() string   { return "Hysteria2 credentials: ready" }
func (Hysteria2Credentials) GoString() string { return "Hysteria2 credentials: ready" }

func NewHysteria2Credentials(password string) (Hysteria2Credentials, error) {
	credentials := Hysteria2Credentials{password: secretText{value: password}}
	if !credentials.valid() {
		return Hysteria2Credentials{}, errors.New("Hysteria2 credentials are invalid")
	}
	return credentials, nil
}

func GenerateHysteria2Credentials() (Hysteria2Credentials, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return Hysteria2Credentials{}, errors.New("Hysteria2 password generation failed")
	}
	return NewHysteria2Credentials(hex.EncodeToString(value))
}

func (credentials Hysteria2Credentials) valid() bool {
	value, err := hex.DecodeString(credentials.password.value)
	return err == nil && len(value) == 32
}

type Hysteria2Observation struct {
	CheckedAt                                time.Time
	ConfigurationSafe, ConfigurationValid    bool
	ConfigurationMatches, CertificateMatches bool
	ServiceUnit, ServiceIdentity             string
	ServiceRunning, NetBindService           bool
	Listener                                 Listener
	ServerFunction                           ProbeStatus
}

type Hysteria2Host interface {
	ObserveHysteria2(context.Context, Hysteria2ViewRequest) Hysteria2Observation
	ValidateHysteria2(context.Context, string, io.Reader) error
}

type Hysteria2ViewRequest struct {
	Revision                           uint64
	Port                               uint16
	Enabled                            bool
	DestinationIP, ServerName          string
	CertificatePointer, SingBoxVersion string
	CertificateID, MasqueradeResponse  string
	Credentials                        Hysteria2Credentials
	DirectTLS                          DirectTLSContribution
	Network                            ListenerPolicyAuthority
}

type ListenerPolicyAuthority interface {
	ConnectionProfilesListeners() (realityPort uint16, realityProtocol string, hysteria2Port uint16, hysteria2Protocol string, valid bool)
}

type Hysteria2Profile struct {
	Name, DestinationIP, ServerName, SingBoxVersion string
	ServiceUnit                                     string
	Enabled, CredentialsReady, ServiceRunning       bool
	Port                                            uint16
	Listener                                        Listener
}

type Hysteria2ViewResult struct {
	Profile        Hysteria2Profile
	Health         Health
	VolatileSHA256 string
	observation    Hysteria2Observation
}

func (module Interface) ViewHysteria2(ctx context.Context, request Hysteria2ViewRequest) Hysteria2ViewResult {
	port := request.Port
	profile := Hysteria2Profile{Name: "Hysteria2", DestinationIP: request.DestinationIP, ServerName: request.ServerName, SingBoxVersion: request.SingBoxVersion, Enabled: request.Enabled, Port: port, CredentialsReady: request.Credentials.valid()}
	host, ok := module.host.(Hysteria2Host)
	if !ok {
		return Hysteria2ViewResult{Profile: profile, Health: blockedHysteria2(time.Time{}, Unknown, "CONNECTION-PROFILES-HYSTERIA2-HOST", "The Ubuntu and native sing-box observation is unavailable", "no local host boundary", "one typed Ubuntu and sing-box observation")}
	}
	observation := host.ObserveHysteria2(ctx, request)
	profile.ServiceUnit, profile.ServiceRunning, profile.Listener = observation.ServiceUnit, observation.ServiceRunning, observation.Listener
	result := Hysteria2ViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = hysteria2ObservationSHA256(request, observation)
	address, addressErr := netip.ParseAddr(request.DestinationIP)
	if !request.Enabled || request.Port != 443 || addressErr != nil || !address.IsGlobalUnicast() || !validHostname(request.ServerName) || request.CertificateID == "" || request.MasqueradeResponse != "Not Found\n" || request.CertificatePointer != directCertificatePointer || request.SingBoxVersion != qualifiedSingBoxVersion || !request.Credentials.valid() {
		result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-INPUT", "The Hysteria2 inputs are invalid", "the destination, listener, TLS name, certificate pointer, credential, enabled state, or qualified release is wrong", "one enabled Hysteria2 profile on public 443/UDP using sing-box 1.13.16 and the shared Direct TLS pair")
		return result
	}
	revision, destination, hostname, _, directValid := request.DirectTLS.SystemChangesDirectTLS()
	if !directValid || revision != request.Revision || destination != request.DestinationIP || hostname != request.ServerName {
		result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-CERTIFICATE", "The reviewed Direct TLS identity does not agree", "the destination, hostname, revision, or shared certificate consumers differ", "one exact Direct TLS Hostname and shared active certificate pair with normal verification")
		return result
	}
	if !protocolAware443(request.Network) {
		result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-NETWORK", "The reviewed protocol-aware listener policy does not agree", "443/TCP REALITY and 443/UDP Hysteria2 were not both proved", "intentional coexistence on numeric port 443 using separate TCP and UDP listeners")
		return result
	}
	if request.Revision > 0 {
		if observation.ConfigurationSafe && observation.ConfigurationValid && !observation.CertificateMatches {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-CERTIFICATE", "The active certificate binding does not agree", "the protected configuration, shared pointer, certificate protection, or certificate identity differs", request.ServerName+" through the shared active Direct TLS pair")
			return result
		}
		if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-CONFIGURATION", "The protected sing-box configuration is unsafe, invalid, or different", "ownership, mode, link, native validity, or active configuration agreement failed", "root-owned service-readable material under /etc/sbxr accepted by sing-box 1.13.16")
			return result
		}
		if observation.ServiceUnit != "sing-box.service" || observation.ServiceIdentity != "sing-box" || !observation.ServiceRunning {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-SERVICE", "The fixed sing-box service is not running safely", "sing-box.service or its distinct non-root identity disagrees", "running sing-box.service as sing-box")
			return result
		}
		if !publicUDPListener(observation.Listener, port) {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-LISTENER", "The Hysteria2 listener disagrees", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), "public 443/UDP")
			return result
		}
		if !observation.NetBindService {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-CAPABILITY", "The sing-box service capability is broader or narrower than required", "CAP_NET_BIND_SERVICE does not match the selected privileged port", "only CAP_NET_BIND_SERVICE for approved port 443/UDP")
			return result
		}
		if observation.ServerFunction != ProbePassed {
			result.Health = blockedHysteria2(observation.CheckedAt, Failed, "CONNECTION-PROFILES-HYSTERIA2-FUNCTION", "The bounded authenticated server-side check did not pass", string(observation.ServerFunction), "one safe authenticated Hysteria2 server-side function proof")
			return result
		}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-HYSTERIA2-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
	return result
}

func protocolAware443(authority ListenerPolicyAuthority) bool {
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
	realityPort, realityProtocol, hysteriaPort, hysteriaProtocol, valid := authority.ConnectionProfilesListeners()
	return valid && realityPort == 443 && realityProtocol == "TCP" && hysteriaPort == 443 && hysteriaProtocol == "UDP"
}

type listenerPolicyBinding struct {
	RealityPort, Hysteria2Port         uint16
	RealityProtocol, Hysteria2Protocol string
	Valid                              bool
}

func reviewedListenerPolicy(authority ListenerPolicyAuthority) listenerPolicyBinding {
	if !protocolAware443(authority) {
		return listenerPolicyBinding{}
	}
	realityPort, realityProtocol, hysteriaPort, hysteriaProtocol, valid := authority.ConnectionProfilesListeners()
	return listenerPolicyBinding{realityPort, hysteriaPort, realityProtocol, hysteriaProtocol, valid}
}

func publicUDPListener(listener Listener, port uint16) bool {
	return listener.Port == port && listener.Protocol == "udp" && (listener.Address == "0.0.0.0" || listener.Address == "::" || listener.Address == "*")
}

func hysteria2ObservationSHA256(request Hysteria2ViewRequest, observation Hysteria2Observation) string {
	encoded, _ := json.Marshal(struct {
		Request     Hysteria2ViewRequest
		Network     listenerPolicyBinding
		Observation Hysteria2Observation
	}{request, reviewedListenerPolicy(request.Network), observation})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blockedHysteria2(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return Health{Time: at, Module: "Connection Profiles", Profile: "Hysteria2", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}}
}

type Hysteria2PlanRequest struct {
	Reality             ViewRequest
	XHTTP               XHTTPViewRequest
	WebSocket           WebSocketViewRequest
	View                Hysteria2ViewRequest
	ChangeSet           string
	StartingStateSHA256 string
	DesiredStateSHA256  string
}

func (module Interface) PlanHysteria2(ctx context.Context, request Hysteria2PlanRequest) PlanResult {
	reality, xhttp, websocket := module.View(ctx, request.Reality), module.ViewXHTTP(ctx, request.XHTTP), module.ViewWebSocket(ctx, request.WebSocket)
	for _, health := range []Health{reality.Health, xhttp.Health, websocket.Health} {
		if health.Outcome != Healthy {
			return PlanResult{Health: health}
		}
	}
	view := module.ViewHysteria2(ctx, request.View)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if request.Reality.Revision != request.View.Revision || request.XHTTP.Revision != request.View.Revision || request.WebSocket.Revision != request.View.Revision || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-PLAN-STATE", "The reviewed State binding is invalid", "a Change Set, revision, or State checksum is missing or contradictory", "one exact current and candidate State binding")}
	}
	xray, err := xrayConfiguration(&request.Reality, &request.XHTTP, &request.WebSocket)
	if err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-CONFIGURATION", "The complete Xray configuration could not be prepared", "the reviewed Xray profiles are incomplete", "one complete protected Xray configuration")}
	}
	singBox, err := hysteria2Configuration(request.View)
	if err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-CONFIGURATION", "The complete sing-box configuration could not be prepared", "the typed Hysteria2 inputs are incomplete", "one complete protected sing-box configuration")}
	}
	if err := module.host.ValidateReality(ctx, request.Reality.XrayVersion, bytes.NewReader(xray)); err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-NATIVE", "The pinned native validator refused the complete prepared configuration", "native Xray validation failed", "complete configurations accepted by Xray and sing-box")}
	}
	host := module.host.(Hysteria2Host)
	if err := host.ValidateHysteria2(ctx, request.View.SingBoxVersion, bytes.NewReader(singBox)); err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-NATIVE", "The pinned native validator refused the complete prepared configuration", "native sing-box validation failed", "one complete configuration accepted by sing-box 1.13.16")}
	}
	preparedBinding, err := opaquePreparedBinding(xray, singBox)
	if err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-BINDING", "The protected prepared-configuration authority is unavailable", "an opaque binding could not be created", "one secret-safe binding to both exact validated configurations")}
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return PlanResult{Health: blockedHysteria2(view.Health.Time, Failed, "CONNECTION-PROFILES-HYSTERIA2-TRANSACTION", "The profile transaction contract is invalid", "the activation or rollback step was refused", "one reversible Connection Profiles step")}
	}
	checks := []systemchanges.Check{}
	for _, suffix := range []string{"CONFIGURATION", "LISTENER", "SERVICE", "CERTIFICATE", "FUNCTION"} {
		phase := systemchanges.PrePublication
		if suffix == "FUNCTION" {
			phase = systemchanges.PostPublication
		}
		checks = append(checks, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: phase, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-HYSTERIA2-" + suffix})
	}
	volatile := sha256.Sum256([]byte(reality.VolatileSHA256 + xhttp.VolatileSHA256 + websocket.VolatileSHA256 + view.VolatileSHA256))
	volatileSHA := hex.EncodeToString(volatile[:])
	binding, _ := json.Marshal(struct {
		Request                         Hysteria2PlanRequest
		Network                         listenerPolicyBinding
		VolatileSHA256, PreparedBinding string
	}{request, reviewedListenerPolicy(request.View.Network), volatileSHA, preparedBinding})
	digest := sha256.Sum256(binding)
	sha := hex.EncodeToString(digest[:])
	plan := &Plan{identity: "profiles-hysteria2-" + sha[:12], sha256: sha, volatileSHA256: volatileSHA, description: "validate and activate Hysteria2 on public 443/UDP through sing-box.service with the shared Direct TLS identity; rollback restores both prior configurations", preparedBinding: preparedBinding, configuration: xray, singBoxConfiguration: singBox, revision: request.View.Revision, changeSet: request.ChangeSet, startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256, realityRequest: request.Reality, xhttpRequest: &request.XHTTP, webSocketRequest: &request.WebSocket, hysteria2Request: &request.View, steps: []systemchanges.Step{step}, checks: checks, used: &atomic.Bool{}}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: "Hysteria2", Outcome: Healthy, Code: "CONNECTION-PROFILES-HYSTERIA2-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func hysteria2ProfileInput(profile state.Hysteria2, secrets state.ConnectionProfileSecretReader) (*Hysteria2ViewRequest, error) {
	if !profile.Enabled {
		return nil, nil
	}
	credentials, err := NewHysteria2Credentials(secrets.ReadClientAccessValue(profile.Password))
	if err != nil || profile.Port != 443 || !validHostname(profile.ServerName) || profile.CertificateID == "" || profile.MasqueradeURL != "https://example.com/" || profile.Obfuscation || profile.ObfuscationSecret != (state.ClientAccessValue{}) {
		return nil, errors.New("Hysteria2 intent is invalid")
	}
	return &Hysteria2ViewRequest{Enabled: true, Port: profile.Port, ServerName: profile.ServerName, CertificateID: profile.CertificateID, MasqueradeResponse: "Not Found\n", CertificatePointer: directCertificatePointer, SingBoxVersion: qualifiedSingBoxVersion, Credentials: credentials}, nil
}

func reviewedHysteria2Matches(reviewed *Hysteria2ViewRequest, profile state.Hysteria2, secrets state.ConnectionProfileSecretReader) bool {
	if reviewed == nil {
		return !profile.Enabled
	}
	return profile.Enabled && profile.Port == reviewed.Port && profile.ServerName == reviewed.ServerName && profile.CertificateID == reviewed.CertificateID && profile.MasqueradeURL == "https://example.com/" && reviewed.MasqueradeResponse == "Not Found\n" && !profile.Obfuscation && profile.ObfuscationSecret == (state.ClientAccessValue{}) && secrets.ReadClientAccessValue(profile.Password) == reviewed.Credentials.password.value
}

func hysteria2Configuration(request Hysteria2ViewRequest) ([]byte, error) {
	if request.Port != 443 || !request.Credentials.valid() || !validHostname(request.ServerName) || request.MasqueradeResponse != "Not Found\n" || request.CertificatePointer != directCertificatePointer {
		return nil, errors.New("Hysteria2 inputs invalid")
	}
	inbound := map[string]any{"type": "hysteria2", "tag": "hysteria2-in", "listen": "0.0.0.0", "listen_port": 443, "users": []any{map[string]any{"password": request.Credentials.password.value}}, "tls": map[string]any{"enabled": true, "server_name": request.ServerName, "certificate_path": request.CertificatePointer + "/fullchain.pem", "key_path": request.CertificatePointer + "/privkey.pem"}, "masquerade": map[string]any{"type": "string", "status_code": 404, "headers": map[string][]string{"content-type": {"text/plain; charset=utf-8"}}, "content": request.MasqueradeResponse}}
	return json.Marshal(map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{inbound}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}})
}

// Hysteria2ConfigurationAgreement compares the complete active JSON to the
// reviewed configuration without returning its protected password.
func Hysteria2ConfigurationAgreement(content []byte, request Hysteria2ViewRequest) bool {
	expected, err := hysteria2Configuration(request)
	if err != nil {
		return false
	}
	var activeValue, expectedValue any
	return json.Unmarshal(content, &activeValue) == nil && json.Unmarshal(expected, &expectedValue) == nil && reflect.DeepEqual(activeValue, expectedValue)
}
