package connectionprofiles

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const qualifiedXrayVersion = "v26.3.27"

var (
	sha256Text = regexp.MustCompile(`^[0-9a-f]{64}$`)
	planName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,63}$`)
	uuidV4     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	shortID    = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

type Outcome string

const (
	Healthy        Outcome = "Healthy"
	NeedsAttention Outcome = "Needs attention"
	Failed         Outcome = "Failed"
	Unknown        Outcome = "Unknown"
)

type Health struct {
	Time        time.Time
	Module      string
	Profile     string
	Outcome     Outcome
	Code        string
	Problem     string
	Found       string
	Required    string
	WhyStopped  string
	NextActions []string
}

type TargetClass string

const (
	OrdinaryTarget    TargetClass = "ordinary"
	CloudflareTarget  TargetClass = "cloudflare-fronted"
	AppleICloudTarget TargetClass = "apple-or-icloud"
)

type ProbeStatus string

const (
	ProbePassed       ProbeStatus = "passed"
	ProbeFailed       ProbeStatus = "failed"
	ProbeInconclusive ProbeStatus = "inconclusive"
)

type RealityTarget struct {
	Address          string
	ServerName       string
	ProviderPrefixes []string
	ListenerPort     uint16
}

type Listener struct {
	Address  string
	Port     uint16
	Protocol string
}

type RealityObservation struct {
	CheckedAt         time.Time
	Probe             ProbeStatus
	Class             TargetClass
	AcceptedNames     []string
	RouteVerified     bool
	ProviderNetwork   bool
	ServiceInstalled  bool
	ServiceUnit       string
	ServiceIdentity   string
	ServiceRunning    bool
	ConfigurationSafe bool
	Listener          Listener
	NetBindService    bool
}

type RealityHost interface {
	ObserveReality(context.Context, RealityTarget) RealityObservation
	ValidateReality(context.Context, string, io.Reader) error
}

type secretText struct{ value string }

func (secretText) String() string   { return "[redacted]" }
func (secretText) GoString() string { return "[redacted]" }

type RealityCredentials struct {
	uuid, privateKey, publicKey, shortID secretText
}

func (RealityCredentials) String() string   { return "REALITY credentials: ready" }
func (RealityCredentials) GoString() string { return "REALITY credentials: ready" }

func NewRealityCredentials(uuid, privateKey, publicKey, short string) (RealityCredentials, error) {
	credentials := RealityCredentials{secretText{uuid}, secretText{privateKey}, secretText{publicKey}, secretText{short}}
	if !credentials.valid() {
		return RealityCredentials{}, errors.New("REALITY credentials are invalid")
	}
	return credentials, nil
}

func GenerateRealityCredentials() (RealityCredentials, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityCredentials{}, errors.New("REALITY key generation failed")
	}
	uuidBytes := make([]byte, 16)
	shortBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, uuidBytes); err != nil {
		return RealityCredentials{}, errors.New("REALITY UUID generation failed")
	}
	if _, err := io.ReadFull(rand.Reader, shortBytes); err != nil {
		return RealityCredentials{}, errors.New("REALITY short ID generation failed")
	}
	uuidBytes[6] = uuidBytes[6]&0x0f | 0x40
	uuidBytes[8] = uuidBytes[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	return NewRealityCredentials(
		uuid,
		base64.RawURLEncoding.EncodeToString(private.Bytes()),
		base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
		hex.EncodeToString(shortBytes),
	)
}

func (credentials RealityCredentials) valid() bool {
	privateBytes, privateErr := base64.RawURLEncoding.DecodeString(credentials.privateKey.value)
	publicBytes, publicErr := base64.RawURLEncoding.DecodeString(credentials.publicKey.value)
	private, keyErr := ecdh.X25519().NewPrivateKey(privateBytes)
	return uuidV4.MatchString(credentials.uuid.value) && shortID.MatchString(credentials.shortID.value) && privateErr == nil && publicErr == nil && keyErr == nil && len(publicBytes) == 32 && bytes.Equal(private.PublicKey().Bytes(), publicBytes)
}

type ViewRequest struct {
	Revision    uint64
	Enabled     bool
	Port        uint16
	Target      RealityTarget
	Fingerprint string
	XrayVersion string
	Credentials RealityCredentials
}

type Profile struct {
	Name, Transport, Security, Flow string
	Target, ServerName, XrayVersion string
	ServiceUnit                     string
	Enabled, CredentialsReady       bool
	ServiceRunning                  bool
	ProviderNetwork                 bool
	Port                            uint16
	Listener                        Listener
}

type ViewResult struct {
	Profile        Profile
	Health         Health
	VolatileSHA256 string

	observation RealityObservation
}

type Interface struct{ host RealityHost }

func New(host RealityHost) Interface { return Interface{host: host} }

func (module Interface) View(ctx context.Context, request ViewRequest) ViewResult {
	profile := Profile{Name: "VLESS REALITY Vision", Transport: "RAW", Security: "REALITY", Flow: "xtls-rprx-vision", Target: request.Target.Address, ServerName: request.Target.ServerName, XrayVersion: request.XrayVersion, Enabled: request.Enabled, Port: request.Port, CredentialsReady: request.Credentials.valid()}
	if module.host == nil {
		return ViewResult{Profile: profile, Health: blocked(time.Time{}, Unknown, "CONNECTION-PROFILES-REALITY-HOST", "The Ubuntu and native Xray observation is unavailable", "no local host boundary", "one typed Ubuntu and Xray observation")}
	}
	target := request.Target
	target.ListenerPort = request.Port
	observation := module.host.ObserveReality(ctx, target)
	profile.ServiceUnit = observation.ServiceUnit
	profile.ServiceRunning = observation.ServiceRunning
	profile.ProviderNetwork = observation.ProviderNetwork
	profile.Listener = observation.Listener
	result := ViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = realityObservationSHA256(request, observation)
	host, port, err := net.SplitHostPort(request.Target.Address)
	if err != nil || port != "443" || host != request.Target.ServerName || !validHostname(host) || request.Port != 443 || request.XrayVersion != qualifiedXrayVersion || request.Fingerprint != "chrome" || !request.Credentials.valid() || !request.Enabled {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET", "The VLESS REALITY Vision inputs are invalid", "the target, selected listener, credential, fingerprint, enabled state, or qualified release is wrong", "one enabled profile using target 443/TCP, Chrome fingerprint, and Xray v26.3.27")
		return result
	}
	if observation.Probe != ProbePassed {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-PROBE", "The bounded REALITY target probe did not pass", string(observation.Probe), "one conclusive xray tls ping route and safety result")
		return result
	}
	if observation.Class == CloudflareTarget || observation.Class == AppleICloudTarget || observation.Class != OrdinaryTarget {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET-CLASS", "The REALITY target belongs to a forbidden or unknown target class", string(observation.Class), "one suitable non-Cloudflare, non-Apple or iCloud target")
		return result
	}
	if !observation.RouteVerified {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-ROUTE", "The REALITY route is unproved", "the target route could not be confirmed", "one conclusive target route")
		return result
	}
	if !slices.Contains(observation.AcceptedNames, request.Target.ServerName) {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-NAME", "The REALITY accepted name does not match", strings.Join(observation.AcceptedNames, ","), request.Target.ServerName)
		return result
	}
	if request.Revision > 0 {
		if !observation.ConfigurationSafe {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-CONFIGURATION", "The protected Xray configuration is unsafe", "ownership, mode, path, or symbolic-link proof failed", "root-owned protected material under /etc/sbxr")
			return result
		}
		if observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "xray" || !observation.ServiceRunning {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-SERVICE", "The fixed Xray service is not running safely", "xray.service or its distinct non-root identity disagrees", "running xray.service as xray")
			return result
		}
		if !publicTCPListener(observation.Listener, request.Port) {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-LISTENER", "The REALITY listener disagrees", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), fmt.Sprintf("public %d/TCP", request.Port))
			return result
		}
		if request.Port < 1024 && !observation.NetBindService || request.Port >= 1024 && observation.NetBindService {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-CAPABILITY", "The Xray service capability is broader or narrower than required", "CAP_NET_BIND_SERVICE does not match the selected port", "the capability only for an approved port below 1024")
			return result
		}
	}
	nextActions := []string{"Build Plan", "Back"}
	if !observation.ProviderNetwork {
		nextActions = []string{"Prefer a suitable target in the VPS provider network", "Build Plan", "Back"}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-REALITY-HEALTHY", NextActions: nextActions}
	return result
}

func publicTCPListener(listener Listener, port uint16) bool {
	return listener.Port == port && listener.Protocol == "tcp" && (listener.Address == "0.0.0.0" || listener.Address == "::" || listener.Address == "*")
}

func realityObservationSHA256(request ViewRequest, observation RealityObservation) string {
	binding := struct {
		Revision                 uint64
		Enabled                  bool
		Port                     uint16
		Target                   RealityTarget
		Fingerprint, XrayVersion string
		Observation              RealityObservation
	}{request.Revision, request.Enabled, request.Port, request.Target, request.Fingerprint, request.XrayVersion, observation}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blocked(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return Health{Time: at, Module: "Connection Profiles", Profile: "VLESS REALITY Vision", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}}
}

type FallbackLimit struct {
	AfterBytes       uint64 `json:"afterBytes"`
	BytesPerSec      uint64 `json:"bytesPerSec"`
	BurstBytesPerSec uint64 `json:"burstBytesPerSec"`
}

type PlanRequest struct {
	View                ViewRequest
	ChangeSet           string
	StartingStateSHA256 string
	DesiredStateSHA256  string
}

type Plan struct {
	identity, sha256, volatileSHA256 string
	description                      string
	preparedBinding                  string
	configuration                    []byte
	revision                         uint64
	changeSet                        string
	startingStateSHA256              string
	desiredStateSHA256               string
	realityRequest                   ViewRequest
	xhttpRequest                     *XHTTPViewRequest
	steps                            []systemchanges.Step
	checks                           []systemchanges.Check
	used                             *atomic.Bool
}

func (plan *Plan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *Plan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *Plan) VolatileSHA256() string {
	if plan == nil {
		return ""
	}
	return plan.volatileSHA256
}
func (plan *Plan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Step(nil), plan.steps...)
}
func (plan *Plan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Check(nil), plan.checks...)
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Connection Profiles Plan: unavailable"
	}
	return fmt.Sprintf("Connection Profiles Plan %s: %s", plan.identity, plan.description)
}
func (plan *Plan) GoString() string { return plan.String() }

type PlanResult struct {
	Plan   *Plan
	Health Health
}

func (module Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	view := module.View(ctx, request.View)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blocked(view.Health.Time, Failed, "CONNECTION-PROFILES-REALITY-PLAN-STATE", "The reviewed State binding is invalid", "a Change Set or State checksum is missing or malformed", "one exact current and candidate State binding")}
	}
	configuration, err := realityConfiguration(request.View)
	if err != nil {
		return PlanResult{Health: blocked(view.Health.Time, Failed, "CONNECTION-PROFILES-REALITY-CONFIGURATION", "The complete Xray configuration could not be prepared", "the typed REALITY inputs are incomplete", "one complete protected Xray configuration")}
	}
	if err := module.host.ValidateReality(ctx, request.View.XrayVersion, bytes.NewReader(configuration)); err != nil {
		return PlanResult{Health: blocked(view.Health.Time, Failed, "CONNECTION-PROFILES-REALITY-NATIVE", "The pinned native Xray validator refused the prepared configuration", "native validation failed", "one complete configuration accepted by Xray v26.3.27")}
	}
	preparedBinding, err := opaquePreparedBinding(configuration)
	if err != nil {
		return PlanResult{Health: blocked(view.Health.Time, Failed, "CONNECTION-PROFILES-REALITY-BINDING", "The protected prepared-configuration authority is unavailable", "an opaque one-use binding could not be created", "one secret-safe binding to the exact validated configuration")}
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return PlanResult{Health: blocked(view.Health.Time, Failed, "CONNECTION-PROFILES-REALITY-TRANSACTION", "The profile transaction contract is invalid", "the activation or rollback step was refused", "one reversible Connection Profiles step")}
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REALITY-CONFIGURATION"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REALITY-LISTENER"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REALITY-SERVICE"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REALITY-SECURITY"},
	}
	binding := struct {
		Request         PlanRequest
		VolatileSHA256  string
		PreparedBinding string
	}{request, view.VolatileSHA256, preparedBinding}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	sha := hex.EncodeToString(digest[:])
	plan := &Plan{
		identity: "profiles-reality-" + sha[:12], sha256: sha, volatileSHA256: view.VolatileSHA256,
		description:     fmt.Sprintf("validate and activate VLESS REALITY Vision on %d/TCP through xray.service, then prove configuration, listener, service, and REALITY security; rollback restores the prior configuration", request.View.Port),
		preparedBinding: preparedBinding, configuration: append([]byte(nil), configuration...), revision: request.View.Revision, changeSet: request.ChangeSet,
		startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256, realityRequest: request.View,
		steps: []systemchanges.Step{step}, checks: checks, used: &atomic.Bool{},
	}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: view.Profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-REALITY-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func (module Interface) ValidateConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	if secrets == nil {
		return errors.New("Connection Profiles secret reader unavailable")
	}
	profile := profiles.VLESSRealityVision
	credentials, err := NewRealityCredentials(
		secrets.ReadClientAccessValue(profile.UUID),
		secrets.ReadInfrastructureSecret(profile.PrivateKey),
		profile.PublicKey,
		secrets.ReadClientAccessValue(profile.ShortID),
	)
	host, port, targetErr := net.SplitHostPort(profile.Target)
	if err != nil || targetErr != nil || port != "443" || host != profile.ServerName || !validHostname(host) || profile.Port != 443 || profile.Fingerprint != "chrome" || !credentials.valid() {
		return errors.New("VLESS REALITY Vision intent is invalid")
	}
	xhttp := profiles.VLESSXHTTP
	if xhttp.Enabled {
		xhttpCredentials, xhttpErr := NewXHTTPCredentials(secrets.ReadClientAccessValue(xhttp.UUID), secrets.ReadClientAccessValue(xhttp.Path))
		if xhttpErr != nil || xhttp.OriginAddress != "127.0.0.1" || xhttp.OriginPort != 11080 || xhttp.Mode != state.XHTTPPacketUp || !validHostname(xhttp.Hostname) || xhttpCredentials.uuid.value == credentials.uuid.value {
			return errors.New("VLESS XHTTP intent is invalid")
		}
	}
	return nil
}

func (module Interface) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	if err := module.ValidateConnectionProfiles(profiles, secrets); err != nil {
		return nil, nil, err
	}
	if profiles.VLESSWebSocket.Enabled || profiles.Hysteria2.Enabled || profiles.TUIC.Enabled || profiles.AnyTLS.Enabled {
		return nil, nil, errors.New("later Connection Profile slices are not prepared yet")
	}
	profile := profiles.VLESSRealityVision
	if !profile.Enabled {
		return nil, nil, nil
	}
	credentials, err := NewRealityCredentials(
		secrets.ReadClientAccessValue(profile.UUID),
		secrets.ReadInfrastructureSecret(profile.PrivateKey),
		profile.PublicKey,
		secrets.ReadClientAccessValue(profile.ShortID),
	)
	if err != nil {
		return nil, nil, errors.New("VLESS REALITY Vision credentials are invalid")
	}
	reality := ViewRequest{Enabled: true, Port: profile.Port, Target: RealityTarget{Address: profile.Target, ServerName: profile.ServerName}, Fingerprint: profile.Fingerprint, XrayVersion: qualifiedXrayVersion, Credentials: credentials}
	var xhttp *XHTTPViewRequest
	if profiles.VLESSXHTTP.Enabled {
		xhttpProfile := profiles.VLESSXHTTP
		xhttpCredentials, credentialErr := NewXHTTPCredentials(secrets.ReadClientAccessValue(xhttpProfile.UUID), secrets.ReadClientAccessValue(xhttpProfile.Path))
		if credentialErr != nil {
			return nil, nil, errors.New("VLESS XHTTP credentials are invalid")
		}
		xhttp = &XHTTPViewRequest{Enabled: true, Hostname: xhttpProfile.Hostname, OriginAddress: xhttpProfile.OriginAddress, OriginPort: xhttpProfile.OriginPort, Mode: xhttpProfile.Mode, XrayVersion: qualifiedXrayVersion, Credentials: xhttpCredentials}
	}
	xray, err := xrayConfiguration(&reality, xhttp)
	return xray, nil, err
}

func (plan *Plan) ValidateConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	if plan == nil || plan.preparedBinding == "" || secrets == nil {
		return errors.New("reviewed Connection Profiles Plan unavailable")
	}
	if err := (Interface{}).ValidateConnectionProfiles(profiles, secrets); err != nil {
		return err
	}
	profile := profiles.VLESSRealityVision
	realityRequest := plan.realityRequest
	if profiles.VLESSWebSocket.Enabled || profiles.Hysteria2.Enabled || profiles.TUIC.Enabled || profiles.AnyTLS.Enabled || profile.Enabled != realityRequest.Enabled || profile.Port != realityRequest.Port || profile.Target != realityRequest.Target.Address || profile.ServerName != realityRequest.Target.ServerName || profile.Fingerprint != realityRequest.Fingerprint ||
		secrets.ReadClientAccessValue(profile.UUID) != realityRequest.Credentials.uuid.value || secrets.ReadInfrastructureSecret(profile.PrivateKey) != realityRequest.Credentials.privateKey.value || profile.PublicKey != realityRequest.Credentials.publicKey.value || secrets.ReadClientAccessValue(profile.ShortID) != realityRequest.Credentials.shortID.value {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	if plan.xhttpRequest == nil {
		if profiles.VLESSXHTTP.Enabled {
			return errors.New("candidate Connection Profiles differ from the reviewed Plan")
		}
		return nil
	}
	xhttp := profiles.VLESSXHTTP
	reviewed := *plan.xhttpRequest
	if !xhttp.Enabled || xhttp.Hostname != reviewed.Hostname || xhttp.OriginAddress != reviewed.OriginAddress || xhttp.OriginPort != reviewed.OriginPort || xhttp.Mode != reviewed.Mode || secrets.ReadClientAccessValue(xhttp.UUID) != reviewed.Credentials.uuid.value || secrets.ReadClientAccessValue(xhttp.Path) != reviewed.Credentials.path.value {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	return nil
}

func (plan *Plan) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	if err := plan.ValidateConnectionProfiles(profiles, secrets); err != nil {
		return nil, nil, err
	}
	binding, err := opaquePreparedBinding(plan.configuration)
	if err != nil || binding != plan.preparedBinding {
		return nil, nil, errors.New("prepared Xray configuration differs from the reviewed Plan")
	}
	return append([]byte(nil), plan.configuration...), nil, nil
}

// ponytail: one process-local HMAC key binds reviewed bytes without retaining or
// publishing a reusable digest of their secrets; durable Plans need a key store.
var preparedBindingKey [32]byte
var preparedBindingKeyOnce sync.Once
var preparedBindingKeyErr error

func opaquePreparedBinding(configuration []byte) (string, error) {
	preparedBindingKeyOnce.Do(func() {
		_, preparedBindingKeyErr = io.ReadFull(rand.Reader, preparedBindingKey[:])
	})
	if preparedBindingKeyErr != nil {
		return "", preparedBindingKeyErr
	}
	digest := hmac.New(sha256.New, preparedBindingKey[:])
	_, _ = digest.Write(configuration)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func realityConfiguration(request ViewRequest) ([]byte, error) {
	if !request.Credentials.valid() {
		return nil, errors.New("credentials invalid")
	}
	return xrayConfiguration(&request, nil)
}

func xrayConfiguration(reality *ViewRequest, xhttp *XHTTPViewRequest) ([]byte, error) {
	var inbounds []any
	if reality != nil {
		if !reality.Credentials.valid() {
			return nil, errors.New("REALITY credentials invalid")
		}
		inbounds = append(inbounds, realityInbound(*reality))
	}
	if xhttp != nil {
		if !xhttp.Credentials.valid() {
			return nil, errors.New("XHTTP credentials invalid")
		}
		inbounds = append(inbounds, map[string]any{
			"tag": "vless-xhttp", "listen": xhttp.OriginAddress, "port": xhttp.OriginPort, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": xhttp.Credentials.uuid.value}}, "decryption": "none"},
			"streamSettings": map[string]any{"method": "xhttp", "security": "none", "xhttpSettings": map[string]any{"mode": string(xhttp.Mode), "path": xhttp.Credentials.path.value}},
		})
	}
	if len(inbounds) == 0 {
		return nil, errors.New("no enabled Xray profile")
	}
	configuration := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "blocked", "protocol": "blackhole"}},
	}
	return json.Marshal(configuration)
}

func realityInbound(request ViewRequest) map[string]any {
	settings := map[string]any{
		"show": false, "target": request.Target.Address, "xver": 0,
		"serverNames": []string{request.Target.ServerName}, "privateKey": request.Credentials.privateKey.value,
		"shortIds": []string{request.Credentials.shortID.value}, "maxTimeDiff": 0,
		"limitFallbackUpload":   FallbackLimit{AfterBytes: 10 << 20, BytesPerSec: 1 << 20, BurstBytesPerSec: 5 << 20},
		"limitFallbackDownload": FallbackLimit{AfterBytes: 20 << 20, BytesPerSec: 2 << 20, BurstBytesPerSec: 10 << 20},
	}
	return map[string]any{
		"tag": "vless-reality-vision", "listen": "0.0.0.0", "port": request.Port, "protocol": "vless",
		"settings":       map[string]any{"clients": []any{map[string]any{"id": request.Credentials.uuid.value, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
		"streamSettings": map[string]any{"method": "raw", "security": "reality", "realitySettings": settings},
	}
}

func (plan *Plan) Apply(module systemchanges.Interface, prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement) systemchanges.ApplyResult {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) || prepared == nil || volatileSHA256 != plan.volatileSHA256 || starting.Revision != plan.revision || starting.SHA256 != plan.startingStateSHA256 {
		return module.Apply(nil)
	}
	changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != plan.changeSet || revision != starting.Revision+1 || startingSHA256 != starting.SHA256 || candidateSHA256 != plan.desiredStateSHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return module.Apply(nil)
	}
	mutation := systemchanges.SettingChangeMutation
	if starting.Status == systemchanges.NotInstalled {
		mutation = systemchanges.InstallationMutation
	} else if starting.Status != systemchanges.Managed {
		return module.Apply(nil)
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.changeSet, Mutation: mutation, OutcomeOwner: systemchanges.ConnectionProfilesModule,
		StartingState: starting, TargetStateSHA256: candidateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256}, PreparedState: prepared,
		Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}, Disk: disk,
	})
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(change)
}
