package connectionprofiles

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
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
	Disabled       Outcome = "Disabled"
	NeedsAttention Outcome = "Needs attention"
	Failed         Outcome = "Failed"
	Unknown        Outcome = "Unknown"
)

type Health struct {
	Time          time.Time
	Module        string
	Profile       string
	Outcome       Outcome
	Code          string
	Problem       string
	Found         string
	Required      string
	WhyStopped    string
	NextActions   []string
	BlockerOwner  BlockerOwner
	BlockerAction string
}

type BlockerOwner string

const (
	SBXROwnedBlocker BlockerOwner = "SBXR"
	ExternalBlocker  BlockerOwner = "External Owner"
)

type CorrectionFlow struct {
	FixWithSBXR, OwnerWork, CheckAgain, Back, Evidence string
}

// CorrectionFlow turns every blocked Health into the same safe, copyable
// owner handoff without adding credentials or raw native output.
func (health Health) CorrectionFlow() CorrectionFlow {
	if health.Outcome == Healthy || health.Outcome == Disabled {
		return CorrectionFlow{}
	}
	flow := CorrectionFlow{CheckAgain: "Check again", Back: "Back", Evidence: fmt.Sprintf("%s: found %s; required %s", health.Code, health.Found, health.Required)}
	if health.BlockerOwner == SBXROwnedBlocker {
		flow.FixWithSBXR = health.BlockerAction
	} else if health.BlockerOwner == ExternalBlocker {
		flow.OwnerWork = health.BlockerAction
	}
	return flow
}

func blockedHealth(health Health) Health {
	health.BlockerOwner, health.BlockerAction = SBXROwnedBlocker, "Fix with SBXR by rebuilding and applying one fresh reviewed Plan, then Check again."
	return health
}

func externalBlockedHealth(health Health, action string) Health {
	health.BlockerOwner, health.BlockerAction = ExternalBlocker, action
	return health
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

type RealityProbeFailure string

const (
	RealityProbeNativeFailure      RealityProbeFailure = "native probe failed"
	RealityProbeUnknownTarget      RealityProbeFailure = "target classification unavailable"
	RealityProbeRouteFailure       RealityProbeFailure = "route failed"
	RealityProbeCertificateFailure RealityProbeFailure = "certificate invalid"
	RealityProbeNameFailure        RealityProbeFailure = "certificate name mismatched"
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
	ProbeFailure      RealityProbeFailure
	Class             TargetClass
	AcceptedNames     []string
	RouteVerified     bool
	ProviderNetwork   bool
	ServiceInstalled  bool
	ServiceUnit       string
	ServiceIdentity   string
	ServiceRunning    bool
	ServiceContained  bool
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
	return generateRealityCredentials(rand.Reader)
}

func GenerateRealityCredentialsFrom(random io.Reader) (RealityCredentials, error) {
	if random == nil {
		return RealityCredentials{}, errors.New("credential entropy unavailable")
	}
	return generateRealityCredentials(random)
}

func generateRealityCredentials(random io.Reader) (RealityCredentials, error) {
	privateBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, privateBytes); err != nil {
		return RealityCredentials{}, errors.New("REALITY key generation failed")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return RealityCredentials{}, errors.New("REALITY key generation failed")
	}
	uuidBytes := make([]byte, 16)
	shortBytes := make([]byte, 8)
	if _, err := io.ReadFull(random, uuidBytes); err != nil {
		return RealityCredentials{}, errors.New("REALITY UUID generation failed")
	}
	if _, err := io.ReadFull(random, shortBytes); err != nil {
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
	Revision            uint64
	Enabled             bool
	Port                uint16
	Target              RealityTarget
	Fingerprint         string
	XrayVersion         string
	Credentials         RealityCredentials
	reviewedAlternative bool
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

type RealityTargetReview struct {
	Target RealityTarget
	Health Health
}

type Interface struct{ host RealityHost }

func New(host RealityHost) Interface { return Interface{host: host} }

func (module Interface) ReviewRealityTarget(ctx context.Context, target RealityTarget) RealityTargetReview {
	if module.host == nil {
		return RealityTargetReview{Target: target, Health: blocked(time.Time{}, Unknown, "CONNECTION-PROFILES-REALITY-HOST", "The Ubuntu and native Xray observation is unavailable", "no local host boundary", "one typed Ubuntu and Xray observation")}
	}
	observedTarget := target
	observedTarget.ListenerPort = 443
	return RealityTargetReview{Target: target, Health: realityTargetHealth(target, module.host.ObserveReality(ctx, observedTarget))}
}

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
	if targetHealth := realityTargetHealth(request.Target, observation); targetHealth.Outcome != Healthy {
		result.Health = targetHealth
		return result
	}
	if !selectedPort(request.Port, 443, request.reviewedAlternative) || request.XrayVersion != qualifiedXrayVersion || request.Fingerprint != "chrome" || !request.Credentials.valid() || !request.Enabled {
		result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET", "The VLESS REALITY Vision SBXR inputs are invalid", "the selected listener, credential, fingerprint, enabled state, or qualified release is wrong", "one enabled profile using the reviewed listener, Chrome fingerprint, and Xray v26.3.27")
		return result
	}
	if request.Revision > 0 {
		if !observation.ConfigurationSafe {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-CONFIGURATION", "The root-runtime Xray configuration is unsafe", "ownership, mode, path, or symbolic-link proof failed", "root:root 0755/0644 material under /etc/sbxr")
			return result
		}
		if !rootServiceHealthy(observation.ServiceUnit, observation.ServiceIdentity, observation.ServiceRunning, observation.ServiceContained, "xray.service") {
			result.Health = blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-SERVICE", "The fixed Xray service is not running safely", "xray.service root identity, state, or containment disagrees", "running contained xray.service as root")
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

func realityTargetHealth(target RealityTarget, observation RealityObservation) Health {
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil || port != "443" || host != target.ServerName || !validHostname(host) {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET", "The VLESS REALITY Vision target is invalid", "the target address, port, or accepted name is wrong", "one ordinary external target using its accepted name on 443/TCP"), "Enter one ordinary non-Cloudflare, non-Apple or iCloud hostname without :443, then Check again.")
	}
	if observation.Class == CloudflareTarget || observation.Class == AppleICloudTarget {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET-CLASS", "The REALITY target belongs to a forbidden target class", string(observation.Class), "one suitable non-Cloudflare, non-Apple or iCloud target"), "Enter a suitable external hostname that is neither Cloudflare nor Apple or iCloud, then Check again.")
	}
	switch observation.ProbeFailure {
	case RealityProbeUnknownTarget:
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET-CLASS", "The REALITY target class could not be proved", string(observation.ProbeFailure), "one suitable non-Cloudflare, non-Apple or iCloud target"), "Enter a suitable external hostname whose target class can be proved, then Check again.")
	case RealityProbeRouteFailure:
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-ROUTE", "The REALITY route failed", string(observation.ProbeFailure), "one reachable target route"), "Correct the external hostname or VPS route until the target is reachable, then Check again.")
	case RealityProbeCertificateFailure:
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-CERTIFICATE", "The REALITY target certificate is invalid", string(observation.ProbeFailure), "one publicly trusted current certificate"), "Enter an external hostname with one publicly trusted current certificate, then Check again.")
	case RealityProbeNameFailure:
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-NAME", "The REALITY accepted name does not match", strings.Join(observation.AcceptedNames, ","), target.ServerName), "Enter the exact hostname accepted by the target certificate, then Check again.")
	case RealityProbeNativeFailure:
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-PROBE", "The bounded native REALITY target probe failed", string(observation.ProbeFailure), "one successful bounded authenticated Xray target probe"), "Correct or replace the external hostname until the bounded native Xray probe passes, then Check again.")
	}
	if observation.Probe != ProbePassed {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-PROBE", "The bounded REALITY target probe did not pass", string(observation.Probe), "one conclusive xray tls ping route, certificate, and safety result"), "Correct or replace the external hostname until the bounded xray tls ping, certificate, route, and safety probe passes, then Check again.")
	}
	if observation.Class != OrdinaryTarget {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-TARGET-CLASS", "The REALITY target belongs to an unknown target class", string(observation.Class), "one suitable non-Cloudflare, non-Apple or iCloud target"), "Enter a suitable external hostname that is neither Cloudflare nor Apple or iCloud, then Check again.")
	}
	if !observation.RouteVerified {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-ROUTE", "The REALITY route is unproved", "the target route could not be confirmed", "one conclusive target route"), "Correct the external hostname or VPS route until the exact route is conclusive, then Check again.")
	}
	if !slices.Contains(observation.AcceptedNames, target.ServerName) {
		return externalBlockedHealth(blocked(observation.CheckedAt, Failed, "CONNECTION-PROFILES-REALITY-NAME", "The REALITY accepted name does not match", strings.Join(observation.AcceptedNames, ","), target.ServerName), "Enter an external hostname whose accepted TLS name exactly matches, then Check again.")
	}
	return Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: "VLESS REALITY Vision", Outcome: Healthy, Code: "CONNECTION-PROFILES-REALITY-TARGET-HEALTHY", NextActions: []string{"Continue Installation", "Back"}}
}

func rootServiceHealthy(unit, identity string, running, contained bool, expectedUnit string) bool {
	return unit == expectedUnit && identity == "root" && running && contained
}

func selectedPort(port, preferred uint16, reviewedAlternative bool) bool {
	return port == preferred || reviewedAlternative && port > 0
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
	return blockedHealth(Health{Time: at, Module: "Connection Profiles", Profile: "VLESS REALITY Vision", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}})
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
	singBoxConfiguration             []byte
	revision                         uint64
	changeSet                        string
	startingStateSHA256              string
	desiredStateSHA256               string
	realityRequest                   ViewRequest
	xhttpRequest                     *XHTTPViewRequest
	webSocketRequest                 *WebSocketViewRequest
	hysteria2Request                 *Hysteria2ViewRequest
	tuicRequest                      *TUICViewRequest
	anyTLSRequest                    *AnyTLSViewRequest
	steps                            []systemchanges.Step
	checks                           []systemchanges.Check
	mutation                         systemchanges.MutationClass
	used                             *atomic.Bool
	stateUsed                        *atomic.Bool
}

type singBoxPlanSpec struct {
	profile, description, xrayVersion, singBoxVersion string
	revision                                          uint64
	changeSet, startingState, desiredState            string
	xray, singBox                                     []byte
	volatileInputs                                    string
	binding                                           any
	reality                                           ViewRequest
	xhttp                                             *XHTTPViewRequest
	websocket                                         *WebSocketViewRequest
	hysteria2                                         *Hysteria2ViewRequest
	tuic                                              *TUICViewRequest
	anyTLS                                            *AnyTLSViewRequest
	mutation                                          systemchanges.MutationClass
}

func (module Interface) buildSingBoxPlan(ctx context.Context, spec singBoxPlanSpec) (*Plan, string) {
	if err := module.host.ValidateReality(ctx, spec.xrayVersion, bytes.NewReader(spec.xray)); err != nil {
		return nil, "NATIVE"
	}
	validator, ok := module.host.(SingBoxValidator)
	if !ok || validator.ValidateSingBox(ctx, spec.singBoxVersion, bytes.NewReader(spec.singBox)) != nil {
		return nil, "NATIVE"
	}
	preparedBinding, err := opaquePreparedBinding(spec.xray, spec.singBox)
	if err != nil {
		return nil, "BINDING"
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return nil, "TRANSACTION"
	}
	checks := make([]systemchanges.Check, 0, 4)
	for _, suffix := range []string{"CONFIGURATION", "LISTENER", "SERVICE", "FUNCTION"} {
		phase := systemchanges.PrePublication
		if suffix == "FUNCTION" {
			phase = systemchanges.PostPublication
		}
		checks = append(checks, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: phase, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-" + spec.profile + "-" + suffix})
	}
	volatile := sha256.Sum256([]byte(spec.volatileInputs))
	volatileSHA := hex.EncodeToString(volatile[:])
	binding, err := json.Marshal(struct {
		Request                         any
		VolatileSHA256, PreparedBinding string
	}{spec.binding, volatileSHA, preparedBinding})
	if err != nil {
		return nil, "BINDING"
	}
	digest := sha256.Sum256(binding)
	sha := hex.EncodeToString(digest[:])
	mutation := spec.mutation
	if mutation == "" {
		mutation = systemchanges.SettingChangeMutation
	}
	return &Plan{identity: "profiles-" + strings.ToLower(spec.profile) + "-" + sha[:12], sha256: sha, volatileSHA256: volatileSHA, description: spec.description, preparedBinding: preparedBinding, configuration: spec.xray, singBoxConfiguration: spec.singBox, revision: spec.revision, changeSet: spec.changeSet, startingStateSHA256: spec.startingState, desiredStateSHA256: spec.desiredState, realityRequest: spec.reality, xhttpRequest: spec.xhttp, webSocketRequest: spec.websocket, hysteria2Request: spec.hysteria2, tuicRequest: spec.tuic, anyTLSRequest: spec.anyTLS, steps: []systemchanges.Step{step}, checks: checks, mutation: mutation, used: &atomic.Bool{}, stateUsed: &atomic.Bool{}}, ""
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

func (plan *Plan) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	if plan == nil || plan.revision != 1 || plan.startingStateSHA256 != "" || plan.desiredStateSHA256 == "" {
		return lifecyclecontract.InstallContribution{}
	}
	return lifecyclecontract.InstallContribution{Name: "Connection Profiles", Owner: systemchanges.ConnectionProfilesModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: plan.volatileSHA256, ChangeSet: plan.changeSet, DesiredStateSHA256: plan.desiredStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}
func (plan *Plan) SoftwareLifecycleUpdateContribution() lifecyclecontract.UpdateContribution {
	if plan == nil || plan.revision < 2 || plan.startingStateSHA256 == "" || plan.desiredStateSHA256 == "" {
		return lifecyclecontract.UpdateContribution{}
	}
	return lifecyclecontract.UpdateContribution{Name: "Connection Profiles", Owner: systemchanges.ConnectionProfilesModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: plan.volatileSHA256, ChangeSet: plan.changeSet, DesiredStateSHA256: plan.desiredStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}
func (plan *Plan) SoftwareLifecycleRepairContribution() lifecyclecontract.RepairContribution {
	if plan == nil || plan.mutation != systemchanges.RepairMutation || plan.revision == 0 || plan.startingStateSHA256 == "" || plan.startingStateSHA256 != plan.desiredStateSHA256 {
		return lifecyclecontract.RepairContribution{}
	}
	return lifecyclecontract.RepairContribution{Name: "Connection Profiles", Owner: systemchanges.ConnectionProfilesModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: plan.volatileSHA256, ChangeSet: plan.changeSet, CurrentRevision: plan.revision, CurrentStateSHA256: plan.startingStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
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

type xrayPlanSpec struct {
	identityPrefix, description, profile, codePrefix, version string
	revision                                                  uint64
	changeSet, startingStateSHA256, desiredStateSHA256        string
	volatileSHA256                                            string
	configuration                                             []byte
	request                                                   any
	reality                                                   ViewRequest
	xhttp                                                     *XHTTPViewRequest
	websocket                                                 *WebSocketViewRequest
	checkedAt                                                 time.Time
}

func (module Interface) buildXrayPlan(ctx context.Context, spec xrayPlanSpec) (*Plan, *Health) {
	fail := func(suffix, problem, found, required string) (*Plan, *Health) {
		health := blockedHealth(Health{Time: spec.checkedAt, Module: "Connection Profiles", Profile: spec.profile, Outcome: Failed, Code: spec.codePrefix + "-" + suffix, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}})
		return nil, &health
	}
	if err := module.host.ValidateReality(ctx, spec.version, bytes.NewReader(spec.configuration)); err != nil {
		return fail("NATIVE", "The pinned native Xray validator refused the complete prepared configuration", "native validation failed", "one complete configuration accepted by Xray v26.3.27")
	}
	preparedBinding, err := opaquePreparedBinding(spec.configuration)
	if err != nil {
		return fail("BINDING", "The protected prepared-configuration authority is unavailable", "an opaque binding could not be created", "one secret-safe binding to the exact validated configuration")
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return fail("TRANSACTION", "The profile transaction contract is invalid", "the activation or rollback step was refused", "one reversible Connection Profiles step")
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: spec.codePrefix + "-CONFIGURATION"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: spec.codePrefix + "-LISTENER"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: spec.codePrefix + "-SERVICE"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: spec.codePrefix + "-CONFIGURATION"},
	}
	binding := struct {
		Request         any
		VolatileSHA256  string
		PreparedBinding string
	}{spec.request, spec.volatileSHA256, preparedBinding}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	sha := hex.EncodeToString(digest[:])
	return &Plan{
		identity: spec.identityPrefix + sha[:12], sha256: sha, volatileSHA256: spec.volatileSHA256, description: spec.description,
		preparedBinding: preparedBinding, configuration: append([]byte(nil), spec.configuration...), revision: spec.revision, changeSet: spec.changeSet,
		startingStateSHA256: spec.startingStateSHA256, desiredStateSHA256: spec.desiredStateSHA256, realityRequest: spec.reality, xhttpRequest: spec.xhttp, webSocketRequest: spec.websocket,
		steps: []systemchanges.Step{step}, checks: checks, used: &atomic.Bool{}, stateUsed: &atomic.Bool{},
	}, nil
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
	plan, failure := module.buildXrayPlan(ctx, xrayPlanSpec{
		identityPrefix: "profiles-reality-", description: fmt.Sprintf("validate and activate VLESS REALITY Vision on %d/TCP through xray.service, then prove configuration, listener, service, and REALITY security; rollback restores the prior configuration", request.View.Port),
		profile: view.Profile.Name, codePrefix: "CONNECTION-PROFILES-REALITY", version: request.View.XrayVersion,
		revision: request.View.Revision, changeSet: request.ChangeSet, startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256,
		volatileSHA256: view.VolatileSHA256, configuration: configuration, request: request, reality: request.View, checkedAt: view.Health.Time,
	})
	if failure != nil {
		return PlanResult{Health: *failure}
	}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: view.Profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-REALITY-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func (module Interface) ValidateConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	reality, xhttp, websocket, err := xrayProfileInputs(profiles, secrets)
	if err != nil {
		return err
	}
	hysteria2, err := hysteria2ProfileInput(profiles.Hysteria2, secrets)
	if err != nil {
		return err
	}
	tuic, err := tuicProfileInput(profiles.TUIC, secrets)
	if err != nil || !independentTUIC(tuic, hysteria2, reality, xhttp, websocket) {
		return errors.New("TUIC intent is invalid")
	}
	anyTLS, err := anyTLSProfileInput(profiles.AnyTLS, secrets)
	if err != nil || !independentAnyTLS(anyTLS, hysteria2, tuic) {
		return errors.New("AnyTLS intent is invalid")
	}
	return nil
}

func xrayProfileInputs(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) (ViewRequest, *XHTTPViewRequest, *WebSocketViewRequest, error) {
	if secrets == nil {
		return ViewRequest{}, nil, nil, errors.New("Connection Profiles secret reader unavailable")
	}
	profile := profiles.VLESSRealityVision
	credentials, err := NewRealityCredentials(
		secrets.ReadClientAccessValue(profile.UUID),
		secrets.ReadInfrastructureSecret(profile.PrivateKey),
		profile.PublicKey,
		secrets.ReadClientAccessValue(profile.ShortID),
	)
	host, port, targetErr := net.SplitHostPort(profile.Target)
	if err != nil || targetErr != nil || port != "443" || host != profile.ServerName || !validHostname(host) || profile.Port == 0 || profile.Fingerprint != "chrome" || !credentials.valid() {
		return ViewRequest{}, nil, nil, errors.New("VLESS REALITY Vision intent is invalid")
	}
	reality := ViewRequest{Enabled: profile.Enabled, Port: profile.Port, Target: RealityTarget{Address: profile.Target, ServerName: profile.ServerName}, Fingerprint: profile.Fingerprint, XrayVersion: qualifiedXrayVersion, Credentials: credentials, reviewedAlternative: profile.Port != 443}
	xhttpRequest, err := xhttpProfileInput(profiles.VLESSXHTTP, secrets, credentials.uuid.value)
	if err != nil {
		return ViewRequest{}, nil, nil, err
	}
	webSocketRequest, err := webSocketProfileInput(profiles.VLESSWebSocket, secrets, credentials.uuid.value, xhttpRequest)
	if err != nil {
		return ViewRequest{}, nil, nil, err
	}
	return reality, xhttpRequest, webSocketRequest, nil
}

func xhttpProfileInput(profile state.VLESSXHTTP, secrets state.ConnectionProfileSecretReader, realityUUID string) (*XHTTPViewRequest, error) {
	if !profile.Enabled && (profile == (state.VLESSXHTTP{}) || profile == (state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp})) {
		return nil, nil
	}
	credentials, err := NewXHTTPCredentials(secrets.ReadClientAccessValue(profile.UUID), secrets.ReadClientAccessValue(profile.Path))
	if err != nil || profile.OriginAddress != "127.0.0.1" || profile.OriginPort == 0 || profile.Mode != state.XHTTPPacketUp || !validHostname(profile.Hostname) || credentials.uuid.value == realityUUID {
		return nil, errors.New("VLESS XHTTP intent is invalid")
	}
	return &XHTTPViewRequest{Enabled: profile.Enabled, Hostname: profile.Hostname, OriginAddress: profile.OriginAddress, OriginPort: profile.OriginPort, Mode: profile.Mode, XrayVersion: qualifiedXrayVersion, Credentials: credentials, reviewedAlternative: profile.OriginPort != 11080}, nil
}

func webSocketProfileInput(profile state.VLESSWebSocket, secrets state.ConnectionProfileSecretReader, realityUUID string, xhttp *XHTTPViewRequest) (*WebSocketViewRequest, error) {
	if !profile.Enabled && (profile == (state.VLESSWebSocket{}) || profile == (state.VLESSWebSocket{Lifecycle: state.ProfileNotSetUp})) {
		return nil, nil
	}
	credentials, err := NewWebSocketCredentials(secrets.ReadClientAccessValue(profile.UUID), secrets.ReadClientAccessValue(profile.Path))
	sharedXHTTPFact := xhttp != nil && (credentials.uuid.value == xhttp.Credentials.uuid.value || credentials.path.value == xhttp.Credentials.path.value || profile.Hostname == xhttp.Hostname)
	if err != nil || profile.OriginAddress != "127.0.0.1" || profile.OriginPort == 0 || !validHostname(profile.Hostname) || credentials.uuid.value == realityUUID || sharedXHTTPFact {
		return nil, errors.New("VLESS WebSocket intent is invalid")
	}
	return &WebSocketViewRequest{Enabled: profile.Enabled, Hostname: profile.Hostname, TLSName: profile.Hostname, HTTPHost: profile.Hostname, OriginAddress: profile.OriginAddress, OriginPort: profile.OriginPort, XrayVersion: qualifiedXrayVersion, Credentials: credentials, reviewedAlternative: profile.OriginPort != 11081}, nil
}

func (module Interface) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	reality, xhttp, websocket, err := xrayProfileInputs(profiles, secrets)
	if err != nil {
		return nil, nil, err
	}
	xray, err := xrayConfiguration(&reality, xhttp, websocket)
	if err != nil {
		return nil, nil, err
	}
	hysteria2, err := hysteria2ProfileInput(profiles.Hysteria2, secrets)
	if err != nil {
		return nil, nil, err
	}
	tuic, err := tuicProfileInput(profiles.TUIC, secrets)
	if err != nil {
		return nil, nil, err
	}
	if !independentTUIC(tuic, hysteria2, reality, xhttp, websocket) {
		return nil, nil, errors.New("TUIC intent is invalid")
	}
	anyTLS, err := anyTLSProfileInput(profiles.AnyTLS, secrets)
	if err != nil || !independentAnyTLS(anyTLS, hysteria2, tuic) {
		return nil, nil, errors.New("AnyTLS intent is invalid")
	}
	if hysteria2 == nil {
		return xray, nil, nil
	}
	profileSet := &SingBoxProfileSet{TUIC: tuic, AnyTLS: anyTLS}
	hysteria2.Profiles = profileSet
	singBox, err := singBoxConfiguration(hysteria2, profileSet)
	return xray, singBox, err
}

func independentAnyTLS(anyTLS *AnyTLSViewRequest, hysteria2 *Hysteria2ViewRequest, tuic *TUICViewRequest) bool {
	if anyTLS == nil {
		return true
	}
	return hysteria2 != nil && tuic != nil && anyTLS.Credentials.password.value != hysteria2.Credentials.password.value && anyTLS.Credentials.password.value != tuic.Credentials.password.value
}

func independentTUIC(tuic *TUICViewRequest, hysteria2 *Hysteria2ViewRequest, reality ViewRequest, xhttp *XHTTPViewRequest, websocket *WebSocketViewRequest) bool {
	if tuic == nil {
		return true
	}
	return hysteria2 != nil && tuic.Credentials.password.value != hysteria2.Credentials.password.value && tuic.Credentials.uuid.value != reality.Credentials.uuid.value && (xhttp == nil || tuic.Credentials.uuid.value != xhttp.Credentials.uuid.value) && (websocket == nil || tuic.Credentials.uuid.value != websocket.Credentials.uuid.value)
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
	if profile.Enabled != realityRequest.Enabled || profile.Port != realityRequest.Port || profile.Target != realityRequest.Target.Address || profile.ServerName != realityRequest.Target.ServerName || profile.Fingerprint != realityRequest.Fingerprint ||
		secrets.ReadClientAccessValue(profile.UUID) != realityRequest.Credentials.uuid.value || secrets.ReadInfrastructureSecret(profile.PrivateKey) != realityRequest.Credentials.privateKey.value || profile.PublicKey != realityRequest.Credentials.publicKey.value || secrets.ReadClientAccessValue(profile.ShortID) != realityRequest.Credentials.shortID.value {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	if !reviewedXHTTPMatches(plan.xhttpRequest, profiles.VLESSXHTTP, secrets) || !reviewedWebSocketMatches(plan.webSocketRequest, profiles.VLESSWebSocket, secrets) {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	if !reviewedHysteria2Matches(plan.hysteria2Request, profiles.Hysteria2, secrets) {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	if !reviewedTUICMatches(plan.tuicRequest, profiles.TUIC, secrets) {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	if !reviewedAnyTLSMatches(plan.anyTLSRequest, profiles.AnyTLS, secrets) {
		return errors.New("candidate Connection Profiles differ from the reviewed Plan")
	}
	return nil
}

func reviewedXHTTPMatches(reviewed *XHTTPViewRequest, profile state.VLESSXHTTP, secrets state.ConnectionProfileSecretReader) bool {
	if reviewed == nil {
		return !profile.Enabled
	}
	return profile.Enabled == reviewed.Enabled && profile.Hostname == reviewed.Hostname && profile.OriginAddress == reviewed.OriginAddress && profile.OriginPort == reviewed.OriginPort && profile.Mode == reviewed.Mode && secrets.ReadClientAccessValue(profile.UUID) == reviewed.Credentials.uuid.value && secrets.ReadClientAccessValue(profile.Path) == reviewed.Credentials.path.value
}

func reviewedWebSocketMatches(reviewed *WebSocketViewRequest, profile state.VLESSWebSocket, secrets state.ConnectionProfileSecretReader) bool {
	if reviewed == nil {
		return !profile.Enabled
	}
	return profile.Enabled == reviewed.Enabled && profile.Hostname == reviewed.Hostname && profile.OriginAddress == reviewed.OriginAddress && profile.OriginPort == reviewed.OriginPort && secrets.ReadClientAccessValue(profile.UUID) == reviewed.Credentials.uuid.value && secrets.ReadClientAccessValue(profile.Path) == reviewed.Credentials.path.value
}

func (plan *Plan) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	if err := plan.ValidateConnectionProfiles(profiles, secrets); err != nil {
		return nil, nil, err
	}
	configurations := [][]byte{plan.configuration}
	if plan.singBoxConfiguration != nil {
		configurations = append(configurations, plan.singBoxConfiguration)
	}
	binding, err := opaquePreparedBinding(configurations...)
	if err != nil || binding != plan.preparedBinding {
		return nil, nil, errors.New("prepared Connection Profiles configuration differs from the reviewed Plan")
	}
	return append([]byte(nil), plan.configuration...), append([]byte(nil), plan.singBoxConfiguration...), nil
}

func (plan *Plan) StateConnectionProfilesRepair() (uint64, string, bool) {
	if plan == nil {
		return 0, "", false
	}
	return plan.revision, plan.startingStateSHA256, plan.mutation == systemchanges.RepairMutation && plan.startingStateSHA256 == plan.desiredStateSHA256
}

// StateProfileSetupConnectionProfiles binds the complete five-profile
// contribution to one exact Managed revision transition.
func (plan *Plan) StateProfileSetupConnectionProfiles() (startingRevision, candidateRevision uint64, startingStateSHA256, desiredStateSHA256, changeSet string, valid bool) {
	if plan == nil || plan.mutation != systemchanges.CloudflareProfileSetupMutation || plan.revision < 2 || plan.stateUsed == nil || !plan.stateUsed.CompareAndSwap(false, true) {
		return 0, 0, "", "", "", false
	}
	return plan.revision - 1, plan.revision, plan.startingStateSHA256, plan.desiredStateSHA256, plan.changeSet, true
}

// ponytail: one process-local HMAC key binds reviewed bytes without retaining or
// publishing a reusable digest of their secrets; durable Plans need a key store.
var preparedBindingKey [32]byte
var preparedBindingKeyOnce sync.Once
var preparedBindingKeyErr error

func opaquePreparedBinding(configurations ...[]byte) (string, error) {
	preparedBindingKeyOnce.Do(func() {
		_, preparedBindingKeyErr = io.ReadFull(rand.Reader, preparedBindingKey[:])
	})
	if preparedBindingKeyErr != nil {
		return "", preparedBindingKeyErr
	}
	digest := hmac.New(sha256.New, preparedBindingKey[:])
	var size [8]byte
	for _, configuration := range configurations {
		binary.BigEndian.PutUint64(size[:], uint64(len(configuration)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write(configuration)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func realityConfiguration(request ViewRequest) ([]byte, error) {
	if !request.Credentials.valid() {
		return nil, errors.New("credentials invalid")
	}
	return xrayConfiguration(&request, nil, nil)
}

func xrayConfiguration(reality *ViewRequest, xhttp *XHTTPViewRequest, websocket *WebSocketViewRequest) ([]byte, error) {
	realityConfig, err := optionalRealityInbound(reality)
	if err != nil {
		return nil, err
	}
	xhttpConfig, err := optionalXHTTPInbound(xhttp)
	if err != nil {
		return nil, err
	}
	webSocketConfig, err := optionalWebSocketInbound(websocket)
	if err != nil {
		return nil, err
	}
	var inbounds []any
	for _, inbound := range []any{realityConfig, xhttpConfig, webSocketConfig} {
		if inbound != nil {
			inbounds = append(inbounds, inbound)
		}
	}
	if len(inbounds) == 0 {
		inbounds = []any{}
	}
	configuration := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "blocked", "protocol": "blackhole"}},
	}
	return json.Marshal(configuration)
}

func optionalRealityInbound(request *ViewRequest) (any, error) {
	if request == nil || !request.Enabled {
		return nil, nil
	}
	if !request.Credentials.valid() {
		return nil, errors.New("REALITY credentials invalid")
	}
	return realityInbound(*request), nil
}

func optionalXHTTPInbound(request *XHTTPViewRequest) (any, error) {
	if request == nil || !request.Enabled {
		return nil, nil
	}
	if !request.Credentials.valid() {
		return nil, errors.New("XHTTP credentials invalid")
	}
	return map[string]any{
		"tag": "vless-xhttp", "listen": request.OriginAddress, "port": request.OriginPort, "protocol": "vless",
		"settings":       map[string]any{"clients": []any{map[string]any{"id": request.Credentials.uuid.value}}, "decryption": "none"},
		"streamSettings": map[string]any{"method": "xhttp", "security": "none", "xhttpSettings": map[string]any{"mode": string(request.Mode), "path": request.Credentials.path.value}},
	}, nil
}

func optionalWebSocketInbound(request *WebSocketViewRequest) (any, error) {
	if request == nil || !request.Enabled {
		return nil, nil
	}
	if !request.Credentials.valid() || request.TLSName != request.Hostname || request.HTTPHost != request.Hostname {
		return nil, errors.New("WebSocket inputs invalid")
	}
	return map[string]any{
		"tag": "vless-websocket", "listen": request.OriginAddress, "port": request.OriginPort, "protocol": "vless",
		"settings":       map[string]any{"clients": []any{map[string]any{"id": request.Credentials.uuid.value}}, "decryption": "none"},
		"streamSettings": map[string]any{"method": "websocket", "security": "none", "wsSettings": map[string]any{"host": request.HTTPHost, "path": request.Credentials.path.value}},
	}, nil
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

func (plan *Plan) Apply(module systemchanges.Interface, prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement, setupConfirmation ...systemchanges.CloudflareSetupConfirmation) systemchanges.ApplyResult {
	expectedRevision := starting.Revision
	if starting.Status == systemchanges.NotInstalled || plan != nil && plan.mutation == systemchanges.CloudflareProfileSetupMutation {
		expectedRevision++
	}
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) || prepared == nil || volatileSHA256 != plan.volatileSHA256 || expectedRevision != plan.revision || starting.SHA256 != plan.startingStateSHA256 {
		return module.Apply(nil)
	}
	changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != plan.changeSet || revision != starting.Revision+1 || startingSHA256 != starting.SHA256 || candidateSHA256 != plan.desiredStateSHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return module.Apply(nil)
	}
	mutation := plan.mutation
	if mutation == "" {
		mutation = systemchanges.SettingChangeMutation
	}
	if starting.Status == systemchanges.NotInstalled {
		mutation = systemchanges.InstallationMutation
	} else if starting.Status != systemchanges.Managed {
		return module.Apply(nil)
	}
	var confirmation systemchanges.CloudflareSetupConfirmation
	if len(setupConfirmation) == 1 {
		confirmation = setupConfirmation[0]
	} else if len(setupConfirmation) != 0 {
		return module.Apply(nil)
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.changeSet, Mutation: mutation, OutcomeOwner: systemchanges.ConnectionProfilesModule,
		StartingState: starting, TargetStateSHA256: candidateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256}, PreparedState: prepared,
		Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}, Disk: disk, CloudflareSetupConfirmation: confirmation,
	})
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(change)
}
