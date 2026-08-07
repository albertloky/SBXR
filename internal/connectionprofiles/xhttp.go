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
	"regexp"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

var xhttpPath = regexp.MustCompile(`^/[0-9a-f]{64}$`)

type XHTTPCredentials struct{ uuid, path secretText }

func (XHTTPCredentials) String() string   { return "XHTTP credentials: ready" }
func (XHTTPCredentials) GoString() string { return "XHTTP credentials: ready" }

func NewXHTTPCredentials(uuid, path string) (XHTTPCredentials, error) {
	credentials := XHTTPCredentials{secretText{uuid}, secretText{path}}
	if !credentials.valid() {
		return XHTTPCredentials{}, errors.New("XHTTP credentials are invalid")
	}
	return credentials, nil
}

func GenerateXHTTPCredentials() (XHTTPCredentials, error) {
	uuidBytes := make([]byte, 16)
	pathBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, uuidBytes); err != nil {
		return XHTTPCredentials{}, errors.New("XHTTP UUID generation failed")
	}
	if _, err := io.ReadFull(rand.Reader, pathBytes); err != nil {
		return XHTTPCredentials{}, errors.New("XHTTP path generation failed")
	}
	uuidBytes[6] = uuidBytes[6]&0x0f | 0x40
	uuidBytes[8] = uuidBytes[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	return NewXHTTPCredentials(uuid, "/"+hex.EncodeToString(pathBytes))
}

func (credentials XHTTPCredentials) valid() bool {
	return uuidV4.MatchString(credentials.uuid.value) && xhttpPath.MatchString(credentials.path.value)
}

type XHTTPObservation struct {
	CheckedAt          time.Time
	ConfigurationSafe  bool
	ConfigurationValid bool
	ServiceUnit        string
	ServiceIdentity    string
	ServiceRunning     bool
	Listener           Listener
}

type XHTTPHost interface {
	ObserveXHTTP(context.Context, uint16) XHTTPObservation
}

type XHTTPViewRequest struct {
	Revision                uint64
	Enabled                 bool
	Hostname, OriginAddress string
	OriginPort              uint16
	Mode                    state.XHTTPMode
	XrayVersion             string
	Credentials             XHTTPCredentials
	RouteHealth             cloudflaretunnel.XHTTPRouteHealth
}

type XHTTPProfile struct {
	Name, Hostname, Origin, Mode, XrayVersion string
	Enabled, CredentialsReady, ServiceRunning bool
	ServiceUnit                               string
	Listener                                  Listener
}

type XHTTPViewResult struct {
	Profile        XHTTPProfile
	Health         Health
	VolatileSHA256 string

	observation XHTTPObservation
}

func (module Interface) ViewXHTTP(ctx context.Context, request XHTTPViewRequest) XHTTPViewResult {
	profile := XHTTPProfile{Name: "VLESS XHTTP", Hostname: request.Hostname, Origin: fmt.Sprintf("%s:%d", request.OriginAddress, request.OriginPort), Mode: string(request.Mode), XrayVersion: request.XrayVersion, Enabled: request.Enabled, CredentialsReady: request.Credentials.valid()}
	host, ok := module.host.(XHTTPHost)
	if !ok {
		return XHTTPViewResult{Profile: profile, Health: blockedXHTTP(time.Time{}, Unknown, "CONNECTION-PROFILES-XHTTP-HOST", "The Ubuntu XHTTP observation is unavailable", "no local host boundary", "one typed Ubuntu XHTTP observation")}
	}
	observation := host.ObserveXHTTP(ctx, request.OriginPort)
	profile.ServiceUnit = observation.ServiceUnit
	profile.ServiceRunning = observation.ServiceRunning
	profile.Listener = observation.Listener
	result := XHTTPViewResult{Profile: profile, observation: observation}
	result.VolatileSHA256 = xhttpObservationSHA256(request, observation)
	if !request.Enabled || request.OriginAddress != "127.0.0.1" || request.OriginPort != 11080 || request.Mode != state.XHTTPPacketUp || request.XrayVersion != qualifiedXrayVersion || !validHostname(request.Hostname) || !request.Credentials.valid() {
		result.Health = blockedXHTTP(observation.CheckedAt, Failed, "CONNECTION-PROFILES-XHTTP-ORIGIN", "The VLESS XHTTP inputs are invalid", "the origin, hostname, credential, mode, enabled state, or qualified release is wrong", "one enabled packet-up profile on 127.0.0.1:11080/TCP")
		return result
	}
	expectedOrigin := fmt.Sprintf("http://%s:%d", request.OriginAddress, request.OriginPort)
	if request.RouteHealth.Hostname != request.Hostname || request.RouteHealth.Origin != expectedOrigin || request.RouteHealth.Health.Module != "Cloudflare Tunnel" || request.RouteHealth.Health.Outcome != cloudflaretunnel.Healthy || request.RouteHealth.Health.Code != "CLOUDFLARE-XHTTP-ROUTE-HEALTHY" {
		result.Health = blockedXHTTP(observation.CheckedAt, Failed, "CONNECTION-PROFILES-XHTTP-ROUTE", "The typed Cloudflare XHTTP route is not healthy or does not match", request.RouteHealth.Health.Code, "the selected hostname mapped to http://127.0.0.1:11080 with CLOUDFLARE-XHTTP-ROUTE-HEALTHY")
		return result
	}
	if request.Revision > 0 {
		if !observation.ConfigurationSafe || !observation.ConfigurationValid {
			result.Health = blockedXHTTP(observation.CheckedAt, Failed, "CONNECTION-PROFILES-XHTTP-CONFIGURATION", "The protected Xray configuration is unsafe", "ownership, mode, path, or symbolic-link proof failed", "root-owned protected material under /etc/sbxr")
			return result
		}
		if observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "xray" || !observation.ServiceRunning {
			result.Health = blockedXHTTP(observation.CheckedAt, Failed, "CONNECTION-PROFILES-XHTTP-SERVICE", "The fixed Xray service is not running safely", "xray.service or its distinct non-root identity disagrees", "running xray.service as xray")
			return result
		}
		if observation.Listener != (Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}) {
			result.Health = blockedXHTTP(observation.CheckedAt, Failed, "CONNECTION-PROFILES-XHTTP-LISTENER", "The XHTTP listener is not loopback-only", fmt.Sprintf("%s/%d/%s", observation.Listener.Address, observation.Listener.Port, observation.Listener.Protocol), "127.0.0.1/11080/tcp")
			return result
		}
	}
	result.Health = Health{Time: observation.CheckedAt, Module: "Connection Profiles", Profile: profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-XHTTP-HEALTHY", NextActions: []string{"Build Plan", "Back"}}
	return result
}

func xhttpObservationSHA256(request XHTTPViewRequest, observation XHTTPObservation) string {
	encoded, _ := json.Marshal(struct {
		Revision                uint64
		Enabled                 bool
		Hostname, OriginAddress string
		OriginPort              uint16
		Mode                    state.XHTTPMode
		XrayVersion             string
		RouteHealth             cloudflaretunnel.XHTTPRouteHealth
		Observation             XHTTPObservation
	}{request.Revision, request.Enabled, request.Hostname, request.OriginAddress, request.OriginPort, request.Mode, request.XrayVersion, request.RouteHealth, observation})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func blockedXHTTP(at time.Time, outcome Outcome, code, problem, found, required string) Health {
	return Health{Time: at, Module: "Connection Profiles", Profile: "VLESS XHTTP", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Connection Profiles fails closed before unsafe proxy or host mutation", NextActions: []string{"Check again", "Back"}}
}

type XHTTPPlanRequest struct {
	Reality             ViewRequest
	View                XHTTPViewRequest
	ChangeSet           string
	StartingStateSHA256 string
	DesiredStateSHA256  string
}

func (module Interface) PlanXHTTP(ctx context.Context, request XHTTPPlanRequest) PlanResult {
	reality := module.View(ctx, request.Reality)
	if reality.Health.Outcome != Healthy {
		return PlanResult{Health: reality.Health}
	}
	view := module.ViewXHTTP(ctx, request.View)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if request.Reality.Revision != request.View.Revision || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: blockedXHTTP(view.Health.Time, Failed, "CONNECTION-PROFILES-XHTTP-PLAN-STATE", "The reviewed State binding is invalid", "a Change Set, revision, or State checksum is missing or malformed", "one exact current and candidate State binding")}
	}
	configuration, err := xrayConfiguration(&request.Reality, &request.View)
	if err != nil {
		return PlanResult{Health: blockedXHTTP(view.Health.Time, Failed, "CONNECTION-PROFILES-XHTTP-CONFIGURATION", "The complete Xray configuration could not be prepared", "the typed REALITY or XHTTP inputs are incomplete", "one complete protected Xray configuration")}
	}
	if err := module.host.ValidateReality(ctx, request.View.XrayVersion, bytes.NewReader(configuration)); err != nil {
		return PlanResult{Health: blockedXHTTP(view.Health.Time, Failed, "CONNECTION-PROFILES-XHTTP-NATIVE", "The pinned native Xray validator refused the complete prepared configuration", "native validation failed", "one complete configuration accepted by Xray v26.3.27")}
	}
	preparedBinding, err := opaquePreparedBinding(configuration)
	if err != nil {
		return PlanResult{Health: blockedXHTTP(view.Health.Time, Failed, "CONNECTION-PROFILES-XHTTP-BINDING", "The protected prepared-configuration authority is unavailable", "an opaque binding could not be created", "one secret-safe binding to the exact validated configuration")}
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return PlanResult{Health: blockedXHTTP(view.Health.Time, Failed, "CONNECTION-PROFILES-XHTTP-TRANSACTION", "The profile transaction contract is invalid", "the activation or rollback step was refused", "one reversible Connection Profiles step")}
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-XHTTP-CONFIGURATION"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-XHTTP-LISTENER"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-XHTTP-SERVICE"},
		{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-XHTTP-ROUTE"},
	}
	volatile := sha256.Sum256([]byte(reality.VolatileSHA256 + view.VolatileSHA256))
	volatileSHA256 := hex.EncodeToString(volatile[:])
	binding := struct {
		Request         XHTTPPlanRequest
		VolatileSHA256  string
		PreparedBinding string
	}{request, volatileSHA256, preparedBinding}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	sha := hex.EncodeToString(digest[:])
	plan := &Plan{
		identity: "profiles-xhttp-" + sha[:12], sha256: sha, volatileSHA256: volatileSHA256,
		description:     "validate and activate VLESS XHTTP on 127.0.0.1:11080/TCP through xray.service and its typed Cloudflare route; rollback restores the prior configuration",
		preparedBinding: preparedBinding, configuration: append([]byte(nil), configuration...), revision: request.View.Revision, changeSet: request.ChangeSet,
		startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256, realityRequest: request.Reality, xhttpRequest: &request.View,
		steps: []systemchanges.Step{step}, checks: checks, used: &atomic.Bool{},
	}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Connection Profiles", Profile: view.Profile.Name, Outcome: Healthy, Code: "CONNECTION-PROFILES-XHTTP-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}
