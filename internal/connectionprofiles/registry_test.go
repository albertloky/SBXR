package connectionprofiles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRegistryCredentialsCanBeRebuiltFromTheSameProtectedEntropy(t *testing.T) {
	first, err := connectionprofiles.GenerateRegistryCredentialsFrom(rand.New(rand.NewSource(144)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectionprofiles.GenerateRegistryCredentialsFrom(rand.New(rand.NewSource(144)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !first.Ready() || !first.Independent() {
		t.Fatal("same protected entropy did not rebuild the same six independent credentials")
	}
}

func TestRegistryViewContainsExactlySixFreshEnabledIndependentProfiles(t *testing.T) {
	request := validRegistryRequest(t)
	credentials, err := connectionprofiles.GenerateRegistryCredentials()
	if err != nil || !credentials.Ready() || !credentials.Independent() {
		t.Fatalf("GenerateRegistryCredentials() = (%+v, %v)", credentials, err)
	}
	request.Reality.Enabled, request.XHTTP.Enabled, request.WebSocket.Enabled = false, false, false
	request.Hysteria2.Enabled, request.TUIC.Enabled, request.AnyTLS.Enabled = false, false, false
	request, err = connectionprofiles.NewFreshRegistry(request, credentials)
	if err != nil {
		t.Fatal(err)
	}

	result := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
	want := []connectionprofiles.ProfileID{
		connectionprofiles.VLESSRealityVisionProfileID,
		connectionprofiles.VLESSXHTTPProfileID,
		connectionprofiles.VLESSWebSocketProfileID,
		connectionprofiles.Hysteria2ProfileID,
		connectionprofiles.TUICProfileID,
		connectionprofiles.AnyTLSProfileID,
	}
	if result.Health.Outcome != connectionprofiles.Healthy || len(result.Profiles) != len(want) || len(result.Publication.Profiles()) != len(want) || len(result.Publication.Omissions()) != 0 {
		t.Fatalf("ViewRegistry() = %+v", result)
	}
	for index, id := range want {
		profile := result.Profiles[index]
		if profile.ID != id || !profile.Enabled || !profile.DefaultEnabled || !profile.CredentialsReady || profile.SelectedListener.Port == 0 || profile.Health.Outcome != connectionprofiles.Healthy {
			t.Fatalf("registry profile %d = %+v", index, profile)
		}
	}
	publication := result.Publication.Profiles()
	if publication[0].Name != "VLESS REALITY Vision" || publication[1].Name != "VLESS XHTTP" || publication[2].Name != "VLESS WebSocket" || publication[3].Name != "Hysteria2" || publication[4].Name != "TUIC" || publication[4].CongestionControl != "cubic" || publication[5].Name != "AnyTLS" {
		t.Fatalf("publication labels or TUIC congestion = %+v", publication)
	}
	if _, ok := result.Profile(connectionprofiles.ProfileID("vmess")); ok {
		t.Fatal("seventh profile entered the fixed registry")
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, xhttpPathMarker) || strings.Contains(rendered, anyTLSPasswordMarker) {
		t.Fatalf("registry View leaked protected values: %s", rendered)
	}
}

func TestFreshRegistrySuppliesTheExactProtectedDesiredProfiles(t *testing.T) {
	request := validRegistryRequest(t)
	credentials, err := connectionprofiles.GenerateRegistryCredentials()
	if err != nil {
		t.Fatal(err)
	}
	request, err = connectionprofiles.NewFreshRegistry(request, credentials)
	if err != nil {
		t.Fatal(err)
	}
	profiles, ok := connectionprofiles.DesiredProfiles(request)
	if !ok || !profiles.VLESSRealityVision.Enabled || !profiles.VLESSXHTTP.Enabled || !profiles.VLESSWebSocket.Enabled || !profiles.Hysteria2.Enabled || !profiles.TUIC.Enabled || !profiles.AnyTLS.Enabled {
		t.Fatalf("DesiredProfiles() = (%+v, %v)", profiles, ok)
	}
	if rendered := fmt.Sprintf("%+v", profiles); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, anyTLSPasswordMarker) {
		t.Fatalf("protected profiles rendered a credential: %s", rendered)
	}
	inputs, err := connectionprofiles.NewFreshRegistryInputs(request)
	if err != nil || inputs.Profiles() != profiles || !connectionprofiles.PublicationInputsMatch(inputs.PublicationSource(), profiles) {
		t.Fatalf("NewFreshRegistryInputs() = (%+v, %v)", inputs, err)
	}
	if err := inputs.WithClientAccessReader(func(reader state.ClientAccessReader) error {
		if reader.ReadClientAccessValue(profiles.VLESSRealityVision.UUID) == "" || reader.ReadClientAccessValue(profiles.AnyTLS.Password) == "" {
			return fmt.Errorf("fresh registry values unavailable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := inputs.WithClientAccessReader(func(state.ClientAccessReader) error { return nil }); err == nil {
		t.Fatal("fresh registry render authority was reusable")
	}
}

func TestPinnedNativeValidatorsAcceptEveryRegistryDisableAndReenable(t *testing.T) {
	xrayBinary, singBoxBinary := os.Getenv("SBXR_XRAY_BIN"), os.Getenv("SBXR_SING_BOX_BIN")
	if xrayBinary == "" || singBoxBinary == "" {
		t.Skip("set SBXR_XRAY_BIN and SBXR_SING_BOX_BIN to the pinned qualified executables")
	}
	disables := []func(*connectionprofiles.RegistryViewRequest){
		func(r *connectionprofiles.RegistryViewRequest) { r.Reality.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.XHTTP.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.WebSocket.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.Hysteria2.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.TUIC.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.AnyTLS.Enabled = false },
	}
	current := validRegistryRequest(t)
	states := []connectionprofiles.RegistryViewRequest{current}
	validate := func(index int, candidate connectionprofiles.RegistryViewRequest) {
		candidate.Exposure = registryPolicyContribution(candidate)
		host := healthyRegistryHost(current)
		native := &nativeRegistryHost{anyTLSHost: host, xray: &nativeRealityHost{binary: xrayBinary}, singBox: &nativeHysteria2Host{hysteria2Host: host.hysteria2Host, binary: singBoxBinary, root: t.TempDir()}}
		module := connectionprofiles.New(native)
		result := module.PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: fmt.Sprintf("profiles-registry-native-%02d", index), StartingStateSHA256: fmt.Sprintf("%064x", index+1), DesiredStateSHA256: fmt.Sprintf("%064x", index+2)})
		if result.Plan == nil {
			t.Fatalf("native registry Plan %d = %+v", index, result)
		}
		current = candidate
	}
	for index, disable := range disables {
		candidate := current
		disable(&candidate)
		candidate.Exposure = registryPolicyContribution(candidate)
		validate(index, candidate)
		states = append(states, candidate)
	}
	for index := len(disables) - 1; index >= 0; index-- {
		validate(index+len(disables), states[index])
	}
}

type nativeRegistryHost struct {
	*anyTLSHost
	xray    *nativeRealityHost
	singBox *nativeHysteria2Host
}

func (host *nativeRegistryHost) ValidateReality(ctx context.Context, version string, configuration io.Reader) error {
	return host.xray.ValidateReality(ctx, version, configuration)
}

func (host *nativeRegistryHost) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
	return host.singBox.ValidateSingBox(ctx, version, configuration)
}

func TestRegistryPlanDisablesAndReenablesEveryProfileWithoutChangingCredentials(t *testing.T) {
	tests := []struct {
		id             connectionprofiles.ProfileID
		purpose        string
		marker         string
		disableRequest func(*connectionprofiles.RegistryViewRequest)
		disableState   func(*state.ConnectionProfiles)
	}{
		{connectionprofiles.VLESSRealityVisionProfileID, "VLESS REALITY Vision", `"tag":"vless-reality-vision"`, func(r *connectionprofiles.RegistryViewRequest) { r.Reality.Enabled = false }, func(p *state.ConnectionProfiles) { p.VLESSRealityVision.Enabled = false }},
		{connectionprofiles.VLESSXHTTPProfileID, "VLESS XHTTP origin", `"tag":"vless-xhttp"`, func(r *connectionprofiles.RegistryViewRequest) { r.XHTTP.Enabled = false }, func(p *state.ConnectionProfiles) { p.VLESSXHTTP.Enabled = false }},
		{connectionprofiles.VLESSWebSocketProfileID, "VLESS WebSocket origin", `"tag":"vless-websocket"`, func(r *connectionprofiles.RegistryViewRequest) { r.WebSocket.Enabled = false }, func(p *state.ConnectionProfiles) { p.VLESSWebSocket.Enabled = false }},
		{connectionprofiles.Hysteria2ProfileID, "Hysteria2", `"tag":"hysteria2-in"`, func(r *connectionprofiles.RegistryViewRequest) { r.Hysteria2.Enabled = false }, func(p *state.ConnectionProfiles) { p.Hysteria2.Enabled = false }},
		{connectionprofiles.TUICProfileID, "TUIC", `"tag":"tuic-in"`, func(r *connectionprofiles.RegistryViewRequest) { r.TUIC.Enabled = false }, func(p *state.ConnectionProfiles) { p.TUIC.Enabled = false }},
		{connectionprofiles.AnyTLSProfileID, "AnyTLS", `"tag":"anytls-in"`, func(r *connectionprofiles.RegistryViewRequest) { r.AnyTLS.Enabled = false }, func(p *state.ConnectionProfiles) { p.AnyTLS.Enabled = false }},
	}
	for index, test := range tests {
		t.Run(string(test.id), func(t *testing.T) {
			current, candidate := validRegistryRequest(t), validRegistryRequest(t)
			test.disableRequest(&candidate)
			candidate.Exposure = registryPolicyContribution(candidate)
			host := healthyRegistryHost(current)
			disabled := connectionprofiles.New(host).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: fmt.Sprintf("profiles-registry-disable-%02d", index), StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
			if disabled.Plan == nil || disabled.Health.Outcome != connectionprofiles.Healthy || !registryPlanIsReversible(disabled.Plan) || len(disabled.Plan.Checks()) != 5 {
				t.Fatalf("disable Plan = %+v", disabled)
			}
			profiles, secrets := completeProfileStateForAnyTLS()
			test.disableState(&profiles)
			xray, singBox, err := disabled.Plan.PrepareConnectionProfiles(profiles, secrets)
			if err != nil || bytes.Contains(xray, []byte(test.marker)) || bytes.Contains(singBox, []byte(test.marker)) {
				t.Fatalf("disabled prepared configuration = (xray=%s sing-box=%s err=%v)", xray, singBox, err)
			}

			reenabled := connectionprofiles.New(healthyRegistryHost(candidate)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: candidate, Candidate: current, ChangeSet: fmt.Sprintf("profiles-registry-enable-%02d", index), StartingStateSHA256: strings.Repeat("b", 64), DesiredStateSHA256: strings.Repeat("c", 64)})
			if reenabled.Plan == nil || reenabled.Health.Outcome != connectionprofiles.Healthy || !registryPlanIsReversible(reenabled.Plan) {
				t.Fatalf("re-enable Plan = %+v", reenabled)
			}
			profiles, secrets = completeProfileStateForAnyTLS()
			xray, singBox, err = reenabled.Plan.PrepareConnectionProfiles(profiles, secrets)
			if err != nil || !bytes.Contains(append(xray, singBox...), []byte(test.marker)) {
				t.Fatalf("re-enabled prepared configuration omitted preserved profile = (xray=%s sing-box=%s err=%v)", xray, singBox, err)
			}
		})
	}
}

func registryPlanIsReversible(plan *connectionprofiles.Plan) bool {
	steps := plan.Steps()
	return len(steps) == 1 && steps[0].Forward() == systemchanges.ActivatePreparedConfiguration && steps[0].Rollback() == systemchanges.RestorePriorConfiguration
}

func TestRegistryPlanRejectsCredentialChangesMultipleTogglesAndStaleExposureWithoutLeaking(t *testing.T) {
	current, candidate := validRegistryRequest(t), validRegistryRequest(t)
	candidate.AnyTLS.Enabled = false
	candidate.Exposure = registryPolicyContribution(candidate)
	changedPassword := strings.Repeat("d", 64)
	credentials, err := connectionprofiles.NewAnyTLSCredentials(changedPassword)
	if err != nil {
		t.Fatal(err)
	}
	candidate.AnyTLS.Credentials = credentials
	changed := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-registry-changed", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
	if changed.Plan != nil || changed.Health.Code != "CONNECTION-PROFILES-REGISTRY-PLAN-STATE" || strings.Contains(fmt.Sprintf("%+v", changed), changedPassword) {
		t.Fatalf("changed-credential registry Plan = %+v", changed)
	}

	candidate = validRegistryRequest(t)
	candidate.AnyTLS.Enabled, candidate.TUIC.Enabled = false, false
	candidate.Exposure = registryPolicyContribution(candidate)
	multiple := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-registry-multiple", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
	if multiple.Plan != nil || multiple.Health.Code != "CONNECTION-PROFILES-REGISTRY-PLAN-STATE" {
		t.Fatalf("multiple-toggle registry Plan = %+v", multiple)
	}

	candidate = validRegistryRequest(t)
	candidate.AnyTLS.Enabled = false
	stale := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-registry-exposure", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
	if stale.Plan != nil || stale.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPOSURE" {
		t.Fatalf("stale-exposure registry Plan = %+v", stale)
	}
}

func TestRegistrySupportsSequentialDisableAndReenableThroughEmptyCoreConfigurations(t *testing.T) {
	disables := []func(*connectionprofiles.RegistryViewRequest){
		func(r *connectionprofiles.RegistryViewRequest) { r.Reality.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.XHTTP.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.WebSocket.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.Hysteria2.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.TUIC.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.AnyTLS.Enabled = false },
	}
	current := validRegistryRequest(t)
	states := []connectionprofiles.RegistryViewRequest{current}
	for index, disable := range disables {
		candidate := current
		disable(&candidate)
		candidate.Exposure = registryPolicyContribution(candidate)
		result := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: fmt.Sprintf("profiles-registry-sequential-disable-%02d", index), StartingStateSHA256: fmt.Sprintf("%064x", index+1), DesiredStateSHA256: fmt.Sprintf("%064x", index+2)})
		if result.Plan == nil || !registryPlanIsReversible(result.Plan) {
			t.Fatalf("sequential disable %d = %+v", index, result)
		}
		current, states = candidate, append(states, candidate)
	}
	for index := len(disables) - 1; index >= 0; index-- {
		candidate := states[index]
		result := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: fmt.Sprintf("profiles-registry-sequential-enable-%02d", index), StartingStateSHA256: fmt.Sprintf("%064x", index+20), DesiredStateSHA256: fmt.Sprintf("%064x", index+21)})
		if result.Plan == nil || !registryPlanIsReversible(result.Plan) {
			t.Fatalf("sequential re-enable %d = %+v", index, result)
		}
		current = candidate
	}
}

func TestRegistryAlwaysReturnsSixProfilesAndFailsClosedWithoutFreshPolicyOrCapability(t *testing.T) {
	request := validRegistryRequest(t)
	host := healthyRegistryHost(request)
	host.webSocketHost.xhttpHost.realityHost.observation.Probe = connectionprofiles.ProbeFailed
	failed := connectionprofiles.New(host).ViewRegistry(t.Context(), request)
	if failed.Health.Outcome != connectionprofiles.Failed || len(failed.Profiles) != 6 || len(failed.Publication.Profiles()) != 0 {
		t.Fatalf("failed registry was partial or publishable: %+v", failed)
	}

	request.Exposure = networkpolicy.NewListenerContribution(networkpolicy.Result{Outcome: networkpolicy.Healthy, Policy: networkpolicy.Policy{Exposures: []networkpolicy.Exposure{{Purpose: "VLESS REALITY Vision", Address: "public", Port: 443, Protocol: networkpolicy.TCP}}}})
	unbound := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
	if unbound.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPOSURE" || len(unbound.Profiles) != 6 || len(unbound.Publication.Profiles()) != 0 {
		t.Fatalf("unbound Network Policy authorized registry: %+v", unbound)
	}

	for _, disable := range []func(*connectionprofiles.RegistryViewRequest){
		func(r *connectionprofiles.RegistryViewRequest) { r.Reality.Enabled = false },
		func(r *connectionprofiles.RegistryViewRequest) { r.Hysteria2.Enabled = false },
	} {
		request = validRegistryRequest(t)
		disable(&request)
		request.Exposure = registryPolicyContribution(request)
		if healthy := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request); healthy.Health.Outcome != connectionprofiles.Healthy {
			t.Fatalf("reduced capability registry = %+v", healthy)
		}
		retained := healthyAnyTLSHost()
		if failed := connectionprofiles.New(retained).ViewRegistry(t.Context(), request); failed.Health.Code != "CONNECTION-PROFILES-REGISTRY-CAPABILITY" && failed.Health.Code != "CONNECTION-PROFILES-TUIC-CAPABILITY" {
			t.Fatalf("retained capability passed: %+v", failed)
		}
	}
	for name, disable := range map[string]func(*connectionprofiles.RegistryViewRequest){
		"Xray": func(r *connectionprofiles.RegistryViewRequest) {
			r.Reality.Enabled, r.XHTTP.Enabled, r.WebSocket.Enabled = false, false, false
		},
		"sing-box": func(r *connectionprofiles.RegistryViewRequest) {
			r.Hysteria2.Enabled, r.TUIC.Enabled, r.AnyTLS.Enabled = false, false, false
		},
	} {
		t.Run(name+" fully disabled", func(t *testing.T) {
			request := validRegistryRequest(t)
			disable(&request)
			request.Exposure = registryPolicyContribution(request)
			if healthy := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request); healthy.Health.Outcome != connectionprofiles.Healthy {
				t.Fatalf("fully disabled core with empty capabilities = %+v", healthy)
			}
			retained := healthyRegistryHost(request)
			retained.coreCapabilities = connectionprofiles.CoreCapabilityObservation{}
			failed := connectionprofiles.New(retained).ViewRegistry(t.Context(), request)
			if failed.Health.Code != "CONNECTION-PROFILES-REGISTRY-CAPABILITY" || len(failed.Profiles) != 6 || len(failed.Publication.Profiles()) != 0 {
				t.Fatalf("fully disabled core retained capability: %+v", failed)
			}
		})
	}
}

func TestRegistryViewReportsEveryDisabledProfileTruthfullyAndOmitsPublication(t *testing.T) {
	tests := []struct {
		id      connectionprofiles.ProfileID
		purpose string
		disable func(*connectionprofiles.RegistryViewRequest)
	}{
		{connectionprofiles.VLESSRealityVisionProfileID, "VLESS REALITY Vision", func(r *connectionprofiles.RegistryViewRequest) { r.Reality.Enabled = false }},
		{connectionprofiles.VLESSXHTTPProfileID, "VLESS XHTTP origin", func(r *connectionprofiles.RegistryViewRequest) { r.XHTTP.Enabled = false }},
		{connectionprofiles.VLESSWebSocketProfileID, "VLESS WebSocket origin", func(r *connectionprofiles.RegistryViewRequest) { r.WebSocket.Enabled = false }},
		{connectionprofiles.Hysteria2ProfileID, "Hysteria2", func(r *connectionprofiles.RegistryViewRequest) { r.Hysteria2.Enabled = false }},
		{connectionprofiles.TUICProfileID, "TUIC", func(r *connectionprofiles.RegistryViewRequest) { r.TUIC.Enabled = false }},
		{connectionprofiles.AnyTLSProfileID, "AnyTLS", func(r *connectionprofiles.RegistryViewRequest) { r.AnyTLS.Enabled = false }},
	}
	for _, test := range tests {
		t.Run(string(test.id), func(t *testing.T) {
			request := validRegistryRequest(t)
			test.disable(&request)
			request.Exposure = registryPolicyContribution(request)
			result := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
			profile, ok := result.Profile(test.id)
			if result.Health.Outcome != connectionprofiles.Healthy || !ok || profile.Health.Outcome != connectionprofiles.Disabled || profile.Health.Code != "CONNECTION-PROFILES-REGISTRY-DISABLED" || len(result.Profiles) != 6 || len(result.Publication.Profiles()) != 5 || len(result.Publication.Omissions()) != 1 || result.Publication.Omissions()[0].ID != test.id {
				t.Fatalf("disabled registry View = %+v", result)
			}
			if _, err := json.Marshal(result.Publication); err == nil {
				t.Fatal("publication source allowed general rendering")
			}

			request.Exposure = validRegistryRequest(t).Exposure
			drift := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
			if drift.Health.Outcome != connectionprofiles.Failed || drift.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPOSURE" {
				t.Fatalf("disabled profile retained exposure: %+v", drift)
			}
		})
	}
}

func validRegistryRequest(t *testing.T) connectionprofiles.RegistryViewRequest {
	t.Helper()
	request := connectionprofiles.RegistryViewRequest{
		ClientAddress: "192.0.2.10",
		Reality:       validRealityRequest(t),
		XHTTP:         validXHTTPRequest(t),
		WebSocket:     validWebSocketRequest(t),
		Hysteria2:     validHysteria2Request(t),
		TUIC:          validTUICRequest(t),
		AnyTLS:        validAnyTLSRequest(t),
	}
	request.Exposure = registryPolicyContribution(request)
	return request
}

func healthyRegistryHost(request connectionprofiles.RegistryViewRequest) *anyTLSHost {
	host := healthyAnyTLSHost()
	host.coreCapabilities = connectionprofiles.CoreCapabilityObservation{XrayNone: !request.Reality.Enabled && !request.XHTTP.Enabled && !request.WebSocket.Enabled, SingBoxNone: !request.Hysteria2.Enabled && !request.TUIC.Enabled && !request.AnyTLS.Enabled}
	noXrayCapabilities := !request.Reality.Enabled || request.Reality.Port >= 1024
	host.webSocketHost.xhttpHost.realityHost.observation.NetBindService = !noXrayCapabilities
	host.webSocketHost.xhttpHost.observation.NoCapabilities = noXrayCapabilities
	host.webSocketHost.observation.NoCapabilities = noXrayCapabilities
	noSingBoxCapabilities := !(request.Hysteria2.Enabled && request.Hysteria2.Port < 1024 || request.TUIC.Enabled && request.TUIC.Port < 1024 || request.AnyTLS.Enabled && request.AnyTLS.Port < 1024)
	host.tuicHost.hysteria2Host.observation.NetBindService = !noSingBoxCapabilities
	host.tuicHost.observation.NetBindService = !noSingBoxCapabilities
	host.tuicHost.observation.NoCapabilities = noSingBoxCapabilities
	host.observation.NetBindService = !noSingBoxCapabilities
	host.observation.NoCapabilities = noSingBoxCapabilities
	return host
}

type registryPolicyAdapter struct{ observations networkpolicy.Observations }

func (adapter registryPolicyAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return adapter.observations, nil
}

func boundRegistryPolicy() networkpolicy.ListenerContribution {
	return registryPolicyContribution(connectionprofiles.RegistryViewRequest{
		ClientAddress: "192.0.2.10",
		Reality:       connectionprofiles.ViewRequest{Revision: 7, Enabled: true, Port: 443},
		XHTTP:         connectionprofiles.XHTTPViewRequest{Revision: 7, Enabled: true, OriginAddress: "127.0.0.1", OriginPort: 11080},
		WebSocket:     connectionprofiles.WebSocketViewRequest{Revision: 7, Enabled: true, OriginAddress: "127.0.0.1", OriginPort: 11081},
		Hysteria2:     connectionprofiles.Hysteria2ViewRequest{Revision: 7, Enabled: true, Port: 443, ServerName: "direct.example.com"},
		TUIC:          connectionprofiles.TUICViewRequest{Revision: 7, Enabled: true, Port: 8443},
		AnyTLS:        connectionprofiles.AnyTLSViewRequest{Revision: 7, Enabled: true, Port: 9443},
	})
}

func registryPolicyContribution(request connectionprofiles.RegistryViewRequest) networkpolicy.ListenerContribution {
	intent := networkpolicy.Intent{
		Revision: request.Reality.Revision, Baseline: networkpolicy.Clean, PublicIPv4: request.ClientAddress, PrimarySubscriptionAddress: request.ClientAddress,
		CertificateHostname: request.Hysteria2.ServerName, SSHPort: 2222, SubscriptionPort: 10443,
		Profiles: networkpolicy.Profiles{
			VLESSRealityVision: networkpolicy.Profile{Enabled: request.Reality.Enabled, Port: request.Reality.Port},
			VLESSXHTTP:         networkpolicy.Profile{Enabled: request.XHTTP.Enabled, Address: request.XHTTP.OriginAddress, Port: request.XHTTP.OriginPort},
			VLESSWebSocket:     networkpolicy.Profile{Enabled: request.WebSocket.Enabled, Address: request.WebSocket.OriginAddress, Port: request.WebSocket.OriginPort},
			Hysteria2:          networkpolicy.Profile{Enabled: request.Hysteria2.Enabled, Port: request.Hysteria2.Port},
			TUIC:               networkpolicy.Profile{Enabled: request.TUIC.Enabled, Port: request.TUIC.Port},
			AnyTLS:             networkpolicy.Profile{Enabled: request.AnyTLS.Enabled, Port: request.AnyTLS.Port},
		},
		Disk: networkpolicy.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100},
	}
	observed := networkpolicy.Observations{
		Host:       networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{request.ClientAddress}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: request.ClientAddress, CurrentSessions: []string{"session-1"}},
		Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"},
		OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"}, Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: request.Hysteria2.ServerName, IPv4: []string{request.ClientAddress}}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}},
		Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
	}
	result := networkpolicy.New(registryPolicyAdapter{observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	return networkpolicy.NewListenerContribution(result)
}
