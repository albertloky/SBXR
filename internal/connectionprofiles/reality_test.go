package connectionprofiles_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	uuidMarker    = "11111111-1111-4111-8111-111111111111"
	shortIDMarker = "0123456789abcdef"
)

var privateKeyMarker, publicKeyMarker = testX25519Pair()

func testX25519Pair() (string, string) {
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	return base64.RawURLEncoding.EncodeToString(private.Bytes()), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
}

type realityHost struct {
	observation connectionprofiles.RealityObservation
	validated   []byte
	validation  error
}

type profileSecrets struct {
	clients        map[state.ClientAccessValue]string
	infrastructure map[state.InfrastructureSecret]string
}

func (secrets profileSecrets) ReadClientAccessValue(value state.ClientAccessValue) string {
	return secrets.clients[value]
}

func (secrets profileSecrets) ReadInfrastructureSecret(value state.InfrastructureSecret) string {
	return secrets.infrastructure[value]
}

func (host *realityHost) ObserveReality(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	return host.observation
}

func (host *realityHost) ValidateReality(_ context.Context, version string, configuration io.Reader) error {
	if version != "v26.3.27" {
		return fmt.Errorf("wrong version")
	}
	host.validated, _ = io.ReadAll(configuration)
	return host.validation
}

func TestRealityViewAndPlanProduceOneSafeNativeConfiguration(t *testing.T) {
	host := &realityHost{observation: healthyRealityObservation()}
	module := connectionprofiles.New(host)
	request := validRealityRequest(t)

	view := module.View(t.Context(), request)
	if view.Health.Outcome != connectionprofiles.Healthy || view.Profile.Name != "VLESS REALITY Vision" || view.Profile.Port != 443 || view.Profile.Transport != "RAW" || view.Profile.Security != "REALITY" || view.Profile.Flow != "xtls-rprx-vision" || !view.Profile.CredentialsReady {
		t.Fatalf("View() = %+v", view)
	}
	if rendered := fmt.Sprintf("%+v", view); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, privateKeyMarker) || strings.Contains(rendered, shortIDMarker) {
		t.Fatalf("View() leaked protected material: %s", rendered)
	}

	planResult := module.Plan(t.Context(), connectionprofiles.PlanRequest{
		View:                request,
		ChangeSet:           "profiles-reality-0001",
		StartingStateSHA256: strings.Repeat("a", 64),
		DesiredStateSHA256:  strings.Repeat("b", 64),
	})
	if planResult.Health.Outcome != connectionprofiles.Healthy || planResult.Plan == nil || len(planResult.Plan.Steps()) != 1 || len(planResult.Plan.Checks()) != 4 {
		t.Fatalf("Plan() = %+v", planResult)
	}
	if rendered := fmt.Sprintf("%+v", planResult); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, privateKeyMarker) || strings.Contains(rendered, shortIDMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("Plan() leaked protected material: %s", rendered)
	}
	for _, protected := range []string{uuidMarker, privateKeyMarker, shortIDMarker, string(host.validated)} {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(protected)))
		if strings.Contains(fmt.Sprintf("%+v", planResult), digest) || planResult.Plan.SHA256() == digest {
			t.Fatalf("Plan() exposed a protected-value digest: %s", digest)
		}
	}

	var configuration struct {
		Inbounds []struct {
			Listen   string
			Port     uint16
			Protocol string
			Settings struct {
				Clients    []struct{ ID, Flow string }
				Decryption string
			}
			StreamSettings struct {
				Method, Security string
				RealitySettings  struct {
					Target      string
					ServerNames []string
					PrivateKey  string
					ShortIDs    []string
					Upload      connectionprofiles.FallbackLimit `json:"limitFallbackUpload"`
					Download    connectionprofiles.FallbackLimit `json:"limitFallbackDownload"`
				}
			}
		}
	}
	if err := json.Unmarshal(host.validated, &configuration); err != nil || len(configuration.Inbounds) != 1 {
		t.Fatalf("prepared Xray configuration = %s, error %v", host.validated, err)
	}
	inbound := configuration.Inbounds[0]
	if inbound.Listen != "0.0.0.0" || inbound.Port != 443 || inbound.Protocol != "vless" || len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != uuidMarker || inbound.Settings.Clients[0].Flow != "xtls-rprx-vision" || inbound.Settings.Decryption != "none" || inbound.StreamSettings.Method != "raw" || inbound.StreamSettings.Security != "reality" || inbound.StreamSettings.RealitySettings.Target != "edge.example.net:443" || strings.Join(inbound.StreamSettings.RealitySettings.ServerNames, ",") != "edge.example.net" || inbound.StreamSettings.RealitySettings.PrivateKey != privateKeyMarker || strings.Join(inbound.StreamSettings.RealitySettings.ShortIDs, ",") != shortIDMarker || !bounded(inbound.StreamSettings.RealitySettings.Upload) || !bounded(inbound.StreamSettings.RealitySettings.Download) {
		t.Fatalf("prepared Xray configuration has wrong REALITY contract: %+v", inbound)
	}
}

func TestRealityViewFailsClosedForEveryNamedTargetBlocker(t *testing.T) {
	tests := []struct {
		name string
		edit func(*connectionprofiles.ViewRequest, *connectionprofiles.RealityObservation)
		code string
	}{
		{"mismatched accepted name", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.AcceptedNames = []string{"other.example.net"}
		}, "CONNECTION-PROFILES-REALITY-NAME"},
		{"wrong target port", func(request *connectionprofiles.ViewRequest, _ *connectionprofiles.RealityObservation) {
			request.Target.Address = "edge.example.net:8443"
		}, "CONNECTION-PROFILES-REALITY-TARGET"},
		{"unsupported selected port", func(request *connectionprofiles.ViewRequest, _ *connectionprofiles.RealityObservation) {
			request.Port = 8443
		}, "CONNECTION-PROFILES-REALITY-TARGET"},
		{"Cloudflare-fronted target", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Class = connectionprofiles.CloudflareTarget
		}, "CONNECTION-PROFILES-REALITY-TARGET-CLASS"},
		{"Apple target", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Class = connectionprofiles.AppleICloudTarget
		}, "CONNECTION-PROFILES-REALITY-TARGET-CLASS"},
		{"failed probe", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Probe = connectionprofiles.ProbeFailed
		}, "CONNECTION-PROFILES-REALITY-PROBE"},
		{"inconclusive probe", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Probe = connectionprofiles.ProbeInconclusive
		}, "CONNECTION-PROFILES-REALITY-PROBE"},
		{"service failure", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.ServiceRunning = false
		}, "CONNECTION-PROFILES-REALITY-SERVICE"},
		{"listener failure", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Listener.Port = 8443
		}, "CONNECTION-PROFILES-REALITY-LISTENER"},
		{"loopback listener", func(_ *connectionprofiles.ViewRequest, observation *connectionprofiles.RealityObservation) {
			observation.Listener.Address = "127.0.0.1"
		}, "CONNECTION-PROFILES-REALITY-LISTENER"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validRealityRequest(t)
			observation := healthyRealityObservation()
			tt.edit(&request, &observation)
			result := connectionprofiles.New(&realityHost{observation: observation}).View(t.Context(), request)
			if result.Health.Outcome == connectionprofiles.Healthy || result.Health.Code != tt.code || len(result.Health.NextActions) < 2 || result.Health.NextActions[len(result.Health.NextActions)-1] != "Back" {
				t.Fatalf("View() = %+v", result)
			}
			if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, uuidMarker) || strings.Contains(rendered, privateKeyMarker) || strings.Contains(rendered, shortIDMarker) {
				t.Fatalf("failure leaked protected material: %s", rendered)
			}
		})
	}
}

func TestRealityViewPrefersProviderNetworkWithoutBlockingAValidTarget(t *testing.T) {
	observation := healthyRealityObservation()
	observation.ProviderNetwork = false
	result := connectionprofiles.New(&realityHost{observation: observation}).View(t.Context(), validRealityRequest(t))
	if result.Health.Outcome != connectionprofiles.Healthy || result.Profile.ProviderNetwork || result.Health.NextActions[0] != "Prefer a suitable target in the VPS provider network" {
		t.Fatalf("provider-network preference = %+v", result)
	}
}

func TestRealityPlanRejectsNativeValidationAndIsDeterministic(t *testing.T) {
	request := validRealityRequest(t)
	planRequest := connectionprofiles.PlanRequest{View: request, ChangeSet: "profiles-reality-0001", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	firstHost := &realityHost{observation: healthyRealityObservation()}
	secondHost := &realityHost{observation: healthyRealityObservation()}
	first := connectionprofiles.New(firstHost).Plan(t.Context(), planRequest)
	second := connectionprofiles.New(secondHost).Plan(t.Context(), planRequest)
	if first.Plan == nil || second.Plan == nil || first.Plan.Identity() != second.Plan.Identity() || first.Plan.SHA256() != second.Plan.SHA256() || !bytes.Equal(firstHost.validated, secondHost.validated) {
		t.Fatalf("same reviewed inputs produced different Plans: first %+v second %+v", first, second)
	}

	failed := connectionprofiles.New(&realityHost{observation: healthyRealityObservation(), validation: fmt.Errorf("SECRET-MARKER native output")}).Plan(t.Context(), planRequest)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-REALITY-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "SECRET-MARKER") {
		t.Fatalf("native validation failure = %+v", failed)
	}
}

func TestRealityPlanBindsExactReviewedConfigurationForState(t *testing.T) {
	request := validRealityRequest(t)
	host := &realityHost{observation: healthyRealityObservation()}
	plan := connectionprofiles.New(host).Plan(t.Context(), connectionprofiles.PlanRequest{View: request, ChangeSet: "profiles-reality-state", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}).Plan
	uuid := state.NewClientAccessValue("uuid")
	privateKey := state.NewInfrastructureSecret("private")
	shortID := state.NewClientAccessValue("short-id")
	profiles := state.ConnectionProfiles{VLESSRealityVision: state.VLESSRealityVision{Enabled: true, Port: 443, UUID: uuid, PrivateKey: privateKey, PublicKey: publicKeyMarker, ShortID: shortID, Target: "edge.example.net:443", ServerName: "edge.example.net", Fingerprint: "chrome"}}
	secrets := profileSecrets{clients: map[state.ClientAccessValue]string{uuid: uuidMarker, shortID: shortIDMarker}, infrastructure: map[state.InfrastructureSecret]string{privateKey: privateKeyMarker}}
	xray, singBox, err := plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || singBox != nil || !bytes.Equal(xray, host.validated) {
		t.Fatalf("reviewed State configuration = (%s, %s, %v)", xray, singBox, err)
	}
	secrets.clients[uuid] = "22222222-2222-4222-8222-222222222222"
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("changed credential accepted by reviewed Plan")
	}
}

func TestRealityApplyBindsStateAndBurnsStaleOrReusedPlans(t *testing.T) {
	request := validRealityRequest(t)
	planRequest := connectionprofiles.PlanRequest{View: request, ChangeSet: "profiles-reality-apply", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	module := connectionprofiles.New(&realityHost{observation: healthyRealityObservation()})
	plan := module.Plan(t.Context(), planRequest).Plan
	prepared := &realityPreparedState{changeSet: planRequest.ChangeSet, revision: 8, starting: planRequest.StartingStateSHA256, candidate: planRequest.DesiredStateSHA256, planIdentity: plan.Identity(), planSHA: plan.SHA256()}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: planRequest.StartingStateSHA256}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	result := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk)
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !result.PlanConsumed {
		t.Fatalf("valid Apply = %+v", result)
	}
	if reused := plan.Apply(systemchanges.Interface{}, prepared, starting, plan.VolatileSHA256(), disk); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("reused Apply = %+v", reused)
	}

	stalePlan := module.Plan(t.Context(), planRequest).Plan
	prepared.planIdentity, prepared.planSHA = stalePlan.Identity(), stalePlan.SHA256()
	if stale := stalePlan.Apply(systemchanges.Interface{}, prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("d", 64)}, stalePlan.VolatileSHA256(), disk); stale.Finding == nil || stale.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("stale Apply = %+v", stale)
	}
	changedPlan := module.Plan(t.Context(), planRequest).Plan
	prepared.planIdentity, prepared.planSHA = changedPlan.Identity(), changedPlan.SHA256()
	if changed := changedPlan.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("e", 64), disk); changed.Finding == nil || changed.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("changed host observations Apply = %+v", changed)
	}
}

type realityPreparedState struct {
	changeSet, starting, candidate, planIdentity, planSHA string
	revision                                              uint64
}

func (prepared *realityPreparedState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.planIdentity, prepared.planSHA, true
}

func (*realityPreparedState) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }

func TestRealitySemanticValidatorUsesStatesOneUseSecretReader(t *testing.T) {
	uuid := state.NewClientAccessValue("uuid")
	privateKey := state.NewInfrastructureSecret("private")
	shortID := state.NewClientAccessValue("short-id")
	profiles := state.ConnectionProfiles{VLESSRealityVision: state.VLESSRealityVision{
		Enabled: true, Port: 443, UUID: uuid, PrivateKey: privateKey, PublicKey: publicKeyMarker,
		ShortID: shortID, Target: "edge.example.net:443", ServerName: "edge.example.net", Fingerprint: "chrome",
	}}
	secrets := profileSecrets{
		clients:        map[state.ClientAccessValue]string{uuid: uuidMarker, shortID: shortIDMarker},
		infrastructure: map[state.InfrastructureSecret]string{privateKey: privateKeyMarker},
	}
	if err := connectionprofiles.New(&realityHost{}).ValidateConnectionProfiles(profiles, secrets); err != nil {
		t.Fatal(err)
	}
	nativeXray, nativeSingBox, err := connectionprofiles.New(&realityHost{}).PrepareConnectionProfiles(profiles, secrets)
	if err != nil || nativeSingBox != nil || !strings.Contains(string(nativeXray), `"method":"raw"`) || !strings.Contains(string(nativeXray), privateKeyMarker) {
		t.Fatalf("prepared State service bytes = (%s, %s, %v)", nativeXray, nativeSingBox, err)
	}
	profiles.VLESSRealityVision.Target = "edge.example.net:8443"
	if err := connectionprofiles.New(&realityHost{}).ValidateConnectionProfiles(profiles, secrets); err == nil || strings.Contains(err.Error(), privateKeyMarker) {
		t.Fatalf("invalid State profile = %v", err)
	}
}

func TestRealityCredentialGenerationProducesIndependentMatchingValues(t *testing.T) {
	first, err := connectionprofiles.GenerateRealityCredentials()
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectionprofiles.GenerateRealityCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%#v", first) != "REALITY credentials: ready" || fmt.Sprintf("%#v", second) != "REALITY credentials: ready" {
		t.Fatalf("generated credential rendering is unsafe: first %#v second %#v", first, second)
	}
	request := validRealityRequest(t)
	request.Credentials = first
	planRequest := connectionprofiles.PlanRequest{View: request, ChangeSet: "profiles-reality-random", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
	firstPlan := connectionprofiles.New(&realityHost{observation: healthyRealityObservation()}).Plan(t.Context(), planRequest)
	request.Credentials = second
	planRequest.View = request
	secondPlan := connectionprofiles.New(&realityHost{observation: healthyRealityObservation()}).Plan(t.Context(), planRequest)
	if firstPlan.Plan == nil || secondPlan.Plan == nil || firstPlan.Plan.SHA256() == secondPlan.Plan.SHA256() {
		t.Fatalf("independent generated credentials were invalid: first %+v second %+v", firstPlan, secondPlan)
	}
}

func TestPinnedNativeXrayAcceptsPreparedRealityConfiguration(t *testing.T) {
	binary := os.Getenv("SBXR_XRAY_BIN")
	if binary == "" {
		t.Skip("set SBXR_XRAY_BIN to the pinned v26.3.27 executable for Seam Verification")
	}
	host := &nativeRealityHost{observation: healthyRealityObservation(), binary: binary}
	request := validRealityRequest(t)
	result := connectionprofiles.New(host).Plan(t.Context(), connectionprofiles.PlanRequest{
		View: request, ChangeSet: "profiles-reality-native", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64),
	})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("pinned native validation = %+v", result)
	}
}

type nativeRealityHost struct {
	observation connectionprofiles.RealityObservation
	binary      string
}

func (host *nativeRealityHost) ObserveReality(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	return host.observation
}

func (host *nativeRealityHost) ValidateReality(ctx context.Context, version string, configuration io.Reader) error {
	if version != "v26.3.27" {
		return fmt.Errorf("wrong version")
	}
	command := exec.CommandContext(ctx, host.binary, "run", "-test", "-config", "stdin:")
	command.Stdin = configuration
	if err := command.Run(); err != nil {
		return fmt.Errorf("native Xray rejected prepared configuration")
	}
	return nil
}

func validRealityRequest(t *testing.T) connectionprofiles.ViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewRealityCredentials(uuidMarker, privateKeyMarker, publicKeyMarker, shortIDMarker)
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.ViewRequest{
		Revision:    7,
		Enabled:     true,
		Port:        443,
		Target:      connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net"},
		Fingerprint: "chrome",
		XrayVersion: "v26.3.27",
		Credentials: credentials,
	}
}

func healthyRealityObservation() connectionprofiles.RealityObservation {
	return connectionprofiles.RealityObservation{
		CheckedAt:         time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
		Probe:             connectionprofiles.ProbePassed,
		Class:             connectionprofiles.OrdinaryTarget,
		AcceptedNames:     []string{"edge.example.net"},
		RouteVerified:     true,
		ServiceInstalled:  true,
		ServiceUnit:       "xray.service",
		ServiceIdentity:   "xray",
		ServiceRunning:    true,
		ConfigurationSafe: true,
		Listener:          connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "tcp"},
		NetBindService:    true,
		ProviderNetwork:   true,
	}
}

func bounded(limit connectionprofiles.FallbackLimit) bool {
	return limit.AfterBytes > 0 && limit.BytesPerSec > 0 && limit.BurstBytesPerSec >= limit.BytesPerSec
}
