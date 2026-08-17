package healthdiagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildSupportBundleIncludesOnlyTypedCapabilityAndOmissionFacts(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	module := New(func() time.Time { return now })
	check := module.Check(t.Context(), InstallationSummary{}, NamedInspection{
		Module: ConnectionProfilesModule, Role: Required,
		Inspect: func(context.Context) (Finding, error) {
			return Finding{Status: Healthy, Code: NamedCheckCode(ConnectionProfilesModule, Healthy), Capabilities: CapabilityInspection{CommittedRevision: 1, CapabilityRows: []CapabilityFact{
				{Name: VLESSRealityVision, Lifecycle: ProfileEnabled},
				{Name: VLESSXHTTP, Lifecycle: ProfileNotSetUp},
				{Name: VLESSWebSocket, Lifecycle: ProfileNotSetUp},
				{Name: Hysteria2, Lifecycle: ProfileNotSetUp},
				{Name: TUIC, Lifecycle: ProfileNotSetUp},
				{Name: AnyTLS, Lifecycle: ProfileNotSetUp},
			}}}, nil
		},
	})
	storage := &bundleMemory{}
	result := module.BuildSupportBundle(storage, BundleRequest{
		Check: check, Events: check.DiagnosticEvents(), Release: testReleaseFacts(),
		Platform: PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []UnitSummary{{Unit: "sbxr-health-check.timer", Status: UnitActive}},
	})
	if result.Status() != BundleCreated {
		t.Fatalf("bundle = %q %q", result.Status(), result.Code())
	}
	items := readBundle(t, storage.archive)
	var facts struct {
		Findings []EventRecord `json:"findings"`
	}
	if err := json.Unmarshal(items["facts.json"], &facts); err != nil || len(facts.Findings) != 1 || facts.Findings[0].Capability == nil || len(facts.Findings[0].Capability.CapabilityRows) != 6 {
		t.Fatalf("bundle capability facts = %s", items["facts.json"])
	}
	for _, forbidden := range []string{"credential", "https://", "provider_identifier", "raw_response", "transaction_secret", "credential-marker"} {
		if strings.Contains(strings.ToLower(string(storage.archive)), forbidden) {
			t.Fatalf("bundle contains forbidden %q", forbidden)
		}
	}
}
