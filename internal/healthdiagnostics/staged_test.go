package healthdiagnostics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

func TestCheckReportsCommittedConnectionProfileCapabilityWithoutIndividualNotSetUpHealth(t *testing.T) {
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	result := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{
				Status: healthdiagnostics.Healthy,
				Code:   healthdiagnostics.NamedCheckCode(healthdiagnostics.ConnectionProfilesModule, healthdiagnostics.Healthy),
				Capabilities: healthdiagnostics.CapabilityInspection{CommittedRevision: 1, CapabilityRows: []healthdiagnostics.CapabilityFact{
					{Name: healthdiagnostics.VLESSRealityVision, Lifecycle: healthdiagnostics.ProfileEnabled},
					{Name: healthdiagnostics.VLESSXHTTP, Lifecycle: healthdiagnostics.ProfileNotSetUp},
					{Name: healthdiagnostics.VLESSWebSocket, Lifecycle: healthdiagnostics.ProfileNotSetUp},
					{Name: healthdiagnostics.Hysteria2, Lifecycle: healthdiagnostics.ProfileNotSetUp},
					{Name: healthdiagnostics.TUIC, Lifecycle: healthdiagnostics.ProfileNotSetUp},
					{Name: healthdiagnostics.AnyTLS, Lifecycle: healthdiagnostics.ProfileNotSetUp},
				}},
			}, nil
		},
	})

	if len(result.Modules) != 1 || result.Modules[0].Status != healthdiagnostics.Healthy || result.Modules[0].Capability == nil || result.Modules[0].Capability.CommittedRevision != 1 || len(result.Modules[0].Capability.CapabilityRows) != 6 {
		t.Fatalf("capability Check = %#v", result)
	}
	for index, profile := range result.Modules[0].Capability.CapabilityRows {
		if index == 0 {
			if profile.Lifecycle != healthdiagnostics.ProfileEnabled || profile.HealthResultOmitted || profile.PublicationOmitted {
				t.Fatalf("Enabled capability = %#v", profile)
			}
			continue
		}
		if profile.Lifecycle != healthdiagnostics.ProfileNotSetUp || !profile.HealthResultOmitted || !profile.PublicationOmitted || profile.Explanation != "No individual Health Result; Cloudflare Profile Setup is required." {
			t.Fatalf("Not set up capability = %#v", profile)
		}
	}
	if records := result.DiagnosticEvents(); len(records) != 1 || records[0].Record().Capability == nil || len(records[0].Record().Capability.CapabilityRows) != 6 {
		t.Fatalf("capability events = %#v", records)
	}
}

func TestCheckRejectsMalformedOrCandidateConnectionProfileCapability(t *testing.T) {
	for _, capability := range []healthdiagnostics.CapabilityInspection{
		{CommittedRevision: 0, CapabilityRows: stagedCapabilities()},
		{CommittedRevision: 2, CapabilityRows: stagedCapabilities()[:5]},
		{CommittedRevision: 2, CapabilityRows: append([]healthdiagnostics.CapabilityFact(nil), stagedCapabilities()...)},
	} {
		if len(capability.CapabilityRows) == 6 && capability.CommittedRevision == 2 {
			capability.CapabilityRows[1].Name = healthdiagnostics.ConnectionProfile("CREDENTIAL-MARKER-77A1")
		}
		result := healthdiagnostics.New(func() time.Time { return checkedAt }).Check(t.Context(), installationSummary(healthdiagnostics.ChangeInProgress), healthdiagnostics.NamedInspection{
			Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required,
			Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
				return healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.ConnectionProfilesModule, healthdiagnostics.Healthy), Capabilities: capability}, nil
			},
		})
		if len(result.Modules) != 1 || result.Modules[0].Status != healthdiagnostics.Unknown || result.Modules[0].Capability != nil || strings.Contains(strings.ToUpper(result.Modules[0].Explanation+result.Modules[0].Correction.Evidence), "MARKER") {
			t.Fatalf("malformed capability = %#v", result.Modules)
		}
	}
}

func TestCheckKeepsCapabilityLifecycleSeparateFromExpectedAbsenceHealth(t *testing.T) {
	for _, status := range []healthdiagnostics.HealthStatus{healthdiagnostics.Healthy, healthdiagnostics.NeedsAttention, healthdiagnostics.Failed, healthdiagnostics.Unknown} {
		result := healthdiagnostics.New(func() time.Time { return checkedAt }).Check(t.Context(), installationSummary(healthdiagnostics.Managed), healthdiagnostics.NamedInspection{
			Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required,
			Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
				return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.ConnectionProfilesModule, status), Capabilities: healthdiagnostics.CapabilityInspection{CommittedRevision: 1, CapabilityRows: stagedCapabilities()}}, nil
			},
		})
		module := result.Modules[0]
		if module.Status != status || module.Capability == nil || len(module.Capability.CapabilityRows) != 6 || module.Capability.CapabilityRows[1].Lifecycle != healthdiagnostics.ProfileNotSetUp {
			t.Fatalf("%s expected-absence result = %#v", status, module)
		}
		guidance := module.Correction.SBXRCorrection + strings.Join(module.Correction.OwnerSteps, " ")
		switch status {
		case healthdiagnostics.NeedsAttention:
			if !strings.Contains(guidance, "only exact proved SBXR-owned local residue") || !strings.Contains(guidance, "do not perform setup") {
				t.Fatalf("Needs attention guidance = %q", guidance)
			}
		case healthdiagnostics.Failed:
			if !strings.Contains(guidance, "without creating deferred values or adopting provider resources") {
				t.Fatalf("Failed guidance = %q", guidance)
			}
		case healthdiagnostics.Unknown:
			if strings.Contains(guidance, "remove") || strings.Contains(guidance, "provider") {
				t.Fatalf("Unknown guidance claimed ownership = %q", guidance)
			}
		}
	}
}

func stagedCapabilities() []healthdiagnostics.CapabilityFact {
	return []healthdiagnostics.CapabilityFact{
		{Name: healthdiagnostics.VLESSRealityVision, Lifecycle: healthdiagnostics.ProfileEnabled},
		{Name: healthdiagnostics.VLESSXHTTP, Lifecycle: healthdiagnostics.ProfileNotSetUp},
		{Name: healthdiagnostics.VLESSWebSocket, Lifecycle: healthdiagnostics.ProfileNotSetUp},
		{Name: healthdiagnostics.Hysteria2, Lifecycle: healthdiagnostics.ProfileNotSetUp},
		{Name: healthdiagnostics.TUIC, Lifecycle: healthdiagnostics.ProfileNotSetUp},
		{Name: healthdiagnostics.AnyTLS, Lifecycle: healthdiagnostics.ProfileNotSetUp},
	}
}
