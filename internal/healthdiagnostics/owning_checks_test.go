package healthdiagnostics_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestCheckConsumesEveryAvailableOwningModuleInspection(t *testing.T) {
	const rawMarker = "RAW-OWNER-MARKER-2C149E"
	checks := []struct {
		module  healthdiagnostics.Module
		inspect func() healthdiagnostics.HealthStatus
	}{
		{healthdiagnostics.StateModule, func() healthdiagnostics.HealthStatus {
			result, _ := state.New(nil).Load(state.LoadRequest{})
			if result.Status == state.RecoveryRequired {
				return healthdiagnostics.Failed
			}
			return healthdiagnostics.Unknown
		}},
		{healthdiagnostics.NetworkPolicyModule, func() healthdiagnostics.HealthStatus {
			return healthdiagnostics.HealthStatus(networkpolicy.New(nil).Evaluate(networkpolicy.Request{}).Outcome)
		}},
		{healthdiagnostics.SystemChangesModule, func() healthdiagnostics.HealthStatus {
			if systemchanges.New(nil).Inspect().Status == systemchanges.RecoveryRequired {
				return healthdiagnostics.Failed
			}
			return healthdiagnostics.Unknown
		}},
		{healthdiagnostics.CloudflareTunnelModule, func() healthdiagnostics.HealthStatus {
			return healthdiagnostics.HealthStatus(cloudflaretunnel.New(nil, nil).View(t.Context(), cloudflaretunnel.ViewRequest{}).Health.Outcome)
		}},
		{healthdiagnostics.CertificateLifecycleModule, func() healthdiagnostics.HealthStatus {
			return healthdiagnostics.HealthStatus(certificatelifecycle.New(nil, nil).View(t.Context(), certificatelifecycle.ViewRequest{}).Health.Outcome)
		}},
		{healthdiagnostics.ConnectionProfilesModule, func() healthdiagnostics.HealthStatus {
			return healthdiagnostics.HealthStatus(connectionprofiles.New(nil).ViewRegistry(t.Context(), connectionprofiles.RegistryViewRequest{}).Health.Outcome)
		}},
		{healthdiagnostics.SubscriptionPublicationModule, func() healthdiagnostics.HealthStatus {
			if (subscriptionpublication.Interface{}).View(subscriptionpublication.ViewRequest{}).Status == subscriptionpublication.PublicationUnavailable {
				return healthdiagnostics.Unknown
			}
			return healthdiagnostics.Failed
		}},
		{healthdiagnostics.SubscriptionServingModule, func() healthdiagnostics.HealthStatus {
			return healthdiagnostics.HealthStatus(subscriptionserving.Result(errors.New(rawMarker)).Status)
		}},
		{healthdiagnostics.HealthDiagnosticsModule, func() healthdiagnostics.HealthStatus { return healthdiagnostics.Healthy }},
		{healthdiagnostics.SoftwareLifecycleModule, func() healthdiagnostics.HealthStatus { return healthdiagnostics.Unknown }},
		{healthdiagnostics.OwnerConsoleModule, func() healthdiagnostics.HealthStatus { return healthdiagnostics.Unknown }},
		{healthdiagnostics.InstallationModule, func() healthdiagnostics.HealthStatus { return healthdiagnostics.Unknown }},
		{healthdiagnostics.CloudflareProfileSetupModule, func() healthdiagnostics.HealthStatus { return healthdiagnostics.Unknown }},
	}
	inspections := make([]healthdiagnostics.NamedInspection, 0, len(checks))
	for _, check := range checks {
		check := check
		inspections = append(inspections, healthdiagnostics.NamedInspection{
			Module: check.module, Role: healthdiagnostics.Required,
			Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
				status := check.inspect()
				return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(check.module, status)}, nil
			},
		})
	}

	installation := healthdiagnostics.InstallationSummaryFrom(systemchanges.New(nil).InstallationHealthInspection())
	result := healthdiagnostics.New(nil).Check(t.Context(), installation, inspections...)
	if len(result.Modules) != len(checks) || strings.Contains(fmt.Sprintf("%#v", result), rawMarker) {
		t.Fatalf("owning Module results = %#v", result)
	}
	for _, module := range result.Modules {
		if module.Code == "" || module.Explanation == "" || module.NextAction == "" || module.Role != healthdiagnostics.Required {
			t.Fatalf("incomplete owning Module result = %#v", module)
		}
	}
}
