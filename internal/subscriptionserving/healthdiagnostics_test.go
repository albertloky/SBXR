package subscriptionserving

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestHealthDiagnosticsCheckConsumesSubscriptionServingHealth(t *testing.T) {
	server, _, token, _ := testServer(t, "127.0.0.1")
	checkedAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	check := healthdiagnostics.New(func() time.Time { return checkedAt })

	installation := healthdiagnostics.InstallationSummaryFrom(systemchanges.New(nil).InstallationHealthInspection())
	result := check.Check(t.Context(), installation, healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.SubscriptionServingModule,
		Role:   healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			health := server.Health()
			status := healthdiagnostics.HealthStatus(health.Status)
			return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.SubscriptionServingModule, status)}, nil
		},
	})

	if len(result.Modules) != 1 || result.Modules[0].Status != healthdiagnostics.Healthy || result.Modules[0].Gate != healthdiagnostics.GatePasses || strings.Contains(fmt.Sprintf("%#v", result), token) {
		t.Fatalf("typed Subscription Serving health = %#v", result)
	}
}
