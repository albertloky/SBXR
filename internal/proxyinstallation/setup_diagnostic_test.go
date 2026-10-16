package proxyinstallation

import (
	"context"
	"slices"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestSetupRevalidationIdentifiesFailedPreflightWithoutEffects(t *testing.T) {
	for _, test := range []struct {
		check  string
		change func(*hostadapter.Preflight)
	}{
		{"Proxy footprint inspection", func(f *hostadapter.Preflight) { f.Resources[0].Observed = false }},
		{"Clean proxy footprint", func(f *hostadapter.Preflight) { f.Resources[0].Present = true }},
		{"Ubuntu version", func(f *hostadapter.Preflight) { f.OSVersion = "unsupported-secret\nBearer secret-token" }},
		{"Architecture", func(f *hostadapter.Preflight) { f.Architecture = "unsupported-secret" }},
		{"Public IPv4", func(f *hostadapter.Preflight) { f.PublicIPv4 = "secret-token" }},
		{"Synchronized clock", func(f *hostadapter.Preflight) { f.ClockSynchronized = false }},
		{"Public TCP port 443", func(f *hostadapter.Preflight) { f.TCP443Available = false }},
		{"Ubuntu package locks", func(f *hostadapter.Preflight) { f.PackageLocksAvailable = false }},
		{"REALITY destination", func(f *hostadapter.Preflight) { f.Destinations[0].HTTP2 = false }},
	} {
		t.Run(test.check, func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			prepared := installation.Review(t.Context(), StartSetupAction).Prepared
			if prepared == nil {
				t.Fatal("setup was not prepared")
			}
			host.preflight.Resources = slices.Clone(host.preflight.Resources)
			host.preflight.Destinations = slices.Clone(host.preflight.Destinations)
			test.change(&host.preflight)
			result := installation.Execute(t.Context(), *prepared, Approved, nil)
			assertSetupDiagnostic(t, result, test.check, "SETUP-PREFLIGHT-", host)
			if strings.Contains(result.Correction, "secret-token") || strings.Contains(result.Correction, "unsupported-secret") {
				t.Fatal("untrusted preflight values escaped into diagnostics")
			}
			if again := installation.Execute(t.Context(), *prepared, Approved, nil); again.FailedCheck != "Prepared Action" {
				t.Fatal("refused authority remained reusable")
			}
		})
	}
}

func TestSetupRevalidationIdentifiesLifecycleIdentityAndDrift(t *testing.T) {
	for _, branch := range []string{"lifecycle", "missing installed identity", "changed installed identity", "public IP drift", "destination drift", "generated identity"} {
		t.Run(branch, func(t *testing.T) {
			host := acceptedHost()
			lifecycle := &mutableLifecycle{result: readyLifecycle{}.Status(t.Context())}
			installation := newInstalledInterface(lifecycle, host, acceptedSingBox{}).(*installedInterface)
			prepared := installation.Review(t.Context(), StartSetupAction).Prepared
			check, code := "Installed SBXR revalidation", "SETUP-REVALIDATION-INSTALLED"
			switch branch {
			case "lifecycle":
				lifecycle.result.State = softwarelifecycle.RecoveryRequiredState
			case "missing installed identity":
				lifecycle.result.Installed = nil
			case "changed installed identity":
				identity := *lifecycle.result.Installed
				identity.Commit = "secret-token"
				lifecycle.result.Installed = &identity
			case "public IP drift":
				host.preflight.PublicIPv4 = "1.1.1.1"
				check, code = "Public IPv4 changed", "SETUP-REVALIDATION-DRIFT"
			case "destination drift":
				host.preflight.Destinations = append(slices.Clone(host.preflight.Destinations), hostadapter.DestinationObservation{Destination: hostadapter.Destination{Address: "secret-token"}})
				check, code = "REALITY destination observations changed", "SETUP-REVALIDATION-DRIFT"
			case "generated identity":
				authority := installation.prepared[prepared.token]
				authority.identity.PrivateKey = "secret-token"
				installation.prepared[prepared.token] = authority
				check, code = "Generated Client Identity revalidation", "SETUP-REVALIDATION-IDENTITY"
			}
			result := installation.Execute(t.Context(), *prepared, Approved, nil)
			assertSetupDiagnostic(t, result, check, code, host)
			for _, secret := range []string{"secret-token", "1.1.1.1", "8.8.8.8", "private", "11111111-2222-4333-8444-555555555555"} {
				if strings.Contains(result.Correction, secret) {
					t.Fatalf("diagnostic contains protected value %q", secret)
				}
			}
		})
	}
}

func TestSetupPreflightDiagnosticsApplyBeforeConfirmation(t *testing.T) {
	host := acceptedHost()
	host.preflight.Destinations[0].TLS13 = false
	review := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), StartSetupAction)
	assertSetupDiagnostic(t, review.Result, "REALITY destination", "SETUP-PREFLIGHT-DESTINATION", host)
	for _, flag := range []string{"DNS=true", "TCP=true", "TLS13=false", "HTTP2=true", "certificate=true"} {
		if !strings.Contains(review.Result.Correction, flag) {
			t.Fatalf("missing %s: %s", flag, review.Result.Correction)
		}
	}
}

func assertSetupDiagnostic(t *testing.T, result Result, check, code string, host *controlledHost) {
	t.Helper()
	if result.Code != ActionRefused || result.FailedCheck != check || !strings.Contains(result.Correction, "Diagnostic: "+code) || !strings.Contains(result.Correction, "expected=") || !strings.Contains(result.Correction, "observed=") {
		t.Fatalf("wrong refusal diagnostic: %#v", result)
	}
	if len(host.ownership) != 0 || len(host.configuration) != 0 || len(host.operations) != 0 {
		t.Fatal("refusal wrote setup effects")
	}
}

// A cancelled context remains refused even when the static preflight fixture is accepted.
func TestSetupRevalidationCancellationRemainsFailClosed(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	prepared := installation.Review(t.Context(), StartSetupAction).Prepared
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := installation.Execute(ctx, *prepared, Approved, nil)
	if result.Code != ActionRefused || result.FailedCheck != "Managed termination" || len(host.ownership) != 0 {
		t.Fatalf("cancelled setup: %#v", result)
	}
}
