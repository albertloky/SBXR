package proxyinstallation

import (
	"bytes"
	"strings"
	"testing"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

// AvailabilityMenuFixture exposes only a test fixture to the external test package,
// allowing the real module and terminal to run together without an import cycle.
func AvailabilityMenuFixture(t *testing.T, scenario string) Interface {
	t.Helper()
	host := acceptedHost()
	m := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	setup := m.Review(t.Context(), StartSetupAction)
	if got := m.Execute(t.Context(), *setup.Prepared, Approved, nil); got.Code != SetupComplete {
		t.Fatal(got.Code)
	}
	if scenario != "disabled" && scenario != "recovery-disabled" {
		enable := m.Review(t.Context(), EnableSubscriptionAction)
		if got := m.Execute(t.Context(), *enable.Prepared, Approved, nil); got.Code != SubscriptionEnabled {
			t.Fatal(got.Code)
		}
	}
	switch scenario {
	case "running", "disabled":
	case "stopped":
		host.active, host.listener, host.subscriptionStopped = false, false, true
	case "unknown":
		host.activeUnknown, host.subscriptionStopped, host.clientCertificateInvalid = true, true, true
	case "recovery-disabled", "recovery-enabled":
		host.clientIdentityFail = "start"
		rotate := m.Review(t.Context(), RotateClientIdentityAction)
		if rotate.Prepared == nil {
			t.Fatal("rotation was not prepared")
		}
		if got := m.Execute(t.Context(), *rotate.Prepared, Approved, nil); got.Code != ClientIdentityRotationNeedsFinish {
			t.Fatal(got.Code)
		}
		m = newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	default:
		t.Fatal("unknown fixture scenario")
	}
	ownership, configuration, credential := bytes.Clone(host.ownership), bytes.Clone(host.configuration), bytes.Clone(host.subscriptionCredential)
	operations, starts := len(host.operations), host.subscriptionStarts
	t.Cleanup(func() {
		if !bytes.Equal(ownership, host.ownership) || !bytes.Equal(configuration, host.configuration) || !bytes.Equal(credential, host.subscriptionCredential) || len(host.operations) != operations || host.subscriptionStarts != starts {
			t.Error("status display or declined recovery mutated the fixture")
		}
	})
	if strings.HasPrefix(scenario, "recovery-") && m.Review(t.Context(), FinishClientIdentityAction).Prepared == nil {
		t.Fatal("recovery was not prepared")
	}
	return m
}
