package proxyinstallation

import (
	"context"
	"reflect"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type acceptedHost struct{}

func (acceptedHost) Inspect(_ context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	return hostadapter.Inspection{Resources: observedAbsent(requested), Complete: true}
}

func (acceptedHost) Preflight(_ context.Context, requested []hostadapter.Resource, _ []hostadapter.Destination) hostadapter.Preflight {
	facts := acceptedPreflightFacts()
	facts.Resources = observedAbsent(requested)
	return facts
}

type controlledHost struct {
	inspection hostadapter.Inspection
	preflight  hostadapter.Preflight
}

func (host *controlledHost) Inspect(_ context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	if host.inspection.Resources == nil {
		return hostadapter.Inspection{Resources: observedAbsent(requested), Complete: true}
	}
	return host.inspection
}

func (host *controlledHost) Preflight(_ context.Context, requested []hostadapter.Resource, _ []hostadapter.Destination) hostadapter.Preflight {
	if host.preflight.Resources == nil {
		host.preflight.Resources = observedAbsent(requested)
	}
	return host.preflight
}

func observedAbsent(requested []hostadapter.Resource) []hostadapter.Resource {
	resources := make([]hostadapter.Resource, len(requested))
	copy(resources, requested)
	for index := range resources {
		resources[index].Observed = true
	}
	return resources
}

func acceptedPreflightFacts() hostadapter.Preflight {
	return hostadapter.Preflight{
		Resources: observedAbsent(footprint),
		OSID:      "ubuntu", OSVersion: "24.04", Architecture: "amd64", PublicIPv4: "8.8.8.8",
		ClockSynchronized: true, TCP443Available: true, MutationLockAvailable: true, PackageLocksAvailable: true,
		Destinations: []hostadapter.DestinationObservation{{Destination: hostadapter.Destination{Address: "microsoft.com:443", ServerName: "microsoft.com"}, DNS: true, TCP: true, TLS13: true, HTTP2: true, CertificateName: true}},
	}
}

type acceptedSingBox struct{}

func (acceptedSingBox) PrepareIdentity() (singboxadapter.Identity, error) {
	return singboxadapter.Identity{UUID: "11111111-2222-4333-8444-555555555555", PrivateKey: "private", PublicKey: "public", ShortID: "01020304"}, nil
}

func (acceptedSingBox) ValidIdentity(identity singboxadapter.Identity) bool {
	return identity.UUID == "11111111-2222-4333-8444-555555555555" && identity.PrivateKey == "private" && identity.PublicKey == "public" && identity.ShortID == "01020304"
}

type readyLifecycle struct{}

func (readyLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

func (readyLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func TestOwnerCanReviewAndDeclineCleanSetup(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost{}, acceptedSingBox{})

	review := installation.Review(t.Context(), StartSetupAction)

	wantActions := []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}
	if review.Version != "v3.0.0" || review.Status != NotSetUp || review.Result.Code != StatusNotSetUp || !reflect.DeepEqual(review.LegalActions, wantActions) || review.Prepared == nil {
		t.Fatalf("Review() = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, required := range []string{"Ubuntu 24.04 amd64", "8.8.8.8:443", "microsoft.com:443", "sing-box 1.13.19 amd64", "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", "24597120 bytes", "one generated Client Identity", "/var/lib/sbxr/proxy-ownership.json", "Infrastructure Secret", "will not change SSH, firewall, routing, or provider settings"} {
		if !strings.Contains(plan, required) {
			t.Errorf("plan missing %q:\n%s", required, plan)
		}
	}

	result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
	if result.Status != NotSetUp || result.Message != "No changes were made." || result.Code != ActionCancelled {
		t.Fatalf("Execute() = %#v", result)
	}
}

func TestFreshInspectionReportsConflictingFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	resources[3].Present = true
	host := &controlledHost{inspection: hostadapter.Inspection{Resources: resources, Complete: true}, preflight: acceptedPreflightFacts()}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || review.Result.Message != "A proxy problem was detected. View details before continuing." || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestFreshInspectionReportsUnknownFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	resources[3].Observed = false
	installation := newInstalledInterface(readyLifecycle{}, &controlledHost{inspection: hostadapter.Inspection{Resources: resources}}, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || !strings.Contains(strings.Join(review.Details, "\n"), "/etc/sing-box could not be inspected") {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestExecuteRefusesUntrustedPreparedAuthority(t *testing.T) {
	newInstallation := func(host *controlledHost) Interface {
		return newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	}
	assertRefused := func(t *testing.T, result Result, failedCheck string) {
		t.Helper()
		if result.Code != ActionRefused || result.FailedCheck != failedCheck {
			t.Fatalf("Execute() = %#v", result)
		}
	}

	t.Run("invalid", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		assertRefused(t, newInstallation(host).Execute(t.Context(), PreparedAction{}, Approved, nil), "Prepared Action")
	})

	t.Run("mismatched module", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		first, second := newInstallation(host), newInstallation(host)
		prepared := first.Review(t.Context(), StartSetupAction).Prepared
		assertRefused(t, second.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("stale after a later review", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Review(t.Context(), StatusAction)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("reused", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Execute(t.Context(), *prepared, Declined, nil)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("changed facts", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		host.preflight.PublicIPv4 = "1.1.1.1"
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action facts")
	})
}

func TestReviewRefusesEveryFailedSetupPreflight(t *testing.T) {
	tests := []struct {
		name   string
		failed string
		change func(*hostadapter.Preflight)
	}{
		{"changed footprint", "Clean proxy footprint", func(facts *hostadapter.Preflight) {
			facts.Resources[3].Present = true
		}},
		{"unsupported Ubuntu", "Ubuntu version", func(facts *hostadapter.Preflight) { facts.OSVersion = "22.04" }},
		{"unsupported architecture", "Architecture", func(facts *hostadapter.Preflight) { facts.Architecture = "arm64" }},
		{"reserved IPv4", "Public IPv4", func(facts *hostadapter.Preflight) { facts.PublicIPv4 = "203.0.113.7" }},
		{"unsynchronized clock", "Synchronized clock", func(facts *hostadapter.Preflight) { facts.ClockSynchronized = false }},
		{"occupied port", "Public TCP port 443", func(facts *hostadapter.Preflight) { facts.TCP443Available = false }},
		{"busy mutation lock", "SBXR mutation lock", func(facts *hostadapter.Preflight) { facts.MutationLockAvailable = false }},
		{"busy package locks", "Ubuntu package locks", func(facts *hostadapter.Preflight) { facts.PackageLocksAvailable = false }},
		{"no compatible destination", "REALITY destination", func(facts *hostadapter.Preflight) { facts.Destinations[0].HTTP2 = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := acceptedPreflightFacts()
			test.change(&facts)
			installation := newInstalledInterface(readyLifecycle{}, &controlledHost{preflight: facts}, acceptedSingBox{})

			review := installation.Review(t.Context(), StartSetupAction)

			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck != test.failed || review.Result.Correction == "" {
				t.Fatalf("Review() = %#v", review)
			}
		})
	}
}

func TestReviewReturnsSecretSafeNotSetUpDetails(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost{}, acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0 " + strings.Repeat("a", 40) + " " + strings.Repeat("b", 64),
		"Proxy Installation Status: Not set up",
		"Ownership Record: Absent",
		"Client Identity: Absent",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private"} {
		if strings.Contains(details, secret) {
			t.Errorf("details disclose %q", secret)
		}
	}
}

func TestReviewRefusesUnsupportedAndIllegalActionsWithoutAuthority(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost{}, acceptedSingBox{})

	unsupported := installation.Review(t.Context(), CompleteRemovalAction)
	if unsupported.Result.Code != ActionRefused || unsupported.Result.FailedCheck != "Complete removal availability" || unsupported.Prepared != nil {
		t.Fatalf("Complete removal Review() = %#v", unsupported)
	}
	illegal := installation.Review(t.Context(), FinishSetupAction)
	if illegal.Result.Code != ActionRefused || illegal.Result.FailedCheck != "Legal action" || illegal.Prepared != nil {
		t.Fatalf("Finish setup Review() = %#v", illegal)
	}
}
