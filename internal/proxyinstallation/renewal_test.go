package proxyinstallation

import (
	"context"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

type renewalTestHost struct {
	*servingTestHost
	runs, hooks                int
	renewalRemoved             bool
	renewalBusy, renewalUnsafe bool
}

func (h *renewalTestHost) InspectRenewal(hostadapter.RenewalAuthority) hostadapter.RenewalInspection {
	if h.renewalUnsafe {
		return hostadapter.RenewalInspection{State: hostadapter.RenewalAttemptUnsafe}
	}
	return hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
}

type testRenewalRunner struct{ host *renewalTestHost }

func (r testRenewalRunner) Run(context.Context) int { r.host.runs++; return 0 }
func (testRenewalRunner) Abort()                    {}
func (h *renewalTestHost) PrepareRenewalRecorder(hostadapter.RenewalAuthority) (hostadapter.RenewalAttemptRunner, bool) {
	return testRenewalRunner{host: h}, true
}
func (h *renewalTestHost) RecordRenewalHook(hostadapter.RenewalAuthority, string, map[string]string) bool {
	h.hooks++
	return true
}
func (h *renewalTestHost) AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool) {
	return &hostadapter.RenewalExclusion{}, !h.renewalBusy
}
func (h *renewalTestHost) RemoveRenewalIntegration(context.Context, hostadapter.RenewalAuthority, *hostadapter.RenewalExclusion) bool {
	h.renewalRemoved = true
	return true
}
func (h *renewalTestHost) RenewalIntegrationAbsent(hostadapter.RenewalAuthority) bool {
	return h.renewalRemoved
}

func renewalInstallation(t *testing.T) (Interface, *renewalTestHost, *controlledRemovalLifecycle) {
	t.Helper()
	_, serving, lifecycle := servingInstallation(t)
	record, ok := decodeOwnership(serving.ownership)
	if !ok {
		t.Fatal("serving authority invalid")
	}
	record.Renewal = &hostadapter.RenewalAuthority{RecorderID: strings.Repeat("a", 32), Lineage: "sbxr-subscription", PublicIPv4: record.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation}
	record.Resources = recordResources(record, false)
	record.ResourceCreatingReleases = nil
	for range record.Resources {
		record.ResourceCreatingReleases = append(record.ResourceCreatingReleases, record.Release)
	}
	serving.ownership = ownershipBytes(record)
	host := &renewalTestHost{servingTestHost: serving}
	return newInstalledInterface(lifecycle, host, acceptedSingBox{}), host, lifecycle
}

func TestManagedRenewalDispatchRequiresExactDurableAuthority(t *testing.T) {
	_, host, lifecycle := renewalInstallation(t)
	if code := recordRenewal(t.Context(), lifecycle, host); code != 0 || host.runs != 1 {
		t.Fatalf("recordRenewal() = %d runs=%d", code, host.runs)
	}
	host.stagedOwnership = []byte("conflicting transaction")
	if code := recordRenewal(t.Context(), lifecycle, host); code != hostadapter.RenewalRecorderRefused || host.runs != 1 {
		t.Fatalf("conflicting recordRenewal() = %d runs=%d", code, host.runs)
	}
}

func TestRenewalEvidenceIsVisibleAndRemovalExcludesWritersBeforeCommit(t *testing.T) {
	m, host, _ := renewalInstallation(t)
	status := m.Review(t.Context(), StatusAction)
	if status.Status != Running || status.SubscriptionStatus != SubscriptionProblemDetected || !strings.Contains(strings.Join(status.Details, "\n"), "Renewal Attempt Evidence: failed") {
		t.Fatalf("Review() = %#v", status)
	}
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("Complete removal not offered")
	}
	before := string(host.ownership)
	host.renewalBusy = true
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || string(host.ownership) != before {
		t.Fatalf("busy Execute() = %#v", result)
	}
	host.renewalBusy = false
	review = m.Review(t.Context(), CompleteRemovalAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || !host.renewalRemoved || !host.removed {
		t.Fatalf("Execute() = %#v renewal=%v serving=%v", result, host.renewalRemoved, host.removed)
	}
}
