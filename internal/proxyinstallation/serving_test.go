package proxyinstallation

import (
	"context"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

type servingTestHost struct {
	*controlledHost
	safe, removed bool
	failRemoval   bool
}

func (h *servingTestHost) InspectServingFiles(hostadapter.ServingAuthority, bool) hostadapter.Observation {
	return hostadapter.Observation{Observed: true, Accepted: h.safe}
}
func (h *servingTestHost) RemoveServingRuntime(context.Context, hostadapter.ServingAuthority) bool {
	if h.failRemoval {
		h.failRemoval = false
		return false
	}
	h.removed = true
	return true
}
func (h *servingTestHost) ServingRuntimeAbsent(hostadapter.ServingAuthority) bool { return h.removed }

func servingInstallation(t *testing.T) (Interface, *servingTestHost, *controlledRemovalLifecycle) {
	t.Helper()
	h := &servingTestHost{controlledHost: acceptedHost(), safe: true}
	l := &controlledRemovalLifecycle{ready: true}
	m := newInstalledInterface(l, h, acceptedSingBox{})
	review := m.Review(t.Context(), StartSetupAction)
	if m.Execute(t.Context(), *review.Prepared, Approved, nil).Status != Running {
		t.Fatal("setup failed")
	}
	record, ok := decodeOwnership(h.ownership)
	if !ok {
		t.Fatal("setup authority failed")
	}
	record.Schema = 2
	record.Serving = &hostadapter.ServingAuthority{LinkID: strings.Repeat("a", 32), CredentialSHA256: strings.Repeat("b", 64), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)}}
	record.Resources = recordResources(record, false)
	for range record.Resources {
		record.ResourceCreatingReleases = append(record.ResourceCreatingReleases, record.Release)
	}
	h.ownership = ownershipBytes(record)
	return m, h, l
}

func TestServingAuthorityPreservesProxyAndSupportsRemovalRecovery(t *testing.T) {
	m, h, l := servingInstallation(t)
	status := m.Review(t.Context(), StatusAction)
	if status.Status != Running || status.SubscriptionStatus != SubscriptionProblemDetected {
		t.Fatal("independent status failed")
	}
	enable := m.Review(t.Context(), EnableSubscriptionAction)
	if enable.Prepared != nil {
		t.Fatal("owner enablement admitted")
	}
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("serving removal not offered")
	}
	h.failRemoval = true
	if m.Execute(t.Context(), *review.Prepared, Approved, nil).Code != RemovalNeedsCompletion || !h.active {
		t.Fatal("failed serving removal changed working proxy")
	}
	m = newInstalledInterface(l, h, acceptedSingBox{})
	review = m.Review(t.Context(), FinishRemovalAction)
	if review.Prepared == nil {
		t.Fatal("serving removal recovery not offered")
	}
	if m.Execute(t.Context(), *review.Prepared, Approved, nil).Code != CompleteRemovalCompleted || !h.removed || len(h.ownership) != 0 {
		t.Fatal("serving removal incomplete")
	}
}
