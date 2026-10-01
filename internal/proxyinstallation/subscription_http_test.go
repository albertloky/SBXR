package proxyinstallation

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type httpRepairHost struct {
	*controlledHost
	certificateCalls int
}

func (h *httpRepairHost) RepairSubscriptionCertificate(context.Context, hostadapter.RenewalAuthority) hostadapter.CertificateRepairResult {
	h.certificateCalls++
	return hostadapter.CertificateRepairResult{}
}
func (h *httpRepairHost) ResolveRenewalFailure(hostadapter.RenewalAuthority, hostadapter.ServingAuthority) bool {
	h.certificateCalls++
	return false
}
func (h *httpRepairHost) AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool) {
	h.certificateCalls++
	return nil, false
}

func TestHTTPSubscriptionRuntimeRepairDoesNotAcquireOrInvokeCertbot(t *testing.T) {
	_, host := enabledIdentityInstallation(t)
	host.subscriptionStopped = true
	h := &httpRepairHost{controlledHost: host}
	m := newInstalledInterface(readyLifecycle{}, h, acceptedSingBox{})
	review := m.Review(t.Context(), RepairSubscriptionAction)
	if review.Prepared == nil || !strings.Contains(strings.Join(review.Plan, "\n"), "HTTP") {
		t.Fatal("HTTP runtime repair not admitted")
	}
	result := m.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Code != SubscriptionRepaired || result.SubscriptionStatus != SubscriptionAvailable || h.certificateCalls != 0 {
		t.Fatalf("HTTP repair: %s %s certificate calls=%d", result.Code, result.FailedCheck, h.certificateCalls)
	}
	record, ok := decodeOwnership(h.ownership)
	if !ok || record.Repair != nil || record.Renewal != nil || !record.Serving.HTTP {
		t.Fatal("HTTP repair manufactured renewal authority")
	}
}

func TestHTTPOwnershipAndUpdateRequireMatchingTransportSupport(t *testing.T) {
	_, host := enabledIdentityInstallation(t)
	body := bytes.Clone(host.ownership)
	record, ok := decodeOwnership(body)
	if !ok {
		t.Fatal("HTTP ownership invalid")
	}
	target := &softwarelifecycle.UpdateTarget{Identity: testInstalledIdentity(), Executable: []byte(expandedProxyAuthorityCapability + " " + hostadapter.LockProvisioningCapability()), Support: &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []softwarelifecycle.ReleaseIdentity{testInstalledIdentity()}}}
	if AdmitSoftwareUpdate(body, testInstalledIdentity(), target) {
		t.Fatal("HTTP ownership admitted target without HTTP support")
	}
	target.Executable = append(target.Executable, []byte(" "+httpSubscriptionCapability)...)
	if !AdmitSoftwareUpdate(body, testInstalledIdentity(), target) {
		t.Fatal("HTTP capable update refused")
	}
	if !bytes.Equal(body, host.ownership) {
		t.Fatal("update admission migrated authority")
	}
	renewal := hostadapter.RenewalAuthority{RecorderID: strings.Repeat("a", 32), Lineage: "sbxr-subscription", PublicIPv4: record.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation}
	record.Renewal = &renewal
	updateSubscriptionResources(&record, record.Release)
	if _, ok := decodeOwnership(ownershipBytes(record)); ok {
		t.Fatal("HTTP authority admitted a renewal writer")
	}
}

func TestHTTPPrivateDispatchComposesProductionModuleWithoutLoadingCertificate(t *testing.T) {
	_, h := enabledIdentityInstallation(t)
	record, ok := decodeOwnership(h.ownership)
	if !ok {
		t.Fatal("HTTP ownership invalid")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := &dispatchTestHost{servingTestHost: &servingTestHost{controlledHost: h, safe: true}, listener: listener, ip: record.PublicIPv4, bound: make(chan struct{}), publicIPv4: make(chan bool, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan subscriptionserving.Code, 1)
	go func() { done <- serveSubscription(ctx, readyLifecycle{}, host, subscriptionserving.New(nil, nil)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != subscriptionserving.Stopped {
				t.Errorf("shutdown %s", code)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP dispatch did not stop")
		}
	})
	select {
	case <-host.bound:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP private dispatch refused")
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + listener.Addr().String() + "/s/" + string(h.subscriptionCredential))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	expected, _, valid := clientArtifact(h.configuration, record.PublicIPv4)
	if err != nil || !valid || response.StatusCode != 200 || !bytes.Equal(body, expected) || response.TLS != nil {
		t.Fatal("HTTP private dispatch did not serve current authenticated REALITY artifact")
	}
}
