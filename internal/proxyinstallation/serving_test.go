package proxyinstallation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type servingTestHost struct {
	*controlledHost
	safe, removed               bool
	failRemoval                 bool
	exclusionBusy, missingFiles bool
}

type dispatchTestHost struct {
	*servingTestHost
	certificate subscriptionserving.Certificate
	listener    net.Listener
	ip          string
	bound       chan struct{}
	publicIPv4  chan bool
	validated   int
	selected    hostadapter.ServingAuthority
}
type advertisedListener struct {
	net.Listener
	ip string
}

func (l advertisedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(l.ip), Port: 8443} }
func (h *dispatchTestHost) ValidateServingDispatch(authority hostadapter.ServingAuthority, _ *hostadapter.RenewalAuthority) bool {
	h.validated++
	h.selected = authority
	return true
}
func (h *dispatchTestHost) ServingPublicIPv4(_ context.Context, ip string) bool { return ip == h.ip }
func (h *dispatchTestHost) WatchServingPublicIPv4(context.Context, string) <-chan bool {
	return h.publicIPv4
}
func (h *dispatchTestHost) ReadServingConfiguration(_ hostadapter.SetupSpec, expected string) ([]byte, error) {
	sum := sha256.Sum256(h.configuration)
	if hex.EncodeToString(sum[:]) != expected {
		return nil, errors.New("test configuration mismatch")
	}
	return h.configuration, nil
}
func (h *dispatchTestHost) LoadServingCertificate(a hostadapter.ServingAuthority) (subscriptionserving.Certificate, bool) {
	return h.certificate, a.CertificateGeneration == h.certificate.Generation && a.CertificateSHA256[2] == hex.EncodeToString(h.certificate.ChainSHA256[:]) && a.CertificateSHA256[3] == hex.EncodeToString(h.certificate.KeySHA256[:])
}
func (h *dispatchTestHost) ServingGeneration(a hostadapter.ServingAuthority) subscriptionserving.Generation {
	return hostadapter.New().ServingGeneration(a)
}
func (h *dispatchTestHost) BindServingListener(ip string) (net.Listener, error) {
	if ip != h.ip {
		return nil, errors.New("test address mismatch")
	}
	close(h.bound)
	return advertisedListener{Listener: h.listener, ip: ip}, nil
}

func TestAcceptedPrivateDispatchComposesAuthorityProfileTLSAndServing(t *testing.T) {
	_, h, lifecycle := servingInstallation(t)
	record, ok := decodeOwnership(h.ownership)
	if !ok {
		t.Fatal("test ownership invalid")
	}
	identity, err := singboxadapter.New().PrepareIdentity()
	if err != nil {
		t.Fatal("test identity failed")
	}
	h.configuration, err = singboxadapter.New().EncodeServerConfiguration(identity, record.DestinationAddress, record.DestinationName)
	if err != nil {
		t.Fatal("test configuration failed")
	}
	sum := sha256.Sum256(h.configuration)
	record.ConfigurationSHA256 = hex.EncodeToString(sum[:])
	token := strings.Repeat("A", 43)
	sum = sha256.Sum256([]byte(token))
	record.Serving.CredentialSHA256 = hex.EncodeToString(sum[:])
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	root, _ = x509.ParseCertificate(der)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), IPAddresses: []net.IP{net.ParseIP(record.PublicIPv4)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal("test certificate failed")
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	cert := subscriptionserving.Certificate{Chain: chain, Key: keyPEM, ChainSHA256: sha256.Sum256(chain), KeySHA256: sha256.Sum256(keyPEM), Lineage: "sbxr-subscription", Generation: 1}
	record.Serving.CertificateSHA256[2] = hex.EncodeToString(cert.ChainSHA256[:])
	record.Serving.CertificateSHA256[3] = hex.EncodeToString(cert.KeySHA256[:])
	record.Resources = recordResources(record, false)
	h.ownership = ownershipBytes(record)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	pool := x509.NewCertPool()
	pool.AddCert(root)
	host := &dispatchTestHost{servingTestHost: h, certificate: cert, listener: listener, ip: record.PublicIPv4, bound: make(chan struct{}), publicIPv4: make(chan bool, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan subscriptionserving.Code, 1)
	go func() { done <- serveSubscription(ctx, lifecycle, host, subscriptionserving.New(pool, nil)) }()
	select {
	case <-host.bound:
	case <-done:
		t.Fatal("private dispatch refused valid authority")
	case <-time.After(3 * time.Second):
		t.Fatal("private dispatch did not bind")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: record.PublicIPv4}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + listener.Addr().String() + "/s/" + token)
	if err != nil {
		t.Fatal("private dispatch HTTPS failed")
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || !strings.HasPrefix(string(body), "vless://"+identity.UUID+"@"+record.PublicIPv4+":443?") {
		t.Fatal("private dispatch did not serve authoritative profile")
	}
	host.publicIPv4 <- false
	if <-done != subscriptionserving.Stopped {
		t.Fatal("private dispatch did not stop after public IPv4 drift")
	}
}

func TestPrivateServingSelectsTheRecordedCertificateActivationTarget(t *testing.T) {
	_, host, lifecycle := servingInstallation(t)
	record, ok := decodeOwnership(host.ownership)
	if !ok {
		t.Fatal("serving authority invalid")
	}
	record.Renewal = &hostadapter.RenewalAuthority{RecorderID: strings.Repeat("1", 32), Lineage: "sbxr-subscription", PublicIPv4: record.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation}
	record.Resources = recordResources(record, false)
	record.ResourceCreatingReleases = make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
	for index := range record.ResourceCreatingReleases {
		record.ResourceCreatingReleases[index] = record.Release
	}
	host.ownership = ownershipBytes(record)
	baseline := &dispatchTestHost{servingTestHost: host, ip: record.PublicIPv4, bound: make(chan struct{}), publicIPv4: make(chan bool)}
	if code := serveSubscription(t.Context(), lifecycle, baseline, subscriptionserving.New(nil, nil)); code != subscriptionserving.Refused || baseline.validated != 1 {
		t.Fatalf("baseline serveSubscription() = %s validated=%d", code, baseline.validated)
	}
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('5'+index)), 64)
	}
	record.Activation = &certificateActivation{Source: *record.Serving, Target: target, Checkpoint: activationTargetRecorded}
	host.ownership = ownershipBytes(record)
	if _, ok := decodeOwnership(host.ownership); !ok {
		t.Fatalf("pending activation authority invalid: %s", host.ownership)
	}
	dispatch := &dispatchTestHost{servingTestHost: host, ip: record.PublicIPv4, bound: make(chan struct{}), publicIPv4: make(chan bool)}
	if code := serveSubscription(t.Context(), lifecycle, dispatch, subscriptionserving.New(nil, nil)); code != subscriptionserving.Refused || dispatch.validated != 1 || dispatch.selected != target {
		t.Fatalf("serveSubscription() = %s validated=%d selected=%#v", code, dispatch.validated, dispatch.selected)
	}
}

func (h *servingTestHost) InspectServingFiles(_ hostadapter.ServingAuthority, removing bool) hostadapter.Observation {
	return hostadapter.Observation{Observed: true, Accepted: h.safe && (!h.missingFiles || removing)}
}
func (h *servingTestHost) AcquireServingExclusion() (*hostadapter.ServingExclusion, bool) {
	return &hostadapter.ServingExclusion{}, !h.exclusionBusy
}
func (h *servingTestHost) RemoveServingRuntime(context.Context, hostadapter.ServingAuthority, *hostadapter.ServingExclusion) bool {
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

func TestMissingServingFilesStillPermitCompleteRemoval(t *testing.T) {
	m, h, _ := servingInstallation(t)
	h.missingFiles = true
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("safely missing serving files blocked removal")
	}
	if m.Execute(t.Context(), *review.Prepared, Approved, nil).Code != CompleteRemovalCompleted {
		t.Fatal("missing-file removal failed")
	}
}

func TestServingExclusionFailureDoesNotCommitRemoval(t *testing.T) {
	m, h, _ := servingInstallation(t)
	before := string(h.ownership)
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("removal review failed")
	}
	h.exclusionBusy = true
	if m.Execute(t.Context(), *review.Prepared, Approved, nil).Code != ActionRefused || string(h.ownership) != before || h.removed {
		t.Fatal("failed exclusion changed authority or resources")
	}
}
