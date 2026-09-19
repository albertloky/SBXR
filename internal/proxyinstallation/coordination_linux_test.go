//go:build linux

package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const isolatedMarker = "/run/sbxr-isolated-test-host"
const startupBarrier = "/run/sbxr-test-start.sock"

// Only the test executable has these fixture roles. The product entry point,
// unit text, trust checks and runtime gate are unchanged. This test requires a
// disposable VM with no installation and an explicit root-owned marker.
func init() {
	if len(os.Args) != 2 || os.Args[0] != "/usr/local/bin/sbxr" {
		return
	}
	if body, err := os.ReadFile(isolatedMarker); err != nil || string(body) != "disposable SBXR test VM\n" {
		os.Exit(90)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	lifecycle := softwarelifecycle.NewInstalledWithUpdateRuntime(nil, AdmitSoftwareUpdate, SoftwareUpdateRuntime())
	switch os.Args[1] {
	case hostadapter.ProxyStartRole:
		if AuthorizeProxyStart(ctx, lifecycle) {
			os.Exit(0)
		}
		os.Exit(1)
	case hostadapter.ServingRole:
		code := serveSubscription(ctx, lifecycle, isolatedServingHost{hostadapter.New()}, subscriptionserving.New(nil, nil))
		if code == subscriptionserving.Refused {
			os.Exit(1)
		}
		os.Exit(0)
	case "--test-proxy-listener":
		listener, err := net.Listen("tcp4", "8.8.8.8:443")
		if err != nil {
			os.Exit(1)
		}
		<-ctx.Done()
		listener.Close()
		os.Exit(0)
	}
}

type isolatedServingHost struct{ hostadapter.Adapter }

func (h isolatedServingHost) ServingPublicIPv4(_ context.Context, ip string) bool {
	return ip == "8.8.8.8"
}
func (h isolatedServingHost) WatchServingPublicIPv4(ctx context.Context, _ string) <-chan bool {
	return nil
}
func (h isolatedServingHost) AcquireRuntimeStartLock(ctx context.Context, role string) (*hostadapter.MutationLock, bool, error) {
	lock, borrowed, err := h.Adapter.AcquireRuntimeStartLock(ctx, role)
	if err != nil {
		return lock, borrowed, err
	}
	// Deterministically hold the real serving-start lock until the test has
	// started the proxy ExecCondition. A missing barrier means ordinary start.
	connection, e := net.Dial("unix", startupBarrier)
	if e == nil {
		connection.SetDeadline(time.Now().Add(10 * time.Second))
		_, e = connection.Write([]byte{1})
		if e == nil {
			_, e = io.ReadFull(connection, make([]byte, 1))
		}
		connection.Close()
		if e != nil {
			lock.Release()
			return nil, false, e
		}
	}
	return lock, borrowed, nil
}

type isolatedCertificateHost struct {
	*repairTestHost
	fs            hostadapter.Adapter
	publishTarget func()
}

func (h *isolatedCertificateHost) PublishOwnership(name, next string, expected, body []byte) error {
	if err := h.fs.PublishOwnership(name, next, expected, body); err != nil {
		return err
	}
	return h.activationTestHost.PublishOwnership(name, next, expected, body)
}

func (h *isolatedCertificateHost) InspectCertificateServingState(a hostadapter.ServingAuthority, pending bool) (hostadapter.ServingAuthority, bool) {
	return h.fs.InspectCertificateServingState(a, pending)
}
func (h *isolatedCertificateHost) PublishCertificateServingState(r hostadapter.RenewalAuthority, a, b hostadapter.ServingAuthority) bool {
	return h.fs.PublishCertificateServingState(r, a, b)
}
func (h *isolatedCertificateHost) InspectServingFiles(a hostadapter.ServingAuthority, removing bool) hostadapter.Observation {
	return h.fs.InspectServingFiles(a, removing)
}
func (h *isolatedCertificateHost) ReadSubscriptionLink(a hostadapter.ServingAuthority, ip string) ([]byte, bool) {
	return h.fs.ReadSubscriptionLink(a, ip)
}
func (h *isolatedCertificateHost) AcquireServingExclusion() (*hostadapter.ServingExclusion, bool) {
	return h.fs.AcquireServingExclusion()
}
func (h *isolatedCertificateHost) RemoveServingRuntime(ctx context.Context, a hostadapter.ServingAuthority, exclusion *hostadapter.ServingExclusion) bool {
	return h.fs.RemoveServingRuntime(ctx, a, exclusion)
}
func (h *isolatedCertificateHost) ServingRuntimeAbsent(a hostadapter.ServingAuthority) bool {
	return h.fs.ServingRuntimeAbsent(a)
}
func (h *isolatedCertificateHost) RepairSubscriptionCertificate(context.Context, hostadapter.RenewalAuthority) hostadapter.CertificateRepairResult {
	h.repairs++
	h.publishTarget()
	return hostadapter.CertificateRepairResult{Replaced: true}
}

func requireIsolatedVM(t *testing.T) {
	t.Helper()
	if os.Getenv("SBXR_ISOLATED_SYSTEMD") != "1" {
		t.Skip("requires explicitly isolated root Linux/systemd VM")
	}
	body, err := os.ReadFile(isolatedMarker)
	if os.Geteuid() != 0 || err != nil || string(body) != "disposable SBXR test VM\n" {
		t.Fatal("isolated VM marker missing")
	}
}

func isolatedCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	body, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, body)
	}
	return string(body)
}

func isolatedWrite(t *testing.T, name string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func fixtureDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func isolatedFixture(t *testing.T) (*isolatedCertificateHost, *controlledRemovalLifecycle, []byte) {
	t.Helper()
	requireIsolatedVM(t)
	// Match the adapter's protected-parent prerequisite. Ubuntu cloud images
	// can ship /var/log group-writable; restore that unrelated mode afterward.
	logInfo, err := os.Stat("/var/log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod("/var/log", logInfo.Mode().Perm()); err != nil {
			t.Errorf("restore log parent: %v", err)
		}
	})
	if err := os.Chmod("/var/log", 0755); err != nil {
		t.Fatal(err)
	}
	paths := []string{"/var/lib/sbxr", "/etc/sing-box", "/usr/local/bin/sbxr", "/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt", hostadapter.ServingUnitPath, hostadapter.ServingUnitWantsPath, hostadapter.ProxyStartupDropInDirectory, "/etc/systemd/system/sing-box.service", "/etc/ssl/certs/sbxr-isolated.pem", "/run/lock/sbxr.lock"}
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("fixture would overwrite %s", path)
		}
	}
	addressCreated, groupCreated := false, false
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, unit := range []string{"sing-box.service", "sbxr-subscription.service"} {
			loaded, err := exec.CommandContext(ctx, "systemctl", "show", "--property=LoadState", "--value", unit).CombinedOutput()
			if err != nil {
				t.Errorf("fixture load state: %v %s", err, loaded)
			} else if strings.TrimSpace(string(loaded)) != "not-found" {
				if output, err := exec.CommandContext(ctx, "systemctl", "stop", unit).CombinedOutput(); err != nil {
					t.Errorf("fixture stop: %v %s", err, output)
				}
			}
			output, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit).CombinedOutput()
			if err != nil {
				t.Errorf("fixture inspect: %v %s", err, output)
				continue
			}
			if strings.TrimSpace(string(output)) == "failed" {
				if output, err := exec.CommandContext(ctx, "systemctl", "reset-failed", unit).CombinedOutput(); err != nil {
					t.Errorf("fixture reset: %v %s", err, output)
				}
			}
		}
		for _, path := range paths {
			if err := os.RemoveAll(path); err != nil {
				t.Errorf("fixture cleanup %s: %v", path, err)
			}
		}
		if output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Errorf("fixture reload: %v %s", err, output)
		}
		if addressCreated {
			if output, err := exec.CommandContext(ctx, "ip", "addr", "del", "8.8.8.8/32", "dev", "lo").CombinedOutput(); err != nil {
				t.Errorf("fixture address cleanup: %v %s", err, output)
			}
		}
		if groupCreated {
			// Complete removal can already have removed this fixture identity.
			_, err := exec.CommandContext(ctx, "getent", "group", "sing-box").Output()
			var exited *exec.ExitError
			if err == nil {
				if output, err := exec.CommandContext(ctx, "groupdel", "sing-box").CombinedOutput(); err != nil {
					t.Errorf("fixture group cleanup: %v %s", err, output)
				}
			} else if !errors.As(err, &exited) || exited.ExitCode() != 2 {
				t.Errorf("fixture group inspection: %v", err)
			}
		}
	})
	isolatedCommand(t, "ip", "addr", "add", "8.8.8.8/32", "dev", "lo")
	addressCreated = true
	isolatedCommand(t, "groupadd", "--system", "sing-box")
	groupCreated = true
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	identity, err := singboxadapter.New().PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := singboxadapter.New().EncodeServerConfiguration(identity, record.DestinationAddress, record.DestinationName)
	if err != nil {
		t.Fatal(err)
	}
	renewal.configuration = configuration
	record.ConfigurationSHA256 = fixtureDigest(configuration)
	record.Serving.CredentialSHA256 = fixtureDigest([]byte(strings.Repeat("A", 43)))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	isolatedWrite(t, "/etc/ssl/certs/sbxr-isolated.pem", caPEM, 0644)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	authorities := []hostadapter.ServingAuthority{*record.Serving, *record.Serving}
	for generation := 1; generation <= 2; generation++ {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(generation + 1)), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(record.PublicIPv4)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		bodies := [][]byte{leafPEM, caPEM, append(bytes.Clone(leafPEM), caPEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
		for i, name := range []string{"cert", "chain", "fullchain", "privkey"} {
			mode := os.FileMode(0644)
			if name == "privkey" {
				mode = 0600
			}
			isolatedWrite(t, fmt.Sprintf("/etc/letsencrypt/archive/sbxr-subscription/%s%d.pem", name, generation), bodies[i], mode)
			authorities[generation-1].CertificateSHA256[i] = fixtureDigest(bodies[i])
		}
		authorities[generation-1].CertificateGeneration = generation
	}
	record.Serving = &authorities[0]
	for _, dir := range []string{"/var/lib/sbxr", hostadapter.ServingStagingPath, "/etc/letsencrypt/archive/sbxr-subscription", "/etc/letsencrypt/live/sbxr-subscription"} {
		if os.MkdirAll(dir, 0700) != nil || os.Chmod(dir, 0700) != nil {
			t.Fatal("protected fixture directory")
		}
	}
	for _, dir := range []string{"/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt"} {
		isolatedWrite(t, dir+"/.certbot.lock", nil, 0600)
	}
	setLinks := func(generation int) {
		for _, name := range []string{"cert", "chain", "fullchain", "privkey"} {
			p := "/etc/letsencrypt/live/sbxr-subscription/" + name + ".pem"
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.Symlink(fmt.Sprintf("../../archive/sbxr-subscription/%s%d.pem", name, generation), p); err != nil {
				t.Fatal(err)
			}
		}
	}
	setLinks(1)
	state, _ := json.Marshal(struct {
		Schema  int                          `json:"schema"`
		Serving hostadapter.ServingAuthority `json:"serving"`
	}{1, *record.Serving})
	state = append(state, '\n')
	isolatedWrite(t, hostadapter.ServingStatePath, state, 0600)
	isolatedWrite(t, hostadapter.ServingTokenPath, []byte(strings.Repeat("A", 43)+"\n"), 0600)
	isolatedWrite(t, hostadapter.ServingUnitPath, []byte(hostadapter.ServingUnit), 0644)
	if err := os.Symlink("../sbxr-subscription.service", hostadapter.ServingUnitWantsPath); err != nil {
		t.Fatal(err)
	}
	startup := hostadapter.ProxyStartupAuthority{DirectoryCreated: true, DropInSHA256: fixtureDigest([]byte(hostadapter.ProxyStartupDropIn))}
	record.Startup = &startup
	isolatedWrite(t, hostadapter.ProxyStartupDropInPath, []byte(hostadapter.ProxyStartupDropIn), 0644)
	isolatedWrite(t, "/etc/systemd/system/sing-box.service", []byte("[Service]\nType=simple\nExecStart=/usr/local/bin/sbxr --test-proxy-listener\nKillMode=control-group\n"), 0644)
	isolatedWrite(t, "/etc/sing-box/config.json", configuration, 0640)
	isolatedCommand(t, "chown", "root:sing-box", "/etc/sing-box/config.json")
	updateSubscriptionResources(&record, record.Release)
	renewal.ownership = ownershipBytes(record)
	isolatedWrite(t, hostSetupSpec.OwnershipPath, renewal.ownership, 0600)
	isolatedWrite(t, "/run/lock/sbxr.lock", nil, 0600)
	payload, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	executable, err := softwarelifecycle.StampReleaseExecutable(payload, record.Release.Tag, record.Release.Commit, 17, softwarelifecycle.Architecture(runtime.GOARCH))
	if err != nil {
		t.Fatal(err)
	}
	isolatedWrite(t, "/usr/local/bin/sbxr", executable, 0755)
	installed, _ := json.Marshal(map[string]any{"schema": 1, "repository": softwarelifecycle.Repository, "tag": record.Release.Tag, "commit": record.Release.Commit, "release_index_sha256": record.Release.IndexSHA256, "sequence": 17, "architecture": runtime.GOARCH, "executable_sha256": fixtureDigest(executable)})
	isolatedWrite(t, "/var/lib/sbxr/installed.json", installed, 0600)
	isolatedCommand(t, "systemctl", "daemon-reload")
	h := &isolatedCertificateHost{repairTestHost: &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving}}, fs: hostadapter.New()}
	h.publishTarget = func() { setLinks(2); h.published = authorities[1] }
	return h, lifecycle, state
}

func TestCertificateAcceptanceAndRecoveryWithRealFilesystem(t *testing.T) {
	h, lifecycle, oldState := isolatedFixture(t)
	m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review := m.Review(t.Context(), ReplaceSubscriptionCertificateAction)
	if review.Prepared == nil {
		t.Fatalf("replacement review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionCertificateReplaced {
		t.Fatalf("replacement: %#v", result)
	}
	record, _ := decodeOwnership(h.ownership)
	if !h.fs.InspectServingFiles(*record.Serving, false).Accepted {
		t.Fatal("real files inconsistent after replacement")
	}
	// Reproduce the retained v3.1.75 state: current accepted/published/loaded
	// generation 2, no pending operation, and the original generation-1 file.
	isolatedWrite(t, hostadapter.ServingStatePath, oldState, 0600)
	m = newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Prepared == nil {
		t.Fatalf("recovery review: %#v", review.Result)
	}
	restarts, requests := h.restarts, h.repairs
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished {
		t.Fatalf("recovery: %#v", result)
	}
	if h.restarts != restarts || h.repairs != requests {
		t.Fatal("recovery repeated runtime/certificate effects")
	}
	if _, ok := h.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !ok {
		t.Fatal("real link read refused")
	}
	review = m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatalf("removal review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("removal: %#v", result)
	}
	if !h.fs.ServingRuntimeAbsent(*record.Serving) {
		t.Fatal("real serving files remain")
	}
}

// This is the state-only maintenance design for an old installed executable
// that cannot expose the repaired Finish action. Run it also with the original
// activation/repair source overlay: the unchanged original removal checks must
// accept the resulting files. It installs no replacement product executable.
func TestExistingMismatchMaintenancePreservesInstalledIdentityAndAllowsRemoval(t *testing.T) {
	h, lifecycle, _ := isolatedFixture(t)
	oldOwnership := bytes.Clone(h.ownership)
	record, _ := decodeOwnership(oldOwnership)
	source := *record.Serving
	h.publishTarget()
	h.loaded = h.published
	record.Serving = &h.published
	updateSubscriptionResources(&record, record.Release)
	h.ownership = ownershipBytes(record)
	if err := h.fs.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, oldOwnership, h.ownership); err != nil {
		t.Fatal(err)
	}
	unchanged := map[string][]byte{}
	for _, path := range []string{"/usr/local/bin/sbxr", "/var/lib/sbxr/installed.json", hostSetupSpec.OwnershipPath, "/etc/sing-box/config.json", hostadapter.ServingTokenPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		unchanged[path] = body
	}
	if h.fs.InspectServingFiles(*record.Serving, true).Accepted {
		t.Fatal("original mismatch not established")
	}
	lock, busy, err := h.fs.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		t.Fatal("maintenance exclusion")
	}
	defer lock.Release()
	installed := softwarelifecycle.NewInstalledWithUpdateRuntime(nil, AdmitSoftwareUpdate, SoftwareUpdateRuntime()).(mutationLifecycle).StatusUnderMutationLock(t.Context(), lock)
	if installed.State != softwarelifecycle.Ready || installed.Installed == nil || !compatibleOwnership(record, *installed.Installed) {
		t.Fatal("installed identity refused")
	}
	exclusion, ok := h.fs.AcquireServingExclusion()
	if !ok {
		t.Fatal("certificate writer exclusion")
	}
	defer exclusion.Release()
	if !h.fs.PublishCertificateServingState(*record.Renewal, source, *record.Serving) || !h.fs.PublishCertificateServingState(*record.Renewal, source, *record.Serving) {
		t.Fatal("idempotent state-only maintenance refused")
	}
	exclusion.Release()
	lock.Release()
	for path, before := range unchanged {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("maintenance changed %s", path)
		}
	}
	if h.repairs != 0 || h.restarts != 0 {
		t.Fatal("maintenance requested certificate or restart")
	}
	// Match the failed VPS's inactive proxy; cleanup must not require first
	// restarting either service or recovering proxy traffic.
	h.active = false
	m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil || review.Status != ProblemDetected {
		t.Fatalf("original removal review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("original removal: %#v", result)
	}
}

func TestOrdinaryStartsUnderIsolatedSystemd(t *testing.T) {
	h, _, _ := isolatedFixture(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: startupBarrier, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); os.Remove(startupBarrier) })
	if err := os.Chmod(startupBarrier, 0600); err != nil {
		t.Fatal(err)
	}
	listener.SetDeadline(time.Now().Add(10 * time.Second))
	isolatedCommand(t, "systemctl", "start", "sbxr-subscription.service")
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("serving did not acquire startup lock: ", err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(connection, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- exec.CommandContext(ctx, "systemctl", "start", "sing-box.service").Run() }()
	select {
	case err := <-proxyDone:
		t.Log(isolatedCommand(t, "systemctl", "show", "--property=Result", "--property=ActiveState", "--property=ConditionResult", "--property=ExecCondition", "sing-box.service"))
		t.Log(isolatedCommand(t, "journalctl", "-u", "sing-box.service", "-n", "5", "--no-pager"))
		t.Fatalf("proxy did not wait for ordinary serving start: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := connection.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if err := <-proxyDone; err != nil {
		t.Fatal(err)
	}
	assertReady := func() {
		for _, unit := range []string{"sing-box.service", "sbxr-subscription.service"} {
			if got := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ActiveState", "--value", unit)); got != "active" {
				t.Fatalf("%s state=%s", unit, got)
			}
		}
		if got := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=Result", "--value", "sing-box.service")); got != "success" {
			t.Fatalf("proxy result=%s", got)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}, Timeout: 3 * time.Second}
		defer client.CloseIdleConnections()
		// Type=simple start completion precedes listener binding. Use the same
		// 15-second readiness bound as production activation, retrying only the
		// not-yet-listening socket, never a certificate or HTTP failure.
		ready, done := context.WithTimeout(t.Context(), 15*time.Second)
		defer done()
		var response *http.Response
		for {
			request, err := http.NewRequestWithContext(ready, http.MethodGet, "https://8.8.8.8:8443/s/"+strings.Repeat("A", 43), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err = client.Do(request)
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("trusted fixture TLS failed: %T", err)
			}
			select {
			case <-ready.Done():
				t.Fatal("serving did not bind within the production readiness bound")
			case <-time.After(25 * time.Millisecond):
			}
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !strings.HasPrefix(string(body), "vless://") {
			t.Fatal("subscription response invalid")
		}
	}
	assertReady()
	// Exercise the ordering where an ordinary systemd job reaches its real
	// ExecCondition while an Owner mutation holds the lock, before the Owner's
	// authenticated handoff listener exists. A later start of the same unit
	// joins that job; the waiting gate must retry and borrow the Owner lock.
	isolatedCommand(t, "systemctl", "stop", "sing-box.service")
	lateLock, busy, err := h.fs.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		t.Fatal("late-handoff owner exclusion")
	}
	lateCtx, lateCancel := context.WithTimeout(t.Context(), 10*time.Second)
	lateDone := make(chan error, 1)
	lateJoined := false
	t.Cleanup(func() {
		lateCancel()
		if lateLock != nil {
			lateLock.Release()
		}
		if !lateJoined {
			select {
			case <-lateDone:
			case <-time.After(20 * time.Second):
				t.Error("late-handoff systemctl did not exit during cleanup")
			}
		}
	})
	go func() { lateDone <- exec.CommandContext(lateCtx, "systemctl", "start", "sing-box.service").Run() }()
	waitingUntil := time.Now().Add(2 * time.Second)
	for {
		controlPID := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ControlPID", "--value", "sing-box.service"))
		pid, parseErr := strconv.Atoi(controlPID)
		if parseErr == nil && pid > 0 {
			break
		}
		select {
		case startErr := <-lateDone:
			lateJoined = true
			t.Fatalf("ordinary start did not wait for Owner authority: %v", startErr)
		default:
		}
		if time.Now().After(waitingUntil) {
			t.Fatal("ordinary ExecCondition did not reach its waiting boundary")
		}
		time.Sleep(25 * time.Millisecond)
	}
	select {
	case startErr := <-lateDone:
		lateJoined = true
		t.Fatalf("ordinary start left its waiting boundary before Owner handoff: %v", startErr)
	case <-time.After(100 * time.Millisecond):
	}
	if !h.fs.WithRuntimeStart(lateCtx, lateLock, hostadapter.ProxyStartRole, func() bool {
		return exec.CommandContext(lateCtx, "systemctl", "start", "sing-box.service").Run() == nil
	}) {
		t.Fatal("late Owner handoff did not complete the waiting systemd job")
	}
	if !lateLock.Holds(hostSetupSpec.LockPath) {
		t.Fatal("late handoff released Owner exclusion")
	}
	if got := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ActiveState", "--value", "sing-box.service")); got != "active" {
		t.Fatalf("late-handoff service state=%s", got)
	}
	if startErr := <-lateDone; startErr != nil {
		lateJoined = true
		t.Fatalf("original waiting systemd start failed: %v", startErr)
	}
	lateJoined = true
	lateLock.Release()
	lateLock = nil
	lateCancel()
	for i := 0; i < 3; i++ {
		isolatedCommand(t, "systemctl", "restart", "sing-box.service", "sbxr-subscription.service")
		assertReady()
	}
	// Real mutation exclusion: cancellation refuses the same gate, then the
	// unchanged installation starts again after release.
	lock, busy, err := h.fs.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		t.Fatal("owner exclusion")
	}
	blocked, stop := context.WithTimeout(t.Context(), 150*time.Millisecond)
	if AuthorizeProxyStart(blocked, softwarelifecycle.NewInstalledWithUpdateRuntime(nil, AdmitSoftwareUpdate, SoftwareUpdateRuntime())) {
		lock.Release()
		stop()
		t.Fatal("mutation lock bypassed")
	}
	stop()
	lock.Release()
	if !AuthorizeProxyStart(t.Context(), softwarelifecycle.NewInstalledWithUpdateRuntime(nil, AdmitSoftwareUpdate, SoftwareUpdateRuntime())) {
		t.Fatal("unchanged gate refused after exclusion")
	}
	t.Log("real systemd ExecCondition and serving sandbox: forced ordinary overlap, late Owner handoff, and 3 simultaneous restarts; both services active, trusted local TLS available; mutation overlap refused")
}
