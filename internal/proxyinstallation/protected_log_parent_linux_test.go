//go:build linux

package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

const (
	protectedLogParentProbeEnvironment = "SBXR_PROTECTED_LOG_PARENT_PROBE"
	protectedLogParentLocksEnvironment = "SBXR_PROTECTED_LOG_PARENT_LOCKS"
	qualifiedLogParentWrapperSHA256    = "4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb"
	qualifiedLogParentSupervisorSHA256 = "9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc"
)

var protectedLogParentCertbotLocks = []string{
	"/etc/letsencrypt/.certbot.lock",
	"/var/lib/letsencrypt/.certbot.lock",
	"/var/log/letsencrypt/.certbot.lock",
}

type protectedLogParentIdentity struct {
	Device uint64      `json:"device"`
	Inode  uint64      `json:"inode"`
	UID    uint32      `json:"uid"`
	GID    uint32      `json:"gid"`
	Links  uint64      `json:"links"`
	Mode   os.FileMode `json:"mode"`
}

type protectedLogParentFileSnapshot struct {
	identity protectedLogParentIdentity
	digest   [sha256.Size]byte
}

func protectedLogParentIdentityOf(name string) (protectedLogParentIdentity, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return protectedLogParentIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return protectedLogParentIdentity{}, fmt.Errorf("%s has no Linux stat identity", name)
	}
	return protectedLogParentIdentity{
		Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid,
		Links: uint64(stat.Nlink), Mode: info.Mode(),
	}, nil
}

func protectedLogParentLockIdentities() (map[string]protectedLogParentIdentity, error) {
	identities := make(map[string]protectedLogParentIdentity, len(protectedLogParentCertbotLocks))
	for _, name := range protectedLogParentCertbotLocks {
		identity, err := protectedLogParentIdentityOf(name)
		if err != nil {
			return nil, err
		}
		identities[name] = identity
	}
	return identities, nil
}

func protectedLogParentAssertIdentities(t *testing.T, want map[string]protectedLogParentIdentity) {
	t.Helper()
	got, err := protectedLogParentLockIdentities()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range protectedLogParentCertbotLocks {
		if got[name] != want[name] {
			t.Fatalf("shared Certbot lock identity changed for %s: got %#v want %#v", name, got[name], want[name])
		}
	}
}

func protectedLogParentSnapshot(name string) (protectedLogParentFileSnapshot, error) {
	body, err := os.ReadFile(name)
	if err != nil {
		return protectedLogParentFileSnapshot{}, err
	}
	identity, err := protectedLogParentIdentityOf(name)
	if err != nil {
		return protectedLogParentFileSnapshot{}, err
	}
	return protectedLogParentFileSnapshot{identity: identity, digest: sha256.Sum256(body)}, nil
}

func protectedLogParentProbeEnvironmentWith(role string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, protectedLogParentProbeEnvironment+"=") {
			environment = append(environment, value)
		}
	}
	return append(environment, protectedLogParentProbeEnvironment+"="+role)
}

func TestProtectedLogParentWindowProbe(t *testing.T) {
	role := os.Getenv(protectedLogParentProbeEnvironment)
	if role == "" {
		t.Skip("private protected log-parent subprocess role")
	}
	requireIsolatedVM(t)
	host := hostadapter.New()
	if role == "contention" {
		if exclusion, ok := host.AcquireServingExclusion(); ok {
			exclusion.Release()
			t.Fatal("real Certbot lock contention was admitted")
		}
		return
	}
	if role != "window" {
		t.Fatalf("unknown protected log-parent probe role %q", role)
	}
	logParent, err := protectedLogParentIdentityOf("/var/log")
	if err != nil || !logParent.Mode.IsDir() || logParent.Mode.Perm() != 0755 {
		t.Fatalf("wrapper did not establish the protected log-parent mode: identity=%#v err=%v", logParent, err)
	}
	var lockIdentities map[string]protectedLogParentIdentity
	if err := json.Unmarshal([]byte(os.Getenv(protectedLogParentLocksEnvironment)), &lockIdentities); err != nil || len(lockIdentities) != len(protectedLogParentCertbotLocks) {
		t.Fatalf("invalid parent lock identities: %v", err)
	}
	protectedLogParentAssertIdentities(t, lockIdentities)
	exclusion, ok := host.AcquireServingExclusion()
	if !ok {
		t.Fatal("real serving exclusion refused inside the protected window")
	}
	released := false
	t.Cleanup(func() {
		if !released {
			exclusion.Release()
		}
	})
	contender := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProtectedLogParentWindowProbe$")
	contender.Env = protectedLogParentProbeEnvironmentWith("contention")
	if output, err := contender.CombinedOutput(); err != nil {
		t.Fatalf("real Certbot lock contention probe failed: %v\n%s", err, output)
	}
	exclusion.Release()
	released = true
	protectedLogParentAssertIdentities(t, lockIdentities)
	isolatedCommand(t, "systemctl", "start", "sbxr-subscription.service")
	isolatedCommand(t, "systemctl", "start", "sing-box.service")
}

func protectedLogParentRequireQualifiedWrapper(t *testing.T) (string, string) {
	t.Helper()
	directory := os.Getenv("SBXR_LOG_PARENT_WRAPPER_DIR")
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("SBXR_LOG_PARENT_WRAPPER_DIR must identify the absolute qualified wrapper directory")
	}
	directoryIdentity, err := protectedLogParentIdentityOf(directory)
	if err != nil || !directoryIdentity.Mode.IsDir() || directoryIdentity.UID != 0 || directoryIdentity.GID != 0 || directoryIdentity.Mode.Perm() != 0700 {
		t.Fatalf("qualified wrapper directory is not root:root 0700: identity=%#v err=%v", directoryIdentity, err)
	}
	files := []struct {
		name   string
		mode   os.FileMode
		digest string
	}{
		{"with-protected-log-parent.sh", 0700, qualifiedLogParentWrapperSHA256},
		{"protected_command_supervisor.py", 0600, qualifiedLogParentSupervisorSHA256},
	}
	for _, file := range files {
		name := filepath.Join(directory, file.name)
		identity, err := protectedLogParentIdentityOf(name)
		if err != nil || !identity.Mode.IsRegular() || identity.UID != 0 || identity.GID != 0 || identity.Links != 1 || identity.Mode.Perm() != file.mode {
			t.Fatalf("qualified %s has unsafe identity: identity=%#v err=%v", file.name, identity, err)
		}
		body, err := os.ReadFile(name)
		sum := sha256.Sum256(body)
		if err != nil || hex.EncodeToString(sum[:]) != file.digest {
			t.Fatalf("qualified %s bytes differ: %v", file.name, err)
		}
	}
	return filepath.Join(directory, "with-protected-log-parent.sh"), filepath.Join(directory, "protected-log-parent-integration.state")
}

func protectedLogParentAssertStateAbsent(t *testing.T, state string) {
	t.Helper()
	for _, name := range []string{state, state + ".control", state + ".result"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("protected window retained %s: %v", name, err)
		}
	}
}

func protectedLogParentWrapperCommand(ctx context.Context, wrapper string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, wrapper, arguments...)
	// The qualified wrapper restores /var/log on managed termination. Give it
	// the same bounded termination path when the parent test is cancelled.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 20 * time.Second
	return command
}

func protectedLogParentRequest(t *testing.T, token string, readiness bool) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://8.8.8.8:8443/s/"+token, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			return response.StatusCode, body
		}
		if !readiness || !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("trusted fixture TLS request failed: %T %v", err, err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("serving did not bind within the production readiness bound")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestProtectedLogParentPerMenuWindowIntegration(t *testing.T) {
	host, _, _ := isolatedFixture(t)
	wrapper, state := protectedLogParentRequireQualifiedWrapper(t)
	protectedLogParentAssertStateAbsent(t, state)
	t.Cleanup(func() {
		if _, err := os.Lstat(state); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if output, restoreErr := exec.CommandContext(ctx, wrapper, "restore", state).CombinedOutput(); restoreErr != nil {
				t.Errorf("protected window cleanup restore: %v %s", restoreErr, output)
			}
		}
	})
	if err := os.Chmod("/var/log", 0775); err != nil {
		t.Fatal(err)
	}
	originalLogParent, err := protectedLogParentIdentityOf("/var/log")
	if err != nil || originalLogParent.Mode.Perm() != 0775 {
		t.Fatalf("original log-parent fixture: identity=%#v err=%v", originalLogParent, err)
	}
	lockIdentities, err := protectedLogParentLockIdentities()
	if err != nil {
		t.Fatal(err)
	}
	if exclusion, ok := host.fs.AcquireServingExclusion(); ok {
		exclusion.Release()
		t.Fatal("real serving exclusion admitted the unsafe group-writable /var/log ancestor")
	}
	protectedLogParentAssertIdentities(t, lockIdentities)

	preservedPaths := []string{
		"/usr/local/bin/sbxr",
		"/var/lib/sbxr/installed.json",
		hostSetupSpec.OwnershipPath,
		"/etc/sing-box/config.json",
		hostadapter.ServingTokenPath,
		hostadapter.ServingStatePath,
		"/etc/letsencrypt/archive/sbxr-subscription/cert1.pem",
		"/etc/letsencrypt/archive/sbxr-subscription/chain1.pem",
		"/etc/letsencrypt/archive/sbxr-subscription/fullchain1.pem",
		"/etc/letsencrypt/archive/sbxr-subscription/privkey1.pem",
	}
	preserved := make(map[string]protectedLogParentFileSnapshot, len(preservedPaths))
	for _, name := range preservedPaths {
		snapshot, err := protectedLogParentSnapshot(name)
		if err != nil {
			t.Fatal(err)
		}
		preserved[name] = snapshot
	}
	encodedLocks, err := json.Marshal(lockIdentities)
	if err != nil {
		t.Fatal(err)
	}
	command := protectedLogParentWrapperCommand(t.Context(), wrapper, "run", state, "--", os.Args[0], "-test.run=^TestProtectedLogParentWindowProbe$")
	command.Env = append(protectedLogParentProbeEnvironmentWith("window"), protectedLogParentLocksEnvironment+"="+string(encodedLocks))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("protected systemd window failed: %v\n%s", err, output)
	}
	protectedLogParentAssertStateAbsent(t, state)
	restoredLogParent, err := protectedLogParentIdentityOf("/var/log")
	if err != nil || restoredLogParent != originalLogParent {
		t.Fatalf("protected systemd window changed /var/log: got %#v want %#v err=%v", restoredLogParent, originalLogParent, err)
	}
	protectedLogParentAssertIdentities(t, lockIdentities)
	for _, unit := range []string{"sbxr-subscription.service", "sing-box.service"} {
		if active := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ActiveState", "--value", unit)); active != "active" {
			t.Fatalf("%s state after protected start=%s", unit, active)
		}
	}
	if status, body := protectedLogParentRequest(t, strings.Repeat("A", 43), true); status != http.StatusOK || !bytes.HasPrefix(body, []byte("vless://")) {
		t.Fatalf("correct subscription token outside window: status=%d body-prefix=%q", status, body[:min(len(body), 16)])
	}
	if status, _ := protectedLogParentRequest(t, strings.Repeat("B", 43), false); status != http.StatusNotFound {
		t.Fatalf("wrong subscription token outside window: status=%d", status)
	}

	isolatedCommand(t, "systemctl", "restart", "sing-box.service", "sbxr-subscription.service")
	if status, body := protectedLogParentRequest(t, strings.Repeat("A", 43), true); status != http.StatusOK || !bytes.HasPrefix(body, []byte("vless://")) {
		t.Fatalf("subscription after ordinary restart: status=%d body-prefix=%q", status, body[:min(len(body), 16)])
	}
	for _, unit := range []string{"sbxr-subscription.service", "sing-box.service"} {
		if active := strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ActiveState", "--value", unit)); active != "active" {
			t.Fatalf("%s state after ordinary restart=%s", unit, active)
		}
	}
	if after, err := protectedLogParentIdentityOf("/var/log"); err != nil || after != originalLogParent {
		t.Fatalf("ordinary restart changed /var/log: got %#v want %#v err=%v", after, originalLogParent, err)
	}
	protectedLogParentAssertIdentities(t, lockIdentities)
	for _, name := range preservedPaths {
		after, err := protectedLogParentSnapshot(name)
		if err != nil || after != preserved[name] {
			t.Fatalf("ordinary starts changed %s: got %#v want %#v err=%v", name, after, preserved[name], err)
		}
	}

	failure := protectedLogParentWrapperCommand(t.Context(), wrapper, "run", state, "--", "/bin/sh", "-c", "exit 37")
	output, failureErr := failure.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(failureErr, &exitError) || exitError.ExitCode() != 37 {
		t.Fatalf("representative protected command did not preserve exit 37: %v %s", failureErr, output)
	}
	protectedLogParentAssertStateAbsent(t, state)
	if after, err := protectedLogParentIdentityOf("/var/log"); err != nil || after != originalLogParent {
		t.Fatalf("failed protected command changed /var/log: got %#v want %#v err=%v", after, originalLogParent, err)
	}
	protectedLogParentAssertIdentities(t, lockIdentities)
	t.Log("qualified wrapper opened one bounded host window; real exclusion, contention, production-role starts, restored-mode HTTPS and ordinary restarts passed; this child probe is not packaged menu or public-CA acceptance")
}
