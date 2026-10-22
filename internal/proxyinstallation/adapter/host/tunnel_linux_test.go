//go:build linux

package host

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This exercises real systemd credential loading without a Cloudflare account
// or network connection. Never opt in on an ordinary host.
func TestDedicatedTunnelUnderIsolatedSystemd(t *testing.T) {
	if os.Getenv("SBXR_ISOLATED_SYSTEMD") != "1" {
		t.Skip("requires a marked disposable systemd VM")
	}
	marker, err := os.ReadFile("/run/sbxr-isolated-test-host")
	if err != nil || string(marker) != "disposable SBXR test VM\n" || os.Geteuid() != 0 {
		t.Fatal("isolated systemd authority missing")
	}
	for _, path := range []string{TunnelBinaryPath, TunnelTokenPath, TunnelUnitPath, TunnelUnitPath + ".sbxr-next", TunnelWantsPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refuse occupied test resource %s: %v", path, err)
		}
	}
	createdDir := false
	if _, err := os.Lstat(filepath.Dir(TunnelTokenPath)); os.IsNotExist(err) {
		if err := os.Mkdir(filepath.Dir(TunnelTokenPath), 0o700); err != nil {
			t.Fatal(err)
		}
		createdDir = true
	}
	token := base64.StdEncoding.EncodeToString([]byte(`{"a":"test-account","t":"12345678-1234-4234-8234-123456789abc","s":"test-secret"}`))
	stub := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'cloudflared version 2026.10.0'; exit 0; fi\nfor last; do :; done\ntest \"$last\" = /run/credentials/sbxr-tunnel.service/tunnel-token || exit 20\ntest \"$(cat \"$last\")\" = '" + token + "' || exit 21\nexec /usr/bin/sleep infinity\n"
	if err := os.WriteFile(TunnelBinaryPath, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TunnelTokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	authority, problem := a.PreflightTunnel(t.Context())
	if problem != "" {
		t.Fatal(problem)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if !a.RemoveTunnel(ctx, authority) {
			t.Error("dedicated unit cleanup failed; dispose this test VM")
		}
		os.Remove(TunnelTokenPath)
		os.Remove(TunnelBinaryPath)
		if createdDir {
			os.Remove(filepath.Dir(TunnelTokenPath))
		}
	})
	if !a.InstallTunnel(t.Context(), authority) {
		t.Fatal("real systemd installation refused")
	}
	if !a.StartTunnel(t.Context(), authority) {
		t.Fatal("real systemd credential loading/start refused")
	}
	if !a.TunnelRemovalSafe(t.Context(), authority) {
		t.Fatal("real effective unit was not recognized")
	}
	if !a.RemoveTunnel(t.Context(), authority) {
		t.Fatal("real systemd connector cleanup failed")
	}
	if _, err := os.Stat(TunnelTokenPath); err != nil {
		t.Fatal("Owner token was removed")
	}
}
