package cloudflaretunnel

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudflaredServiceUsesProtectedTokenFileAndNonRootIdentity(t *testing.T) {
	unit := CloudflaredServiceUnit()
	if !ValidateCloudflaredServiceUnit(unit) || strings.Contains(unit, "TOKEN=") || strings.Contains(unit, "PLAN-SECRET-MARKER") {
		t.Fatalf("unsafe cloudflared unit:\n%s", unit)
	}
	if ValidateCloudflaredServiceUnit(strings.Replace(unit, "User=cloudflared", "User=root", 1)) {
		t.Fatal("root cloudflared service accepted")
	}
}

func TestLocalOriginObserverReturnsRealReachability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if reachable, err := (localOriginObserver{}).Reachable(context.Background(), address); err != nil || !reachable {
		t.Fatalf("listening origin = %t, %v", reachable, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if reachable, err := (localOriginObserver{}).Reachable(context.Background(), address); err != nil || reachable {
		t.Fatalf("stopped origin = %t, %v", reachable, err)
	}
}

func TestInstalledCloudflaredServiceRequiresExactProtectedLayout(t *testing.T) {
	root := t.TempDir()
	for name, mode := range map[string]os.FileMode{"etc/sbxr": 0o700, "etc/sbxr/cloudflared": 0o750, "etc/systemd/system": 0o755} {
		if err := os.MkdirAll(filepath.Join(root, name), mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/token"), []byte("SERVICE-TOKEN-MARKER"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"), []byte("ingress: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(root, "etc/systemd/system/cloudflared.service")
	if err := os.WriteFile(unit, []byte(CloudflaredServiceUnit()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstalledService(root, os.Geteuid(), os.Getegid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr/cloudflared/token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstalledService(root, os.Geteuid(), os.Getegid(), os.Getegid()); err == nil {
		t.Fatal("wider token mode accepted")
	}
}
