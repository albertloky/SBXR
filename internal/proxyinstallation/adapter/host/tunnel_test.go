package host

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func tunnelFixture(t *testing.T) Adapter {
	t.Helper()
	a := lockProvisionFixture(t)
	for _, dir := range []string{"etc/cloudflared", "usr/bin"} {
		if err := os.MkdirAll(a.path("/"+dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	token := base64.StdEncoding.EncodeToString([]byte(`{"a":"account","t":"12345678-1234-4234-8234-123456789abc","s":"secret"}`))
	if err := os.WriteFile(a.path(TunnelTokenPath), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.path(TunnelBinaryPath), []byte("#!/bin/sh\necho cloudflared version 2026.10.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.tunnelCommand = func(_ context.Context, name string, args ...string) (string, int, bool) {
		if name == a.path(TunnelBinaryPath) {
			return "cloudflared version 2026.10.0", 0, true
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "show" {
			return tunnelSystemdProperty(args[1]), 0, true
		}
		return "", 0, true
	}
	return a
}

func tunnelSystemdProperty(property string) string {
	switch property {
	case "--property=LoadState":
		return "loaded"
	case "--property=FragmentPath":
		return TunnelUnitPath
	case "--property=MainPID", "--property=ControlPID":
		return "0"
	case "--property=ActiveState":
		return "inactive"
	case "--property=ExecStart":
		return "{ path=/usr/bin/cloudflared ; argv[]=" + tunnelExec + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	}
	return ""
}

func TestTunnelPrerequisitesAndDedicatedLifecycle(t *testing.T) {
	a := tunnelFixture(t)
	authority, problem := a.PreflightTunnel(t.Context())
	if problem != "" || !authority.Valid() {
		t.Fatal("prerequisite refused", problem)
	}
	if !a.InstallTunnel(t.Context(), authority) || !a.StartTunnel(t.Context(), authority) {
		t.Fatal("dedicated connector did not start")
	}
	unit, _ := os.ReadFile(a.path(TunnelUnitPath))
	if strings.Contains(string(unit), "secret") || !strings.Contains(string(unit), "--token-file") || strings.Contains(string(unit), "--token ") {
		t.Fatal("unsafe unit credential handling")
	}
	if !a.RemoveTunnel(t.Context(), authority) || !a.RemoveTunnel(t.Context(), authority) {
		t.Fatal("idempotent connector cleanup failed")
	}
	if _, err := os.Stat(a.path(TunnelTokenPath)); err != nil {
		t.Fatal("owner token was removed")
	}
	if _, err := os.Stat(a.path(TunnelBinaryPath)); err != nil {
		t.Fatal("owner binary was removed")
	}
}

func TestTunnelRefusesCredentialAndServiceDrift(t *testing.T) {
	for _, change := range []string{"token-mode", "token-symlink", "token-content", "binary", "drop-in", "foreign-unit", "foreign-link"} {
		t.Run(change, func(t *testing.T) {
			a := tunnelFixture(t)
			authority, problem := a.PreflightTunnel(t.Context())
			if problem != "" {
				t.Fatal(problem)
			}
			switch change {
			case "token-mode":
				os.Chmod(a.path(TunnelTokenPath), 0o644)
			case "token-symlink":
				os.Rename(a.path(TunnelTokenPath), a.path(TunnelTokenPath+".old"))
				os.Symlink(TunnelTokenPath+".old", a.path(TunnelTokenPath))
			case "token-content":
				os.WriteFile(a.path(TunnelTokenPath), []byte("other-secret"), 0o600)
			case "binary":
				os.WriteFile(a.path(TunnelBinaryPath), []byte("changed"), 0o755)
			case "drop-in":
				os.Mkdir(a.path(TunnelUnitPath+".d"), 0o755)
			case "foreign-unit":
				os.WriteFile(a.path(TunnelUnitPath), []byte("foreign"), 0o644)
			case "foreign-link":
				os.Symlink("../foreign.service", a.path(TunnelWantsPath))
			}
			if a.InstallTunnel(t.Context(), authority) || a.StartTunnel(t.Context(), authority) {
				t.Fatal("drift started connector")
			}
			if change == "drop-in" || change == "foreign-unit" || change == "foreign-link" {
				if a.RemoveTunnel(t.Context(), authority) {
					t.Fatal("unproved service was removed")
				}
			}
		})
	}
}

func TestTunnelRemovalDoesNotNeedCredentialsOrBinary(t *testing.T) {
	a := tunnelFixture(t)
	authority, _ := a.PreflightTunnel(t.Context())
	if !a.InstallTunnel(t.Context(), authority) {
		t.Fatal("install")
	}
	os.Remove(a.path(TunnelTokenPath))
	os.Remove(a.path(TunnelBinaryPath))
	if !a.RemoveTunnel(t.Context(), authority) {
		t.Fatal("cleanup depended on external prerequisites")
	}
	if _, err := os.Lstat(a.path(TunnelUnitPath)); !os.IsNotExist(err) {
		t.Fatal("unit remains")
	}
}

func TestTunnelSupportsUbuntuMergedUsrAndInterruptedPublication(t *testing.T) {
	for _, finish := range []string{"install", "remove"} {
		t.Run(finish, func(t *testing.T) {
			a := tunnelFixture(t)
			if err := os.Symlink("usr/lib", a.path("/lib")); err != nil {
				t.Fatal(err)
			}
			authority, problem := a.PreflightTunnel(t.Context())
			if problem != "" {
				t.Fatal("merged usr refused", problem)
			}
			if err := os.WriteFile(a.path(TunnelUnitPath+".sbxr-next"), []byte(tunnelUnit), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(a.path(TunnelUnitPath+".sbxr-next"), a.path(TunnelUnitPath)); err != nil {
				t.Fatal(err)
			}
			if finish == "install" {
				if !a.InstallTunnel(t.Context(), authority) {
					t.Fatal("two-link publication could not finish")
				}
			}
			if !a.RemoveTunnel(t.Context(), authority) {
				t.Fatal("two-link publication could not clean up")
			}
		})
	}
}

func TestTunnelRemovalAcceptsSafelyAbsentSharedParent(t *testing.T) {
	a := tunnelFixture(t)
	authority, problem := a.PreflightTunnel(t.Context())
	if problem != "" {
		t.Fatal(problem)
	}
	if err := os.Remove(a.path("/etc/systemd/system/multi-user.target.wants")); err != nil {
		t.Fatal(err)
	}
	if !a.TunnelRemovalSafe(t.Context(), authority) || !a.RemoveTunnel(t.Context(), authority) {
		t.Fatal("absent shared parent blocked safe removal")
	}
	if a.InstallTunnel(t.Context(), authority) {
		t.Fatal("installation accepted missing shared parent")
	}
}
