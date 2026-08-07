package cloudflaretunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLocalOriginObserverRequiresHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	if reachable, err := (localOriginObserver{}).Reachable(context.Background(), address); err != nil || !reachable {
		t.Fatalf("HTTP origin = %t, %v", reachable, err)
	}

	listener := newJunkTCPServer(t)
	defer listener.Close()
	if reachable, err := (localOriginObserver{}).Reachable(context.Background(), listener.Addr().String()); err != nil || reachable {
		t.Fatalf("non-HTTP listener = %t, %v", reachable, err)
	}
}

func TestExecutorInstallsAndRollsBackProtectedCloudflaredService(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"etc", "etc/systemd", "etc/systemd/system"} {
		mode := os.FileMode(0o755)
		if err := os.MkdirAll(filepath.Join(root, name), mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
			t.Fatal(err)
		}
	}
	var commands []string
	serviceGID := testServiceGID(t)
	executor := Executor{
		serviceIdentity: func() (int, int, int, error) { return os.Geteuid(), os.Getegid(), serviceGID, nil },
		command: func(_ context.Context, name string, arguments ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(arguments, " "))
			if len(arguments) == 1 && arguments[0] == "--version" {
				return []byte("cloudflared version 2026.7.3 (built 2026-08-01)"), nil
			}
			return nil, nil
		},
	}
	material := `{"tunnel_id":"11111111-1111-4111-8111-111111111111","tunnel_run_token":"RUN-TOKEN-MARKER","routes":[{"hostname":"xhttp.example.com","origin":"http://127.0.0.1:11080"},{"hostname":"ws.example.com","origin":"http://127.0.0.1:11081"}]}`
	var rollback []byte
	if err := executor.CaptureServiceRollback(root, func(source io.Reader) error {
		var err error
		rollback, err = io.ReadAll(source)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if evidence, err := executor.ActivateService(root, strings.NewReader(material), time.Minute); err != nil || evidence.Code != "cloudflared-service-activated" {
		t.Fatalf("ActivateService() = %+v, %v", evidence, err)
	}
	if err := ValidateInstalledService(root, os.Geteuid(), os.Getegid(), serviceGID); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(root, "etc/sbxr/cloudflared/token"))
	if err != nil || string(token) != "RUN-TOKEN-MARKER\n" {
		t.Fatalf("token file = %q, %v", token, err)
	}
	config, err := os.ReadFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"))
	if err != nil || !strings.Contains(string(config), xhttpOrigin) || !strings.Contains(string(config), webSocketOrigin) || !strings.Contains(string(config), "http_status:404") || strings.Contains(string(config), "https://") {
		t.Fatalf("config = %q, %v", config, err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "RUN-TOKEN-MARKER") {
		t.Fatalf("command leaked token: %v", commands)
	}
	if len(commands) != 4 || commands[0] != "/usr/bin/cloudflared --version" || !strings.Contains(commands[1], "/usr/bin/cloudflared --config ") || !strings.HasSuffix(commands[1], " tunnel ingress validate") || commands[2] != "/usr/bin/systemctl daemon-reload" || commands[3] != "/usr/bin/systemctl enable --now cloudflared.service" {
		t.Fatalf("activation commands = %v", commands)
	}
	if evidence, err := executor.ReverseService(root, strings.NewReader(string(rollback)), time.Minute); err != nil || evidence.Code != "cloudflared-service-removed" {
		t.Fatalf("ReverseService() = %+v, %v", evidence, err)
	}
	for _, name := range []string{"etc/sbxr/cloudflared/token", "etc/sbxr/cloudflared/config.yml", "etc/systemd/system/cloudflared.service"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("rollback retained %s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/sbxr")); !os.IsNotExist(err) {
		t.Fatalf("rollback did not restore absent /etc/sbxr: %v", err)
	}
}

func TestInspectServiceFindsDirectoriesCreatedBeforeFirstFile(t *testing.T) {
	for _, directory := range []string{"etc/sbxr", "etc/sbxr/cloudflared"} {
		t.Run(directory, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755); err != nil {
				t.Fatal(err)
			}
			executor := Executor{serviceIdentity: func() (int, int, int, error) { return os.Geteuid(), os.Getegid(), testServiceGID(t), nil }}
			var rollback []byte
			if err := executor.CaptureServiceRollback(root, func(source io.Reader) error {
				var err error
				rollback, err = io.ReadAll(source)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
				t.Fatal(err)
			}
			effect, err := executor.InspectService(root, strings.NewReader(string(rollback)))
			if err != nil || effect != "Present" {
				t.Fatalf("InspectService() = %q, %v", effect, err)
			}
		})
	}
}

func TestWriteServiceFileNeverReplacesExistingTarget(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("token", []byte("UNOWNED"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeServiceFile(root, "token", []byte("SBXR"), 0o600, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("existing target was accepted")
	}
	content, err := root.ReadFile("token")
	if err != nil || string(content) != "UNOWNED" {
		t.Fatalf("existing target = %q, %v", content, err)
	}
}

func TestQualifiedCloudflaredRequiresExactOutputPrefix(t *testing.T) {
	for output, want := range map[string]bool{
		"cloudflared version 2026.7.3 (built 2026-08-01)": true,
		"untrusted binary version 2026.7.3":               false,
		"prefix cloudflared version 2026.7.3":             false,
		"cloudflared version 2026.7.30":                   false,
	} {
		if got := qualifiedCloudflared([]byte(output)); got != want {
			t.Fatalf("qualifiedCloudflared(%q) = %t, want %t", output, got, want)
		}
	}
}

func newJunkTCPServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			_, _ = fmt.Fprint(connection, "not http")
			_ = connection.Close()
		}
	}()
	return listener
}

func TestInstalledCloudflaredServiceRequiresExactProtectedLayout(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []struct {
		name string
		mode os.FileMode
	}{{"etc", 0o755}, {"etc/sbxr", 0o755}, {"etc/sbxr/cloudflared", 0o750}, {"etc/systemd", 0o755}, {"etc/systemd/system", 0o755}} {
		name, mode := directory.name, directory.mode
		if err := os.MkdirAll(filepath.Join(root, name), mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
			t.Fatal(err)
		}
	}
	serviceGID := testServiceGID(t)
	if err := os.Chown(filepath.Join(root, "etc/sbxr/cloudflared"), os.Geteuid(), serviceGID); err != nil {
		t.Fatal(err)
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
	for _, name := range []string{"etc/sbxr/cloudflared/token", "etc/sbxr/cloudflared/config.yml"} {
		if err := os.Chown(filepath.Join(root, name), os.Geteuid(), serviceGID); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateInstalledService(root, os.Geteuid(), os.Getegid(), serviceGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr/cloudflared/token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstalledService(root, os.Geteuid(), os.Getegid(), serviceGID); err == nil {
		t.Fatal("wider token mode accepted")
	}
}

func testServiceGID(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range groups {
		if gid != os.Getegid() {
			return gid
		}
	}
	t.Skip("a distinct supplementary group is required")
	return 0
}
