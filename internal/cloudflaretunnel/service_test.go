package cloudflaretunnel

import (
	"bytes"
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

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestCloudflaredServiceUsesProtectedTokenFileAndRootIdentity(t *testing.T) {
	unit := CloudflaredServiceUnit()
	if !ValidateCloudflaredServiceUnit(unit) || strings.Contains(unit, "TOKEN=") || strings.Contains(unit, "PLAN-SECRET-MARKER") {
		t.Fatalf("unsafe cloudflared unit:\n%s", unit)
	}
	if !strings.Contains(unit, "User=root\nGroup=root") || ValidateCloudflaredServiceUnit(strings.Replace(unit, "Group=root", "Group=cloudflared", 1)) {
		t.Fatal("cloudflared unit did not enforce one root runtime identity")
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
	serviceGID := os.Getegid()
	executor := Executor{
		request:         PlanRequest{XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com"},
		serviceIdentity: func() (int, int, error) { return os.Geteuid(), serviceGID, nil },
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
	if err := ValidateInstalledService(root, os.Geteuid(), serviceGID); err != nil {
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

func TestExecutorSnapshotsRestartsAndRestoresManagedCloudflaredService(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"etc", "etc/systemd", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	serviceGID := os.Getegid()
	var commands []string
	executor := Executor{request: PlanRequest{XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com"}, serviceIdentity: func() (int, int, error) { return os.Geteuid(), serviceGID, nil }, command: func(_ context.Context, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		if len(arguments) == 1 && arguments[0] == "--version" {
			return []byte("cloudflared version 2026.7.3 (built 2026-08-01)"), nil
		}
		return nil, nil
	}}
	material := `{"tunnel_id":"11111111-1111-4111-8111-111111111111","tunnel_run_token":"RUN-TOKEN-MARKER","routes":[{"hostname":"xhttp.example.com","origin":"http://127.0.0.1:11080"},{"hostname":"ws.example.com","origin":"http://127.0.0.1:11081"}]}`
	if _, err := executor.ActivateService(root, strings.NewReader(material), time.Minute); err != nil {
		t.Fatal(err)
	}
	priorUnit, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/cloudflared.service"))
	priorToken, _ := os.ReadFile(filepath.Join(root, "etc/sbxr/cloudflared/token"))
	priorConfig, _ := os.ReadFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"))
	executor.releaseUpdate = true
	var rollback []byte
	if err := executor.CaptureServiceRollback(root, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	candidateUnit := bytes.Replace(priorUnit, []byte("/usr/bin/cloudflared"), []byte("/opt/sbxr/releases/candidate/cloudflared"), 1)
	executor.request.CandidateServiceUnit = string(candidateUnit)
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/cloudflared.service"), candidateUnit, 0o644); err != nil {
		t.Fatal(err)
	}
	commands = nil
	if evidence, err := executor.ActivateService(root, strings.NewReader(material), time.Minute); err != nil || evidence.Code != "cloudflared-service-updated" {
		t.Fatalf("ActivateService(update) = (%+v, %v)", evidence, err)
	}
	if effect, err := executor.InspectService(root, bytes.NewReader(rollback)); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("InspectService(update) = (%s, %v)", effect, err)
	}
	for _, hostile := range []struct {
		name, path string
		candidate  []byte
		mode       os.FileMode
	}{{"token", "etc/sbxr/cloudflared/token", priorToken, 0o644}, {"config", "etc/sbxr/cloudflared/config.yml", priorConfig, 0o644}, {"unit", "etc/systemd/system/cloudflared.service", candidateUnit, 0o644}} {
		t.Run("changed "+hostile.name, func(t *testing.T) {
			name := filepath.Join(root, hostile.path)
			changed := append(append([]byte(nil), hostile.candidate...), 'x')
			if err := os.WriteFile(name, changed, hostile.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ReverseService(root, bytes.NewReader(rollback), time.Minute); err == nil {
				t.Fatal("changed managed service was overwritten")
			}
			if retained, _ := os.ReadFile(name); !bytes.Equal(retained, changed) {
				t.Fatal("changed managed service was not retained for Recovery Required")
			}
			if err := os.WriteFile(name, hostile.candidate, hostile.mode); err != nil {
				t.Fatal(err)
			}
		})
	}
	if evidence, err := executor.ReverseService(root, bytes.NewReader(rollback), time.Minute); err != nil || evidence.Code != "cloudflared-service-restored" {
		t.Fatalf("ReverseService(update) = (%+v, %v)", evidence, err)
	}
	restored, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/cloudflared.service"))
	if !bytes.Equal(restored, priorUnit) || len(commands) != 3 || commands[0] != "/usr/bin/systemctl daemon-reload" || commands[1] != "/usr/bin/systemctl restart cloudflared.service" || commands[2] != "/usr/bin/systemctl daemon-reload" {
		t.Fatalf("managed restore = unit match %t, commands %v", bytes.Equal(restored, priorUnit), commands)
	}
	if effect, err := executor.InspectService(root, bytes.NewReader(rollback)); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("InspectService(restored) = (%s, %v)", effect, err)
	}
}

func TestInspectServiceFindsDirectoriesCreatedBeforeFirstFile(t *testing.T) {
	for _, directory := range []string{"etc/sbxr", "etc/sbxr/cloudflared"} {
		t.Run(directory, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755); err != nil {
				t.Fatal(err)
			}
			executor := Executor{serviceIdentity: func() (int, int, error) { return os.Geteuid(), os.Getegid(), nil }}
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

func TestExecutorRemovesTheOldTokenAtCheckpointAndRestartsOnlyWithTheNewToken(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"etc", "etc/systemd", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	serviceGID := os.Getegid()
	var commands []string
	executor := Executor{request: PlanRequest{XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com"}, serviceIdentity: func() (int, int, error) { return os.Geteuid(), serviceGID, nil }, command: func(_ context.Context, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		if len(arguments) == 1 && arguments[0] == "--version" {
			return []byte("cloudflared version 2026.7.3 (built 2026-08-01)"), nil
		}
		return nil, nil
	}}
	oldMaterial := `{"tunnel_id":"11111111-1111-4111-8111-111111111111","tunnel_run_token":"OLD-RUN-TOKEN-MARKER","routes":[{"hostname":"xhttp.example.com","origin":"http://127.0.0.1:11080"},{"hostname":"ws.example.com","origin":"http://127.0.0.1:11081"}]}`
	if _, err := executor.ActivateService(root, strings.NewReader(oldMaterial), time.Minute); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := executor.RunTokenFingerprint(root)
	if err != nil || len(fingerprint) != 64 {
		t.Fatalf("fingerprint = %q, %v", fingerprint, err)
	}
	if err := executor.RemoveRunToken(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/sbxr/cloudflared/token")); !os.IsNotExist(err) {
		t.Fatalf("old token file remains: %v", err)
	}
	commands = nil
	newMaterial := strings.Replace(oldMaterial, "OLD-RUN-TOKEN-MARKER", "NEW-RUN-TOKEN-MARKER", 1)
	evidence, err := executor.RotateService(root, strings.NewReader(newMaterial), time.Minute)
	if err != nil || evidence.Code != "cloudflared-run-token-rotated" {
		t.Fatalf("RotateService() = %+v, %v", evidence, err)
	}
	token, err := os.ReadFile(filepath.Join(root, "etc/sbxr/cloudflared/token"))
	if err != nil || string(token) != "NEW-RUN-TOKEN-MARKER\n" {
		t.Fatalf("new token file = %q, %v", token, err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "RUN-TOKEN-MARKER") || commands[len(commands)-1] != "/usr/bin/systemctl restart cloudflared.service" {
		t.Fatalf("rotation commands = %v", commands)
	}
	if _, err := executor.RotateService(root, strings.NewReader(oldMaterial), time.Minute); err == nil {
		t.Fatal("old invalid token was accepted after the checkpoint")
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
	}{{"etc", 0o755}, {"etc/sbxr", 0o755}, {"etc/sbxr/cloudflared", 0o755}, {"etc/systemd", 0o755}, {"etc/systemd/system", 0o755}} {
		name, mode := directory.name, directory.mode
		if err := os.MkdirAll(filepath.Join(root, name), mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
			t.Fatal(err)
		}
	}
	serviceGID := os.Getegid()
	if err := os.Chown(filepath.Join(root, "etc/sbxr/cloudflared"), os.Geteuid(), serviceGID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/token"), []byte("SERVICE-TOKEN-MARKER"), 0o644); err != nil {
		t.Fatal(err)
	}
	material := serviceMaterial{Routes: []struct {
		Hostname string `json:"hostname"`
		Origin   string `json:"origin"`
	}{{Hostname: "xhttp.example.com", Origin: xhttpOrigin}, {Hostname: "ws.example.com", Origin: webSocketOrigin}}}
	configuration := serviceConfiguration(material)
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"), configuration, 0o644); err != nil {
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
	executor := Executor{request: PlanRequest{XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com"}, serviceIdentity: func() (int, int, error) { return os.Geteuid(), serviceGID, nil }}
	if err := executor.ValidateInstalledService(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"), []byte(`{"ingress":[]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executor.ValidateInstalledService(root); err == nil {
		t.Fatal("incomplete ingress configuration accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/cloudflared/config.yml"), configuration, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr/cloudflared/token"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.ValidateInstalledService(root); err == nil {
		t.Fatal("wrong token mode accepted")
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr/cloudflared/token"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"old identity":        "User=cloudflared\nGroup=cloudflared",
		"mixed identity":      "User=root\nGroup=cloudflared",
		"missing containment": "User=root\nGroup=root",
		"unsafe token":        "User=root\nGroup=root",
	} {
		candidate := CloudflaredServiceUnit()
		switch name {
		case "old identity", "mixed identity":
			candidate = strings.Replace(candidate, "User=root\nGroup=root", replacement, 1)
		case "missing containment":
			candidate = strings.Replace(candidate, "PrivateTmp=true\n", "", 1)
		case "unsafe token":
			candidate = strings.Replace(candidate, "--token-file /etc/sbxr/cloudflared/token", "--token SERVICE-TOKEN-MARKER", 1)
		}
		if err := os.WriteFile(unit, []byte(candidate), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := executor.ValidateInstalledService(root); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
