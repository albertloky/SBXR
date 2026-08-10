package ubuntu

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestInstallHostActivatesAndReversesOnlyPreparedProxyConfigurations(t *testing.T) {
	root := t.TempDir()
	prepared := filepath.Join(root, transactionDirectory, "install-session-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/sbxr"), 0o755); err != nil {
		t.Fatal(err)
	}
	xray, singBox := []byte(`{"inbounds":[{"tag":"xray"}]}`), []byte(`{"inbounds":[{"tag":"sing-box"}]}`)
	if err := os.WriteFile(filepath.Join(prepared, "xray.json"), xray, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prepared, "sing-box.json"), singBox, 0o600); err != nil {
		t.Fatal(err)
	}
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), xrayGID: os.Getegid(), singGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(_ context.Context, name string, arguments ...string) error {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		return nil
	}}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot []byte
	if err := host.CaptureRollback(step, func(source io.Reader) error { snapshot, err = io.ReadAll(source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"etc/sbxr/xray/config.json": xray, "etc/sbxr/sing-box/config.json": singBox} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, %v", name, got, err)
		}
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("InspectStep = %q, %v", effect, err)
	}
	if _, err := host.Reverse(step, bytes.NewReader(snapshot), time.Second); err != nil {
		t.Fatal(err)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("rollback InspectStep = %q, %v", effect, err)
	}
	if len(commands) < 3 {
		t.Fatalf("managed systemd lifecycle was not invoked: %v", commands)
	}
}

func TestInstallHostProvesEverySelectedClientAccessListener(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"etc/sbxr/xray/config.json":     `{"inbounds":[{"listen":"127.0.0.1","port":11080}]}`,
		"etc/sbxr/sing-box/config.json": `{"inbounds":[{"type":"tuic","listen":"0.0.0.0","listen_port":8443}]}`,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil || os.WriteFile(path, []byte(body), 0o640) != nil {
			t.Fatal("write active configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil || os.WriteFile(filepath.Join(prepared, "xray.json"), []byte(`{"inbounds":[{"listen":"127.0.0.1","port":11080}]}`), 0o600) != nil || os.WriteFile(filepath.Join(prepared, "sing-box.json"), []byte(`{"inbounds":[{"type":"tuic","listen":"0.0.0.0","listen_port":8443}]}`), 0o600) != nil {
		t.Fatal("write reviewed configuration")
	}
	listeners := []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\n")
	host := InstallHost{root: root, output: func(context.Context, string, ...string) ([]byte, error) { return listeners, nil }}
	check := systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Code: "CONNECTION-PROFILES-CLIENT-ACCESS-LISTENERS"}
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Healthy {
		t.Fatalf("listener health = %s, %v", status, err)
	}
	listeners = listeners[:bytes.Index(listeners, []byte("udp"))]
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("missing listener health = %s, %v", status, err)
	}
	listeners = []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\ntcp LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:((\"sing-box\",pid=2,fd=3))\n")
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("extra listener health = %s, %v", status, err)
	}
	listeners = []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\ntcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=3,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\n")
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("duplicate listener health = %s, %v", status, err)
	}
}

func TestManagedInstallHostSnapshotsActivatesAndRestoresPriorConfigurations(t *testing.T) {
	root := t.TempDir()
	prior := map[string][]byte{"etc/sbxr/xray/config.json": []byte(`{"prior":"xray"}`), "etc/sbxr/sing-box/config.json": []byte(`{"prior":"sing-box"}`)}
	for name, body := range prior {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil || os.WriteFile(path, body, 0o640) != nil {
			t.Fatal("write prior configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil || os.WriteFile(filepath.Join(prepared, "xray.json"), []byte(`{"next":"xray"}`), 0o600) != nil || os.WriteFile(filepath.Join(prepared, "sing-box.json"), []byte(`{"next":"sing-box"}`), 0o600) != nil {
		t.Fatal("write prepared configuration")
	}
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), xrayGID: os.Getegid(), singGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), managed: true, run: func(_ context.Context, name string, arguments ...string) error {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		return nil
	}}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	var snapshot []byte
	if err := host.CaptureRollback(step, func(source io.Reader) error { var err error; snapshot, err = io.ReadAll(source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "systemctl restart xray.service") || !slices.Contains(commands, "systemctl restart sing-box.service") {
		t.Fatalf("affected core restarts = %v", commands)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("candidate effect = %s, %v", effect, err)
	}
	if _, err := host.Reverse(step, bytes.NewReader(snapshot), time.Second); err != nil {
		t.Fatal(err)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("restored effect = %s, %v", effect, err)
	}
	for name, want := range prior {
		if got, err := os.ReadFile(filepath.Join(root, name)); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored %s = %q, %v", name, got, err)
		}
	}
}
