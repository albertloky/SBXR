package ubuntu

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
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
