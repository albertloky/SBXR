package ubuntu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectTLSExecutorValidatesRestartsAndProvesEachConsumer(t *testing.T) {
	root := writeProbeConfiguration(t)
	var commands, proofs []string
	executor := DirectTLSExecutor{
		run: func(_ context.Context, name string, arguments ...string) error {
			commands = append(commands, name+" "+strings.Join(arguments, " "))
			return nil
		},
		prove: func(_ context.Context, _, profile, destination, hostname string) error {
			proofs = append(proofs, profile+" "+destination+" "+hostname)
			return nil
		},
	}
	if err := executor.ValidateConfiguration(root, "192.0.2.10", "direct.example.com", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", time.Minute); err != nil {
		t.Fatal(err)
	}
	if commands[0] != "sing-box check -c "+filepath.Join(root, "etc/sbxr/sing-box/config.json") || commands[1] != "sing-box check -c "+filepath.Join(root, probeConfiguration) || commands[2] != "systemctl restart sing-box.service" {
		t.Fatalf("commands = %#v", commands)
	}
	want := []string{"hysteria2 192.0.2.10 direct.example.com", "tuic 192.0.2.10 direct.example.com", "anytls 192.0.2.10 direct.example.com"}
	if strings.Join(proofs, "|") != strings.Join(want, "|") {
		t.Fatalf("proofs = %#v", proofs)
	}
	proofs = nil
	if err := executor.Restore(root, "192.0.2.10", "direct.example.com", time.Minute); err != nil || len(proofs) != 3 {
		t.Fatalf("prior consumer re-proof = %#v, %v", proofs, err)
	}
}

func TestDirectTLSExecutorFailsWhenOneConsumerFails(t *testing.T) {
	root := writeProbeConfiguration(t)
	executor := DirectTLSExecutor{
		run: func(context.Context, string, ...string) error { return nil },
		prove: func(_ context.Context, _, profile, _, _ string) error {
			if profile == "tuic" {
				return errors.New("private failure marker")
			}
			return nil
		},
	}
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", time.Minute); err == nil || strings.Contains(err.Error(), "marker") {
		t.Fatalf("one-consumer failure = %v", err)
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS", time.Minute); err != nil || !healthy {
		t.Fatalf("individual healthy check = %t, %v", healthy, err)
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-TUIC-DIRECT-TLS", time.Minute); err == nil || healthy {
		t.Fatalf("individual failed check = %t, %v", healthy, err)
	}
}

func TestDirectTLSExecutorStopsOnRestartFailureBeforeConsumerProof(t *testing.T) {
	root := writeProbeConfiguration(t)
	proofs := 0
	executor := DirectTLSExecutor{
		run: func(_ context.Context, name string, _ ...string) error {
			if name == "systemctl" {
				return errors.New("PRIVATE-RESTART-MARKER")
			}
			return nil
		},
		prove: func(context.Context, string, string, string, string) error { proofs++; return nil },
	}
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", time.Minute); err == nil || strings.Contains(err.Error(), "MARKER") || proofs != 0 {
		t.Fatalf("restart refusal err=%v proofs=%d", err, proofs)
	}
}

func TestDirectTLSExecutorRejectsWeakOrDisagreeingProbeConfiguration(t *testing.T) {
	for _, replacement := range []struct{ old, new string }{
		{`"server_name":"direct.example.com"`, `"server_name":"other.example.com"`},
		{`"enabled":true`, `"enabled":true,"insecure":true`},
		{`"enabled":true`, `"enabled":true,"certificate_path":"/tmp/staging.pem"`},
	} {
		root := writeProbeConfiguration(t)
		name := filepath.Join(root, probeConfiguration)
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(strings.Replace(string(content), replacement.old, replacement.new, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		executor := DirectTLSExecutor{run: func(context.Context, string, ...string) error { return nil }}
		if err := executor.ValidateConfiguration(root, "192.0.2.10", "direct.example.com", time.Minute); err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
			t.Fatalf("weak probe configuration accepted: %v", err)
		}
	}
}

func writeProbeConfiguration(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeProbeConfigurationAt(t, root)
	return root
}

func writeProbeConfigurationAt(t *testing.T, root string) {
	t.Helper()
	name := filepath.Join(root, probeConfiguration)
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"outbounds":[{"type":"hysteria2","tag":"sbxr-proof-hysteria2","server":"192.0.2.10","server_port":443,"password":"HYSTERIA2-SECRET-MARKER","tls":{"enabled":true,"server_name":"direct.example.com"}},{"type":"tuic","tag":"sbxr-proof-tuic","server":"192.0.2.10","server_port":8443,"uuid":"00000000-0000-4000-8000-000000000000","password":"TUIC-SECRET-MARKER","tls":{"enabled":true,"server_name":"direct.example.com"}},{"type":"anytls","tag":"sbxr-proof-anytls","server":"192.0.2.10","server_port":9443,"password":"ANYTLS-SECRET-MARKER","tls":{"enabled":true,"server_name":"direct.example.com"}}]}`
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
