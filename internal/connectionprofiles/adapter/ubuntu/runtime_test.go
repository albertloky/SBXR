package ubuntu

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRuntimeExecutorRejectsMixedRootRuntimeServiceIdentity(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"etc/sbxr/xray/config.json":     `{"inbounds":[{"listen":"0.0.0.0","port":443}]}`,
		"etc/sbxr/sing-box/config.json": `{"inbounds":[{"type":"hysteria2","listen":"0.0.0.0","listen_port":443}]}`,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	group := "root"
	executor := RuntimeExecutor{observe: func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		command := name + " " + strings.Join(arguments, " ")
		switch {
		case strings.Contains(command, "--property=Id"):
			return arguments[len(arguments)-1], nil
		case strings.Contains(command, "--property=User"):
			return "root", nil
		case strings.Contains(command, "--property=Group"):
			return group, nil
		case strings.Contains(command, "is-active"):
			return "active", nil
		case strings.Contains(command, "CapabilityBoundingSet"), strings.Contains(command, "AmbientCapabilities"):
			return "CAP_NET_BIND_SERVICE", nil
		case strings.Contains(command, "NoNewPrivileges"), strings.Contains(command, "ProtectHome"):
			return "yes", nil
		case strings.Contains(command, "ProtectSystem"):
			return "strict", nil
		case strings.HasPrefix(command, "ss "):
			return "", nil
		default:
			return "", errors.New("unexpected root-runtime observation")
		}
	}}
	xraySHA256, singBoxSHA256 := configurationDigests(t, root)
	runtime := systemchanges.ConnectionProfilesRuntimeBinding{XraySHA256: xraySHA256, SingBoxSHA256: singBoxSHA256}
	if healthy, err := executor.Check(root, "", "", "CONNECTION-PROFILES-REGISTRY-SERVICE", runtime, time.Second); err != nil || !healthy {
		t.Fatalf("root-runtime service = (%t, %v)", healthy, err)
	}
	group = "sing-box"
	if healthy, err := executor.Check(root, "", "", "CONNECTION-PROFILES-REGISTRY-SERVICE", runtime, time.Second); err != nil || healthy {
		t.Fatalf("mixed root-runtime service = (%t, %v)", healthy, err)
	}
}

func TestRuntimeExecutorUsesExactActiveListenerAndFunctionFacts(t *testing.T) {
	root := writeProbeConfiguration(t)
	for name, body := range map[string]string{
		"etc/sbxr/xray/config.json":     `{"inbounds":[{"listen":"127.0.0.1","port":12080}]}`,
		"etc/sbxr/sing-box/config.json": `{"inbounds":[{"type":"anytls","listen":"0.0.0.0","listen_port":19443}]}`,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var proved []string
	executor := RuntimeExecutor{
		observe: func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
			command := name + " " + strings.Join(arguments, " ")
			switch {
			case strings.Contains(command, "-ltn") && strings.Contains(command, ":12080"):
				return "LISTEN 0 4096 127.0.0.1:12080 0.0.0.0:*", nil
			case strings.Contains(command, "-ltn") && strings.Contains(command, ":19443"):
				return "LISTEN 0 4096 0.0.0.0:19443 0.0.0.0:*", nil
			default:
				return "", errors.New("stale or unexpected listener requested")
			}
		},
		prove: func(_ context.Context, _ string, profile, _, _ string) error {
			proved = append(proved, profile)
			return nil
		},
	}
	xraySHA256, singBoxSHA256 := configurationDigests(t, root)
	runtime := systemchanges.ConnectionProfilesRuntimeBinding{XraySHA256: xraySHA256, SingBoxSHA256: singBoxSHA256}
	if healthy, err := executor.Check(root, "", "", "CONNECTION-PROFILES-REGISTRY-LISTENER", runtime, time.Second); err != nil || !healthy {
		t.Fatalf("non-default listeners = (%t, %v)", healthy, err)
	}
	if healthy, err := executor.Check(root, "", "", "CONNECTION-PROFILES-REGISTRY-FUNCTION", runtime, time.Second); err != nil || !healthy || strings.Join(proved, ",") != "anytls" {
		t.Fatalf("enabled function facts = (%t, %v), proved=%v", healthy, err, proved)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/sing-box/config.json"), []byte(`{"inbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if healthy, err := executor.Check(root, "", "", "CONNECTION-PROFILES-REGISTRY-FUNCTION", runtime, time.Second); err != nil || healthy {
		t.Fatalf("incomplete reviewed function facts = (%t, %v)", healthy, err)
	}
}

func TestRuntimeExecutorValidatesRestartsAndProvesEachConsumer(t *testing.T) {
	root := writeProbeConfiguration(t)
	var commands, proofs []string
	executor := RuntimeExecutor{
		run: func(_ context.Context, name string, arguments ...string) error {
			commands = append(commands, name+" "+strings.Join(arguments, " "))
			return nil
		},
		prove: func(_ context.Context, _, profile, destination, hostname string) error {
			proofs = append(proofs, profile+" "+destination+" "+hostname)
			return nil
		},
	}
	runtime := directTLSRuntimeBinding(t, root)
	if err := executor.ValidateConfiguration(root, "192.0.2.10", "direct.example.com", runtime, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", runtime, time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 3 || commands[0] != "sing-box check -c /dev/stdin" || commands[1] != "sing-box check -c /dev/stdin" || commands[2] != "systemctl restart sing-box.service" {
		t.Fatalf("commands = %#v", commands)
	}
	want := []string{"hysteria2 192.0.2.10 direct.example.com", "tuic 192.0.2.10 direct.example.com", "anytls 192.0.2.10 direct.example.com"}
	if strings.Join(proofs, "|") != strings.Join(want, "|") {
		t.Fatalf("proofs = %#v", proofs)
	}
	proofs = nil
	if err := executor.Restore(root, "192.0.2.10", "direct.example.com", runtime, time.Minute); err != nil || len(proofs) != 3 {
		t.Fatalf("prior consumer re-proof = %#v, %v", proofs, err)
	}
}

func TestRuntimeExecutorFailsWhenOneConsumerFails(t *testing.T) {
	root := writeProbeConfiguration(t)
	executor := RuntimeExecutor{
		run: func(context.Context, string, ...string) error { return nil },
		prove: func(_ context.Context, _, profile, _, _ string) error {
			if profile == "tuic" {
				return errors.New("private failure marker")
			}
			return nil
		},
	}
	runtime := directTLSRuntimeBinding(t, root)
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", runtime, time.Minute); err == nil || strings.Contains(err.Error(), "marker") {
		t.Fatalf("one-consumer failure = %v", err)
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS", runtime, time.Minute); err != nil || !healthy {
		t.Fatalf("individual healthy check = %t, %v", healthy, err)
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-TUIC-DIRECT-TLS", runtime, time.Minute); err == nil || healthy {
		t.Fatalf("individual failed check = %t, %v", healthy, err)
	}
}

func TestRuntimeExecutorSkipsDisabledDirectTLSConsumer(t *testing.T) {
	root := writeProbeConfiguration(t)
	reviewedAll := directTLSRuntimeBinding(t, root)
	name := filepath.Join(root, singBoxConfigurationPath)
	content := `{"inbounds":[{"type":"hysteria2","listen":"0.0.0.0","listen_port":443,"users":[{"password":"HYSTERIA2-SECRET-MARKER"}],"tls":{"enabled":true,"server_name":"direct.example.com"}},{"type":"tuic","listen":"0.0.0.0","listen_port":8443,"users":[{"uuid":"00000000-0000-4000-8000-000000000000","password":"TUIC-SECRET-MARKER"}],"tls":{"enabled":true,"server_name":"direct.example.com"}}]}`
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var proved []string
	executor := RuntimeExecutor{
		run: func(context.Context, string, ...string) error { return nil },
		prove: func(_ context.Context, _, profile, _, _ string) error {
			proved = append(proved, profile)
			return nil
		},
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-ANYTLS-DIRECT-TLS", reviewedAll, time.Second); err == nil || healthy {
		t.Fatalf("missing reviewed Direct TLS consumer = (%t, %v)", healthy, err)
	}
	runtime := directTLSRuntimeBinding(t, root)
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", runtime, time.Second); err != nil || strings.Join(proved, ",") != "hysteria2,tuic" {
		t.Fatalf("enabled Direct TLS activation = (%v, %v)", proved, err)
	}
	if healthy, err := executor.Check(root, "192.0.2.10", "direct.example.com", "CONNECTION-PROFILES-ANYTLS-DIRECT-TLS", runtime, time.Second); err != nil || !healthy {
		t.Fatalf("disabled Direct TLS check = (%t, %v)", healthy, err)
	}
}

func TestRuntimeExecutorStopsOnRestartFailureBeforeConsumerProof(t *testing.T) {
	root := writeProbeConfiguration(t)
	proofs := 0
	executor := RuntimeExecutor{
		run: func(_ context.Context, name string, _ ...string) error {
			if name == "systemctl" {
				return errors.New("PRIVATE-RESTART-MARKER")
			}
			return nil
		},
		prove: func(context.Context, string, string, string, string) error { proofs++; return nil },
	}
	if err := executor.Activate(root, "192.0.2.10", "direct.example.com", directTLSRuntimeBinding(t, root), time.Minute); err == nil || strings.Contains(err.Error(), "MARKER") || proofs != 0 {
		t.Fatalf("restart refusal err=%v proofs=%d", err, proofs)
	}
}

func TestRuntimeExecutorRejectsWeakOrDisagreeingProbeConfiguration(t *testing.T) {
	for _, replacement := range []struct{ old, new string }{
		{`"server_name":"direct.example.com"`, `"server_name":"other.example.com"`},
		{`"password":"HYSTERIA2-SECRET-MARKER"`, `"password":""`},
		{`"type":"hysteria2"`, `"type":"unsupported"`},
	} {
		root := writeProbeConfiguration(t)
		name := filepath.Join(root, singBoxConfigurationPath)
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(strings.Replace(string(content), replacement.old, replacement.new, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		executor := RuntimeExecutor{run: func(context.Context, string, ...string) error { return nil }}
		if err := executor.ValidateConfiguration(root, "192.0.2.10", "direct.example.com", directTLSRuntimeBinding(t, root), time.Minute); err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
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

func configurationDigests(t *testing.T, root string) (string, string) {
	t.Helper()
	xray, err := os.ReadFile(filepath.Join(root, realityConfigurationPath))
	if err != nil {
		t.Fatal(err)
	}
	singBox, err := os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
	if err != nil {
		t.Fatal(err)
	}
	return runtimeDigest(xray), runtimeDigest(singBox)
}

func directTLSRuntimeBinding(t *testing.T, root string) systemchanges.ConnectionProfilesRuntimeBinding {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
	if err != nil {
		t.Fatal(err)
	}
	return systemchanges.ConnectionProfilesRuntimeBinding{SingBoxSHA256: runtimeDigest(content)}
}

func writeProbeConfigurationAt(t *testing.T, root string) {
	t.Helper()
	name := filepath.Join(root, singBoxConfigurationPath)
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"inbounds":[{"type":"hysteria2","listen":"0.0.0.0","listen_port":443,"users":[{"password":"HYSTERIA2-SECRET-MARKER"}],"tls":{"enabled":true,"server_name":"direct.example.com"}},{"type":"tuic","listen":"0.0.0.0","listen_port":8443,"users":[{"uuid":"00000000-0000-4000-8000-000000000000","password":"TUIC-SECRET-MARKER"}],"tls":{"enabled":true,"server_name":"direct.example.com"}},{"type":"anytls","listen":"0.0.0.0","listen_port":9443,"users":[{"password":"ANYTLS-SECRET-MARKER"}],"tls":{"enabled":true,"server_name":"direct.example.com"}}]}`
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
}
