package ubuntu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestNativeFirewallRequiresExactCandidateExposureSet(t *testing.T) {
	candidate := "table inet sbxr {\n chain input {\n  ip daddr 192.0.2.10 tcp dport { 443, 2222 } accept\n  ip daddr 192.0.2.10 udp dport 8443 accept\n }\n}"
	active := []byte(candidate)
	firewall := newNativeFirewall(func(context.Context, []byte, string, ...string) ([]byte, error) { return active, nil })
	step, err := systemchanges.NewFirewallPolicyStep(candidate, 2222)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := firewall.CheckCandidate(step, time.Second); err != nil || status != systemchanges.Healthy {
		t.Fatalf("candidate health = %s, %v", status, err)
	}
	active = []byte(strings.Replace(candidate, "443, ", "", 1))
	if status, err := firewall.CheckCandidate(step, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("missing exposure health = %s, %v", status, err)
	}
	active = []byte(strings.Replace(candidate, "443, 2222", "443, 2222, 9443", 1))
	if status, err := firewall.CheckCandidate(step, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("extra exposure health = %s, %v", status, err)
	}
	active = []byte(strings.Replace(candidate, "chain input", "chain output", 1))
	if status, err := firewall.CheckCandidate(step, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("wrong chain health = %s, %v", status, err)
	}
	active = []byte(strings.Replace(candidate, "ip daddr", "drop\n  ip daddr", 1))
	if status, err := firewall.CheckCandidate(step, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("preceding drop health = %s, %v", status, err)
	}
}

func TestNativeFirewallUsesWatchdogAndExactHTTP01Handle(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "198.51.100.2 50000 192.0.2.10 2222")
	var commands []string
	table, temporary := false, false
	run := func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command+" stdin="+string(input))
		switch {
		case command == "nft -j list tables":
			if table {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"unrelated"}},{"table":{"family":"inet","name":"sbxr"}}]}`), nil
			}
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"unrelated"}}]}`), nil
		case command == "nft --check --file -", strings.HasPrefix(command, "systemd-run "):
			return nil, nil
		case command == "systemctl stop sbxr-firewall-watchdog.timer sbxr-firewall-watchdog.service":
			return nil, errors.New("controlled transient-unit stop status")
		case command == "systemctl is-active sbxr-firewall-watchdog.timer sbxr-firewall-watchdog.service":
			return []byte("inactive\ninactive\n"), errors.New("controlled inactive status")
		case command == "nft --file -":
			table = true
			temporary = strings.Contains(string(input), "sbxr:acme-http-01")
			return nil, nil
		case command == "ss -Htn state established":
			return []byte("ESTAB 0 0 192.0.2.10:2222 198.51.100.2:50000"), nil
		case command == "nft -j list table inet sbxr":
			return []byte(`{"nftables":[{"rule":{"family":"inet","table":"sbxr","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":2222}},{"accept":null}]}}]}`), nil
		case command == "nft -a list chain inet sbxr input":
			if temporary {
				return []byte(`tcp dport 80 accept comment "sbxr:acme-http-01" # handle 41`), nil
			}
			return []byte("tcp dport 2222 accept # handle 7"), nil
		case command == "nft list chain inet sbxr input":
			return []byte("tcp dport 2222 accept"), nil
		case command == "nft delete rule inet sbxr input handle 41":
			temporary = false
			return nil, nil
		}
		return nil, errors.New("unexpected command")
	}
	firewall := newNativeFirewall(run)
	candidate := "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n  tcp dport 80 accept comment \"sbxr:acme-http-01\"\n }\n}"
	open, err := systemchanges.NewHTTP01OpenStep(candidate, 2222)
	if err != nil {
		t.Fatal(err)
	}
	var rollback string
	if err := firewall.CaptureRollback(open, func(source io.Reader) error {
		data, readErr := io.ReadAll(source)
		rollback = string(data)
		return readErr
	}); err != nil || rollback != "delete table inet sbxr\n" {
		t.Fatalf("rollback capture = %q, %v", rollback, err)
	}
	evidence, err := firewall.Execute(open, "/var/lib/sbxr/transactions/change-0008/snapshot/step-001.rollback", time.Second, systemchanges.NewCancellation())
	if err != nil || evidence.Code != "network-http01-handle-41" || !temporary {
		t.Fatalf("HTTP-01 open = (%+v, %v), temporary=%t", evidence, err, temporary)
	}
	if strings.Contains(strings.Join(commands, "\n"), "systemctl stop") {
		t.Fatal("watchdog was cancelled before step evidence became durable")
	}
	if err := firewall.Commit(open, evidence); err != nil {
		t.Fatal(err)
	}
	closeHTTP, _ := systemchanges.NewHTTP01CloseStep()
	evidence, err = firewall.Execute(closeHTTP, "/var/lib/sbxr/transactions/change-0008/snapshot/step-002.rollback", time.Second, systemchanges.NewCancellation())
	if err != nil || evidence.Code != "network-http01-removed-41" || temporary {
		t.Fatalf("HTTP-01 close = (%+v, %v), temporary=%t", evidence, err, temporary)
	}
	joined := strings.Join(commands, "\n")
	for _, required := range []string{"nft --check --file -", "systemd-run --quiet --unit sbxr-firewall-watchdog", "ss -Htn state established", "nft delete rule inet sbxr input handle 41", "systemctl stop sbxr-firewall-watchdog.timer sbxr-firewall-watchdog.service", "systemctl is-active sbxr-firewall-watchdog.timer sbxr-firewall-watchdog.service"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("commands omit %q:\n%s", required, joined)
		}
	}
	if strings.Contains(joined, "flush ruleset") || strings.Contains(joined, "delete table inet unrelated") {
		t.Fatalf("unrelated nftables state was targeted:\n%s", joined)
	}
}

func TestNativeFirewallErrorsNeverExposeCommandOutput(t *testing.T) {
	firewall := newNativeFirewall(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("SECRET-MARKER"), errors.New("SECRET-MARKER")
	})
	step, _ := systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}", 2222)
	_, err := firewall.Execute(step, "/protected/rollback", time.Second, systemchanges.NewCancellation())
	if err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("secret-bearing native error = %v", err)
	}
}

func TestNativeFirewallKeepsTheWatchdogWhenEitherUnitIsActive(t *testing.T) {
	firewall := newNativeFirewall(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) == 3 && args[0] == "stop" {
			return nil, nil
		}
		if name == "systemctl" && len(args) == 3 && args[0] == "is-active" {
			return []byte("inactive\nactive\n"), nil
		}
		return nil, errors.New("unexpected command")
	})
	step, _ := systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}", 2222)
	if err := firewall.Commit(step, systemchanges.StepEvidence{Code: "network-policy-applied"}); err == nil {
		t.Fatal("active watchdog unit was accepted as cancelled")
	}
}

func TestSSHProofRejectsAnotherConnectionAndEarlierTerminalVerdict(t *testing.T) {
	if currentSSHSessionPresent([]byte("ESTAB 0 0 192.0.2.10:2222 198.51.100.9:50000"), 2222, "198.51.100.2 50000 192.0.2.10 2222") {
		t.Fatal("another established connection was accepted as the current SSH session")
	}
	for _, verdict := range []string{"drop", "return"} {
		policy := []byte(fmt.Sprintf(`{"nftables":[
			{"rule":{"family":"inet","table":"sbxr","chain":"input","expr":[{"%s":null}]}},
			{"rule":{"family":"inet","table":"sbxr","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":2222}},{"accept":null}]}}
		]}`, verdict))
		if admitsTCPPort(policy, 2222) {
			t.Fatalf("an accept after an earlier %s verdict was treated as effective", verdict)
		}
	}
}

func TestProductionFirewallSeam(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("SBXR_CONTROLLED_FIREWALL_SEAM") != "1" {
		t.Skip("controlled production firewall mutation requires isolated Ubuntu and explicit approval")
	}
	for _, command := range []string{"nft", "ss", "systemd-run", "systemctl"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("controlled production firewall seam requires %s", command)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	client := connection.LocalAddr().(*net.TCPAddr)
	server := accepted.LocalAddr().(*net.TCPAddr)
	t.Setenv("SSH_CONNECTION", fmt.Sprintf("%s %d %s %d", client.IP.String(), client.Port, server.IP.String(), server.Port))
	candidate := fmt.Sprintf("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  ct state established,related accept\n  iifname \"lo\" accept\n  tcp dport %d accept\n }\n}", port)
	step, err := systemchanges.NewFirewallPolicyStep(candidate, port)
	if err != nil {
		t.Fatal(err)
	}
	firewall := NewNativeFirewall()
	var prior []byte
	if err := firewall.CaptureRollback(step, func(source io.Reader) error { var readErr error; prior, readErr = io.ReadAll(source); return readErr }); err != nil {
		t.Fatal(err)
	}
	rollbackDir, err := os.MkdirTemp("/var/tmp", "sbxr-firewall-seam-")
	if err != nil {
		t.Fatal(err)
	}
	rollbackPath := filepath.Join(rollbackDir, "firewall.rollback")
	if err := os.WriteFile(rollbackPath, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("nft", "add", "table", "inet", "sbxr_test_unrelated").CombinedOutput(); err != nil {
		t.Fatalf("create controlled unrelated table: %v: %s", err, output)
	}
	defer exec.Command("nft", "delete", "table", "inet", "sbxr_test_unrelated").Run()
	if _, err := firewall.Execute(step, rollbackPath, 10*time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	if _, err := firewall.Reverse(step, strings.NewReader(string(prior)), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(rollbackDir); err != nil {
		t.Fatal(err)
	}

	failureDir, err := os.MkdirTemp("/var/tmp", "sbxr-firewall-seam-failure-")
	if err != nil {
		t.Fatal(err)
	}
	failurePath := filepath.Join(failureDir, "firewall.rollback")
	if err := os.WriteFile(failurePath, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	cancellation := systemchanges.NewCancellation()
	cancellation.Request()
	if _, err := firewall.Execute(step, failurePath, 10*time.Second, cancellation); err == nil {
		t.Fatal("controlled cancellation after firewall mutation succeeded")
	}
	if snapshot, err := os.ReadFile(failurePath); err != nil || !bytes.Equal(snapshot, prior) {
		t.Fatalf("armed watchdog rollback snapshot unavailable after failure: %v", err)
	}
	if _, err := firewall.Reverse(step, strings.NewReader(string(prior)), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(failureDir); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("nft", "list", "table", "inet", "sbxr_test_unrelated").CombinedOutput(); err != nil {
		t.Fatalf("unrelated table changed: %v: %s", err, output)
	}
}
