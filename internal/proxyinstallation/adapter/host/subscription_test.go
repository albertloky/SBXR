package host

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSubscriptionCertbotLockChild(t *testing.T) {
	path := os.Getenv("SBXR_TEST_CERTBOT_LOCK")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_WRLCK}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestSubscriptionPreflightObservesRealCertbotPOSIXLock(t *testing.T) {
	adapter, _ := subscriptionReviewHost(t)
	path := filepath.Join(adapter.root, "etc/letsencrypt/.certbot.lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubscriptionCertbotLockChild$")
	child.Env = append(os.Environ(), "SBXR_TEST_CERTBOT_LOCK="+path)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); child.Wait() })
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lock readiness: %q %v", line, err)
	}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.RenewalIdle.Accepted {
		t.Fatal("active POSIX lock was treated as idle Certbot")
	}
}

func TestSubscriptionPreflightRefusesUnprotectedCertbotLock(t *testing.T) {
	adapter, _ := subscriptionReviewHost(t)
	path := filepath.Join(adapter.root, "etc/letsencrypt/.certbot.lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+"-alias"); err != nil {
		t.Fatal(err)
	}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.RenewalIdle.Accepted {
		t.Fatal("shared Certbot lock inode accepted")
	}
}

func subscriptionReviewHost(t *testing.T) (Adapter, map[string]OperationResult) {
	t.Helper()
	commands := map[string]OperationResult{
		"pgrep":         {Code: 1, Observed: true},
		"iptables-save": {Fact: "# Generated at one instant\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n# Completed at one instant\n", Observed: true},
		"dpkg-query":    {Code: 1, Observed: true},
		"snap list":     {Fact: "Name Version Rev Tracking Publisher Notes\ncertbot 5.4.0 5000 latest/stable certbot-eff✓ classic\n", Observed: true},
		"snap changes":  {Fact: "ID Status Spawn Ready Summary\n1 Done today today Installed\n", Observed: true},
	}
	adapter := Adapter{root: t.TempDir(), clockSynchronized: func(context.Context) bool { return true }, packageLocksAvailable: func() bool { return true }, subscriptionBind: func(string, string) bool { return true }}
	adapter.subscriptionCommand = func(_ context.Context, name string, args ...string) (string, int, bool) {
		key := name
		if name == "snap" {
			key += " " + args[0]
		}
		result, ok := commands[key]
		if !ok {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return result.Fact, result.Code, result.Observed
	}
	return adapter, commands
}

func TestSubscriptionPreflightReportsCreationOrReuseWithoutFiles(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		adapter, commands := subscriptionReviewHost(t)
		if reuse {
			commands["dpkg-query"] = OperationResult{Fact: "snapd installed 2.73\n", Code: 1, Observed: true}
		}
		facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8")
		for _, fact := range []Observation{facts.TCP80, facts.TCP8443, facts.Clock, facts.PackageLocks, facts.RenewalIdle, facts.Dependencies, facts.Firewall} {
			if !fact.Observed || !fact.Accepted {
				t.Fatalf("reuse=%t facts=%#v", reuse, facts)
			}
		}
		if facts.SnapdInstalled != reuse || facts.CertbotInstalled != reuse {
			t.Fatalf("wrong dependency effects: %#v", facts)
		}
		entries, err := os.ReadDir(adapter.root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("review created files: %v %v", entries, err)
		}
		if strings.Contains(facts.DependencyIdentity, "certbot") {
			t.Fatal("raw process output escaped")
		}
	}
}

func TestSubscriptionPreflightReusesSnapdWithProvedEmptySnapInventory(t *testing.T) {
	adapter, commands := subscriptionReviewHost(t)
	commands["dpkg-query"] = OperationResult{Fact: "snapd installed 2.73\n", Code: 1, Observed: true}
	commands["snap list"] = OperationResult{Observed: true}
	commands["snap changes"] = OperationResult{Observed: true}
	facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8")
	if !facts.Dependencies.Accepted || !facts.SnapdInstalled || facts.CertbotInstalled {
		t.Fatalf("mixed creation/reuse refused: %#v", facts)
	}
	commands["snap list"] = OperationResult{Code: 1, Observed: true}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.Dependencies.Accepted {
		t.Fatal("failed inventory treated as empty")
	}
}

func TestSubscriptionPreflightRequestsStablePublisherOutput(t *testing.T) {
	adapter, commands := subscriptionReviewHost(t)
	commands["dpkg-query"] = OperationResult{Fact: "snapd installed 2.73\n", Code: 1, Observed: true}
	command := adapter.subscriptionCommand
	adapter.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
		if name == "snap" && args[0] == "list" && !slices.Equal(args, []string{"list", "--unicode=always", "--color=never"}) {
			return "", 1, true
		}
		return command(ctx, name, args...)
	}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); !facts.Dependencies.Accepted {
		t.Fatal("publisher inspection depends on terminal formatting")
	}
}

func TestSubscriptionPreflightRefusesUnknownAndUnsupportedDependencies(t *testing.T) {
	for _, test := range []struct {
		name, command, body string
		code                int
		observed            bool
	}{
		{"unknown", "dpkg-query", "", 0, false},
		{"empty success", "dpkg-query", "", 0, true},
		{"APT Certbot", "dpkg-query", "snapd installed 2.73\ncertbot installed 2.9\n", 0, true},
		{"partial package", "dpkg-query", "snapd unpacked 2.73\n", 1, true},
		{"malformed snap", "snap list", "garbage", 0, true},
		{"old snap", "snap list", "Name Version Rev Tracking Publisher Notes\ncertbot 5.3.0 1 latest/stable certbot-eff✓ classic\n", 0, true},
		{"wrong publisher", "snap list", "Name Version Rev Tracking Publisher Notes\ncertbot 5.4.0 1 latest/stable somebody classic\n", 0, true},
		{"active snap", "snap changes", "ID Status Spawn Ready Summary\n1 Doing today - Refresh\n", 0, true},
		{"unknown changes", "snap changes", "garbage", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, commands := subscriptionReviewHost(t)
			commands["dpkg-query"] = OperationResult{Fact: "snapd installed 2.73\n", Code: 1, Observed: true}
			commands[test.command] = OperationResult{Fact: test.body, Code: test.code, Observed: test.observed}
			if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.Dependencies.Accepted {
				t.Fatalf("unsafe dependencies: %#v", facts)
			}
		})
	}
}

func TestSubscriptionPreflightRefusesConflictAndIgnoresFirewallTimestamps(t *testing.T) {
	adapter, commands := subscriptionReviewHost(t)
	before := adapter.PreflightSubscription(t.Context(), "8.8.8.8")
	rules := commands["iptables-save"]
	rules.Fact = strings.ReplaceAll(rules.Fact, "one instant", "another instant")
	commands["iptables-save"] = rules
	if after := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); before != after {
		t.Fatal("timestamp alone invalidated read-only approval")
	}
	commands["iptables-save"] = OperationResult{Fact: "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment sbxr-subscription -j ACCEPT\nCOMMIT\n", Observed: true}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.Firewall.Accepted {
		t.Fatal("unowned firewall contribution accepted")
	}
	commands["pgrep"] = OperationResult{Fact: "1234", Observed: true}
	if facts := adapter.PreflightSubscription(t.Context(), "8.8.8.8"); facts.RenewalIdle.Accepted {
		t.Fatal("active renewal accepted")
	}
	adapter.subscriptionBind = nil
	listener, err := net.Listen("tcp4", "127.0.0.1:8443")
	if err != nil {
		t.Skipf("cannot reserve port for local conflict check: %v", err)
	}
	defer listener.Close()
	if facts := adapter.PreflightSubscription(t.Context(), "127.0.0.1"); facts.TCP8443.Accepted {
		t.Fatal("occupied TCP 8443 accepted")
	}
}

func TestSubscriptionReviewLockNeverCreatesFiles(t *testing.T) {
	adapter, _ := subscriptionReviewHost(t)
	name := "/run/lock/sbxr.lock"
	if lock, _, err := adapter.AcquireSubscriptionReviewLock(name); err == nil {
		lock.Release()
		t.Fatal("absent lock accepted")
	}
	entries, _ := os.ReadDir(adapter.root)
	if len(entries) != 0 {
		t.Fatal("read-only refusal created lock parents")
	}
	path := filepath.Join(adapter.root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, busy, err := adapter.AcquireSubscriptionReviewLock(name)
	if err != nil || busy || !lock.Holds(path) {
		t.Fatalf("existing lock: %v %v", busy, err)
	}
	defer lock.Release()
	if other, busy, err := adapter.AcquireSubscriptionReviewLock(name); err != nil || !busy {
		other.Release()
		t.Fatalf("held lock: %v %v", busy, err)
	}
}
