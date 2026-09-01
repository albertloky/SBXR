package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

func TestSubscriptionLinkRedisclosureRequiresExactProtectedCredential(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	directory := adapter.path("/var/lib/sbxr")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	token := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
	sum := sha256.Sum256(token)
	authority := ServingAuthority{LinkID: strings.Repeat("1", 32), CredentialSHA256: hex.EncodeToString(sum[:]), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64)}}
	if err := os.WriteFile(adapter.path(ServingTokenPath), append(token, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapter.path(ServingStatePath), servingStateBytes(authority), 0600); err != nil {
		t.Fatal(err)
	}
	link, ok := adapter.ReadSubscriptionLink(authority, "8.8.8.8")
	if !ok || string(link) != "https://8.8.8.8:8443/s/"+string(token) {
		t.Fatalf("link=%q ok=%t", link, ok)
	}
	if err := os.Chmod(adapter.path(ServingTokenPath), 0644); err != nil {
		t.Fatal(err)
	}
	if link, ok := adapter.ReadSubscriptionLink(authority, "8.8.8.8"); ok || len(link) != 0 {
		t.Fatal("unsafe credential was disclosed")
	}
	if err := os.Chmod(adapter.path(ServingTokenPath), 0600); err != nil {
		t.Fatal(err)
	}
	changed := authority
	changed.LinkID = strings.Repeat("6", 32)
	if err := os.WriteFile(adapter.path(ServingStatePath), servingStateBytes(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if link, ok := adapter.ReadSubscriptionLink(authority, "8.8.8.8"); ok || len(link) != 0 {
		t.Fatal("mismatched serving state was disclosed")
	}
}

func TestSubscriptionRotationKeepsSourceCanonicalUntilTargetPublication(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	if err := os.MkdirAll(adapter.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	sourceCredential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	targetCredential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	sourceDigest, targetDigest := sha256.Sum256(sourceCredential), sha256.Sum256(targetCredential)
	source := ServingAuthority{LinkID: strings.Repeat("1", 32), CredentialSHA256: hex.EncodeToString(sourceDigest[:]), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64)}}
	target := source
	target.LinkID, target.CredentialSHA256 = strings.Repeat("6", 32), hex.EncodeToString(targetDigest[:])
	for path, body := range map[string][]byte{ServingTokenPath: append(bytes.Clone(sourceCredential), '\n'), ServingStatePath: servingStateBytes(source)} {
		if err := os.WriteFile(adapter.path(path), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := SubscriptionRotationInput{Source: source, Target: target, Renewal: RenewalAuthority{RecorderID: strings.Repeat("7", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}, Credential: targetCredential}
	if !adapter.PrepareSubscriptionRotation(input) {
		t.Fatal("replacement preparation refused")
	}
	if link, ok := adapter.ReadSubscriptionLink(source, "8.8.8.8"); !ok || !bytes.Contains(link, sourceCredential) {
		t.Fatalf("source changed before commitment: %q %t", link, ok)
	}
	failed := false
	adapter.syncDirectoryFault = func(string) error {
		if !failed {
			failed = true
			return errors.New("late directory sync failure")
		}
		return nil
	}
	if adapter.PublishSubscriptionRotation(input) {
		t.Fatal("late directory sync failure reported success")
	}
	adapter.syncDirectoryFault = nil
	if !adapter.PublishSubscriptionRotation(input) || !adapter.SubscriptionRotationStagingEmpty() {
		t.Fatal("target publication refused")
	}
	if link, ok := adapter.ReadSubscriptionLink(target, "8.8.8.8"); !ok || !bytes.Contains(link, targetCredential) {
		t.Fatalf("target not authoritative: %q %t", link, ok)
	}
	if _, ok := adapter.ReadSubscriptionLink(source, "8.8.8.8"); ok {
		t.Fatal("source remained authoritative after commitment")
	}
}

func TestSubscriptionRotationQuiescenceIncludesProcessGroupAndListener(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	events := adapter.path(servingCgroup + "/cgroup.events")
	if err := os.MkdirAll(filepath.Dir(events), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(events, []byte("populated 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if adapter.ServingQuiescent() {
		t.Fatal("populated serving cgroup treated as quiescent")
	}
	if err := os.WriteFile(events, []byte("populated 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:8443")
	if err != nil {
		t.Skipf("cannot reserve TCP 8443: %v", err)
	}
	if adapter.ServingQuiescent() {
		t.Fatal("live listener treated as quiescent")
	}
	listener.Close()
	if !adapter.ServingQuiescent() {
		t.Fatal("empty cgroup and absent listener not proved quiescent")
	}
}

func TestCommittedRotationRemovalRequiresExclusionAndRefusesConflictingCanonicalMaterial(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	adapter.subscriptionCommand = func(_ context.Context, name string, arguments ...string) (string, int, bool) {
		if name != "systemctl" || !slices.Equal(arguments, []string{"disable", "--now", "sbxr-subscription.service"}) {
			t.Fatalf("unexpected command %s %v", name, arguments)
		}
		return "", 0, true
	}
	for _, path := range append(slices.Clone(certbotDirectoryLocks), servingCgroup+"/cgroup.events") {
		full := adapter.path(path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		body := []byte(nil)
		if strings.HasSuffix(path, "cgroup.events") {
			body = []byte("populated 0\n")
		}
		if err := os.WriteFile(full, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if !adapter.ServingQuiescent() {
		t.Skip("TCP 8443 is not available for the production quiescence check")
	}
	if err := os.MkdirAll(adapter.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	sourceCredential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	targetCredential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	sourceDigest, targetDigest := sha256.Sum256(sourceCredential), sha256.Sum256(targetCredential)
	source := ServingAuthority{LinkID: strings.Repeat("1", 32), CredentialSHA256: hex.EncodeToString(sourceDigest[:]), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64)}}
	target := source
	target.LinkID, target.CredentialSHA256 = strings.Repeat("6", 32), hex.EncodeToString(targetDigest[:])
	for path, body := range map[string][]byte{ServingTokenPath: append(bytes.Clone(sourceCredential), '\n'), ServingStatePath: servingStateBytes(source), SubscriptionCandidateTokenPath: append(bytes.Clone(targetCredential), '\n'), SubscriptionCandidateStatePath: servingStateBytes(target)} {
		if err := os.MkdirAll(filepath.Dir(adapter.path(path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(adapter.path(path), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := SubscriptionRotationInput{Source: source, Target: target, Renewal: RenewalAuthority{RecorderID: strings.Repeat("7", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}}
	if adapter.RemoveSubscriptionRotation(t.Context(), input, nil) {
		t.Fatal("rotation removal accepted no retained exclusion")
	}
	exclusion, ok := adapter.AcquireServingExclusion()
	if !ok {
		t.Fatal("serving exclusion refused")
	}
	defer exclusion.Release()
	conflict := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if err := os.WriteFile(adapter.path(ServingTokenPath), append(conflict, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if adapter.RemoveSubscriptionRotation(t.Context(), input, exclusion) {
		t.Fatal("rotation removal accepted conflicting canonical credential")
	}
	if err := os.WriteFile(adapter.path(ServingTokenPath), append(sourceCredential, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if !adapter.RemoveSubscriptionRotation(t.Context(), input, exclusion) || !adapter.safelyAbsent(ServingTokenPath) || !adapter.safelyAbsent(ServingStatePath) || !adapter.safelyAbsent(SubscriptionCandidateTokenPath) || !adapter.safelyAbsent(SubscriptionCandidateStatePath) {
		t.Fatal("proved source/target rotation material was not removed")
	}
}

func TestSubscriptionFirewallRequiresBothExactOwnedRules(t *testing.T) {
	adapter := Adapter{}
	adapter.subscriptionCommand = func(context.Context, string, ...string) (string, int, bool) {
		return "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT\n-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\nCOMMIT\n", 0, true
	}
	if !adapter.exactSubscriptionFirewall("8.8.8.8") {
		t.Fatal("exact firewall rules refused")
	}
	adapter.subscriptionCommand = func(context.Context, string, ...string) (string, int, bool) {
		return "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT\nCOMMIT\n", 0, true
	}
	if adapter.exactSubscriptionFirewall("8.8.8.8") {
		t.Fatal("partial firewall ownership accepted")
	}
}

func TestSubscriptionStagingRefusesExistingSymlink(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	if err := os.MkdirAll(adapter.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	target := adapter.path("/var/lib/sbxr/target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, adapter.path(ServingStagingPath)); err != nil {
		t.Fatal(err)
	}
	if adapter.prepareServingStaging() {
		t.Fatal("symlink staging path was accepted")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("target was changed: %v %v", info, err)
	}
}

func TestSubscriptionPublicationNeverReplacesUnexpectedCurrentValue(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	if err := os.MkdirAll(adapter.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	unexpected := []byte("unexpected current value\n")
	if err := os.WriteFile(adapter.path(ServingTokenPath), unexpected, 0600); err != nil {
		t.Fatal(err)
	}
	if adapter.publishSubscriptionFile(ServingTokenPath, []byte("authorized value\n"), 0600) {
		t.Fatal("unexpected current value was replaced")
	}
	current, err := os.ReadFile(adapter.path(ServingTokenPath))
	if err != nil || !bytes.Equal(current, unexpected) {
		t.Fatalf("current value changed: %q %v", current, err)
	}
}

func TestSubscriptionPublicationFinishesExactSynchronizedStaging(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	if err := os.MkdirAll(adapter.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("authorized value\n")
	if err := os.WriteFile(adapter.path(ServingTokenPath+".sbxr-next"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if !adapter.publishSubscriptionFile(ServingTokenPath, body, 0600) {
		t.Fatal("exact staged publication did not finish")
	}
	current, err := os.ReadFile(adapter.path(ServingTokenPath))
	if err != nil || !bytes.Equal(current, body) || !adapter.safelyAbsent(ServingTokenPath+".sbxr-next") {
		t.Fatalf("publication = %q err=%v", current, err)
	}
}

func TestSubscriptionCleanupRemovesExactFirewallAndRenewalStaging(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	for _, file := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{SubscriptionFirewallUnitPath, []byte(subscriptionFirewallUnit("8.8.8.8")), 0644},
		{RenewalDropInPath, []byte(RenewalDropIn), 0644},
	} {
		if err := os.MkdirAll(filepath.Dir(adapter.path(file.path)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(adapter.path(file.path+".sbxr-next"), file.body, file.mode); err != nil {
			t.Fatal(err)
		}
		if !adapter.removeSubscriptionPublication(file.path, file.body, file.mode) || !adapter.safelyAbsent(file.path+".sbxr-next") {
			t.Fatalf("pending publication remained for %s", file.path)
		}
	}
}

func TestSubscriptionFirewallUnitIsIdempotentAndRemovesExactDuplicates(t *testing.T) {
	unit := subscriptionFirewallUnit("8.8.8.8")
	for _, want := range []string{"-C INPUT -d 8.8.8.8/32", "while /usr/sbin/iptables -w -C INPUT", "-D INPUT -d 8.8.8.8/32"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q: %s", want, unit)
		}
	}
}

func TestInterruptedCertbotEffectRecoversExactServingAuthority(t *testing.T) {
	adapter, renewal := renewalFiles(t)
	installRenewalCertificate(t, adapter, renewal.PublicIPv4)
	credential := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
	sum := sha256.Sum256(credential)
	resources := SubscriptionResourceAuthority{PublicIPv4: renewal.PublicIPv4, FirewallSHA256: strings.Repeat("1", 64)}
	serving, ok := adapter.recoverEnablementServing(SubscriptionCleanupInput{
		Checkpoint: 7, LinkID: strings.Repeat("2", 32), CredentialSHA256: hex.EncodeToString(sum[:]), RecorderID: renewal.RecorderID, Resources: &resources,
	})
	if !ok || serving.CertificateGeneration != 1 || serving.LinkID != strings.Repeat("2", 32) || serving.CredentialSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("recovered = %#v ok=%t", serving, ok)
	}
}

func TestInterruptedCertbotEffectCleansExactPartialLineage(t *testing.T) {
	adapter := Adapter{root: t.TempDir()}
	for _, directory := range []string{servingArchive, servingLive} {
		if err := os.MkdirAll(adapter.path(directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(adapter.path(servingArchive+"/cert1.pem"), []byte("partial certificate\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../archive/sbxr-subscription/cert1.pem", adapter.path(servingLive+"/cert.pem")); err != nil {
		t.Fatal(err)
	}
	if !adapter.removeOwnedLineage(nil) || !adapter.safelyAbsent(servingArchive) || !adapter.safelyAbsent(servingLive) {
		t.Fatal("exact partial lineage was not cleaned")
	}
}
