//go:build linux && amd64 && sbxr_snapshot_recovery

package proxyinstallation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

// Exercises the separately built helper and retained original amd64 executable.
// ipify and snap metadata are explicit local fixtures; systemd, TLS, the product
// processes, locks, filesystem, dpkg and Complete removal are real.
func TestSnapshotRecoveryExecutableHandoff(t *testing.T) {
	snapshotRecoveryExecutableHandoff(t, false)
}

func TestSnapshotRecoveryPostRebootExecutableHandoff(t *testing.T) {
	snapshotRecoveryExecutableHandoff(t, true)
}

func snapshotRecoveryExecutableHandoff(t *testing.T, postReboot bool) {
	requireIsolatedVM(t)
	artifacts := os.Getenv("SBXR_RECOVERY_ARTIFACTS")
	if artifacts == "" || !filepath.IsAbs(artifacts) {
		t.Fatal("absolute SBXR_RECOVERY_ARTIFACTS required")
	}
	original, err := os.ReadFile(filepath.Join(artifacts, "sbxr"))
	if err != nil || recoveryDigest(original) != RecoveryExecutableSHA256 {
		t.Fatal("exact retained executable required")
	}
	h, _, oldState := isolatedFixture(t)
	record, _ := decodeOwnership(h.ownership)
	h.publishTarget()
	record.Serving = &h.published
	record.Release = recoveryRelease
	// The retained executable predates boot provisioning. Keep this fixture's
	// complete record in its original supported shape, even as new setup evolves.
	record.LockProvisioning = nil
	record.ResourceCreatingReleases = nil
	record.SubscriptionResources = ptrRecoveryResources(hostadapter.SubscriptionResourcesForEnablement(record.PublicIPv4, hostadapter.SubscriptionPreflight{SnapdInstalled: true, CertbotInstalled: true, RecorderDirectoryCreated: true}))
	updateSubscriptionResources(&record, recoveryRelease)
	if !validOwnership(record) {
		t.Fatal("fixture ownership invalid")
	}
	ownership := ownershipBytes(record)
	isolatedWrite(t, hostSetupSpec.OwnershipPath, ownership, 0600)
	isolatedWrite(t, "/usr/local/bin/sbxr", original, 0755)
	installed := []byte(`{"schema":1,"repository":"albertloky/SBXR","tag":"v3.1.75","commit":"cf2e89aae5cfa56ae316505d24f16d50b8a25069","release_index_sha256":"3b4026ca92c6af03367c6b638df2e574e9a607dde5f09c613b6e6da1763b34b9","sequence":153,"architecture":"amd64","executable_sha256":"` + RecoveryExecutableSHA256 + `"}` + "\n")
	isolatedWrite(t, "/var/lib/sbxr/installed.json", installed, 0600)
	var source struct {
		Serving hostadapter.ServingAuthority `json:"serving"`
	}
	json.Unmarshal(oldState, &source)
	mode := "active-serving-v1"
	if postReboot {
		mode = "post-reboot-quiescent-v1"
	}
	plan := SnapshotRecoveryPlan{
		Schema: 1, ServiceMode: mode, ExecutableSHA256: RecoveryExecutableSHA256,
		InstalledSHA256: recoveryDigest(installed), OwnershipSHA256: recoveryDigest(ownership),
		SourceSHA256: recoveryDigest(oldState), TargetSHA256: recoveryDigest(recoveryState(*record.Serving)), Source: source.Serving,
	}
	planBytes, _ := json.Marshal(plan)
	isolatedWrite(t, filepath.Join(artifacts, "plan.json"), append(planBytes, '\n'), 0600)
	isolatedWrite(t, filepath.Join(artifacts, "source.json"), oldState, 0600)
	isolatedWrite(t, filepath.Join(artifacts, "target.json"), recoveryState(*record.Serving), 0600)

	// Extra disposable resources are always unwound, including failed assertions.
	extra := []string{filepath.Dir(hostadapter.RenewalDropInPath), "/etc/systemd/system/snap.certbot.renew.service", "/etc/systemd/system/snap.certbot.renew.timer", hostadapter.SubscriptionFirewallUnitPath, hostSetupSpec.APTKeyPath, hostSetupSpec.APTSourcePath, "/etc/ssl/certs/sbxr-ipify.pem", "/root/sbxr-v3175-recovery"}
	for _, p := range extra {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("extra fixture already exists: %s", p)
		}
	}
	snapOriginal, snapErr := os.ReadFile("/usr/bin/snap")
	if snapErr != nil && !os.IsNotExist(snapErr) {
		t.Fatal(snapErr)
	}
	hosts, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, u := range []string{"snap.certbot.renew.timer", "snap.certbot.renew.service", "sbxr-subscription-firewall.service"} {
			exec.Command("systemctl", "disable", "--now", u).Run()
		}
		// Base fixture stops subscription too, but do so before deleting package data.
		exec.Command("systemctl", "stop", "sbxr-subscription.service", "sing-box.service").Run()
		exec.Command("apt-mark", "unhold", "sing-box").Run()
		exec.Command("dpkg", "--purge", "sing-box").Run()
		exec.Command("userdel", "sing-box").Run()
		for _, p := range append(extra, "/var/lib/sing-box") {
			if err := os.RemoveAll(p); err != nil {
				t.Errorf("fixture cleanup %s: %v", p, err)
			}
		}
		if err := os.WriteFile("/etc/hosts", hosts, 0644); err != nil {
			t.Errorf("restore hosts: %v", err)
		}
		if snapErr == nil {
			if err := os.WriteFile("/usr/bin/snap", snapOriginal, 0755); err != nil {
				t.Errorf("restore snap: %v", err)
			}
		} else if err := os.Remove("/usr/bin/snap"); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove snap fixture: %v", err)
		}
		if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Errorf("fixture reload: %v %s", err, output)
		}
		// Cleanup attempts above may legitimately report already absent resources.
		// Check their desired postconditions instead of hiding real cleanup failures.
		for _, unit := range []string{"snap.certbot.renew.timer", "snap.certbot.renew.service", "sbxr-subscription-firewall.service", "sing-box.service", "sbxr-subscription.service"} {
			output, err := exec.Command("systemctl", "show", "--property=ActiveState", "--value", unit).CombinedOutput()
			if err == nil && strings.TrimSpace(string(output)) == "failed" {
				if reset, resetErr := exec.Command("systemctl", "reset-failed", unit).CombinedOutput(); resetErr != nil {
					t.Errorf("fixture failed-state cleanup %s: %v %s", unit, resetErr, reset)
				}
				output, err = exec.Command("systemctl", "show", "--property=ActiveState", "--value", unit).CombinedOutput()
			}
			if err != nil || strings.TrimSpace(string(output)) != "inactive" {
				t.Errorf("fixture unit remains: %s %v %s", unit, err, output)
			}
		}
		if output, err := exec.Command("dpkg-query", "--show", "--showformat=${db:Status-Abbrev}", "sing-box").CombinedOutput(); err == nil || !strings.Contains(string(output), "no packages found") {
			t.Errorf("fixture package remains: %v %s", err, output)
		}
		if output, err := exec.Command("getent", "passwd", "sing-box").CombinedOutput(); err == nil || len(output) != 0 {
			t.Errorf("fixture user remains: %v %s", err, output)
		}
	})
	// The installed package and its removal scripts are the pinned real .deb.
	packageBytes, err := os.ReadFile(filepath.Join(artifacts, "sing-box.deb"))
	if err != nil || recoveryDigest(packageBytes) != hostSetupSpec.PackageSHA256 {
		t.Fatal("pinned package required")
	}
	if err := os.Remove("/etc/systemd/system/sing-box.service"); err != nil {
		t.Fatal(err)
	}
	configuration, err := os.ReadFile("/etc/sing-box/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove("/etc/sing-box/config.json"); err != nil {
		t.Fatal(err)
	}
	isolatedCommand(t, "dpkg", "-i", filepath.Join(artifacts, "sing-box.deb"))
	isolatedWrite(t, "/etc/sing-box/config.json", configuration, 0640)
	isolatedCommand(t, "systemctl", "disable", "--now", "sing-box.service")
	isolatedCommand(t, "apt-mark", "hold", "sing-box")
	isolatedCommand(t, "chown", "root:sing-box", "/etc/sing-box/config.json")
	if err := os.MkdirAll("/var/lib/sing-box", 0755); err != nil {
		t.Fatal(err)
	}
	isolatedCommand(t, "chown", "sing-box:sing-box", "/var/lib/sing-box")
	key, _ := os.ReadFile(filepath.Join(artifacts, "sagernet.asc"))
	if recoveryDigest(key) != hostSetupSpec.APTKeySHA256 {
		t.Fatal("pinned APT key required")
	}
	isolatedWrite(t, hostSetupSpec.APTKeyPath, key, 0644)
	isolatedWrite(t, hostSetupSpec.APTSourcePath, aptSourceBody, 0644)
	for path, fixture := range map[string]struct {
		body string
		mode os.FileMode
	}{
		hostadapter.RenewalDropInPath:                    {hostadapter.RenewalDropIn, 0644},
		hostadapter.RenewalDeployHookPath:                {hostadapter.RenewalDeployHook, 0700},
		hostadapter.RenewalPostHookPath:                  {hostadapter.RenewalPostHook, 0700},
		hostadapter.RenewalEvidencePath:                  {`{"schema":1,"recorder_id":"` + record.Renewal.RecorderID + `","established_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","attempts":[]}` + "\n", 0600},
		hostadapter.RenewalAdmissionPath:                 {"sbxr renewal admission v1\n", 0600},
		hostadapter.RenewalWriterPath:                    {"sbxr renewal writer v1\n", 0600},
		"/etc/systemd/system/snap.certbot.renew.service": {"[Service]\nType=oneshot\nExecStart=/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew\n", 0644},
		// Two daily slots comfortably away from this test; no issuance command exists.
		"/etc/systemd/system/snap.certbot.renew.timer": {"[Timer]\nOnCalendar=*-*-* 01:00:00\nOnCalendar=*-*-* 13:00:00\nUnit=snap.certbot.renew.service\n[Install]\nWantedBy=timers.target\n", 0644},
		"/usr/bin/snap": {"#!/bin/sh\ncase \"$*\" in\n 'list certbot --unicode=always --color=never') printf 'Name Version Rev Tracking Publisher Notes\\ncertbot 5.8.0 5000 latest/stable certbot-eff✓ classic\\n';;\n changes) printf 'ID Status Spawn Ready Summary\\n';;\n *) exit 99;;\nesac\n", 0755},
	} {
		isolatedWrite(t, path, []byte(fixture.body), fixture.mode)
	}
	// The production helper reconstructs and validates this fixed unit itself.
	firewall := recoveryFirewall(record.PublicIPv4)
	if recoveryDigest([]byte(firewall)) != record.SubscriptionResources.FirewallSHA256 {
		t.Fatal("firewall fixture drift")
	}
	isolatedWrite(t, hostadapter.SubscriptionFirewallUnitPath, []byte(firewall), 0644)
	// ipify is served through normal TLS using the local fixture CA.
	caPEM, _ := os.ReadFile("/etc/letsencrypt/archive/sbxr-subscription/chain1.pem")
	block, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(block.Bytes)
	keyPEM, _ := os.ReadFile("/etc/letsencrypt/archive/sbxr-subscription/privkey1.pem")
	block, _ = pem.Decode(keyPEM)
	private, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	caKey := private.(*ecdsa.PrivateKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(91), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"api.ipify.org"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp4", "127.0.0.2:19443", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(record.PublicIPv4)) })}
	go server.Serve(listener)
	natRule := []string{"-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.2/32", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "127.0.0.2:19443"}
	isolatedCommand(t, "iptables", natRule...)
	t.Cleanup(func() {
		natRule[2] = "-D"
		if output, err := exec.Command("iptables", natRule...).CombinedOutput(); err != nil {
			t.Errorf("fixture NAT cleanup: %v %s", err, output)
		}
	})
	t.Cleanup(func() { server.Close() })
	isolatedWrite(t, "/etc/hosts", append(hosts, []byte("\n127.0.0.2 api.ipify.org\n")...), 0644)
	isolatedCommand(t, "systemctl", "daemon-reload")
	isolatedCommand(t, "systemctl", "enable", "--now", "snap.certbot.renew.timer", "sbxr-subscription-firewall.service")
	isolatedCommand(t, "systemctl", "start", "sbxr-subscription.service")
	// Type=simple is not readiness. Use the same bound as production.
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, e := net.DialTimeout("tcp4", "8.8.8.8:8443", time.Second)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original serving process did not bind")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if postReboot {
		// Reproduce the observed boot shape with the original executable: the
		// volatile lock is absent, serving exits 1, and the recorder exits 125
		// before its issuer. The real installed proxy remains running.
		isolatedCommand(t, "systemctl", "enable", "sing-box.service")
		isolatedCommand(t, "systemctl", "start", "sing-box.service")
		isolatedCommand(t, "systemctl", "stop", "sbxr-subscription.service")
		if err := os.Remove("/run/lock/sbxr.lock"); err != nil {
			t.Fatal(err)
		}
		for _, unit := range []string{"sbxr-subscription.service", "snap.certbot.renew.service"} {
			// Type=simple start may finish before its process fails; inspect the
			// actual terminal state rather than assuming a systemctl exit code.
			exec.Command("systemctl", "start", unit).Run()
			deadline := time.Now().Add(15 * time.Second)
			for strings.TrimSpace(isolatedCommand(t, "systemctl", "show", "--property=ActiveState", "--value", unit)) != "failed" {
				if time.Now().After(deadline) {
					t.Fatalf("original %s did not fail for missing lock", unit)
				}
				time.Sleep(25 * time.Millisecond)
			}
		}
		if _, err := os.Lstat("/run/lock/sbxr.lock"); !os.IsNotExist(err) {
			t.Fatal("original failed starts recreated the missing lock")
		}
	}
	driverBudget := 10 * time.Minute
	if !postReboot {
		// The original server's request budget requires three 60-second
		// refills and one 30-second refill in rehearse.py. Preserve the same
		// execution allowance in addition to that deliberate idle time.
		driverBudget += 3*time.Minute + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(t.Context(), driverBudget)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", filepath.Join(artifacts, "rehearse.py"), artifacts)
	if postReboot {
		// Exercise the exact temporary permission window needed on the VPS.
		// The base fixture still restores its original mode on every exit.
		if err := os.Chmod("/var/log", 0775); err != nil {
			t.Fatal(err)
		}
		windowState := filepath.Join(artifacts, "log-parent.before")
		if _, err := os.Lstat(windowState); !os.IsNotExist(err) {
			t.Fatal("unexpected existing log-parent window state")
		}
		command = exec.CommandContext(ctx, "bash", filepath.Join(artifacts, "with-protected-log-parent.sh"),
			"run", windowState, "--", "timeout", "--foreground", "--signal=TERM", "--kill-after=15s", "1200",
			"python3", filepath.Join(artifacts, "rehearse.py"), artifacts)
		// Let the wrapper terminate its private process group and restore the
		// original permissions before any Go fixture cleanup runs.
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		command.WaitDelay = 20 * time.Second
	}
	logFile, err := os.OpenFile(filepath.Join(artifacts, "rehearsal.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr = logFile, logFile
	err = command.Run()
	if closeErr := logFile.Close(); closeErr != nil {
		t.Error(closeErr)
	}
	output, readErr := os.ReadFile(filepath.Join(artifacts, "rehearsal.log"))
	if readErr != nil {
		t.Error(readErr)
	}
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
	if postReboot {
		info, err := os.Stat("/var/log")
		if err != nil || info.Mode().Perm() != 0775 {
			t.Fatal("log-parent window did not restore the original permissions")
		}
		if _, err := os.Lstat(filepath.Join(artifacts, "log-parent.before")); !os.IsNotExist(err) {
			t.Fatal("log-parent window retained unexpected state")
		}
	}
}
func ptrRecoveryResources(r hostadapter.SubscriptionResourceAuthority) *hostadapter.SubscriptionResourceAuthority {
	return &r
}
func recoveryFirewall(ip string) string {
	r80 := `-d ` + ip + `/32 -p tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT`
	r8443 := `-d ` + ip + `/32 -p tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT`
	command := `/usr/sbin/iptables -w`
	return "[Unit]\nDescription=SBXR Subscription Firewall\nBefore=sbxr-subscription.service snap.certbot.renew.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -ec '" + command + " -C INPUT " + r80 + " || " + command + " -I INPUT 1 " + r80 + "'\nExecStart=/bin/sh -ec '" + command + " -C INPUT " + r8443 + " || " + command + " -I INPUT 1 " + r8443 + "'\nExecStop=/bin/sh -ec 'while " + command + " -C INPUT " + r8443 + "; do " + command + " -D INPUT " + r8443 + "; done'\nExecStop=/bin/sh -ec 'while " + command + " -C INPUT " + r80 + "; do " + command + " -D INPUT " + r80 + "; done'\n\n[Install]\nWantedBy=multi-user.target\n"
}
