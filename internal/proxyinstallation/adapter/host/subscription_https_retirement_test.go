package host

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func httpsRetirementFixture(t *testing.T) (Adapter, HTTPSRetirementAuthority, ServingAuthority) {
	t.Helper()
	a, serving := servingFiles(t)
	renewalAdapter, renewal := renewalFiles(t)
	configuration := "archive_dir = " + servingArchive + "\n"
	for _, name := range certificateNames {
		configuration += name + " = " + servingLive + "/" + name + ".pem\n"
	}
	evidence, err := os.ReadFile(renewalAdapter.path(RenewalEvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	retired := HTTPSRetirementAuthority{Serving: serving, Renewal: renewal, Resources: SubscriptionResourcesForEnablement(renewal.PublicIPv4, SubscriptionPreflight{}), ConfigurationMode: 0600, ConfigurationSHA256: digest([]byte(configuration)), EvidenceSHA256: digest(evidence)}
	if !retired.Valid() || len(retired.ResourcesList()) != 20 {
		t.Fatal("retirement authority fixture")
	}
	if os.Mkdir(a.path(HTTPSRetirementDirectory), 0700) != nil || os.WriteFile(a.path(HTTPSRetirementDirectory+"/renewal.conf"), []byte(configuration), 0600) != nil {
		t.Fatal("retired configuration fixture")
	}
	destinations := map[string]string{RenewalDropInPath: HTTPSRetirementDirectory + "/recorder.conf", RenewalDeployHookPath: HTTPSRetirementDirectory + "/deploy-hook", RenewalPostHookPath: HTTPSRetirementDirectory + "/post-hook"}
	for _, path := range []string{RenewalDropInPath, RenewalDeployHookPath, RenewalPostHookPath, RenewalEvidencePath, RenewalAdmissionPath, RenewalWriterPath} {
		body, err := os.ReadFile(renewalAdapter.path(path))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(renewalAdapter.path(path))
		if err != nil {
			t.Fatal(err)
		}
		destination := path
		if backup, ok := destinations[path]; ok {
			destination = backup
		}
		if os.MkdirAll(filepath.Dir(a.path(destination)), 0755) != nil || os.WriteFile(a.path(destination), body, info.Mode().Perm()) != nil {
			t.Fatal("retained renewal fixture")
		}
	}
	target := ServingAuthority{HTTP: true, LinkID: serving.LinkID, CredentialSHA256: serving.CredentialSHA256}
	resources := SubscriptionResourcesForEnablement(renewal.PublicIPv4, SubscriptionPreflight{HTTP: true})
	if os.WriteFile(a.path(ServingStatePath), servingStateBytes(target), 0600) != nil || os.WriteFile(a.path(SubscriptionFirewallUnitPath), []byte(subscriptionResourceUnit(resources)), 0644) != nil {
		t.Fatal("HTTP fixture")
	}
	firewall := true
	a.subscriptionCommand = func(_ context.Context, name string, args ...string) (string, int, bool) {
		if value, ok := firewallFixtureProperty(a, resources, name, args); ok {
			return value, 0, true
		}
		if name == "iptables-save" {
			body := "*filter\n:INPUT ACCEPT [0:0]\n"
			if firewall {
				body += "-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n"
			}
			return body + "COMMIT\n", 0, true
		}
		if name == "systemctl" && slices.Equal(args, []string{"stop", "sbxr-subscription-firewall.service"}) {
			firewall = false
		}
		return "", 0, true
	}
	if !a.InspectHTTPSRetirement(retired, false) {
		t.Fatal("retained state fixture")
	}
	exclusion, ok := a.AcquireHTTPSRetirementExclusion(retired, false)
	if !ok {
		t.Fatal("retirement exclusion fixture")
	}
	t.Cleanup(exclusion.Release)
	return a, retired, target
}

func TestHTTPSRetirementCleanupPreservesUnrelatedCA(t *testing.T) {
	a, r, target := httpsRetirementFixture(t)
	shared, ok := a.AcquireServingExclusion()
	if !ok {
		t.Fatal("shared exclusion")
	}
	defer shared.Release()
	if !a.RemoveServingRuntime(t.Context(), target, shared) || !a.RemoveSubscriptionResources(t.Context(), SubscriptionResourcesForEnablement(r.Renewal.PublicIPv4, SubscriptionPreflight{HTTP: true}), &target) {
		t.Fatal("active HTTP cleanup")
	}
	if !a.InspectHTTPSRetirement(r, false) {
		t.Fatal("HTTP cleanup erased retained authority")
	}
	marker := "/etc/letsencrypt/accounts/unrelated/operator-marker"
	if os.MkdirAll(filepath.Dir(a.path(marker)), 0700) != nil || os.WriteFile(a.path(marker), []byte("unrelated CA account\n"), 0600) != nil {
		t.Fatal("CA account fixture")
	}
	if !a.RemoveHTTPSRetirement(t.Context(), r) || !a.RemoveHTTPSRetirement(t.Context(), r) {
		t.Fatal("retained cleanup")
	}
	for _, path := range []string{servingArchive, servingLive, HTTPSRetirementDirectory, RenewalEvidencePath, RenewalAdmissionPath, RenewalWriterPath} {
		if !a.safelyAbsent(path) {
			t.Fatalf("owned residue %s", path)
		}
	}
	if body, err := os.ReadFile(a.path(marker)); err != nil || string(body) != "unrelated CA account\n" {
		t.Fatal("unrelated CA state changed")
	}
	for _, path := range certbotDirectoryLocks {
		if _, err := os.Stat(a.path(path)); err != nil {
			t.Fatal("shared Certbot lock removed")
		}
	}
}

func TestHTTPSRetirementRejectsUnsafeHistoryBeforeRemoval(t *testing.T) {
	for _, defect := range []string{"symlink", "wrong mode", "hard link", "foreign owner", "newer generation"} {
		t.Run(defect, func(t *testing.T) {
			a, r, _ := httpsRetirementFixture(t)
			// Model a source that had accepted generation 2 while retaining 1.
			for _, name := range certificateNames {
				body, err := os.ReadFile(a.path(servingArchive + "/" + name + "1.pem"))
				mode := os.FileMode(0644)
				if name == "privkey" {
					mode = 0600
				}
				if err != nil || os.WriteFile(a.path(servingArchive+"/"+name+"2.pem"), body, mode) != nil || os.Remove(a.path(servingLive+"/"+name+".pem")) != nil || os.Symlink("../../archive/sbxr-subscription/"+name+"2.pem", a.path(servingLive+"/"+name+".pem")) != nil {
					t.Fatal("certificate history fixture")
				}
			}
			r.Serving.CertificateGeneration = 2
			if !a.InspectHTTPSRetirement(r, false) {
				t.Fatal("safe history refused")
			}
			path := a.path(servingArchive + "/cert1.pem")
			switch defect {
			case "symlink":
				if os.Remove(path) != nil || os.Symlink("cert2.pem", path) != nil {
					t.Fatal("symlink fixture")
				}
			case "wrong mode":
				if os.Chmod(path, 0666) != nil {
					t.Fatal("mode fixture")
				}
			case "hard link":
				if os.Link(path, a.path("/etc/letsencrypt/foreign-alias")) != nil {
					t.Fatal("link fixture")
				}
			case "foreign owner":
				if os.Geteuid() != 0 {
					t.Skip("requires root for foreign certificate owner fixture")
				}
				if os.Chown(path, 1, 1) != nil {
					t.Fatal("owner fixture")
				}
			case "newer generation":
				for _, name := range certificateNames {
					mode := os.FileMode(0644)
					if name == "privkey" {
						mode = 0600
					}
					if os.WriteFile(a.path(servingArchive+"/"+name+"3.pem"), []byte("orphan generation\n"), mode) != nil {
						t.Fatal("newer generation fixture")
					}
				}
			}
			if a.InspectHTTPSRetirement(r, false) || a.InspectHTTPSRetirement(r, true) {
				t.Fatal("unsafe history admitted before commitment")
			}
			if _, err := a.protectedServingFile(ServingTokenPath, 0600, ""); err != nil {
				t.Fatal("inspection changed token")
			}
			if _, err := a.protectedServingFile(SubscriptionFirewallUnitPath, 0644, ""); err != nil {
				t.Fatal("inspection changed HTTP firewall")
			}
		})
	}
}
