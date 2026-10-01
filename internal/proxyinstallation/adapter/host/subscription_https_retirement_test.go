package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func httpsRetirementFixture(t *testing.T) (Adapter, HTTPSRetirementAuthority, ServingAuthority, *RenewalExclusion) {
	t.Helper()
	a, serving := servingFiles(t)
	renewalAdapter, renewal := renewalFiles(t)
	a.renewalCertificateValid = func(RenewalAuthority, int) bool { return true }
	paths := []string{RenewalDropInPath, RenewalDeployHookPath, RenewalPostHookPath, RenewalEvidencePath, RenewalAdmissionPath, RenewalWriterPath}
	for _, path := range paths {
		body, err := os.ReadFile(renewalAdapter.path(path))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(renewalAdapter.path(path))
		if err != nil {
			t.Fatal(err)
		}
		if os.MkdirAll(filepath.Dir(a.path(path)), 0755) != nil || os.WriteFile(a.path(path), body, info.Mode().Perm()) != nil {
			t.Fatal("renewal fixture")
		}
	}
	configuration := "archive_dir = " + servingArchive + "\n"
	for _, name := range certificateNames {
		configuration += name + " = " + servingLive + "/" + name + ".pem\n"
	}
	if os.MkdirAll(filepath.Dir(a.path(httpsRenewalConfiguration)), 0755) != nil || os.WriteFile(a.path(httpsRenewalConfiguration), []byte(configuration), 0600) != nil || os.WriteFile(a.path(SubscriptionFirewallUnitPath), []byte(subscriptionFirewallUnit(renewal.PublicIPv4)), 0644) != nil {
		t.Fatal("configuration fixture")
	}
	resources := SubscriptionResourcesForEnablement(renewal.PublicIPv4, SubscriptionPreflight{})
	legacyFirewall, httpFirewall := true, false
	loaded := ServingAuthority{}
	fallback := renewalAdapter.subscriptionCommand
	a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
		if name == "iptables-save" {
			body := "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
			for _, port := range []string{"80", "8443"} {
				if legacyFirewall || httpFirewall && port == "8443" {
					body += "-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport " + port + " -m comment --comment sbxr-subscription -j ACCEPT\n"
				}
			}
			return body + "COMMIT\n", 0, true
		}
		if name == "systemctl" {
			if slices.Equal(args, []string{"show", "--property=ExecStart", "--value", "snap.certbot.renew.service"}) {
				if a.safelyAbsent(RenewalDropInPath) {
					return "/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew\n", 0, true
				}
				return "/usr/local/bin/sbxr --certbot-recorder\n", 0, true
			}
			if slices.Equal(args, []string{"show", "--property=FragmentPath", "--value", "sbxr-subscription-firewall.service"}) {
				return SubscriptionFirewallUnitPath, 0, true
			}
			if slices.Equal(args, []string{"show", "--property=DropInPaths", "--value", "sbxr-subscription-firewall.service"}) {
				return "", 0, true
			}
			if slices.Equal(args, []string{"stop", "sbxr-subscription.service"}) {
				loaded = ServingAuthority{}
			}
			if slices.Equal(args, []string{"stop", "sbxr-subscription-firewall.service"}) {
				legacyFirewall, httpFirewall = false, false
			}
			if slices.Equal(args, []string{"enable", "--now", "sbxr-subscription-firewall.service"}) {
				legacyFirewall, httpFirewall = false, true
			}
			if slices.Equal(args, []string{"disable", "--now", "sbxr-subscription-firewall.service"}) {
				legacyFirewall, httpFirewall = false, false
			}
			if slices.Equal(args, []string{"enable", "--now", "sbxr-subscription.service"}) {
				loaded = ServingAuthority{HTTP: true, LinkID: serving.LinkID, CredentialSHA256: serving.CredentialSHA256}
			}
		}
		if name != "systemctl" && name != "snap" {
			t.Fatalf("migration invoked unrelated command %s %v", name, args)
		}
		return fallback(ctx, name, args...)
	}
	a.servingLoaded = func(context.Context, RenewalAuthority, ServingAuthority, ServingAuthority) (ServingAuthority, bool) {
		return loaded, true
	}
	exclusion, ok := a.AcquireRenewalExclusion(renewal)
	if !ok {
		t.Fatal("renewal exclusion")
	}
	t.Cleanup(exclusion.Release)
	retired, ok := a.SnapshotHTTPSRetirement(serving, renewal, resources, exclusion)
	if !ok {
		t.Fatal("retirement snapshot")
	}
	target := ServingAuthority{HTTP: true, LinkID: serving.LinkID, CredentialSHA256: serving.CredentialSHA256}
	return a, retired, target, exclusion
}

func TestHTTPSRetirementResumesEachCommandFailureAndRetainsExactCredentialsAndCertificates(t *testing.T) {
	for _, failure := range []int{0, 1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			a, r, target, exclusion := httpsRetirementFixture(t)
			token, _ := os.ReadFile(a.path(ServingTokenPath))
			before := map[string][]byte{}
			for _, name := range certificateNames {
				path := servingArchive + "/" + name + "1.pem"
				before[path], _ = os.ReadFile(a.path(path))
			}
			unrelated := a.path("/etc/letsencrypt/archive/unrelated")
			if os.Mkdir(unrelated, 0700) != nil {
				t.Fatal("unrelated fixture")
			}
			run := a.subscriptionCommand
			calls := 0
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && len(args) > 0 && args[0] != "show" {
					calls++
					if calls == failure {
						return "", 1, true
					}
				}
				return run(ctx, name, args...)
			}
			if ok := a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion); ok != (failure == 0) {
				t.Fatalf("interruption %d accepted=%v calls=%d", failure, ok, calls)
			}
			a.subscriptionCommand = run
			if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) || !a.InspectHTTPSRetirement(r, false) || !a.InspectPreparedSubscription(t.Context(), target, RenewalAuthority{PublicIPv4: r.Renewal.PublicIPv4}).Accepted {
				t.Fatal("forward retry refused")
			}
			current, _ := os.ReadFile(a.path(ServingTokenPath))
			if !bytes.Equal(current, token) {
				t.Fatal("token changed")
			}
			for path, body := range before {
				current, err := os.ReadFile(a.path(path))
				if err != nil || !bytes.Equal(current, body) {
					t.Fatal("certificate changed")
				}
			}
			if _, err := os.Stat(unrelated); err != nil {
				t.Fatal("unrelated lineage changed")
			}
		})
	}
}

func TestHTTPSRetirementRejectsUnknownBackupBeforeStopping(t *testing.T) {
	a, r, target, exclusion := httpsRetirementFixture(t)
	if os.Mkdir(a.path(HTTPSRetirementDirectory), 0700) != nil || os.WriteFile(a.path(HTTPSRetirementDirectory+"/renewal.conf"), []byte("foreign configuration\n"), 0600) != nil {
		t.Fatal("foreign backup fixture")
	}
	run := a.subscriptionCommand
	stops := 0
	a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
		if name == "systemctl" && len(args) > 0 && args[0] == "stop" {
			stops++
		}
		return run(ctx, name, args...)
	}
	if a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) || stops != 0 {
		t.Fatal("foreign backup adopted after stopping")
	}
}

func TestHTTPSRetirementResumesPartialProtectedPublications(t *testing.T) {
	for _, publication := range []string{"renewal.conf", "recorder.conf", "deploy-hook", "post-hook", "serving", "firewall"} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-empty=%v", publication, empty), func(t *testing.T) {
				a, r, target, exclusion := httpsRetirementFixture(t)
				path, body, mode := ServingStatePath, servingStateBytes(target), os.FileMode(0600)
				if publication == "firewall" {
					path, body, mode = SubscriptionFirewallUnitPath, []byte(httpSubscriptionFirewallUnit(r.Renewal.PublicIPv4)), 0644
				} else if publication != "serving" {
					if os.Mkdir(a.path(HTTPSRetirementDirectory), 0700) != nil {
						t.Fatal("retirement directory")
					}
					for _, p := range r.publications() {
						if filepath.Base(p.backup) == publication {
							path, mode = p.backup, p.mode
							body, _ = os.ReadFile(a.path(p.source))
						}
					}
				}
				partial := body[:len(body)/2]
				if empty {
					partial = nil
				}
				if os.WriteFile(a.path(path+".sbxr-next"), partial, mode) != nil {
					t.Fatal("interrupted write")
				}
				if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) || !a.InspectHTTPSRetirement(r, false) {
					t.Fatal("partial publication did not recover")
				}
			})
		}
	}
}

func TestHTTPMigrationOwnershipPublicationRemovalIsExactAndKeepsCurrent(t *testing.T) {
	for _, variant := range []string{"complete", "partial", "empty", "absent", "foreign", "wrong mode", "hard link", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			a := Adapter{root: t.TempDir()}
			if os.MkdirAll(a.path("/var/lib/sbxr"), 0700) != nil {
				t.Fatal("fixture")
			}
			current, next := []byte("current authority\n"), []byte("selected authority\n")
			currentPath, nextPath := a.path("/var/lib/sbxr/proxy-ownership.json"), a.path("/var/lib/sbxr/.proxy-ownership.json.next")
			if os.WriteFile(currentPath, current, 0600) != nil {
				t.Fatal("current fixture")
			}
			staged, mode := next, os.FileMode(0600)
			switch variant {
			case "partial":
				staged = next[:5]
			case "empty":
				staged = nil
			case "foreign":
				staged = []byte("foreign authority\n")
			case "wrong mode":
				mode = 0644
			}
			if variant != "absent" && variant != "symlink" && os.WriteFile(nextPath, staged, mode) != nil {
				t.Fatal("staging fixture")
			}
			if variant == "hard link" && os.Link(nextPath, a.path("/var/lib/sbxr/foreign-alias")) != nil {
				t.Fatal("link fixture")
			}
			if variant == "symlink" && os.Symlink(currentPath, nextPath) != nil {
				t.Fatal("symlink fixture")
			}
			accepted := variant == "complete" || variant == "partial" || variant == "empty" || variant == "absent"
			if a.DiscardHTTPMigrationPublication(current, next) != accepted {
				t.Fatal("publication selection not exact")
			}
			body, err := a.ReadOwnership("/var/lib/sbxr/proxy-ownership.json")
			if err != nil || !bytes.Equal(body, current) {
				t.Fatal("current authority removed")
			}
			if accepted && !a.safelyAbsent("/var/lib/sbxr/.proxy-ownership.json.next") {
				t.Fatal("selected publication remains")
			}
		})
	}
}

func TestHTTPSRetirementConfigurationRejectsForeignOrDuplicateLineagePaths(t *testing.T) {
	a, r, _, _ := httpsRetirementFixture(t)
	body, _ := os.ReadFile(a.path(httpsRenewalConfiguration))
	for _, wrong := range []string{strings.ReplaceAll(string(body), "sbxr-subscription", "foreign"), string(body) + "cert = " + servingLive + "/cert.pem\n"} {
		if ownedHTTPSRenewalConfiguration([]byte(wrong)) {
			t.Fatal("foreign or duplicate lineage adopted")
		}
	}
	if len(r.ResourcesList()) != 20 {
		t.Fatal("retirement resource contract changed")
	}
}

func TestHTTPSRetirementResumesEveryDirectorySyncFailure(t *testing.T) {
	a, r, target, exclusion := httpsRetirementFixture(t)
	count := 0
	a.syncDirectoryFault = func(string) error { count++; return nil }
	if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) || count == 0 {
		t.Fatal("successful migration fixture")
	}
	for failAt := 1; failAt <= count; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			a, r, target, exclusion := httpsRetirementFixture(t)
			calls := 0
			a.syncDirectoryFault = func(string) error {
				calls++
				if calls == failAt {
					return errors.New("interrupted directory sync")
				}
				return nil
			}
			if a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) {
				t.Fatal("incomplete directory sync accepted")
			}
			a.syncDirectoryFault = nil
			if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) || !a.InspectHTTPSRetirement(r, false) {
				t.Fatal("directory sync failure did not recover")
			}
		})
	}
}

func TestHTTPSRetirementCleanupResumesPartialRemovalAndPreservesUnrelatedCA(t *testing.T) {
	for _, missing := range []string{"", "certificate", "backup", "evidence", "admission", "writer"} {
		t.Run(missing, func(t *testing.T) {
			a, r, target, exclusion := httpsRetirementFixture(t)
			if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) {
				t.Fatal("migration fixture")
			}
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
			path := map[string]string{"certificate": servingArchive + "/cert1.pem", "backup": HTTPSRetirementDirectory + "/deploy-hook", "evidence": RenewalEvidencePath, "admission": RenewalAdmissionPath, "writer": RenewalWriterPath}[missing]
			if path != "" && os.Remove(a.path(path)) != nil {
				t.Fatal("partial cleanup")
			}
			if !a.RemoveHTTPSRetirement(t.Context(), r) || !a.RemoveHTTPSRetirement(t.Context(), r) {
				t.Fatal("retained cleanup retry")
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
		})
	}
}

func TestHTTPSRetirementRejectsUnsafeHistoryBeforeRemoval(t *testing.T) {
	for _, defect := range []string{"symlink", "wrong mode", "hard link", "foreign owner", "newer generation"} {
		t.Run(defect, func(t *testing.T) {
			a, r, target, exclusion := httpsRetirementFixture(t)
			if !a.MigrateHTTPSRetirement(t.Context(), r, target, exclusion) {
				t.Fatal("migration fixture")
			}
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

func TestHTTPSRetirementSnapshotRejectsNewerHistoryBeforeSelectingMigration(t *testing.T) {
	a, r, _, exclusion := httpsRetirementFixture(t)
	state, _ := os.ReadFile(a.path(ServingStatePath))
	for _, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if os.WriteFile(a.path(servingArchive+"/"+name+"2.pem"), []byte("unaccepted certificate generation\n"), mode) != nil {
			t.Fatal("history fixture")
		}
	}
	if _, accepted := a.SnapshotHTTPSRetirement(r.Serving, r.Renewal, r.Resources, exclusion); accepted {
		t.Fatal("unsafe source selected forward migration")
	}
	current, _ := os.ReadFile(a.path(ServingStatePath))
	if !bytes.Equal(current, state) || !a.safelyAbsent(HTTPSRetirementDirectory) {
		t.Fatal("refused snapshot changed source")
	}
}
