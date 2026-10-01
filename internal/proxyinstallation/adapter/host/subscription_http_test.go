package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func httpSubscriptionFixture(t *testing.T) (Adapter, *bool) {
	t.Helper()
	a := Adapter{root: t.TempDir(), subscriptionBind: func(_, port string) bool {
		if port != "8443" {
			t.Fatal("HTTP inspected certificate challenge port")
		}
		return true
	}, packageLocksAvailable: func() bool { return true }}
	for _, dir := range []string{"/etc/systemd/system", "/etc/systemd/system/multi-user.target.wants", "/var/lib/sbxr"} {
		mode := os.FileMode(0755)
		if dir == "/var/lib/sbxr" {
			mode = 0700
		}
		if err := os.MkdirAll(a.path(dir), mode); err != nil {
			t.Fatal(err)
		}
	}
	firewall := false
	a.subscriptionCommand = func(_ context.Context, name string, args ...string) (string, int, bool) {
		switch name {
		case "iptables-save":
			rules := "*filter\n:INPUT ACCEPT [0:0]\n"
			if firewall {
				rules += "-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n"
			}
			return rules + "COMMIT\n", 0, true
		case "systemctl":
			if slices.Equal(args, []string{"enable", "--now", "sbxr-subscription-firewall.service"}) {
				firewall = true
			}
			if slices.Equal(args, []string{"disable", "--now", "sbxr-subscription-firewall.service"}) {
				firewall = false
			}
			return "", 0, true
		default:
			t.Fatalf("HTTP invoked unrelated command %s", name)
			return "", 1, true
		}
	}
	return a, &firewall
}

func TestHTTPSubscriptionPreparationAndEveryInterruptedCheckpointCleanOnlyOwnedFiles(t *testing.T) {
	checkpoints := []int{1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 22}
	for _, failAt := range append(slices.Clone(checkpoints), 0) {
		t.Run(string(rune('A'+failAt)), func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			// Unrelated CA state is deliberately uninspectable to the old TLS admission.
			unrelated := a.path("/etc/letsencrypt/owner-marker")
			if err := os.MkdirAll(filepath.Dir(unrelated), 0775); err != nil || os.WriteFile(unrelated, []byte("preserve owner CA state\n"), 0600) != nil {
				t.Fatal("CA fixture")
			}
			credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: digest(credential)}
			resources := SubscriptionResourcesForEnablement("8.8.8.8", a.PreflightHTTPSubscription(t.Context(), "8.8.8.8"))
			last := 0
			input := SubscriptionEnableInput{PublicIPv4: "8.8.8.8", Credential: credential, Serving: serving, Resources: resources, Authorize: func(next int, _ *ServingAuthority) bool { last = next; return next != failAt }}
			result := a.PrepareSubscription(t.Context(), input)
			if result.Prepared != (failAt == 0) {
				t.Fatalf("preparation at %d: %v", last, result.Prepared)
			}
			if failAt == 0 {
				if result.Renewal != (RenewalAuthority{}) || !a.safelyAbsent(servingArchive) || !a.safelyAbsent(RenewalDropInPath) || !a.InspectServingFiles(serving, true).Accepted {
					t.Fatal("HTTP created certificate authority or unsafe serving state")
				}
				// systemd supplies this link on activation; exercise its real protected-file inspection.
				if err := os.Symlink("../sbxr-subscription.service", a.path(ServingUnitWantsPath)); err != nil {
					t.Fatal(err)
				}
				if !a.InspectServingFiles(serving, false).Accepted {
					t.Fatal("complete HTTP footprint refused")
				}
				link, ok := a.ReadSubscriptionLink(serving, "8.8.8.8")
				if !ok || !strings.HasPrefix(string(link), "http://8.8.8.8:8443/s/") {
					t.Fatal("HTTP link not emitted")
				}
			}
			if !a.CleanupPreparedSubscription(t.Context(), SubscriptionCleanupInput{Checkpoint: last, LinkID: serving.LinkID, CredentialSHA256: serving.CredentialSHA256, Resources: &resources, Serving: &serving}) {
				t.Fatalf("cleanup refused checkpoint %d", last)
			}
			body, err := os.ReadFile(unrelated)
			if err != nil || string(body) != "preserve owner CA state\n" {
				t.Fatal("HTTP cleanup disturbed unrelated CA state")
			}
		})
	}
}

func TestHTTPAuthorityRejectsCertificateAndDependencyClaims(t *testing.T) {
	serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: strings.Repeat("b", 64)}
	if !serving.Valid() {
		t.Fatal("HTTP authority refused")
	}
	serving.CertificateGeneration = 1
	if serving.Valid() {
		t.Fatal("mixed HTTP/certificate authority accepted")
	}
	resources := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
	resources.CertbotCreated = true
	if resources.Valid() {
		t.Fatal("HTTP admitted Certbot dependency removal authority")
	}
}

func TestFreshHTTPActivationAllowsOnlyMissingEnablementLink(t *testing.T) {
	for _, missing := range []string{"", ServingTokenPath, ServingStatePath, ServingUnitPath, ServingStagingPath, "foreign enablement link", "writable enablement parent", "symlinked enablement parent", "missing enablement parent", "foreign-owned enablement parent"} {
		t.Run(missing, func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: digest(credential)}
			resources := SubscriptionResourcesForEnablement("8.8.8.8", a.PreflightHTTPSubscription(t.Context(), "8.8.8.8"))
			prepared := a.PrepareSubscription(t.Context(), SubscriptionEnableInput{PublicIPv4: "8.8.8.8", Credential: credential, Serving: serving, Resources: resources, Authorize: func(int, *ServingAuthority) bool { return true }})
			if !prepared.Prepared || !a.safelyAbsent(ServingUnitWantsPath) {
				t.Fatal("fresh disabled serving preparation failed")
			}
			parent := filepath.Dir(a.path(ServingUnitWantsPath))
			if missing == "writable enablement parent" {
				if err := os.Chmod(parent, 0775); err != nil {
					t.Fatal(err)
				}
			} else if missing == "symlinked enablement parent" {
				if err := os.Rename(parent, parent+".foreign"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+".foreign", parent); err != nil {
					t.Fatal(err)
				}
			} else if missing == "missing enablement parent" {
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
			} else if missing == "foreign-owned enablement parent" {
				if os.Geteuid() != 0 {
					t.Skip("foreign ownership fixture requires root")
				}
				if err := os.Chown(parent, 1, -1); err != nil {
					t.Fatal(err)
				}
			} else if missing == "foreign enablement link" {
				if err := os.Symlink("../foreign.service", a.path(ServingUnitWantsPath)); err != nil {
					t.Fatal(err)
				}
			} else if missing != "" {
				if err := os.Remove(a.path(missing)); err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			run := a.subscriptionCommand
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && slices.Equal(args, []string{"enable", "--now", "sbxr-subscription.service"}) {
					starts++
					if err := os.Symlink("../sbxr-subscription.service", a.path(ServingUnitWantsPath)); err != nil {
						t.Fatal(err)
					}
				}
				return run(ctx, name, args...)
			}
			a.servingLoaded = func(context.Context, RenewalAuthority, ServingAuthority, ServingAuthority) (ServingAuthority, bool) {
				if starts == 1 {
					return serving, true
				}
				return ServingAuthority{}, true
			}
			ok := a.ActivatePreparedSubscription(t.Context(), serving, RenewalAuthority{PublicIPv4: "8.8.8.8"})
			if ok != (missing == "") || starts != 0 && missing != "" || ok && !a.InspectPreparedSubscription(t.Context(), serving, RenewalAuthority{PublicIPv4: "8.8.8.8"}).Accepted {
				t.Fatalf("activation accepted=%v starts=%d", ok, starts)
			}
		})
	}
}
