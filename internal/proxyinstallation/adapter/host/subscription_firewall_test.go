package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPPreparationRefusesForeignFirewallRoutesBeforeEnable(t *testing.T) {
	for _, variant := range []string{"drop-in", "alternate-fragment", "effective-drop-in", "effective-start", "foreign-link"} {
		t.Run(variant, func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			path := SubscriptionFirewallUnitPath + ".d/owner.conf"
			if variant == "alternate-fragment" {
				path = "/run/systemd/system/sbxr-subscription-firewall.service"
			}
			if variant == "drop-in" || variant == "alternate-fragment" {
				if err := os.MkdirAll(filepath.Dir(a.path(path)), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(a.path(path), []byte("[Service]\nExecStart=/bin/false\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "foreign-link" {
				if err := os.Symlink("../owner.service", a.path("/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service")); err != nil {
					t.Fatal(err)
				}
			}
			run := a.subscriptionCommand
			enabled := false
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && len(args) > 1 {
					if args[0] == "enable" {
						enabled = true
					}
					if args[1] == "--property=DropInPaths" && variant == "effective-drop-in" {
						return "/run/systemd/system/sbxr-subscription-firewall.service.d/owner.conf", 0, true
					}
					if args[1] == "--property=ExecStart" && variant == "effective-start" {
						return "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no }", 0, true
					}
				}
				return run(ctx, name, args...)
			}
			credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: digest(credential)}
			resources := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
			result := a.PrepareSubscription(t.Context(), SubscriptionEnableInput{PublicIPv4: "8.8.8.8", Credential: credential, Serving: serving, Resources: resources, Authorize: func(int, *ServingAuthority) bool { return true }})
			if result.Prepared || enabled {
				t.Fatal("foreign firewall route reached enable--now")
			}
		})
	}
}

func TestFirewallRemovalRemovesOnlyExactEnablementLinks(t *testing.T) {
	for _, variant := range []string{"dangling-owned", "foreign-link", "effective-stop"} {
		t.Run(variant, func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			authority := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
			unitPath := a.path(SubscriptionFirewallUnitPath)
			linkPath := a.path("/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service")
			target := "../sbxr-subscription-firewall.service"
			if variant == "foreign-link" {
				target = "../owner.service"
			}
			if err := os.Symlink(target, linkPath); err != nil {
				t.Fatal(err)
			}
			if variant == "effective-stop" {
				if err := os.WriteFile(unitPath, []byte(subscriptionResourceUnit(authority)), 0644); err != nil {
					t.Fatal(err)
				}
			}
			run := a.subscriptionCommand
			stopped := false
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && len(args) > 0 {
					if args[0] == "disable" || args[0] == "stop" {
						stopped = true
					}
					if len(args) > 1 && args[1] == "--property=ExecStop" && variant == "effective-stop" {
						return "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no }", 0, true
					}
				}
				return run(ctx, name, args...)
			}
			removed := a.RemoveSubscriptionResources(t.Context(), authority, nil)
			foreign := variant == "foreign-link" || variant == "effective-stop"
			if foreign {
				if removed || stopped {
					t.Fatal("foreign route reached stop or removal")
				}
				if _, err := os.Lstat(linkPath); err != nil {
					t.Fatal("foreign link removed")
				}
				return
			}
			if !removed {
				t.Fatal("owned dangling link refused")
			}
			if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
				t.Fatalf("owned firewall enablement link remains: %v", err)
			}
		})
	}
}

func TestFirewallRemovalRefusesCachedAuxiliaryCommandsBeforeEffects(t *testing.T) {
	for _, property := range []string{"ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStopPost"} {
		t.Run(property, func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			authority := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
			unit := []byte(subscriptionResourceUnit(authority))
			if err := os.WriteFile(a.path(SubscriptionFirewallUnitPath), unit, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../sbxr-subscription-firewall.service", a.path(SubscriptionFirewallWantsPath)); err != nil {
				t.Fatal(err)
			}
			run := a.subscriptionCommand
			stopped := false
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && len(args) > 1 {
					if args[0] == "disable" || args[0] == "stop" {
						stopped = true
					}
					if args[1] == "--property="+property {
						return "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no }", 0, true
					}
				}
				return run(ctx, name, args...)
			}
			if a.RemoveSubscriptionResources(t.Context(), authority, nil) || stopped {
				t.Fatal("cached auxiliary command reached stop or removal")
			}
			current, err := os.ReadFile(a.path(SubscriptionFirewallUnitPath))
			if err != nil || !bytes.Equal(current, unit) {
				t.Fatal("refusal changed owned unit")
			}
			target, err := os.Readlink(a.path(SubscriptionFirewallWantsPath))
			if err != nil || target != "../sbxr-subscription-firewall.service" {
				t.Fatal("refusal changed enablement link")
			}
		})
	}
}

func TestFirewallRemovalPreservesForeignAlias(t *testing.T) {
	a, _ := httpSubscriptionFixture(t)
	authority := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
	if err := os.WriteFile(a.path(SubscriptionFirewallUnitPath), []byte(subscriptionResourceUnit(authority)), 0644); err != nil {
		t.Fatal(err)
	}
	alias := a.path("/etc/systemd/system/owner-alias.service")
	target := "sbxr-subscription-firewall.service"
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	run := a.subscriptionCommand
	stopped := false
	a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
		if name == "systemctl" && len(args) > 0 {
			if args[0] == "stop" {
				stopped = true
			}
			// systemctl disable removes matching manually created aliases too.
			if args[0] == "disable" {
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
			}
		}
		return run(ctx, name, args...)
	}
	if !a.RemoveSubscriptionResources(t.Context(), authority, nil) {
		t.Fatal("canonical firewall removal refused")
	}
	actual, err := os.Readlink(alias)
	if err != nil || actual != target || !stopped {
		t.Fatal("firewall removal changed foreign alias or omitted exact stop")
	}
}

func TestFirewallRemovalDoesNotStopCachedUnitWithoutMainFile(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "inactive", true: "active"}[active], func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			authority := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
			if err := os.Symlink("../sbxr-subscription-firewall.service", a.path(SubscriptionFirewallWantsPath)); err != nil {
				t.Fatal(err)
			}
			run := a.subscriptionCommand
			stopped := false
			a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
				if name == "systemctl" && len(args) > 1 {
					if args[0] == "stop" || args[0] == "disable" {
						stopped = true
					}
					switch args[1] {
					case "--property=LoadState":
						return "loaded", 0, true
					case "--property=FragmentPath":
						return SubscriptionFirewallUnitPath, 0, true
					case "--property=ActiveState":
						if active {
							return "active", 0, true
						}
					case "--property=MainPID":
						if active {
							return "27", 0, true
						}
					}
				}
				return run(ctx, name, args...)
			}
			if removed := a.RemoveSubscriptionResources(t.Context(), authority, nil); removed == active || stopped {
				t.Fatal("cached unit without owned main file was stopped or incorrectly admitted")
			}
			_, err := os.Lstat(a.path(SubscriptionFirewallWantsPath))
			if active && err != nil || !active && !os.IsNotExist(err) {
				t.Fatal("absent-main cleanup did not preserve active residue or remove inactive owned link")
			}
		})
	}
}

func TestFirewallRemovalRefusesNonzeroServicePIDs(t *testing.T) {
	for _, property := range []string{"MainPID", "ControlPID"} {
		for _, absent := range []bool{false, true} {
			t.Run(property+map[bool]string{false: "/present", true: "/absent"}[absent], func(t *testing.T) {
				a, _ := httpSubscriptionFixture(t)
				authority := SubscriptionResourcesForEnablement("8.8.8.8", SubscriptionPreflight{HTTP: true})
				if !absent {
					if err := os.WriteFile(a.path(SubscriptionFirewallUnitPath), []byte(subscriptionResourceUnit(authority)), 0644); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("../sbxr-subscription-firewall.service", a.path(SubscriptionFirewallWantsPath)); err != nil {
					t.Fatal(err)
				}
				run := a.subscriptionCommand
				stopped := false
				a.subscriptionCommand = func(ctx context.Context, name string, args ...string) (string, int, bool) {
					if name == "systemctl" && len(args) > 1 {
						if args[0] == "disable" || args[0] == "stop" {
							stopped = true
						}
						if args[1] == "--property="+property {
							return "27", 0, true
						}
					}
					return run(ctx, name, args...)
				}
				if a.RemoveSubscriptionResources(t.Context(), authority, nil) || stopped {
					t.Fatal("nonzero service PID reached stop or removal")
				}
				if _, err := os.Lstat(a.path(SubscriptionFirewallWantsPath)); err != nil {
					t.Fatal("busy-unit refusal removed the owned link")
				}
			})
		}
	}
}

// The command fixtures expose systemd's structured effective execution values;
// the tests above independently substitute foreign properties before effects.
func firewallFixtureProperty(a Adapter, authority SubscriptionResourceAuthority, name string, args []string) (string, bool) {
	if name != "systemctl" || len(args) != 4 || args[0] != "show" || args[3] != "sbxr-subscription-firewall.service" {
		return "", false
	}
	property := strings.TrimPrefix(args[1], "--property=")
	absent := a.safelyAbsent(SubscriptionFirewallUnitPath)
	switch property {
	case "LoadState":
		if absent {
			return "not-found", true
		}
		return "loaded", true
	case "FragmentPath":
		if absent {
			return "", true
		}
		return SubscriptionFirewallUnitPath, true
	case "DropInPaths":
		return "", true
	case "MainPID", "ControlPID":
		return "0", true
	case "ActiveState":
		return "inactive", true
	case "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStopPost":
		return "", true
	case "ExecStart", "ExecStop":
		var entries []string
		for _, line := range strings.Split(subscriptionResourceUnit(authority), "\n") {
			if value, ok := strings.CutPrefix(line, property+"="); ok {
				value = strings.TrimSuffix(strings.Replace(value, "/bin/sh -ec '", "/bin/sh -ec ", 1), "'")
				entries = append(entries, "{ path=/bin/sh ; argv[]="+value+" ; ignore_errors=no }")
			}
		}
		return strings.Join(entries, " "), true
	}
	return "", false
}

func TestSubscriptionAbsenceRefusesFirewallFootprint(t *testing.T) {
	for _, residue := range []string{"", SubscriptionFirewallUnitPath + ".d/owner.conf", SubscriptionFirewallWantsPath, "/run/systemd/system/sbxr-subscription-firewall.service"} {
		t.Run(residue, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"systemctl", "ss", "iptables-save"} {
				body := "#!/bin/sh\nexit 0\n"
				if name == "systemctl" {
					body = "#!/bin/sh\nprintf 'not-found\\n'\n"
				}
				if name == "iptables-save" {
					body = "#!/bin/sh\nprintf '*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT\\n'\n"
				}
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			a := Adapter{root: root}
			if err := os.MkdirAll(a.path("/var/lib"), 0755); err != nil {
				t.Fatal(err)
			}
			if residue != "" {
				if err := os.MkdirAll(filepath.Dir(a.path(residue)), 0755); err != nil {
					t.Fatal(err)
				}
				if residue == SubscriptionFirewallWantsPath {
					if err := os.Symlink("../sbxr-subscription-firewall.service", a.path(residue)); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(a.path(residue), []byte("owner file"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			facts := a.InspectSubscriptionAbsence(t.Context())
			if facts.Accepted != (residue == "") {
				t.Fatalf("firewall residue treated as absent: %#v", facts)
			}
		})
	}
}
