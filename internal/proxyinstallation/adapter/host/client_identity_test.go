package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestClientIdentityPublicationsFailClosedAndRetryFromObservedFiles(t *testing.T) {
	root := t.TempDir()
	for path, mode := range map[string]os.FileMode{"var/lib/sbxr": 0700, "run": 0755} {
		if err := os.MkdirAll(filepath.Join(root, path), mode); err != nil || os.Chmod(filepath.Join(root, path), mode) != nil {
			t.Fatal(err)
		}
	}
	adapter := Adapter{root: root}
	target := []byte("target configuration\n")
	targetDigest := digest(target)
	adapter.syncDirectoryFault = func(string) error { return errors.New("test late sync failure") }
	if adapter.PrepareClientIdentityTarget(target, targetDigest) {
		t.Fatal("late synchronization failure was accepted")
	}
	adapter.syncDirectoryFault = nil
	if !adapter.PrepareClientIdentityTarget(target, targetDigest) {
		t.Fatal("observed staged target did not finish safely")
	}
	if err := os.Remove(adapter.path(ClientIdentityTargetPath)); err != nil || os.WriteFile(adapter.path(ClientIdentityTargetPath), target, 0644) != nil {
		t.Fatal(err)
	}
	if adapter.PrepareClientIdentityTarget(target, targetDigest) {
		t.Fatal("unsafe target mode was accepted")
	}
	if err := os.Remove(adapter.path(ClientIdentityTargetPath)); err != nil || os.Symlink("elsewhere", adapter.path(ClientIdentityTargetPath)) != nil {
		t.Fatal(err)
	}
	if idle := adapter.ClientIdentityPreparationIdle(); !idle.Observed || idle.Accepted {
		t.Fatalf("symlink target admitted as idle: %#v", idle)
	}

	if err := os.Remove(adapter.path(ClientIdentityTargetPath)); err != nil || !adapter.publishSubscriptionFile(proxyStartAuthorizationPath, []byte(targetDigest+"\n"), 0600) {
		t.Fatal("start authorization setup failed")
	}
	if adapter.ConsumeProxyStartAuthorization(strings.Repeat("0", 64)) {
		t.Fatal("stale start authorization was consumed")
	}
	if !adapter.ConsumeProxyStartAuthorization(targetDigest) || adapter.ConsumeProxyStartAuthorization(targetDigest) {
		t.Fatal("start authorization was not exactly one-use")
	}
}

func TestProxyStartupElevatesOnlyAuthorizationCommand(t *testing.T) {
	want := "[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n"
	if ProxyStartupDropIn != want {
		t.Fatalf("unexpected startup authority settings: %q", ProxyStartupDropIn)
	}
	// systemd consumes the privilege prefix; it is not part of effective argv.
	if exactProxyStartCondition("{ path=/usr/local/bin/sbxr ; argv[]=+/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }") {
		t.Fatal("prefix incorrectly accepted as executable argument")
	}
}

func TestProxyStartConditionRequiresTheExactEffectiveCommand(t *testing.T) {
	for fact, want := range map[string]bool{
		"/usr/local/bin/sbxr --proxy-start-authorize":                                                                                  false,
		"{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }":                       true,
		"{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=yes ; }":                      false,
		"{ path=/bin/echo ; argv[]=/bin/echo /usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }":                       false,
		"{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; }\n{ path=/bin/true ; argv[]=/bin/true ; }": false,
		"": false,
	} {
		if got := exactProxyStartCondition(fact); got != want {
			t.Errorf("exactProxyStartCondition(%q) = %t, want %t", fact, got, want)
		}
	}
}

func TestClientIdentityCutoverUsesProtectedTargetStartupGateAndExpectedSource(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(strconv.FormatBool(fresh), func(t *testing.T) {
			testClientIdentityCutover(t, fresh)
		})
	}
}

func testClientIdentityCutover(t *testing.T, fresh bool) {
	t.Helper()
	root := t.TempDir()
	for path, mode := range map[string]os.FileMode{
		"var/lib/sbxr": 0700, "etc/sing-box": 0755, "etc/systemd/system": 0755, "run": 0755, "sys/fs/cgroup/system.slice/sing-box.service": 0755,
	} {
		if err := os.MkdirAll(filepath.Join(root, path), mode); err != nil || os.Chmod(filepath.Join(root, path), mode) != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "sys/fs/cgroup/system.slice/sing-box.service/cgroup.events"), []byte("populated 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	command := `#!/bin/sh
case "${0##*/}:$1:$2" in
getent:group:sing-box) printf 'sing-box:x:` + strconv.Itoa(os.Getegid()) + `:\n';;
systemctl:daemon-reload:*) exit 0;;
systemctl:show:--property=ExecCondition) printf '{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; ignore_errors=no ; }\n';;
systemctl:show:--property=KillMode) printf 'control-group\n';;
systemctl:show:--property=ControlGroup) printf '/system.slice/sing-box.service\n';;
systemctl:show:--property=MainPID) printf '0\n';;
systemctl:stop:*|systemctl:start:*) exit 0;;
systemctl:is-active:*) printf 'inactive\n'; exit 3;;
pgrep:*) exit 1;;
ss:*) exit 0;;
*) exit 1;;
esac
`
	commandPath := filepath.Join(root, "command")
	if err := os.WriteFile(commandPath, []byte(command), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"getent", "systemctl", "pgrep", "ss"} {
		if err := os.Symlink(commandPath, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root)
	adapter := Adapter{root: root, subscriptionCommand: func(context.Context, string, ...string) (string, int, bool) { return "", 1, true }}
	source, target := []byte("source configuration\n"), []byte("target configuration\n")
	if err := os.WriteFile(adapter.path("/etc/sing-box/config.json"), source, 0640); err != nil {
		t.Fatal(err)
	}
	planned, inspection := adapter.PlanProxyStartupIntegration()
	if !inspection.Observed || !inspection.Accepted {
		t.Fatalf("preflight = %#v", inspection)
	}
	if idle := adapter.ClientIdentityPreparationIdle(); !idle.Observed || !idle.Accepted {
		t.Fatalf("idle preparation = %#v", idle)
	}
	if !adapter.PrepareClientIdentityTarget(target, digest(target)) {
		t.Fatal("target preparation failed")
	}
	if idle := adapter.ClientIdentityPreparationIdle(); !idle.Observed || idle.Accepted {
		t.Fatalf("present target admitted as idle: %#v", idle)
	}
	authority := planned
	wrongAuthority := authority
	wrongAuthority.DropInSHA256 = strings.Repeat("0", 64)
	if adapter.PublishProxyStartupIntegration(wrongAuthority) {
		t.Fatal("wrong startup digest was published")
	}
	if fresh {
		prior := syscall.Umask(0077)
		defer syscall.Umask(prior)
		if !adapter.PublishProxyStartupIntegration(authority) {
			t.Fatal("startup publication under restrictive umask failed")
		}
		syscall.Umask(prior)
		info, err := os.Stat(adapter.path(ProxyStartupDropInDirectory))
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("startup directory differs from its declared mode: %v %v", info, err)
		}
	}
	if !adapter.PublishProxyStartupIntegration(authority) || !authority.Valid() || !authority.DirectoryCreated {
		t.Fatalf("startup authority = %#v", authority)
	}
	if !adapter.ReloadProxyStartupIntegration(t.Context()) || !adapter.VerifyProxyStartupIntegration(t.Context(), authority) {
		t.Fatal("effective startup route refused")
	}
	if !adapter.StopProxyForClientIdentityRotation(t.Context()) {
		t.Fatal("owned process group was not stopped")
	}
	if err := os.Remove(filepath.Join(root, "sys/fs/cgroup/system.slice/sing-box.service/cgroup.events")); err != nil {
		t.Fatal(err)
	}
	if adapter.ProxyQuiescentForClientIdentityRotation(t.Context()) {
		t.Fatal("missing cgroup proof admitted quiescence")
	}
	if err := os.WriteFile(filepath.Join(root, "sys/fs/cgroup/system.slice/sing-box.service/cgroup.events"), []byte("populated 0\n"), 0644); err != nil || !adapter.ProxyQuiescentForClientIdentityRotation(t.Context()) {
		t.Fatal("owned process group was not proved quiescent")
	}
	if adapter.PublishClientIdentityConfiguration(strings.Repeat("0", 64), digest(target)) {
		t.Fatal("changed source admitted target publication")
	}
	unchanged, err := os.ReadFile(adapter.path("/etc/sing-box/config.json"))
	if err != nil || !bytes.Equal(unchanged, source) {
		t.Fatalf("source changed after refused publication: %q, %v", unchanged, err)
	}
	if err := os.WriteFile(adapter.path("/etc/sing-box/.config.json.sbxr-next"), target, 0640); err != nil {
		t.Fatal(err)
	}
	adapter.packageLocksAvailable = func() bool { return true }
	removal := adapter.InspectClientIdentityRemoval(t.Context(), testSetupSpec(), nil, nil, digest(source), digest(target), "8.8.8.8", true)
	if !removal.Configuration.Accepted || !removal.ConfigurationEntries.Accepted {
		t.Fatal("proved interrupted target publication blocked removal")
	}
	var priorUmask int
	if fresh {
		if err := os.Remove(adapter.path(ClientIdentityConfigurationNextPath)); err != nil {
			t.Fatal(err)
		}
		priorUmask = syscall.Umask(0077)
		defer syscall.Umask(priorUmask)
	}
	if !adapter.PublishClientIdentityConfiguration(digest(source), digest(target)) {
		t.Fatal("expected-current target publication failed")
	}
	if fresh {
		syscall.Umask(priorUmask)
	}
	published, err := os.ReadFile(adapter.path("/etc/sing-box/config.json"))
	if err != nil || string(published) != string(target) {
		t.Fatalf("published = %q, %v", published, err)
	}
	removal = adapter.InspectClientIdentityRemoval(t.Context(), testSetupSpec(), nil, nil, digest(source), digest(target), "8.8.8.8", true)
	if !removal.Configuration.Accepted || !removal.ConfigurationEntries.Accepted {
		t.Fatal("target rename before record checkpoint blocked removal")
	}
	if err := os.WriteFile(adapter.path(ClientIdentityConfigurationNextPath), target, 0640); err != nil {
		t.Fatal(err)
	}
	if !adapter.StartProxyForClientIdentityRotation(t.Context(), digest(target)) || !adapter.RemoveClientIdentityTarget(digest(source), digest(target)) || !adapter.RemoveProxyStartupIntegration(t.Context(), authority) {
		t.Fatal("finishing cleanup failed")
	}
	for _, path := range []string{ClientIdentityTargetPath, ClientIdentityConfigurationNextPath, ProxyStartupDropInPath, ProxyStartupDropInDirectory} {
		if _, err := os.Lstat(adapter.path(path)); !os.IsNotExist(err) {
			t.Fatalf("owned path survived: %s (%v)", path, err)
		}
	}
	if strings.Contains(string(published), "source") {
		t.Fatal("source remained authoritative")
	}
}

func TestClientIdentityQuiescenceAfterSystemdRemovesStoppedGroup(t *testing.T) {
	for _, test := range []struct {
		name, shape, group, active, pid, events string
		process, listener                       bool
		want                                    bool
	}{
		{name: "removed stopped group", shape: "absent", want: true},
		{name: "empty extant group", shape: "directory", group: "/system.slice/sing-box.service", events: "populated 0\n", want: true},
		{name: "missing events inside extant group", shape: "directory", group: "/system.slice/sing-box.service"},
		{name: "populated group", shape: "directory", group: "/system.slice/sing-box.service", events: "populated 1\n"},
		{name: "empty property with extant group", shape: "directory", events: "populated 0\n"},
		{name: "foreign group", shape: "absent", group: "/system.slice/foreign.service"},
		{name: "symlink group", shape: "symlink"},
		{name: "symlink parent", shape: "parent-symlink"},
		{name: "unknown parent", shape: "missing-parent"},
		{name: "symlink events", shape: "events-symlink", group: "/system.slice/sing-box.service"},
		{name: "non-file events", shape: "events-directory", group: "/system.slice/sing-box.service"},
		{name: "active unit", shape: "absent", active: "active"},
		{name: "remaining main PID", shape: "absent", pid: "123"},
		{name: "remaining process", shape: "absent", process: true},
		{name: "remaining listener", shape: "absent", listener: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			adapter := Adapter{root: root}
			parent := adapter.path("/sys/fs/cgroup/system.slice")
			group := filepath.Join(parent, "sing-box.service")
			if err := os.MkdirAll(parent, 0755); err != nil {
				t.Fatal(err)
			}
			switch test.shape {
			case "directory", "events-symlink", "events-directory":
				if err := os.Mkdir(group, 0755); err != nil {
					t.Fatal(err)
				}
				if test.events != "" {
					if err := os.WriteFile(filepath.Join(group, "cgroup.events"), []byte(test.events), 0644); err != nil {
						t.Fatal(err)
					}
				}
				if test.shape == "events-symlink" {
					target := filepath.Join(root, "events")
					if err := os.WriteFile(target, []byte("populated 0\n"), 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, filepath.Join(group, "cgroup.events")); err != nil {
						t.Fatal(err)
					}
				}
				if test.shape == "events-directory" {
					if err := os.Mkdir(filepath.Join(group, "cgroup.events"), 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "symlink":
				if err := os.Symlink("missing", group); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(root, parent); err != nil {
					t.Fatal(err)
				}
			case "missing-parent":
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
			}
			active, pid := test.active, test.pid
			if active == "" {
				active = "inactive"
			}
			if pid == "" {
				pid = "0"
			}
			t.Setenv("SBXR_TEST_GROUP", test.group)
			t.Setenv("SBXR_TEST_ACTIVE", active)
			t.Setenv("SBXR_TEST_PID", pid)
			t.Setenv("SBXR_TEST_PROCESS", strconv.FormatBool(test.process))
			t.Setenv("SBXR_TEST_LISTENER", strconv.FormatBool(test.listener))
			script := `#!/bin/sh
case "${0##*/}:$1:$2" in
systemctl:show:--property=KillMode) printf 'control-group\n';;
systemctl:show:--property=ControlGroup) printf '%s\n' "$SBXR_TEST_GROUP";;
systemctl:show:--property=MainPID) printf '%s\n' "$SBXR_TEST_PID";;
systemctl:is-active:*) printf '%s\n' "$SBXR_TEST_ACTIVE"; [ "$SBXR_TEST_ACTIVE" = active ] || exit 3;;
pgrep:*) [ "$SBXR_TEST_PROCESS" = true ] && { printf '123\n'; exit 0; }; exit 1;;
ss:*) [ "$SBXR_TEST_LISTENER" = true ] && printf 'LISTEN\n'; exit 0;;
*) exit 1;;
esac
`
			command := filepath.Join(root, "command")
			if err := os.WriteFile(command, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"systemctl", "pgrep", "ss"} {
				if err := os.Symlink(command, filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", root)
			if got := adapter.ProxyQuiescentForClientIdentityRotation(t.Context()); got != test.want {
				t.Fatalf("quiescent = %t, want %t", got, test.want)
			}
		})
	}
}
