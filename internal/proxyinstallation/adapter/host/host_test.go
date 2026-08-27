package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAdapterReportsFreshReadOnlyHostFacts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{
		root: root, architecture: "amd64",
		publicIPv4:            func(context.Context) string { return "203.0.113.7" },
		clockSynchronized:     func(context.Context) bool { return true },
		tcp443Available:       func(string) bool { return true },
		mutationLockAvailable: func() bool { return true },
		packageLocksAvailable: func() bool { return true },
		probeDestination: func(_ context.Context, destination Destination) DestinationObservation {
			return DestinationObservation{Destination: destination, DNS: true, TCP: true, TLS13: true, HTTP2: true, CertificateName: true}
		},
	}
	requested := []Resource{{Kind: PathResource, Name: "/var/lib/sbxr/proxy-ownership.json"}}

	if inspection := adapter.Inspect(t.Context(), requested); !inspection.Complete || resourcePresent(inspection.Resources, "/var/lib/sbxr/proxy-ownership.json") {
		t.Fatalf("clean inspection = %#v", inspection)
	}
	ownership := filepath.Join(root, "var", "lib", "sbxr", "proxy-ownership.json")
	if err := os.MkdirAll(filepath.Dir(ownership), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownership, []byte("conflict"), 0o600); err != nil {
		t.Fatal(err)
	}
	if inspection := adapter.Inspect(t.Context(), requested); !inspection.Complete || !resourcePresent(inspection.Resources, "/var/lib/sbxr/proxy-ownership.json") {
		t.Fatalf("conflicting inspection = %#v", inspection)
	}

	destination := Destination{Address: "microsoft.com:443", ServerName: "microsoft.com"}
	facts := adapter.Preflight(t.Context(), requested, []Destination{destination})
	if facts.OSID != "ubuntu" || facts.OSVersion != "24.04" || facts.Architecture != "amd64" || facts.PublicIPv4 != "203.0.113.7" || !facts.ClockSynchronized || !facts.TCP443Available || !facts.MutationLockAvailable || !facts.PackageLocksAvailable || len(facts.Destinations) != 1 || facts.Destinations[0].Destination != destination || !facts.Destinations[0].Compatible() || !resourcePresent(facts.Resources, "/var/lib/sbxr/proxy-ownership.json") {
		t.Fatalf("Preflight() = %#v", facts)
	}
}

func TestOwnershipRecordIsStrictAndCrashSafe(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "var", "lib", "sbxr")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{root: root}
	spec := testSetupSpec()
	first, second := []byte("{\"schema\":1}\n"), []byte("{\"schema\":2}\n")
	if err := adapter.PublishOwnership(spec.OwnershipPath, spec.OwnershipNextPath, nil, first); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(directory, "proxy-ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		t.Fatalf("ownership metadata = %#v, %v", info, err)
	}
	if body, err := adapter.ReadOwnership(spec.OwnershipPath); err != nil || !bytes.Equal(body, first) {
		t.Fatalf("ReadOwnership() = %q, %v", body, err)
	}
	staged := filepath.Join(directory, ".proxy-ownership.json.next")
	if err := os.WriteFile(staged, second, 0o600); err != nil || adapter.PublishOwnership(spec.OwnershipPath, spec.OwnershipNextPath, first, second) != nil {
		t.Fatalf("staged checkpoint recovery failed: %v", err)
	}
	if body, err := adapter.ReadOwnership(spec.OwnershipPath); err != nil || !bytes.Equal(body, second) {
		t.Fatalf("recovered ownership = %q, %v", body, err)
	}
	if err := os.Link(filepath.Join(directory, "proxy-ownership.json"), filepath.Join(directory, "extra-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ReadOwnership(spec.OwnershipPath); err == nil {
		t.Fatal("ReadOwnership() accepted a shared hard link")
	}
}

func TestMutationLockAuthorityIsBoundToItsExactHeldFile(t *testing.T) {
	root := t.TempDir()
	adapter := Adapter{root: root}
	if new(MutationLock).Holds(filepath.Join(root, "run/lock/sbxr.lock")) {
		t.Fatal("zero mutation lock claimed authority")
	}
	lock, busy, err := adapter.AcquireMutationLock("/run/lock/sbxr.lock")
	wantPath := filepath.Join(root, "run/lock/sbxr.lock")
	if err != nil || busy || !lock.Holds(wantPath) || lock.Holds(filepath.Join(root, "run/lock/other.lock")) {
		t.Fatalf("AcquireMutationLock() = lock=%#v busy=%t err=%v", lock, busy, err)
	}
	lock.Release()
	if lock.Holds(wantPath) {
		t.Fatal("released mutation lock retained authority")
	}
}

func TestFinalOwnershipRemovalRestoresRecoveryAuthorityUntilStateDirectoryIsEmpty(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "var", "lib", "sbxr")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{root: root}
	spec := testSetupSpec()
	finalName := "/var/lib/.sbxr-removal.json"
	body := []byte("{\"schema\":1}\n")
	if err := adapter.PublishOwnership(spec.OwnershipPath, spec.OwnershipNextPath, nil, body); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(directory, "unknown")
	if err := os.WriteFile(unknown, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.RemoveFinalOwnership(spec.OwnershipPath, spec.OwnershipNextPath, finalName, body); err == nil {
		t.Fatal("final removal accepted a non-empty state directory")
	}
	if _, err := adapter.ReadOwnership(spec.OwnershipPath); !os.IsNotExist(err) {
		t.Fatalf("ordinary ownership still exists: %v", err)
	}
	if final, err := adapter.ReadOwnership(finalName); err != nil || !bytes.Equal(final, body) {
		t.Fatalf("finalization authority = %q, %v", final, err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	if err := adapter.RemoveFinalOwnership(spec.OwnershipPath, spec.OwnershipNextPath, finalName, body); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("state directory still exists: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "lib", ".sbxr-removal.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.RemoveFinalOwnership(spec.OwnershipPath, spec.OwnershipNextPath, finalName, body); err != nil {
		t.Fatalf("resume after state-directory removal: %v", err)
	}
}

func TestAdapterDurablyWritesAndRemovesOwnedConfigurationFiles(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"etc/apt/sources.list.d", "etc/sing-box", "var/lib/sing-box"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	adapter := Adapter{root: root}
	spec := testSetupSpec()
	source := []byte("Types: deb\nURIs: https://deb.sagernet.org/\n")
	configuration := []byte("{\"inbounds\":[]}\n")
	if result := adapter.Apply(t.Context(), OperationInput{Operation: InstallAPTSource, Spec: spec, Body: source}); !result.OK {
		t.Fatalf("InstallAPTSource = %#v", result)
	}
	if result := adapter.Apply(t.Context(), OperationInput{Operation: InstallConfiguration, Spec: spec, Body: configuration}); !result.OK {
		t.Fatalf("InstallConfiguration = %#v", result)
	}
	for _, expected := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{
		{"etc/apt/sources.list.d/sagernet.sources", source, 0o644},
		{"etc/sing-box/config.json", configuration, 0o640},
	} {
		body, err := os.ReadFile(filepath.Join(root, expected.name))
		info, statErr := os.Stat(filepath.Join(root, expected.name))
		if err != nil || statErr != nil || !bytes.Equal(body, expected.body) || info.Mode().Perm() != expected.mode {
			t.Fatalf("%s = %q mode=%v read=%v stat=%v", expected.name, body, info.Mode().Perm(), err, statErr)
		}
	}
	if result := adapter.Apply(t.Context(), OperationInput{Operation: RemoveConfigurationState, Spec: spec, SHA256: digest(configuration)}); !result.OK {
		t.Fatalf("RemoveConfigurationState = %#v", result)
	}
	for _, name := range []string{"etc/sing-box", "var/lib/sing-box"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("%s remains: %v", name, err)
		}
	}
}

func TestWriteFileAppliesExactModeUnderRestrictiveUmask(t *testing.T) {
	root := t.TempDir()
	adapter := Adapter{root: root}
	priorUmask := syscall.Umask(0o077)
	defer syscall.Umask(priorUmask)

	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "/etc/apt/keyrings/sagernet.asc", mode: 0o644},
		{name: "/etc/apt/sources.list.d/sagernet.sources", mode: 0o644},
		{name: "/etc/sing-box/config.json", mode: 0o640},
	} {
		if result := adapter.writeFile(test.name, []byte("fixture\n"), test.mode); !result.OK {
			t.Fatalf("writeFile(%q) = %#v", test.name, result)
		}
		info, err := os.Stat(adapter.path(test.name))
		if err != nil || info.Mode().Perm() != test.mode {
			t.Fatalf("writeFile(%q) mode = %v, err = %v", test.name, info.Mode().Perm(), err)
		}
	}
}

func TestConfigurationRemovalNeverRecursivelyDeletesUnknownEntries(t *testing.T) {
	root := t.TempDir()
	configurationDirectory := filepath.Join(root, "etc/sing-box")
	stateDirectory := filepath.Join(root, "var/lib/sing-box")
	if err := os.MkdirAll(configurationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	configuration := []byte("{}\n")
	if err := os.WriteFile(filepath.Join(configurationDirectory, "config.json"), configuration, 0o640); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(stateDirectory, "owner-data")
	if err := os.WriteFile(unknown, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := (Adapter{root: root}).Apply(t.Context(), OperationInput{Operation: RemoveConfigurationState, Spec: testSetupSpec(), SHA256: digest(configuration)})
	if result.OK {
		t.Fatal("removal accepted a non-empty state directory")
	}
	if body, err := os.ReadFile(unknown); err != nil || string(body) != "preserve" {
		t.Fatalf("unknown entry changed: %q, %v", body, err)
	}
}

func TestPackageIdentityRemovalAcceptsGroupRemovedByUserdel(t *testing.T) {
	directory := t.TempDir()
	commandPath := filepath.Join(directory, "command")
	statePath := filepath.Join(directory, "identity-removed")
	groupdelPath := filepath.Join(directory, "groupdel-called")
	command := `#!/bin/sh
case "${0##*/}:$1" in
getent:passwd) [ ! -e "$IDENTITY_REMOVED" ] || exit 2; printf '%s\n' 'sing-box:x:999:999::/var/lib/sing-box:/usr/sbin/nologin';;
getent:group) [ ! -e "$IDENTITY_REMOVED" ] || exit 2; printf '%s\n' 'sing-box:x:999:';;
find:*) exit 0;;
pgrep:*) exit 1;;
userdel:*) : > "$IDENTITY_REMOVED";;
groupdel:*) : > "$GROUPDEL_CALLED"; exit 6;;
esac
`
	if err := os.WriteFile(commandPath, []byte(command), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"getent", "find", "pgrep", "userdel", "groupdel"} {
		if err := os.Symlink(commandPath, filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	t.Setenv("IDENTITY_REMOVED", statePath)
	t.Setenv("GROUPDEL_CALLED", groupdelPath)

	result := (Adapter{root: directory}).Apply(t.Context(), OperationInput{Operation: RemovePackageIdentity, Spec: testSetupSpec()})
	if !result.OK || result.Fact != "package identity absent" {
		t.Fatalf("RemovePackageIdentity = %#v", result)
	}
	if _, err := os.Stat(groupdelPath); !os.IsNotExist(err) {
		t.Fatalf("groupdel ran after userdel removed the group: %v", err)
	}
}

func TestReadBoundFileReturnsOnlyTheExactSafeConfiguration(t *testing.T) {
	root := t.TempDir()
	name := "/etc/sing-box/config.json"
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"inbounds":[]}` + "\n")
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{root: root}
	got, err := adapter.readConfigurationFile(name, digest(body), uint32(os.Getgid()))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("readConfigurationFile() = %q, %v", got, err)
	}
	if _, err := adapter.readConfigurationFile(name, digest([]byte("changed")), uint32(os.Getgid())); err == nil {
		t.Fatal("readConfigurationFile accepted a changed digest")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.readConfigurationFile(name, digest(body), uint32(os.Getgid())); err == nil {
		t.Fatal("readConfigurationFile accepted unsafe permissions")
	}
}

func testSetupSpec() SetupSpec {
	return SetupSpec{
		OwnershipPath: "/var/lib/sbxr/proxy-ownership.json", OwnershipNextPath: "/var/lib/sbxr/.proxy-ownership.json.next", LockPath: "/run/lock/sbxr.lock",
		PackageArtifactPath: "/var/lib/sbxr/sing-box_1.13.19_amd64.deb", APTKeyPath: "/etc/apt/keyrings/sagernet.asc", APTSourcePath: "/etc/apt/sources.list.d/sagernet.sources",
		ConfigurationPath: "/etc/sing-box/config.json", StatePath: "/var/lib/sing-box", Service: "sing-box.service", ServiceUnitPath: "/usr/lib/systemd/system/sing-box.service",
		PackageName: "sing-box", PackageVersion: "1.13.19", Architecture: "amd64", PackageSize: 24597120, User: "sing-box", Group: "sing-box", ListenerPort: "443",
	}
}

func TestRunningInspectionUsesExactPinnedServiceUnitProvenance(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "dpkg-query.log")
	commandPath := filepath.Join(directory, "dpkg-query")
	command := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DPKG_QUERY_LOG\"\nif [ \"$1\" = --search ]; then printf '%s\\n' \"$DPKG_QUERY_OWNER\"; else printf '1.13.19 amd64 ii\\n'; fi\n"
	if err := os.WriteFile(commandPath, []byte(command), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("DPKG_QUERY_LOG", logPath)
	t.Setenv("DPKG_QUERY_OWNER", "sing-box: /usr/lib/systemd/system/sing-box.service")
	adapter := Adapter{root: directory, architecture: "amd64", publicIPv4: func(context.Context) string { return "" }}
	spec := testSetupSpec()
	if fact := adapter.InspectRunning(t.Context(), spec, nil, nil, "", "").ServiceProvenance; !fact.Accepted || !fact.Observed {
		t.Fatalf("sing-box provenance = %#v", fact)
	}
	body, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(body), "--search /usr/lib/systemd/system/sing-box.service\n") {
		t.Fatalf("dpkg-query calls = %q, %v", body, err)
	}
	t.Setenv("DPKG_QUERY_OWNER", "other-package: /usr/lib/systemd/system/sing-box.service")
	if fact := adapter.InspectRunning(t.Context(), spec, nil, nil, "", "").ServiceProvenance; fact.Accepted || !fact.Observed {
		t.Fatalf("outside package provenance = %#v", fact)
	}
}

func TestRunningInspectionRequiresExactHeldPackageAndSeparateHold(t *testing.T) {
	directory := t.TempDir()
	commandPath := filepath.Join(directory, "command")
	command := `#!/bin/sh
case "${0##*/}" in
dpkg-query) printf '%s\n' "$PACKAGE_FACT";;
apt-mark) printf '%s\n' "$PACKAGE_HOLDS";;
esac
`
	if err := os.WriteFile(commandPath, []byte(command), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dpkg-query", "apt-mark"} {
		if err := os.Symlink(commandPath, filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	t.Setenv("PACKAGE_FACT", "1.13.19 amd64 hi")
	t.Setenv("PACKAGE_HOLDS", "sing-box")
	adapter := Adapter{root: directory, architecture: "amd64", publicIPv4: func(context.Context) string { return "203.0.113.7" }}
	inspect := func() RunningInspection {
		return adapter.InspectRunning(t.Context(), testSetupSpec(), nil, nil, "", "203.0.113.7")
	}

	if facts := inspect(); !facts.Package.Accepted || !facts.Package.Observed || !facts.Hold.Accepted || !facts.Hold.Observed {
		t.Fatalf("exact held package facts = %#v", facts)
	}
	t.Setenv("PACKAGE_HOLDS", "")
	if facts := inspect(); !facts.Package.Accepted || facts.Hold.Accepted || !facts.Hold.Observed {
		t.Fatalf("missing separate hold facts = %#v", facts)
	}
	t.Setenv("PACKAGE_FACT", "1.13.19 amd64 ii")
	t.Setenv("PACKAGE_HOLDS", "sing-box")
	if facts := inspect(); facts.Package.Accepted || !facts.Package.Observed || !facts.Hold.Accepted {
		t.Fatalf("unheld dpkg state facts = %#v", facts)
	}
}

func TestExactPackageIdentityAcceptsRecoverableDpkgStatesOnly(t *testing.T) {
	spec := testSetupSpec()
	for _, test := range []struct {
		fact string
		want bool
	}{
		{"1.13.19 amd64 ii", true},
		{"1.13.19 amd64 iF", true},
		{"1.13.18 amd64 iF", false},
		{"1.13.19 arm64 iF", false},
		{"unparseable", false},
	} {
		if got := exactPackageIdentity(test.fact, spec); got != test.want {
			t.Errorf("exactPackageIdentity(%q) = %t, want %t", test.fact, got, test.want)
		}
	}
}

func TestExactHeldPackageIdentityAcceptsOnlyInstalledHoldState(t *testing.T) {
	spec := testSetupSpec()
	for _, test := range []struct {
		fact string
		want bool
	}{
		{"1.13.19 amd64 hi", true},
		{"1.13.19 amd64 ii", false},
		{"1.13.19 amd64 hF", false},
		{"1.13.18 amd64 hi", false},
		{"1.13.19 arm64 hi", false},
		{"unparseable", false},
	} {
		if got := exactHeldPackageIdentity(test.fact, spec); got != test.want {
			t.Errorf("exactHeldPackageIdentity(%q) = %t, want %t", test.fact, got, test.want)
		}
	}
}

func TestServiceStoppedRequiresFreshInactiveProcessAndListenerFacts(t *testing.T) {
	observed := func(fact string) OperationResult { return OperationResult{OK: true, Fact: fact, Observed: true} }
	absent := OperationResult{Code: 1, Observed: true}
	if !serviceStopped(observed("loaded"), observed("disabled"), observed("inactive"), absent, observed(""), "sing-box") {
		t.Fatal("fresh stopped and disabled facts were refused")
	}
	if serviceStopped(observed("loaded"), observed("disabled"), observed("active"), absent, observed(""), "sing-box") {
		t.Fatal("disabled but active service was accepted")
	}
	if serviceStopped(observed("not-found"), OperationResult{Observed: true}, observed("inactive"), observed("123"), observed("sing-box :443"), "sing-box") {
		t.Fatal("missing unit with surviving process and listener was accepted")
	}
}

func TestRemovalInspectionRejectsUnexpectedDirectoryEntries(t *testing.T) {
	root := t.TempDir()
	configurationDirectory := filepath.Join(root, "etc", "sing-box")
	stateDirectory := filepath.Join(root, "var", "lib", "sing-box")
	for _, directory := range []string{configurationDirectory, stateDirectory} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	configuration := filepath.Join(configurationDirectory, "config.json")
	if err := os.WriteFile(configuration, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{root: root}
	if accepted, observed := adapter.directoryContainsOnly("/etc/sing-box", 0o750, uint32(os.Getuid()), uint32(os.Getgid()), "config.json"); !accepted || !observed {
		t.Fatalf("clean directory = accepted %t observed %t", accepted, observed)
	}
	if err := os.WriteFile(filepath.Join(configurationDirectory, "unknown"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if accepted, observed := adapter.directoryContainsOnly("/etc/sing-box", 0o750, uint32(os.Getuid()), uint32(os.Getgid()), "config.json"); accepted || !observed {
		t.Fatalf("unknown entry = accepted %t observed %t", accepted, observed)
	}
}

func TestRemovalListenerMustBelongOnlyToThePackage(t *testing.T) {
	if !listenerOwnedOnly(`LISTEN users:(("sing-box",pid=42,fd=7))`, "sing-box") {
		t.Fatal("exact package listener was refused")
	}
	if listenerOwnedOnly(`LISTEN users:(("not-sing-box",pid=42,fd=7))`, "sing-box") || listenerOwnedOnly(`LISTEN users:(("sing-box",pid=42,fd=7))`+"\n"+`LISTEN users:(("nginx",pid=43,fd=7))`, "sing-box") || listenerOwnedOnly("", "sing-box") {
		t.Fatal("missing or outside listener was accepted")
	}
}

func TestRemovalAcceptsOnlyExactRunningOrStoppedServiceFacts(t *testing.T) {
	fact := func(value string) OperationResult { return OperationResult{OK: true, Observed: true, Fact: value} }
	absent := OperationResult{Observed: true, Code: 1}
	listener := fact(`LISTEN users:(("sing-box",pid=42,fd=7))`)
	for _, test := range []struct {
		name                                    string
		enabled, active, pid, process, listener OperationResult
		want                                    bool
	}{
		{"running enabled", fact("enabled"), fact("active"), fact("42"), fact("42"), listener, true},
		{"running disabled", OperationResult{Observed: true, Fact: "disabled"}, fact("active"), fact("42"), fact("42"), listener, true},
		{"stopped enabled", fact("enabled"), OperationResult{Observed: true, Fact: "inactive"}, fact("0"), absent, fact(""), true},
		{"stopped disabled", OperationResult{Observed: true, Fact: "disabled"}, OperationResult{Observed: true, Fact: "inactive"}, fact("0"), absent, fact(""), true},
		{"outside listener", fact("enabled"), fact("active"), fact("42"), fact("42"), fact(`LISTEN users:(("nginx",pid=43,fd=7))`), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := serviceStateRemovalSafe(test.enabled, test.active, test.pid, test.process, test.listener, "sing-box"); got != test.want {
				t.Fatalf("serviceStateRemovalSafe() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRemovalRejectsOutsideIdentityProcessUse(t *testing.T) {
	set := func(values ...string) map[string]struct{} {
		result := make(map[string]struct{}, len(values))
		for _, value := range values {
			result[value] = struct{}{}
		}
		return result
	}
	if !processSetsExclusive(set("42"), set("42"), set("42")) {
		t.Fatal("exact package process identity was refused")
	}
	if processSetsExclusive(set("42", "99"), set("42"), set("42")) {
		t.Fatal("outside identity process use was accepted")
	}
}

func resourcePresent(resources []Resource, name string) bool {
	for _, resource := range resources {
		if resource.Name == name {
			return resource.Present
		}
	}
	return false
}
