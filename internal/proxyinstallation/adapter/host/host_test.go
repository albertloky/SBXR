package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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

func testSetupSpec() SetupSpec {
	return SetupSpec{
		OwnershipPath: "/var/lib/sbxr/proxy-ownership.json", OwnershipNextPath: "/var/lib/sbxr/.proxy-ownership.json.next", LockPath: "/run/lock/sbxr.lock",
		PackageArtifactPath: "/var/lib/sbxr/sing-box_1.13.19_amd64.deb", APTKeyPath: "/etc/apt/keyrings/sagernet.asc", APTSourcePath: "/etc/apt/sources.list.d/sagernet.sources",
		ConfigurationPath: "/etc/sing-box/config.json", StatePath: "/var/lib/sing-box", Service: "sing-box.service", ServiceUnitPath: "/lib/systemd/system/sing-box.service",
		PackageName: "sing-box", PackageVersion: "1.13.19", Architecture: "amd64", PackageSize: 24597120, User: "sing-box", Group: "sing-box", ListenerPort: "443",
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

func resourcePresent(resources []Resource, name string) bool {
	for _, resource := range resources {
		if resource.Name == name {
			return resource.Present
		}
	}
	return false
}
