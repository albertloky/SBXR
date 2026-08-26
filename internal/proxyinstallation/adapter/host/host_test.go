package host

import (
	"context"
	"os"
	"path/filepath"
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

func resourcePresent(resources []Resource, name string) bool {
	for _, resource := range resources {
		if resource.Name == name {
			return resource.Present
		}
	}
	return false
}
