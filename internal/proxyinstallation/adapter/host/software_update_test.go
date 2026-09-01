package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoftwareUpdateObservesExactServingExecutableAndRefusesUnknownState(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	for _, dir := range []string{"/usr/local/bin", "/proc/42"} {
		if err := os.MkdirAll(a.path(dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	executable := []byte(strings.Repeat("x", 128<<10))
	for _, name := range []string{"/usr/local/bin/sbxr", "/proc/42/exe"} {
		if err := os.WriteFile(a.path(name), executable, 0755); err != nil {
			t.Fatal(err)
		}
	}
	state := "active"
	a.subscriptionCommand = func(_ context.Context, _ string, args ...string) (string, int, bool) {
		switch strings.Join(args, " ") {
		case "show --property=ActiveState --value sbxr-subscription.service":
			return state, 0, true
		case "show --property=MainPID --value sbxr-subscription.service":
			return "42", 0, true
		default:
			t.Fatal("unexpected effect")
			return "", 1, false
		}
	}
	if got := a.servingExecutable(t.Context()); !got.Accepted || !got.Observed {
		t.Fatalf("candidate=%+v", got)
	}
	if err := os.WriteFile(a.path("/proc/42/exe"), []byte("prior executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := a.servingExecutable(t.Context()); got.Accepted || !got.Observed {
		t.Fatalf("prior=%+v", got)
	}
	if err := os.Remove(a.path("/proc/42/exe")); err != nil {
		t.Fatal(err)
	}
	if got := a.servingExecutable(t.Context()); got.Observed {
		t.Fatal("missing process treated as restart authority")
	}
	state = "activating"
	if a.CompleteSoftwareUpdateServing(t.Context(), ServingAuthority{}, RenewalAuthority{}) {
		t.Fatal("transitional service accepted")
	}
	// The installed path is never followed through an alias.
	os.Remove(a.path("/usr/local/bin/sbxr"))
	os.Symlink(filepath.Join(a.root, "outside"), a.path("/usr/local/bin/sbxr"))
	if _, err := a.readInstalledUpdateExecutable(); err == nil {
		t.Fatal("unsafe installed path accepted")
	}
}
