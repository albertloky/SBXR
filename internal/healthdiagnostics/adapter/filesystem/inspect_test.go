package filesystem

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

func TestSelfInspectorProvesUnitsAndRefusesUnsafeStagingWithoutWriting(t *testing.T) {
	root := t.TempDir()
	uid := os.Geteuid()
	for _, directory := range []string{"var/lib/sbxr", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	units, _ := healthdiagnostics.SystemdUnits()
	for name, body := range units {
		if err := os.WriteFile(filepath.Join(root, "etc/systemd/system", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inspector := newSelfInspector(root, uid, func() time.Time { return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC) })
	if finding, err := inspector.Inspect(); err != nil || finding.Status != healthdiagnostics.Healthy {
		t.Fatalf("healthy inspection = %#v, %v", finding, err)
	}
	for _, directory := range []string{"var/lib/sbxr/diagnostics", "var/lib/sbxr/diagnostics/bundles", "var/lib/sbxr/diagnostics/staging"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(root, "var/lib/sbxr/diagnostics/staging", "unfinished")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Inspect(); err == nil {
		t.Fatal("unsafe staging was accepted")
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "unchanged" {
		t.Fatalf("inspection changed staging = %q, %v", body, err)
	}
}
