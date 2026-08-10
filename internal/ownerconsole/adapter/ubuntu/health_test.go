package ubuntu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

func TestInspectionRequiresTheExactInstalledExecutable(t *testing.T) {
	directory := t.TempDir()
	installed := filepath.Join(directory, "sbxr")
	running := filepath.Join(directory, "running")
	if err := os.WriteFile(installed, []byte("executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(installed, running); err != nil {
		t.Fatal(err)
	}
	if got := inspect(installed, running, uint32(os.Geteuid())); got != ownerconsole.HealthHealthy {
		t.Fatalf("matching executable = %s", got)
	}
	if err := os.Remove(running); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(running, []byte("different"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := inspect(installed, running, uint32(os.Geteuid())); got != ownerconsole.HealthFailed {
		t.Fatalf("different executable = %s", got)
	}
}
