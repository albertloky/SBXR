package installation

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
)

func TestControlledInstallationSelectedSeamCollisionReturnsNestedCorrection(t *testing.T) {
	correction, err := ControlledInstallationCollisionCorrection(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if correction == nil || !strings.Contains(correction.Evidence, "INSTALL-PLAN-REFUSED; NETWORK-RECLAMATION-UNPROVED") || !strings.Contains(correction.Found, "caddy") {
		t.Fatalf("selected-seam correction = %+v", correction)
	}
}

func TestControlledInstallationRunsThroughRevisionOneAndCleansItsRoot(t *testing.T) {
	parent := t.TempDir()
	root, err := os.MkdirTemp(parent, "sbxr-controlled-install-")
	if err != nil {
		t.Fatal(err)
	}
	load, err := RunControlledInstallationAt(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := statefilesystem.NewAt(root).Load(load)
	if err != nil || loaded.Snapshot == nil || !controlledRevisionOne(loaded.Snapshot.DesiredState) {
		t.Fatalf("revision 1 = %+v, %v", loaded, err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("controlled root cleanup = %v, %v", entries, err)
	}
}

func TestControlledInstallationDeathRestartsAfterStatePublication(t *testing.T) {
	if os.Getenv("SBXR_CONTROLLED_INSTALL_DEATH_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestControlledInstallationDeathRestartsAfterStatePublication$")
		command.Env = append(os.Environ(), "SBXR_CONTROLLED_INSTALL_DEATH_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("controlled Installation death subprocess: %v\n%s", err, output)
		}
		return
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := QualifyControlledInstallationRestart(t.Context(), root); err != nil {
		t.Fatal(err)
	}
}

func TestControlledInstallationCleansItsRootAfterRefusal(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunControlledInstallation(ctx, parent); err == nil {
		t.Fatal("cancelled controlled Installation passed")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused controlled root cleanup = %v, %v", entries, err)
	}
}
