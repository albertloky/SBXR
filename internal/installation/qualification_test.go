package installation

import (
	"context"
	"os"
	"testing"
)

func TestControlledInstallationRunsThroughRevisionOneAndCleansItsRoot(t *testing.T) {
	parent := t.TempDir()
	if err := RunControlledInstallation(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("controlled root cleanup = %v, %v", entries, err)
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
