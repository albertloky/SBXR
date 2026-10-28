package architecture_test

import (
	"os/exec"
	"testing"
)

func TestReleaseSafetyAdapters(t *testing.T) {
	if output, err := exec.Command("python3", "-B", ".github/scripts/test_release_safety.py").CombinedOutput(); err != nil {
		t.Fatalf("inert release safety regressions: %v\n%s", err, output)
	}
}
