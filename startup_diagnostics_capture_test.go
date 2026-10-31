package architecture_test

import (
	"os"
	"os/exec"
	"testing"
)

func TestStartupDiagnosticCaptureContracts(t *testing.T) {
	command := exec.Command("python3", ".github/scripts/test_capture_startup_diagnostics.py", "-v")
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("startup diagnostic capture contracts: %v\n%s", err, output)
	}
}
