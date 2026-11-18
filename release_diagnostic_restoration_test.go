package architecture_test

import (
	"os/exec"
	"testing"
)

func TestDiagnosticRestorationBindings(t *testing.T) {
	for _, path := range []string{
		".github/scripts/test_disclosure_diagnostic.py",
		".github/scripts/test_diagnostic_restoration.py",
		".github/scripts/test_diagnostic_karing_handoff.py",
		".github/scripts/test_diagnostic_karing_producer.py",
		".github/scripts/test_diagnostic_karing_profile.py",
	} {
		if output, err := exec.Command("python3", "-B", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, output)
		}
	}
}
