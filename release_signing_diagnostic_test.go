package architecture_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSigningDiagnosticShellBoundary(t *testing.T) {
	cmd := exec.Command("python3", "-B", ".github/scripts/test_signing_latest_recheck.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("signing diagnostics: %v\n%s", err, output)
	}
}

func TestSigningDiagnosticsWorkflowBoundary(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, sign, ok := strings.Cut(string(body), "\n  sign:\n")
	if !ok {
		t.Fatal("missing sign job")
	}
	sign, _, _ = strings.Cut(sign, "\n  acceptance-vps:")
	for _, required := range []string{
		"id: signing-manifest",
		"bash .github/scripts/signing-latest-recheck.sh",
		"if: ${{ always() && steps.signing-manifest.outcome == 'failure' }}",
		"name: candidate-signing-diagnostics\n",
		"path: signing-latest-diagnostics.json\n",
		"if-no-files-found: ignore",
		"retention-days: 1",
	} {
		if !strings.Contains(sign, required) {
			t.Errorf("signing diagnostics missing %q", required)
		}
	}
	_, upload, ok := strings.Cut(sign, "      - name: Retain filtered signing recheck diagnostics\n")
	if !ok {
		t.Fatal("missing diagnostic upload")
	}
	upload, _, _ = strings.Cut(upload, "\n      - ")
	if strings.Count(upload, "path:") != 1 || !strings.Contains(upload, "          path: signing-latest-diagnostics.json\n") || strings.Contains(upload, "current-source-verification.json") {
		t.Fatal("diagnostic upload must contain only filtered result")
	}
	for _, forbidden := range []string{"continue-on-error:", "set -x", "BASH_COMMAND", "printenv"} {
		if strings.Contains(sign, forbidden) {
			t.Errorf("signing diagnostics weaken failure or expose input: %s", forbidden)
		}
	}
}
