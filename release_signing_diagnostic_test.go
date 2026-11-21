package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
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
		"if: ${{ failure() }}",
		"name: candidate-signing-diagnostics\n",
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
	const paths = "          path: |\n            ${{ runner.temp }}/signing-latest-diagnostics.json\n            ${{ runner.temp }}/signing-latest-http.json\n            ${{ runner.temp }}/signing-failure-stage.txt\n          if-no-files-found: ignore"
	if strings.Count(upload, "path:") != 1 || !strings.Contains(upload, paths) {
		t.Fatal("diagnostic upload must contain only the filtered result and typed HTTP receipt")
	}
	for _, forbidden := range []string{"continue-on-error:", "set -x", "BASH_COMMAND", "printenv"} {
		if strings.Contains(sign, forbidden) {
			t.Errorf("signing diagnostics weaken failure or expose input: %s", forbidden)
		}
	}
}

func TestPublicLatestMissingStageFallback(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		step, stage, state, path, want string
	}{
		{"Record candidate preflight failure before diagnostics", "setup-tools", "not started", "candidate-preflight-diagnostics.txt",
			"Candidate preflight failed at stage: setup-tools\nPublic-latest verifier: not started\n"},
		{"Record signing failure stage", "host-readiness", "not started", "signing-failure-stage.txt",
			"Signing failed at stage: host-readiness\nPublic-latest verifier: not started\n"},
		{"Record signing failure stage", "create-manifest", "unknown", "signing-failure-stage.txt",
			"Signing failed at stage: create-manifest\nPublic-latest verifier: unknown\n"},
	} {
		t.Run(fixture.stage, func(t *testing.T) {
			_, definition, found := strings.Cut(string(body), "      - name: "+fixture.step+"\n")
			if !found {
				t.Fatal("missing failure fallback for a verifier that never started")
			}
			definition, _, _ = strings.Cut(definition, "\n      - ")
			_, script, found := strings.Cut(definition, "        run: |\n")
			if !found || !strings.Contains(definition, "if: ${{ failure() }}") {
				t.Fatal("fallback must run after a failed earlier step")
			}
			lines := strings.Split(script, "\n")
			for i := range lines {
				lines[i] = strings.TrimPrefix(lines[i], "          ")
			}
			dir := t.TempDir()
			command := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", strings.Join(lines, "\n"))
			command.Dir = dir
			command.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "FAILURE_STAGE="+fixture.stage, "VERIFIER_STATE="+fixture.state, "GH_TOKEN=never-retain-fixture-secret")
			output, err := command.CombinedOutput()
			if err != nil || string(output) != fixture.want {
				t.Fatalf("fallback output = %q, error = %v", output, err)
			}
			receipt, err := os.ReadFile(filepath.Join(dir, fixture.path))
			if err != nil || string(receipt) != fixture.want {
				t.Fatalf("fallback artifact = %q, error = %v", receipt, err)
			}
		})
	}
}
