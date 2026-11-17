package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDisclosureDiagnosticWorkflowPreservesQualificationBoundary(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			If    string
			Steps []struct {
				Name, Run, If, Uses string
				Env, With           map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	foundReadiness, foundRecord, foundArtifact := false, false, false
	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run != "" {
				// Parse actual workflow shell; expression values are data at runtime.
				script := regexp.MustCompile(`\$\{\{[^}]*\}\}`).ReplaceAllString(step.Run, "fixture")
				cmd := exec.Command("bash", "-n")
				cmd.Stdin = strings.NewReader(script)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s/%s syntax: %v %s", jobName, step.Name, err, out)
				}
			}
			if step.Name == "Evaluate the Acceptance VPS result and write exact Module records" {
				foundRecord = true
				if step.If != "${{ !fromJSON(inputs.v3_attempt || '{}').diagnostic }}" {
					t.Fatal("diagnostic may emit qualification record")
				}
			}
			if jobName == "acceptance-vps" && strings.HasPrefix(step.With["name"], "installer-updater-acceptance-") {
				foundArtifact = true
				if step.If != "${{ !fromJSON(inputs.v3_attempt || '{}').diagnostic }}" {
					t.Fatal("diagnostic may upload qualification artifacts")
				}
			}
			if step.Name != "Verify Acceptance VPS readiness before signing" {
				continue
			}
			foundReadiness = true
			if step.Env["V3_ATTEMPT"] != "${{ inputs.v3_attempt }}" {
				t.Fatal("readiness has no bound attempt")
			}
			if _, err := exec.LookPath("jq"); err != nil {
				t.Fatal("jq required for real readiness shell")
			}
			for _, diagnostic := range []bool{false, true} {
				dir := t.TempDir()
				bin := filepath.Join(dir, "bin")
				if err := os.Mkdir(bin, 0700); err != nil {
					t.Fatal(err)
				}
				// Only SSH is replaced: capture the exact guarded command, never contact a host.
				if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/bash\nprintf '%s\\n' \"${!#}\" > \"$CAPTURE\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				attempt := "{}"
				expected := "/root/sbxr-qualification-evidence"
				if diagnostic {
					attempt = `{"diagnostic":{"start_unix":1,"test_until_unix":7201,"finish_unix":10801}}`
					expected = "/root/sbxr-diagnostic-run-123-attempt-1"
				}
				capture := filepath.Join(dir, "command")
				cmd := exec.Command("bash", "-c", step.Run)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "V3_ATTEMPT="+attempt, "ACCEPTANCE_VPS_HOST=fixture.invalid", "ACCEPTANCE_VPS_HOST_KEY=fixture", "ACCEPTANCE_VPS_SSH_PRIVATE_KEY=fixture", "GITHUB_RUN_ID=123", "GITHUB_RUN_ATTEMPT=1", "CAPTURE="+capture)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("readiness shell: %v %s", err, out)
				}
				command, err := os.ReadFile(capture)
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{expected, "/usr/local/bin/sbxr", "/var/lib/sbxr", "/root/sbxr-qualification-v3"} {
					normalized := strings.ReplaceAll(string(command), "'", "")
					if !strings.Contains(normalized, "test ! -e "+path+" && test ! -L "+path) {
						t.Fatalf("missing no-follow absence guard %s: %s", path, command)
					}
				}
				if diagnostic && strings.Contains(string(command), "/root/sbxr-qualification-evidence") {
					t.Fatal("diagnostic still requires moving old evidence")
				}
			}
		}
	}
	if !foundReadiness || !foundRecord || !foundArtifact {
		t.Fatal("workflow boundaries missing")
	}
	if !strings.Contains(workflow.Jobs["cleanup-unqualified"].If, "!fromJSON(inputs.v3_attempt || '{}').diagnostic") {
		t.Fatal("diagnostic may finalize draft")
	}
}
