package architecture_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type preflightDiagnosticStep struct {
	ID, If, Run, Uses string
	ContinueOnError   bool `yaml:"continue-on-error"`
	With              map[string]string
}

func stableDiagnosticSteps(t *testing.T) map[string]preflightDiagnosticStep {
	t.Helper()
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			If              string
			ContinueOnError bool `yaml:"continue-on-error"`
			Steps           []preflightDiagnosticStep
		}
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	steps := map[string]preflightDiagnosticStep{}
	for _, step := range workflow.Jobs["preflight"].Steps {
		steps[step.ID] = step
	}
	if workflow.Jobs["preflight"].ContinueOnError || steps["eligibility"].Run == "" || steps["eligibility"].ContinueOnError {
		t.Fatal("real validation no longer fails closed")
	}
	if workflow.Jobs["finalize-failure"].If != "always() && inputs.operation == 'abandon'" {
		t.Fatal("recoverable publishing failure triggers finalization or burn")
	}
	return steps
}

func TestStablePreflightDiagnosticSummaryDoesNotRetainRawFacts(t *testing.T) {
	steps := stableDiagnosticSteps(t)
	stage, upload := steps["preflight-diagnostics"], steps["preflight-diagnostics-upload"]
	if stage.If != "always()" || !stage.ContinueOnError || stage.Run == "" || !upload.ContinueOnError ||
		upload.If != "always() && steps.preflight-diagnostics.outcome == 'success'" ||
		upload.Uses != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" ||
		upload.With["path"] != "preflight-diagnostics/summary.json" || upload.With["retention-days"] != "90" {
		t.Fatal("diagnostics can fail preflight or upload unfiltered inputs")
	}
	const secret = "arbitrary-private-value-without-a-known-marker"
	facts := `{"body":"` + secret + `","burned_identities":[{}],"subscription_history":{"complete":true,"releases":[{},{}]}}`
	for _, tc := range []struct{ name, body string }{
		{"free text", facts},
		{"escaped secret", strings.ReplaceAll(facts, "private", `pr\u0069vate`)},
		{"malformed JSON", `{"body":"` + secret},
		{"known outcomes", facts},
		{"empty refused decision", facts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDiagnosticInput(t, dir, "verified/stable-preflight-facts.json", tc.body)
			decision, latest := `{"outcome":"`+secret+`"}`, `{"outcome":"`+secret+`"}`
			wantDecision, wantLatest := "invalid", "invalid"
			if tc.name == "known outcomes" {
				decision, latest = `{"outcome":"actions-required"}`, `{"outcome":"accepted"}`
				wantDecision, wantLatest = "actions-required", "accepted"
			}
			if tc.name == "empty refused decision" {
				decision, wantDecision = "", "unavailable"
			}
			writeDiagnosticInput(t, dir, "verified/stable-preflight-decision.json", decision)
			writeDiagnosticInput(t, dir, "current-source-verification.json", latest)
			writeDiagnosticInput(t, dir, "current-release-history.json", `[{"body":"`+secret+`"}]`)
			writeDiagnosticInput(t, dir, "ssh.key", secret)
			if output, err := runDiagnosticShell(dir, stage.Run); err != nil || len(output) != 0 {
				t.Fatalf("summary failed or disclosed input: %v %q", err, output)
			}
			entries, err := os.ReadDir(filepath.Join(dir, "preflight-diagnostics"))
			if err != nil || len(entries) != 1 || entries[0].Name() != "summary.json" {
				t.Fatal("diagnostics retained unnecessary files")
			}
			body, err := os.ReadFile(filepath.Join(dir, "preflight-diagnostics/summary.json"))
			if err != nil || bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte("body")) || bytes.Contains(body, []byte(`pr\u0069vate`)) {
				t.Fatal("diagnostic summary retained raw input")
			}
			var summary map[string]any
			if json.Unmarshal(body, &summary) != nil || len(summary) != 7 || summary["schema"] != "sbxr-stable-preflight-diagnostics-v1" || summary["validation_outcome"] != wantDecision || summary["public_latest_outcome"] != wantLatest {
				t.Fatalf("unsafe diagnostic schema: %s", body)
			}
			if tc.name != "malformed JSON" && (summary["history_complete"] != true || summary["history_release_count"] != float64(2) || summary["burned_identity_count"] != float64(1)) {
				t.Fatal("summary lost the bounded history observations")
			}
			files := summary["files"].(map[string]any)
			if len(files) != 4 {
				t.Fatal("diagnostic input allowlist changed")
			}
			fact := files["stable-preflight-facts.json"].(map[string]any)
			digest := sha256.Sum256([]byte(tc.body))
			if len(fact) != 2 || fact["sha256"] != hex.EncodeToString(digest[:]) || fact["size"] != float64(len(tc.body)) {
				t.Fatal("summary lost the exact input binding")
			}
		})
	}
}

func TestStablePreflightDiagnosticFailuresPreserveValidationResult(t *testing.T) {
	steps := stableDiagnosticSteps(t)
	stage, upload, warning := steps["preflight-diagnostics"], steps["preflight-diagnostics-upload"], steps["preflight-diagnostics-warning"]
	if warning.If != "always() && (steps.preflight-diagnostics.outcome == 'failure' || steps.preflight-diagnostics-upload.outcome == 'failure')" || !warning.ContinueOnError {
		t.Fatal("diagnostic failures lack a non-fatal safe warning")
	}
	for _, validationFailed := range []bool{false, true} {
		for _, failure := range []string{"none", "live-symlink", "dangling-symlink", "directory", "oversize", "staging", "upload", "warning"} {
			t.Run(map[bool]string{false: "accepted", true: "refused"}[validationFailed]+"/"+failure, func(t *testing.T) {
				dir := t.TempDir()
				writeDiagnosticInput(t, dir, "verified/stable-preflight-facts.json", `{}`)
				input := filepath.Join(dir, "verified/stable-preflight-facts.json")
				if failure == "oversize" {
					writeDiagnosticInput(t, dir, "verified/stable-preflight-facts.json", strings.Repeat("x", (16<<20)+1))
				}
				if failure == "directory" {
					if err := os.Remove(input); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(input, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasSuffix(failure, "symlink") {
					if err := os.Remove(input); err != nil {
						t.Fatal(err)
					}
					if failure == "live-symlink" {
						writeDiagnosticInput(t, dir, "private-key", "private")
					}
					if err := os.Symlink("../private-key", input); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "staging" || failure == "warning" {
					if err := os.Mkdir(filepath.Join(dir, "preflight-diagnostics"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				output, stageErr := runDiagnosticShell(dir, stage.Run)
				if len(output) != 0 {
					t.Fatalf("collector disclosed input: %q", output)
				}
				stageFailed := stageErr != nil
				if stageFailed != (failure == "live-symlink" || failure == "dangling-symlink" || failure == "directory" || failure == "oversize" || failure == "staging" || failure == "warning") {
					t.Fatalf("unexpected collector result: %v", stageErr)
				}
				// A failed outcome skips upload even when continue-on-error makes its conclusion successful.
				uploadFailed := false
				if !stageFailed {
					command := "exit 0"
					if failure == "upload" {
						command = "exit 1"
					}
					_, err := runDiagnosticShell(dir, command)
					uploadFailed = err != nil
				}
				warningFailed := false
				if stageFailed || uploadFailed {
					script := warning.Run
					if failure == "warning" {
						script += "\nexit 1"
					}
					output, err := runDiagnosticShell(dir, script)
					warningFailed = err != nil
					if warningFailed != (failure == "warning") || string(output) != "::warning::Stable preflight diagnostics unavailable; validation result unchanged.\n" {
						t.Fatalf("warning was not fixed and safe: %v %q", err, output)
					}
				}
				// Apply documented GitHub step conclusions to the actual YAML configuration.
				jobFailed := validationFailed || stageFailed && !stage.ContinueOnError || uploadFailed && !upload.ContinueOnError || warningFailed && !warning.ContinueOnError
				if jobFailed != validationFailed {
					t.Fatal("diagnostics changed validation and therefore the burn trigger")
				}
			})
		}
	}
}

func TestStablePreflightDiagnosticRetryCannotUploadStaleSummary(t *testing.T) {
	steps := stableDiagnosticSteps(t)
	dir := t.TempDir()
	writeDiagnosticInput(t, dir, "verified/placeholder", "")
	input := filepath.Join(dir, "verified/stable-preflight-facts.json")
	if err := os.Symlink("missing", input); err != nil {
		t.Fatal(err)
	}
	if output, err := runDiagnosticShell(dir, steps["preflight-diagnostics"].Run); err == nil || len(output) != 0 {
		t.Fatal("unsafe first collection was not refused silently")
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	writeDiagnosticInput(t, dir, "verified/stable-preflight-facts.json", `{}`)
	if output, err := runDiagnosticShell(dir, steps["preflight-diagnostics"].Run); err != nil || len(output) != 0 {
		t.Fatal("safe collection after refusal failed")
	}
	summary := filepath.Join(dir, "preflight-diagnostics/summary.json")
	before, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	writeDiagnosticInput(t, dir, "verified/stable-preflight-facts.json", `{"changed":true}`)
	if output, err := runDiagnosticShell(dir, steps["preflight-diagnostics"].Run); err == nil || len(output) != 0 {
		t.Fatal("retry overwrote an existing diagnostic summary")
	}
	after, err := os.ReadFile(summary)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed retry changed retained diagnostic bytes")
	}
	if steps["preflight-diagnostics-upload"].If != "always() && steps.preflight-diagnostics.outcome == 'success'" {
		t.Fatal("failed retry can upload an older summary")
	}
}

func writeDiagnosticInput(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runDiagnosticShell(dir, script string) ([]byte, error) {
	command := exec.Command("bash", "-c", script)
	command.Dir = dir
	return command.CombinedOutput()
}
