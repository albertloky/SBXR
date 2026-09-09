package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeclarationDispatchStopsBeforeGitHubOnRefusal(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-candidate-dispatch.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"check", "dispatch"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"tool":    "#!/bin/sh\ncat > \"$CAPTURE\"\nexit 1\n",
				"gh":      "#!/bin/sh\ntouch \"$CALLED\"\nexit 99\n",
				"facts":   `{"candidate":{"mode":"v3"}}`,
				"attempt": `{"schema":"first","schema":"duplicate"}`,
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script, mode, filepath.Join(dir, "tool"), filepath.Join(dir, "facts"), filepath.Join(dir, "attempt"))
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CAPTURE="+filepath.Join(dir, "capture"), "CALLED="+filepath.Join(dir, "called"))
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("refusal succeeded: %s", out)
			}
			if _, err := os.Stat(filepath.Join(dir, "called")); !os.IsNotExist(err) {
				t.Fatalf("GitHub called after refusal: %v", err)
			}
			input, err := os.ReadFile(filepath.Join(dir, "capture"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(input), files["attempt"]) {
				t.Fatalf("declaration normalized before validation: %s", input)
			}
		})
	}
}

func TestDeclarationDispatchUsesValidatedSnapshot(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-candidate-dispatch.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"check", "dispatch", "changed-main"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"tool":    "#!/bin/sh\ncat > \"$CAPTURE\"\nprintf '{\"outcome\":\"accepted\"}'\n",
				"gh":      "#!/bin/sh\nif [ \"$1\" = api ]; then printf '%s' \"$CURRENT\"; else cat > \"$DISPATCHED\"; fi\n",
				"facts":   `{"candidate":{"b_sequence":132,"b_tag":"v3.1.51","mode":"v3"},"commit":"source","remote_main":"source"}`,
				"attempt": `{"schema":"declaration"}`,
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			mode, current := "dispatch", "source"
			if scenario == "check" {
				mode = "check"
			}
			if scenario == "changed-main" {
				current = "other"
			}
			cmd := exec.Command("bash", script, mode, filepath.Join(dir, "tool"), filepath.Join(dir, "facts"), filepath.Join(dir, "attempt"))
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CAPTURE="+filepath.Join(dir, "capture"), "DISPATCHED="+filepath.Join(dir, "dispatched"), "CURRENT="+current)
			out, err := cmd.CombinedOutput()
			if (err != nil) != (scenario == "changed-main") {
				t.Fatalf("unexpected result: %v %s", err, out)
			}
			data, err := os.ReadFile(filepath.Join(dir, "dispatched"))
			if scenario != "dispatch" {
				if !os.IsNotExist(err) {
					t.Fatalf("unexpected dispatch: %v %s", err, data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"b_tag":"v3.1.51"`) || !strings.Contains(string(data), `"b_sequence":"132"`) || !strings.Contains(string(data), `"v3_attempt":"{\"schema\":\"declaration\"}"`) {
				t.Fatalf("dispatch inputs changed: %s", data)
			}
		})
	}
}

func TestV4DeclarationDispatchRequiresRehearsedOperator(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-candidate-dispatch.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"check", "dispatch"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"tool":    "#!/bin/sh\ncat >/dev/null\nprintf '{\"outcome\":\"accepted\"}'\n",
				"gh":      "#!/bin/sh\ntouch \"$CALLED\"\nexit 99\n",
				"facts":   `{"candidate":{"mode":"v3"}}`,
				"attempt": `{"evidence_policy":"repair-issuance-bounded-v4"}`,
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script, mode, filepath.Join(dir, "tool"), filepath.Join(dir, "facts"), filepath.Join(dir, "attempt"))
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALLED="+filepath.Join(dir, "called"), "SBXR_OPERATOR_REHEARSAL_REPORT="+filepath.Join(dir, "missing-report"))
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), `"ready": false`) {
				t.Fatalf("missing operator rehearsal was not refused: %v %s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "called")); !os.IsNotExist(err) {
				t.Fatalf("GitHub called before operator readiness: %v", err)
			}
		})
	}
}
