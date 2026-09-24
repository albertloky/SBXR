package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func lateConfirmationFixture(t *testing.T) map[string]any {
	t.Helper()
	document, err := os.ReadFile("testdata/r24-late-confirmation.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if err := json.Unmarshal(document, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestLateConfirmationSupplementCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	document := qualificationDocument(t, lateConfirmationFixture(t))
	output, err := runQualificationCommand(binary, document)
	if err != nil || !bytes.Contains(output, []byte(`"outcome":"accepted-supplement"`)) {
		t.Fatalf("CLI: %v\n%s", err, output)
	}
	// The supplement cannot be presented to any existing release-result route.
	for _, stage := range []string{"owner-exception-result", "v3-packaged-live-result", "stable-preflight", "stable-publication"} {
		facts := lateConfirmationFixture(t)
		facts["stage"] = stage
		if output, err := runQualificationCommand(binary, qualificationDocument(t, facts)); err == nil {
			t.Fatalf("CLI accepted supplement as %s: %s", stage, output)
		}
	}
}

func TestLateConfirmationSupplement(t *testing.T) {
	facts := lateConfirmationFixture(t)
	document := qualificationDocument(t, facts)
	var output bytes.Buffer
	if err := runQualification(strings.NewReader(document), &output); err != nil {
		t.Fatal(err)
	}
	var decision map[string]any
	if err := json.Unmarshal(output.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision["outcome"] != "accepted-supplement" || decision["release_eligible"] != false || decision["original_result"] != "failed" || decision["cleanup_performed_at"] != nil || decision["owner_confirmation_recorded_at"] != "2026-09-24T09:26:44.001843+00:00" || decision["facts_sha256"] != documentSHA256([]byte(document)) {
		t.Fatalf("dishonest or unbound decision: %s", output.Bytes())
	}
	for _, forbidden := range []string{"actions", "records", "acceptance_record"} {
		if _, exists := decision[forbidden]; exists {
			t.Fatalf("supplement grants %s", forbidden)
		}
	}
}

func TestLateConfirmationSupplementRefusesOverrides(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"other exception":    func(f map[string]any) { f["exception_id"] = "other" },
		"missing evidence":   func(f map[string]any) { f["evidence"] = f["evidence"].([]any)[1:] },
		"duplicate evidence": func(f map[string]any) { e := f["evidence"].([]any); e[1] = e[0] },
		"extra evidence": func(f map[string]any) {
			f["evidence"] = append(f["evidence"].([]any), map[string]any{"name": "waiver", "content": "approved"})
		},
		"runtime approval":             func(f map[string]any) { f["approved"] = true },
		"burned target":                func(f map[string]any) { f["target"] = "v3.1.80" },
		"unapproved fresh target":      func(f map[string]any) { f["target"] = "v3.1.81" },
		"unbound applicability review": func(f map[string]any) { f["applicability_review"] = "approved" },
		"ordinary live stage":          func(f map[string]any) { f["stage"] = "v3-packaged-live-result" },
		"old exception stage":          func(f map[string]any) { f["stage"] = "owner-exception-result" },
		"stable preflight":             func(f map[string]any) { f["stage"] = "stable-preflight" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			facts := lateConfirmationFixture(t)
			mutate(facts)
			var output bytes.Buffer
			if runQualification(strings.NewReader(qualificationDocument(t, facts)), &output) == nil || output.Len() != 0 {
				t.Fatal("override accepted")
			}
		})
	}
	// Every archived byte is bound, including the source/run/attempt, prior
	// failures, completed checks, and the real late confirmation timestamp.
	for i, raw := range lateConfirmationFixture(t)["evidence"].([]any) {
		name := raw.(map[string]any)["name"].(string)
		t.Run("altered/"+name, func(t *testing.T) {
			facts := lateConfirmationFixture(t)
			e := facts["evidence"].([]any)[i].(map[string]any)
			e["content"] = e["content"].(string) + " "
			var output bytes.Buffer
			if runQualification(strings.NewReader(qualificationDocument(t, facts)), &output) == nil || output.Len() != 0 {
				t.Fatal("altered evidence accepted")
			}
		})
	}
}

func TestLateConfirmationRejectsReinterpretedHistory(t *testing.T) {
	for _, tc := range []struct{ name, file, old, replacement string }{
		{"other source", "signed/qualification-manifest.json", "1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52", strings.Repeat("a", 40)},
		{"other attempt", "signed/qualification-manifest.json", `"run_attempt":2`, `"run_attempt":3`},
		{"other prior tag", "signed/qualification-manifest.json", "v3.1.80", "v3.1.81"},
		{"failed functional check", "01-observation.json", `"result": "observed"`, `"result": "failed"`},
		{"backdated confirmation", "owner-late-cleanup-confirmation.json", "2026-09-24T09:26:44.001843+00:00", "2026-09-24T08:00:00.000000+00:00"},
		{"invented cleanup time", "owner-late-cleanup-confirmation.json", "not established", "2026-09-24T08:00:00Z"},
		{"revived original result", "failure-decision.json", `"outcome":"failed"`, `"outcome":"accepted"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := lateConfirmationFixture(t)
			changed := false
			for _, raw := range facts["evidence"].([]any) {
				e := raw.(map[string]any)
				if e["name"] != tc.file {
					continue
				}
				content := e["content"].(string)
				if !strings.Contains(content, tc.old) {
					t.Fatal("mutation did not exercise expected field")
				}
				e["content"] = strings.ReplaceAll(content, tc.old, tc.replacement)
				changed = true
			}
			if !changed {
				t.Fatal("missing mutation target")
			}
			var output bytes.Buffer
			if runQualification(strings.NewReader(qualificationDocument(t, facts)), &output) == nil || output.Len() != 0 {
				t.Fatal("rewritten history accepted")
			}
		})
	}
}
