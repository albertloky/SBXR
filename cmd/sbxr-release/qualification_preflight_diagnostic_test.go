package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestStablePreflightReportsSafeRefusalGate(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	base := mainReviewPreflightFixture(t, binary)
	for _, tc := range []struct {
		name, gate string
		change     func(map[string]any)
	}{
		{"acceptance replay", "acceptance-decision", func(f map[string]any) {
			f["acceptance_decision"].(map[string]any)["facts_sha256"] = strings.Repeat("0", 64)
		}},
		{"candidate provenance", "candidate-run", func(f map[string]any) {
			f["candidate_run"].(map[string]any)["event"] = "push"
		}},
		{"archive", "archive", func(f map[string]any) {
			f["archive"].(map[string]any)["commit"] = strings.Repeat("0", 40)
		}},
		{"unavailable Latest", "subscription-history-public-latest", func(f map[string]any) {
			f["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["outcome"] = "unavailable"
		}},
		{"refused Latest", "subscription-history-public-latest", func(f map[string]any) {
			f["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["outcome"] = "refused"
		}},
		{"incomplete history", "subscription-history", func(f map[string]any) {
			f["subscription_history"].(map[string]any)["complete"] = false
		}},
		{"Latest identity", "latest-release-id", func(f map[string]any) { f["latest_release_id"] = 9999 }},
		{"release bytes", "release-identity-assets", func(f map[string]any) {
			f["releases"].([]any)[0].(map[string]any)["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		}},
		{"release state", "release-state", func(f map[string]any) { f["releases"].([]any)[0].(map[string]any)["draft"] = false }},
		{"release body", "release-body", func(f map[string]any) {
			f["releases"].([]any)[0].(map[string]any)["body"] = "sensitive-value-must-not-appear"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := jsonObject(t, []byte(qualificationDocument(t, base)))
			tc.change(facts)
			assertPreflightDiagnostic(t, binary, qualificationDocument(t, facts), tc.gate)
		})
	}
	assertPreflightDiagnostic(t, binary, qualificationDocument(t, base)+"\n", "canonical-facts")
}

func assertPreflightDiagnostic(t *testing.T, binary, document, gate string) {
	t.Helper()
	command := exec.Command(binary, "qualification")
	command.Stdin = strings.NewReader(document)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	want := "sbxr release qualification refused: stable-preflight/" + gate + "\n"
	if err == nil || stdout.Len() != 0 || stderr.String() != want {
		t.Fatalf("refusal: error=%v stdout=%q stderr=%q; want %q", err, stdout.String(), stderr.String(), want)
	}
}
