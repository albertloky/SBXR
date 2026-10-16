package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestQualificationInputDiagnosticsDoNotEchoRejectedValues(t *testing.T) {
	for _, tc := range []struct{ name, document, want string }{
		{"empty", "", "qualification-input/empty"},
		{"invalid JSON", `{"secret":"sensitive-input-marker"`, "qualification-input/unique-json"},
		{"duplicate field", `{"schema":"sensitive-input-marker","schema":"other"}`, "qualification-input/unique-json"},
		{"schema", `{"schema":"sensitive-input-marker","stage":"candidate-preflight"}`, "qualification-input/schema"},
		{"stage", `{"schema":"sbxr-release-qualification-facts-v1","stage":"sensitive-input-marker"}`, "qualification-input/stage"},
		{"unknown field", `{"schema":"sbxr-release-qualification-facts-v1","stage":"candidate-preflight","sensitive-input-marker":true}`, "candidate-preflight/canonical-facts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runQualification(strings.NewReader(tc.document), &out)
			if err == nil || err.Error() != tc.want || out.Len() != 0 {
				t.Fatalf("error=%v output=%q; want %s", err, out.String(), tc.want)
			}
		})
	}
	var out bytes.Buffer
	err := runQualification(io.LimitReader(strings.NewReader(strings.Repeat(" ", maxQualificationFactsBytes+1)), maxQualificationFactsBytes+1), &out)
	if err == nil || !strings.Contains(err.Error(), "qualification-input/size") || !strings.Contains(err.Error(), "expected<=16777216 observed>=16777217") {
		t.Fatalf("oversize diagnostic=%v", err)
	}
}

type failedQualificationReader struct{ err error }

func (r failedQualificationReader) Read([]byte) (int, error) { return 0, r.err }

func TestQualificationInputDiagnosticPreservesPrivateCause(t *testing.T) {
	cause := errors.New("sensitive-reader-marker")
	err := runQualification(failedQualificationReader{cause}, &bytes.Buffer{})
	if err == nil || err.Error() != "qualification-input/read" || !errors.Is(err, cause) {
		t.Fatalf("read diagnostic lost safe context or cause: %v", err)
	}
}

func TestStablePublicationDiagnosticsPreserveExactPreflightGate(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	assertQualificationDiagnosticCLI(t, binary, `{"schema":"sensitive-input-marker","stage":"candidate-preflight"}`, "qualification-input/schema")
	base := automaticPublicationFixture(t, binary, mainReviewPreflightFixture(t, binary))
	for _, tc := range []struct {
		name, want string
		change     func(map[string]any)
	}{
		{"preflight replay", "stable-publication/preflight: stable-preflight/release-body", func(f map[string]any) {
			f["preflight_facts"].(map[string]any)["releases"].([]any)[0].(map[string]any)["body"] = "sensitive-release-marker"
		}},
		{"preflight decision", "stable-publication/preflight-decision", func(f map[string]any) {
			f["preflight_decision"].(map[string]any)["facts_sha256"] = strings.Repeat("0", 64)
		}},
		{"approval", "stable-publication/approval", func(f map[string]any) {
			f["approval"].(map[string]any)["state"] = "sensitive-approval-marker"
		}},
		{"observation", "stable-publication/observation", func(f map[string]any) {
			f["observation"].(map[string]any)["body"] = "sensitive-release-marker"
		}},
		{"action index", "stable-publication/action-index expected<1 observed=9", func(f map[string]any) { f["action_index"] = 9 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := jsonObject(t, []byte(qualificationDocument(t, base)))
			tc.change(facts)
			assertQualificationDiagnosticCLI(t, binary, qualificationDocument(t, facts), tc.want)
			var out bytes.Buffer
			err := runQualification(strings.NewReader(qualificationDocument(t, facts)), &out)
			if err == nil || err.Error() != tc.want || out.Len() != 0 {
				t.Fatalf("error=%v output=%q; want %s", err, out.String(), tc.want)
			}
		})
	}
}

func assertQualificationDiagnosticCLI(t *testing.T, binary, document, want string) {
	t.Helper()
	command := exec.Command(binary, "qualification")
	command.Stdin = strings.NewReader(document)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err == nil || stdout.Len() != 0 || stderr.String() != "sbxr release qualification refused: "+want+"\n" {
		t.Fatalf("CLI error=%v stdout=%q stderr=%q; want %s", err, stdout.String(), stderr.String(), want)
	}
}
