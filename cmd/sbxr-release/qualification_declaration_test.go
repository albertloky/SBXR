package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestQualificationDeclarationAcceptsCompleteV3Preparation(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	document := qualificationDeclarationFixture(t)
	output, err := runQualificationDeclarationCommand(binary, document)
	if err != nil {
		t.Fatalf("complete declaration refused: %v\n%s", err, output)
	}
	decision := jsonObject(t, output)
	if decision["schema"] != qualificationDecisionSchema || decision["stage"] != qualificationDeclarationStage || decision["outcome"] != "accepted" || decision["facts_sha256"] != sha256String(document) {
		t.Fatalf("unexpected declaration decision: %s", output)
	}
}

func TestQualificationDeclarationRejectsInvalidDeclaredFields(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	document := qualificationDeclarationFixture(t)
	for name, mutate := range map[string]func(map[string]any){
		"identical Certbot before and after refresh": func(v map[string]any) {
			attempt := v["attempt"].(map[string]any)
			attempt["after_snap_refresh"].(map[string]any)["certbot"] = attempt["packages"].(map[string]any)["certbot"]
		},
		"scenario limit": func(v map[string]any) {
			v["attempt"].(map[string]any)["scenario_limit_seconds"] = 1801
		},
		"scenario matrix": func(v map[string]any) {
			attempt := v["attempt"].(map[string]any)
			scenarios := attempt["required_scenarios"].([]any)
			attempt["required_scenarios"] = scenarios[:len(scenarios)-1]
		},
		"support": func(v map[string]any) {
			v["attempt"].(map[string]any)["support"].(map[string]any)["contract"] = "other"
		},
		"package": func(v map[string]any) {
			v["attempt"].(map[string]any)["proxy_package"].(map[string]any)["version"] = "1.13.20"
		},
		"invalid preflight": func(v map[string]any) {
			v["preflight"].(map[string]any)["candidate"].(map[string]any)["b_sequence"] = 85
		},
		"signing-derived baseline": func(v map[string]any) {
			v["attempt"].(map[string]any)["baseline"] = historyBaselineFromRequest(t, v)
		},
		"signing-derived candidate index": func(v map[string]any) {
			v["attempt"].(map[string]any)["candidate_index"] = "{}"
		},
	} {
		t.Run(name, func(t *testing.T) {
			variant := jsonObject(t, []byte(document))
			mutate(variant)
			assertQualificationDeclarationRefused(t, binary, qualificationDocument(t, variant), name)
		})
	}
}

func TestQualificationDeclarationRequiresCanonicalUniqueJSON(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	document := qualificationDeclarationFixture(t)
	duplicate := strings.Replace(document, `"scenario_limit_seconds":1800`, `"scenario_limit_seconds":1800,"scenario_limit_seconds":1800`, 1)
	assertQualificationDeclarationRefused(t, binary, duplicate, "duplicate member")
	variant := jsonObject(t, []byte(document))
	variant["attempt"].(map[string]any)["waiver"] = true
	assertQualificationDeclarationRefused(t, binary, qualificationDocument(t, variant), "unknown member")
	assertQualificationDeclarationRefused(t, binary, document+"\n", "noncanonical whitespace")
}

func qualificationDeclarationFixture(t *testing.T) string {
	t.Helper()
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.1", 84, 3
	source := repairBaselineFixture(t)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	facts.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []decisionReleaseIdentity{}}
	if json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &facts.SubscriptionHistory) != nil {
		t.Fatal("history fixture")
	}
	attemptMap := recurringAttemptFixture(t, source)
	attemptMap["schema"] = "sbxr-v3-qualification-attempt-v3"
	attemptMap["support"] = facts.Candidate.Support
	attemptMap["sources"] = []any{}
	attemptMap["evidence_policy"] = softwarelifecycle.RepairTwoIssuanceEvidencePolicy
	attemptMap["automated_only_scenarios"] = strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
	var attempt v3QualificationAttempt
	if json.Unmarshal([]byte(qualificationDocument(t, attemptMap)), &attempt) != nil {
		t.Fatal("attempt fixture")
	}
	attempt.RequiredScenarios = attemptScenarios(attempt)
	return qualificationDocument(t, map[string]any{"attempt": attempt, "preflight": facts})
}

func historyBaselineFromRequest(t *testing.T, request map[string]any) qualificationRelease {
	t.Helper()
	var facts qualificationFacts
	encoded := qualificationDocument(t, request["preflight"])
	if json.Unmarshal([]byte(encoded), &facts) != nil {
		t.Fatal("preflight fixture")
	}
	return historyBaseline(facts.SubscriptionHistory)
}

func buildQualificationDeclarationBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return binary
}

func runQualificationDeclarationCommand(binary, document string) ([]byte, error) {
	run := exec.Command(binary, "qualification-declaration")
	run.Stdin = strings.NewReader(document)
	return run.CombinedOutput()
}

func assertQualificationDeclarationRefused(t *testing.T, binary, document, name string) {
	t.Helper()
	if output, err := runQualificationDeclarationCommand(binary, document); err == nil {
		t.Fatalf("%s accepted: %s", name, output)
	}
}
