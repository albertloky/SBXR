package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// These inputs describe owner-observed outcomes, not values calculated by the
// validator. In particular, no interrupted operation or package refresh occurs.
var mvpObservedChecks = [][]string{
	strings.Fields("packaged-install reviewed-setup outside-proxy-traffic menu-status-and-lifecycle ssh-access-preserved"),
	strings.Fields("trusted-outside-https one-correct-subscription-node wrong-token-refused private-files-and-logs-protected karing-import fresh-karing-node-latency manual-refresh selected-connection-preserved"),
	strings.Fields("old-established-session-terminated old-proxy-credential-refused replacement-proxy-traffic same-link-refreshed-identity old-link-refused replacement-link-usable proxy-identity-unchanged-by-link-rotation fresh-karing-replacement-latency"),
	strings.Fields("official-renewal-route certificate-replaced accepted-activation outside-trusted-tls proxy-traffic-preserved"),
	strings.Fields("restart-preserves-access reviewed-complete-removal owned-resources-absent outside-access-refused unrelated-resources-preserved test-client-and-secret-cleanup ssh-access-preserved"),
}

func mvpQualificationFixture(t *testing.T, binary string) (string, []byte, map[string]any) {
	t.Helper()
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.1", 84, 3
	source := repairBaselineFixture(t)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	facts.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []decisionReleaseIdentity{}}
	if err := json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &facts.SubscriptionHistory); err != nil {
		t.Fatal(err)
	}
	attempt := recurringAttemptFixture(t, source)
	attempt["schema"] = "sbxr-v3-qualification-attempt-v3"
	attempt["evidence_policy"] = "mvp-live-v1"
	attempt["support"], attempt["baseline"], attempt["sources"] = facts.Candidate.Support, historyBaseline(facts.SubscriptionHistory), []any{}
	attempt["required_scenarios"] = strings.Fields("mvp-install mvp-subscription mvp-credentials mvp-renewal mvp-removal")
	attempt["after_snap_refresh"] = attempt["packages"]
	var assets []softwarelifecycle.LatestAssetProof
	for _, raw := range draftAssets(0) {
		a := raw.(map[string]any)
		if a["name"] != "release-index.json" {
			assets = append(assets, softwarelifecycle.LatestAssetProof{Name: a["name"].(string), Size: int64(a["size"].(int)), SHA256: a["sha256"].(string)})
		}
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(facts.Candidate.BTag, facts.Commit, facts.Candidate.BSequence, assets, facts.Candidate.Support.lifecycle())
	if err != nil {
		t.Fatal(err)
	}
	attempt["candidate_index"] = string(index)
	boundary, manifest := qualificationBoundaryForCandidate(t, binary, facts, attempt)
	evidence := recurringEvidenceFixture(t, manifest, attempt)
	evidence["schema"] = "sbxr-v3-packaged-live-evidence-v3"
	for i, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		s["schema"] = "sbxr-v3-scenario-evidence-v3"
		if i == 0 {
			s["initial_state"] = "Not installed"
		}
		if i == 4 {
			s["final_state"] = "Not installed"
		}
		checks := []any{}
		for _, check := range mvpObservedChecks[i] {
			checks = append(checks, map[string]any{"record": map[string]any{"check": check, "observed_at": s["completed_at"], "result": "observed"}, "sha256": ""})
		}
		s["evidence"] = checks
	}
	rebindRecurringEvidence(t, evidence)
	return boundary, manifest, evidence
}

func TestMVPLiveQualificationAcceptsFiveNormalJourneys(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	boundary, manifest, evidence := mvpQualificationFixture(t, binary)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	output, err := runQualificationCommand(binary, document)
	if err != nil || jsonObject(t, output)["outcome"] != "accepted" {
		t.Fatalf("five normal journeys refused: %v\n%s", err, output)
	}
	body := jsonObject(t, output)["records"].([]any)[0].(map[string]any)["body"].(string)
	for _, required := range []string{"Evidence policy: mvp-live-v1\n", "Live acceptance coverage: " + softwarelifecycle.MVPLiveCoverage, "Karing connectivity evidence: " + softwarelifecycle.MVPKaringEvidence} {
		if !strings.Contains(body, required) {
			t.Fatalf("missing scope disclosure: %s", required)
		}
	}
	if strings.Count(body, "\nScenario: ") != 5 || strings.Contains(body, "Automated-only result:") || strings.Contains(body, "Karing checks not performed:") {
		t.Fatal("MVP acceptance claimed historical matrix or wrong scenario count")
	}
	for i := 0; i < 5; i++ {
		t.Run("missing-outcome-"+strings.Fields(softwarelifecycle.MVPLiveScenarios)[i], func(t *testing.T) {
			v := jsonObject(t, []byte(document))
			e := v["detailed_evidence"].(map[string]any)
			s := e["scenarios"].([]any)[i].(map[string]any)
			s["evidence"] = s["evidence"].([]any)[1:]
			rebindRecurringEvidence(t, e)
			v["detailed_evidence_sha256"] = sha256String(qualificationDocument(t, e))
			assertQualificationRefused(t, binary, qualificationDocument(t, v), "missing actual outcome")
		})
	}
	for name, mutate := range map[string]func([]any){
		"missing-removal":     func(s []any) { s[4].(map[string]any)["final_state"] = "Running" },
		"forced-interruption": func(s []any) { s[2].(map[string]any)["boundary"] = "after-commitment" },
		"failed-renewal":      func(s []any) { s[3].(map[string]any)["actual_result"] = "unexpected-failure" },
		"skipped-install":     func(s []any) { s[0].(map[string]any)["initial_state"] = "Running" },
		"historical-scenario": func(s []any) { s[0].(map[string]any)["scenario_id"] = "baseline-clean" },
	} {
		t.Run(name, func(t *testing.T) {
			v := jsonObject(t, []byte(document))
			e := v["detailed_evidence"].(map[string]any)
			mutate(e["scenarios"].([]any))
			rebindRecurringEvidence(t, e)
			v["detailed_evidence_sha256"] = sha256String(qualificationDocument(t, e))
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
}

func TestMVPLiveScopeDoesNotReinterpretHistoricalPolicies(t *testing.T) {
	attempt := v3QualificationAttempt{Support: &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []decisionReleaseIdentity{}}, Sources: []v3QualificationSource{}, EvidencePolicy: softwarelifecycle.MVPLiveEvidencePolicy, RequiredScenarios: strings.Fields(softwarelifecycle.MVPLiveScenarios)}
	if !validAttemptSupport(attempt) {
		t.Fatal("five-journey scope refused")
	}
	for _, policy := range []string{"unknown", softwarelifecycle.RepairEvidencePolicy, softwarelifecycle.RepairLifecycleEvidencePolicy, softwarelifecycle.RepairKaringLatencyEvidencePolicy, softwarelifecycle.RepairTwoIssuanceEvidencePolicy} {
		changed := attempt
		changed.EvidencePolicy = policy
		if validAttemptSupport(changed) {
			t.Fatalf("%s reinterpreted as five journeys", policy)
		}
	}
	changed := attempt
	changed.AutomatedOnlyScenarios = strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
	if validAttemptSupport(changed) {
		t.Fatal("MVP accepted blanket historical automated-matrix claim")
	}
	changed = attempt
	changed.RequiredScenarios = slices.Clone(attempt.RequiredScenarios)
	changed.RequiredScenarios[0], changed.RequiredScenarios[1] = changed.RequiredScenarios[1], changed.RequiredScenarios[0]
	if validAttemptSupport(changed) {
		t.Fatal("subscription before installation accepted")
	}
	changed = attempt
	support := *attempt.Support
	support.Scope = softwarelifecycle.FirstSubscriptionCleanInstall
	changed.Support = &support
	if validAttemptSupport(changed) {
		t.Fatal("repair policy leaked into another scope")
	}
}
