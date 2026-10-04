package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func cleanInstallOnlyBaselineFixture(t *testing.T) observedRelease {
	t.Helper()
	// Synthetic current-baseline metadata, not packaged or live v3.1.81 proof.
	source := recurringSourceFixture()
	source.Body = strings.NewReplacer(source.Tag, "v3.1.81", "Sequence: 17\n", "Sequence: 159\n").Replace(source.Body)
	source.Tag, source.Index.Tag = "v3.1.81", "v3.1.81"
	*source.Sequence, source.Index.Sequence, source.Index.Schema = 159, 159, 2
	source.Index.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []decisionReleaseIdentity{}}
	return source
}

func TestReleaseIndexDefaultsToCleanInstallOnly(t *testing.T) {
	directory := t.TempDir()
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("index fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(directory, "release-index.json")
	if err := buildReleaseIndexFile(indexOptions{directory: directory, output: output, tag: "v3.1.82", commit: strings.Repeat("a", 40), sequence: 160}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), `"support":{"scope":"subscription-clean-install-only","sources":[],"contract":"sbxr-subscription-update-v1"}`) {
		t.Fatalf("default index lacks explicit clean-install-only support: %v %s", err, data)
	}
}

func TestCleanInstallOnlyScopeRequiresHTTPAndNoIncomingSources(t *testing.T) {
	attempt := v3QualificationAttempt{
		Support: &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallOnly, Sources: []decisionReleaseIdentity{}},
		Sources: []v3QualificationSource{}, EvidencePolicy: softwarelifecycle.MVPHTTPEvidencePolicy, RequiredScenarios: strings.Fields(softwarelifecycle.MVPHTTPScenarios),
	}
	if !validAttemptSupport(attempt) || !mvpLiveAttempt(attempt) || !slices.Equal(attemptScenarios(attempt), strings.Fields(softwarelifecycle.MVPHTTPScenarios)) {
		t.Fatal("clean-install-only five-journey HTTP scope refused")
	}
	for name, change := range map[string]func(*v3QualificationAttempt){
		"missing sources":           func(a *v3QualificationAttempt) { a.Sources = nil },
		"incoming source":           func(a *v3QualificationAttempt) { a.Sources = []v3QualificationSource{{}} },
		"missing support sources":   func(a *v3QualificationAttempt) { a.Support.Sources = nil },
		"declared incoming support": func(a *v3QualificationAttempt) { a.Support.Sources = []decisionReleaseIdentity{{}} },
		"legacy HTTPS policy":       func(a *v3QualificationAttempt) { a.EvidencePolicy = softwarelifecycle.MVPLiveEvidencePolicy },
		"recurring HTTP policy":     func(a *v3QualificationAttempt) { a.EvidencePolicy = softwarelifecycle.MVPHTTPRecurringEvidencePolicy },
		"repair waiver":             func(a *v3QualificationAttempt) { a.OwnerException = softwarelifecycle.LateConfirmationID },
		"repair review": func(a *v3QualificationAttempt) {
			a.LateConfirmationReview = &softwarelifecycle.LateConfirmationReview{}
		},
		"blanket matrix":  func(a *v3QualificationAttempt) { a.AutomatedOnlyScenarios = []string{"identity-precommit"} },
		"missing serving": func(a *v3QualificationAttempt) { a.RequiredScenarios = a.RequiredScenarios[:4] },
		"old certificate journey": func(a *v3QualificationAttempt) {
			a.RequiredScenarios = strings.Fields(softwarelifecycle.MVPLiveScenarios)
		},
	} {
		a := attempt
		support := *attempt.Support
		a.Support = &support
		change(&a)
		if validAttemptSupport(a) {
			t.Fatalf("%s accepted", name)
		}
	}
	var history v3ReleaseHistory
	if err := json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, cleanInstallOnlyBaselineFixture(t)))), &history); err != nil {
		t.Fatal(err)
	}
	if !validSubscriptionHistory(&history, softwarelifecycle.SubscriptionCleanInstallOnly, nil) || validSubscriptionHistory(&history, softwarelifecycle.SubscriptionCleanInstallRepair, nil) {
		t.Fatal("current baseline rejected or historical repair restriction weakened")
	}
	history.Complete = false
	if validSubscriptionHistory(&history, softwarelifecycle.SubscriptionCleanInstallOnly, nil) {
		t.Fatal("incomplete history accepted")
	}
}

func TestCleanInstallOnlyQualificationDeclarationRecordAndPublication(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	boundary, manifest, evidence := mvpQualificationFixtureForSupport(t, binary, false, true, true)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	out, err := runQualificationCommand(binary, document)
	if err != nil || jsonObject(t, out)["outcome"] != "accepted" {
		t.Fatalf("clean-install-only HTTP qualification: %v %s", err, out)
	}
	body := jsonObject(t, out)["records"].([]any)[0].(map[string]any)["body"].(string)
	for _, required := range []string{
		`Release support: {"scope":"subscription-clean-install-only","sources":[],"contract":"sbxr-subscription-update-v1"}`,
		"Evidence policy: mvp-http-live-v1\n", "Incoming source upgrades: Not applicable\n", "Two-release update/recovery: Not applicable\n",
		"Subscription transport: " + softwarelifecycle.MVPHTTPTransportDisclosure + "\n", "Scenario: mvp-serving ",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("missing clean-install scope disclosure: %s", required)
		}
	}
	if strings.Count(body, "\nScenario: ") != 5 || strings.Contains(body, "Scenario: source-") || strings.Contains(body, "Automated-only result:") {
		t.Fatal("record claims upgrade or historical matrix evidence")
	}
	var bf qualificationBoundaryFacts
	var vf candidateDraftVerificationFacts
	var cf candidateDraftConstructionFacts
	var pre qualificationFacts
	var m qualificationManifest
	if !decodeCanonical([]byte(boundary), &bf) || !decodeCanonical(bf.DraftVerificationFacts, &vf) || !decodeCanonical(vf.ConstructionFacts, &cf) || !decodeCanonical(cf.PreflightFacts, &pre) || !decodeCanonical(manifest, &m) {
		t.Fatal("fixture decision chain")
	}
	declaration := *m.V3Attempt
	declaration.Baseline, declaration.CandidateIndex = nil, ""
	var declared bytes.Buffer
	if err := runQualificationDeclaration(strings.NewReader(qualificationDocument(t, qualificationDeclarationFacts{Attempt: declaration, Preflight: pre})), &declared); err != nil {
		t.Fatalf("unsigned declaration: %v", err)
	}
	r := m.Releases[0]
	support := m.V3Attempt.Support.lifecycle()
	public := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: r.ReleaseIdentity.Repository, Tag: r.Tag, Commit: r.Commit, IndexSHA256: r.ReleaseIdentity.ReleaseIndexSHA256}, Sequence: r.Sequence, Support: &support}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(qualificationDocument(t, map[string]any{"body": body, "release": public, "assets": r.Assets})), 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("go", "test", "../../internal/softwarelifecycle/adapter/github", "-run", "TestCleanInstallOnlyRecordCompatibility", "-count=1")
	check.Env = append(os.Environ(), "SBXR_TEST_CLEAN_INSTALL_ONLY_RECORD="+path)
	if result, err := check.CombinedOutput(); err != nil {
		t.Fatalf("public/frozen reader: %v %s", err, result)
	}
	for i, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		for j := range s["evidence"].([]any) {
			v := jsonObject(t, []byte(qualificationDocument(t, evidence)))
			item := v["scenarios"].([]any)[i].(map[string]any)
			checks := item["evidence"].([]any)
			item["evidence"] = append(checks[:j], checks[j+1:]...)
			rebindRecurringEvidence(t, v)
			assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, v), "missing "+s["scenario_id"].(string)+" observation")
		}
	}
	assertCleanInstallOnlyPublication(t, binary, pre, m, document, out)
}

func assertCleanInstallOnlyPublication(t *testing.T, binary string, pre qualificationFacts, m qualificationManifest, document string, decision []byte) {
	t.Helper()
	source, release := pre.Releases[0], m.Releases[0]
	body := jsonObject(t, decision)["records"].([]any)[0].(map[string]any)["body"].(string)
	stable := map[string]any{
		"acceptance_decision": jsonObject(t, decision), "acceptance_facts": jsonObject(t, []byte(document)),
		"archive":           map[string]any{"commit": pre.ArchiveCommit, "remote_commit": pre.ArchiveRemoteCommit, "remote_tag_object": pre.ArchiveRemoteTagObject, "tag_object": pre.ArchiveTagObject, "type": "tag"},
		"burned_identities": []any{}, "candidate_run": map[string]any{"conclusion": "success", "created_at": m.V3Attempt.StartedAt, "event": "workflow_dispatch", "head_sha": m.Workflow.Commit, "id": m.Workflow.RunID, "path": m.Workflow.Path},
		"checklist_sha256": m.AcceptanceVPSChecklistSHA256, "latest_release_id": source.ID, "latest_tag": source.Tag, "manifest_attested": true, "observed_at": "2026-09-02T00:00:00Z",
		"releases":    []any{map[string]any{"assets": release.Assets, "body": body, "commit": release.Commit, "draft": true, "immutable": false, "prerelease": false, "release_id": release.ReleaseID, "release_identity": release.ReleaseIdentity, "sequence": release.Sequence, "tag": release.Tag}},
		"remote_main": m.Workflow.Commit, "schema": qualificationFactsSchema, "signed_manifest": m, "stage": "stable-preflight", "subscription_history": pre.SubscriptionHistory,
	}
	if out, err := runQualificationCommand(binary, qualificationDocument(t, stable)); err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("clean-install-only publication gate: %v %s", err, out)
	}
	for name, change := range map[string]func(map[string]any){
		"changed record": func(v map[string]any) {
			v["releases"].([]any)[0].(map[string]any)["body"] = strings.Replace(body, "Scenario: mvp-install ", "Omitted: ", 1)
		},
		"baseline drift": func(v map[string]any) {
			v["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["release_identity"].(map[string]any)["commit"] = strings.Repeat("f", 40)
		},
		"failed candidate": func(v map[string]any) { v["candidate_run"].(map[string]any)["conclusion"] = "failure" },
	} {
		v := jsonObject(t, []byte(qualificationDocument(t, stable)))
		change(v)
		assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
	}
}
