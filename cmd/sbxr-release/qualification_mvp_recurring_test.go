package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const ordinarySourceChecks = "exact-source-and-candidate actual-source-packaged-updater source-record-schema-proved both-releases-understand-recovery reviewed-update-confirmation admission-exclusion creation-provenance-preserved no-ownership-migration proxy-not-restarted both-credentials-unchanged subscription-link-unchanged outside-proxy-traffic outside-trusted-https ssh-access-preserved private-files-and-logs-protected no-helper-or-intermediate-release"

func ordinaryFixtureChecks(id string) []string {
	for i, name := range strings.Fields(softwarelifecycle.MVPLiveScenarios) {
		if id == name {
			return mvpObservedChecks[i]
		}
	}
	extra := "candidate-installed-record-proved serving-only-restart no-transaction-residue"
	if strings.HasSuffix(id, "-precommit") {
		extra = "observed-precommit-interruption actual-source-packaged-recovery prior-exact-restoration source-installed-record-restored no-transaction-residue"
	}
	if strings.HasSuffix(id, "-postcommit") {
		extra = "observed-postcommit-interruption candidate-forward-runtime-completion candidate-installed-record-proved serving-only-restart no-transaction-residue"
	}
	return strings.Fields(ordinarySourceChecks + " " + extra)
}

func mvpRecurringQualificationFixture(t *testing.T, binary string) (string, []byte, map[string]any) {
	t.Helper()
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.82", 160, 3
	// Synthetic source metadata; this is not a downloaded v3.1.81 or live proof.
	source := recurringSourceFixture()
	source.Body = strings.NewReplacer(source.Tag, "v3.1.81", "Sequence: 17\n", "Sequence: 159\n").Replace(source.Body)
	source.Tag, source.Index.Tag = "v3.1.81", "v3.1.81"
	*source.Sequence, source.Index.Sequence, source.Index.Schema = 159, 159, 2
	source.Index.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []decisionReleaseIdentity{}}
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	facts.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Sources: []decisionReleaseIdentity{sourceAction(source).ReleaseIdentity}}
	if err := json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &facts.SubscriptionHistory); err != nil {
		t.Fatal(err)
	}
	attempt := recurringAttemptFixture(t, source)
	attempt["schema"], attempt["evidence_policy"] = "sbxr-v3-qualification-attempt-v3", "mvp-recurring-live-v1"
	attempt["support"], attempt["baseline"] = facts.Candidate.Support, historyBaseline(facts.SubscriptionHistory)
	attempt["sources"].([]any)[0].(map[string]any)["ownership_schema"] = 2
	attempt["required_scenarios"] = strings.Fields("source-v3.1.81-precommit source-v3.1.81-upgrade source-v3.1.81-postcommit mvp-install mvp-subscription mvp-credentials mvp-renewal mvp-removal")
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
	for _, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		s["schema"] = "sbxr-v3-scenario-evidence-v3"
		id := s["scenario_id"].(string)
		if id == "mvp-install" {
			s["initial_state"] = "Not installed"
		}
		if id == "mvp-removal" {
			s["final_state"] = "Not installed"
		}
		var checks []any
		for _, check := range ordinaryFixtureChecks(id) {
			checks = append(checks, map[string]any{"record": map[string]any{"check": check, "observed_at": s["completed_at"], "result": "observed"}, "sha256": ""})
		}
		s["evidence"] = checks
	}
	rebindRecurringEvidence(t, evidence)
	return boundary, manifest, evidence
}

func TestMVPRecurringQualificationAndReleasedReader(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	boundary, manifest, evidence := mvpRecurringQualificationFixture(t, binary)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	out, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("new ordinary scope refused: %v %s", err, out)
	}
	body := jsonObject(t, out)["records"].([]any)[0].(map[string]any)["body"].(string)
	if strings.Count(body, "\nJourney: ") != 5 || strings.Count(body, "\nScenario: ") != 3 || !strings.Contains(body, "Recurring evidence policy: mvp-recurring-live-v1\n") || strings.Contains(body, "Incoming source upgrades: Not applicable") || strings.Contains(body, "Automated-only result:") {
		t.Fatal("incorrect coverage disclosure")
	}
	var m qualificationManifest
	if !decodeCanonical(manifest, &m) {
		t.Fatal("manifest")
	}
	r := m.Releases[0]
	support := m.V3Attempt.Support.lifecycle()
	public := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: r.ReleaseIdentity.Repository, Tag: r.Tag, Commit: r.Commit, IndexSHA256: r.ReleaseIdentity.ReleaseIndexSHA256}, Sequence: r.Sequence, Support: &support}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(qualificationDocument(t, map[string]any{"body": body, "release": public, "assets": r.Assets})), 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("go", "test", "../../internal/softwarelifecycle/adapter/github", "-run", "TestOrdinaryRecordCompatibility|TestFrozenV3181Reader", "-count=1")
	check.Env = append(os.Environ(), "SBXR_TEST_RECURRING_RECORD="+path)
	if result, err := check.CombinedOutput(); err != nil {
		t.Fatalf("released/current reader: %v %s", err, result)
	}
	assertOrdinaryPublicationGates(t, binary, boundary, manifest, document, out)
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
	for name, mutate := range map[string]func(map[string]any){
		"missing-source":      func(s map[string]any) { s["source"] = nil },
		"wrong-recovery":      func(s map[string]any) { s["recovery_direction"] = "forward" },
		"unobserved-boundary": func(s map[string]any) { s["boundary"] = "observed" },
		"late-validation":     func(s map[string]any) { s["validated_at"] = "2026-09-01T00:26:01Z" },
		"failed":              func(s map[string]any) { s["actual_result"] = "unexpected-failure" },
	} {
		v := jsonObject(t, []byte(qualificationDocument(t, evidence)))
		mutate(v["scenarios"].([]any)[0].(map[string]any))
		rebindRecurringEvidence(t, v)
		assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, v), name)
	}
	for name, mutate := range map[string]func(*v3QualificationAttempt){
		"old-policy":           func(a *v3QualificationAttempt) { a.EvidencePolicy = softwarelifecycle.MVPLiveEvidencePolicy },
		"historical-recurring": func(a *v3QualificationAttempt) { a.EvidencePolicy = "" },
		"blanket-matrix":       func(a *v3QualificationAttempt) { a.AutomatedOnlyScenarios = []string{"x"} },
		"borrowed-exception":   func(a *v3QualificationAttempt) { a.OwnerException = softwarelifecycle.LateConfirmationID },
		"five-only":            func(a *v3QualificationAttempt) { a.RequiredScenarios = a.RequiredScenarios[3:] },
		"wrong-order": func(a *v3QualificationAttempt) {
			a.RequiredScenarios = slices.Clone(a.RequiredScenarios)
			a.RequiredScenarios[0], a.RequiredScenarios[1] = a.RequiredScenarios[1], a.RequiredScenarios[0]
		},
	} {
		a := *m.V3Attempt
		mutate(&a)
		if validAttemptSupport(a) {
			t.Fatalf("%s admitted", name)
		}
	}
}

func assertOrdinaryPublicationGates(t *testing.T, binary, boundary string, manifest []byte, document string, decision []byte) {
	t.Helper()
	var bf qualificationBoundaryFacts
	var vf candidateDraftVerificationFacts
	var cf candidateDraftConstructionFacts
	var pre qualificationFacts
	var m qualificationManifest
	if !decodeCanonical([]byte(boundary), &bf) || !decodeCanonical(bf.DraftVerificationFacts, &vf) || !decodeCanonical(vf.ConstructionFacts, &cf) || !decodeCanonical(cf.PreflightFacts, &pre) || !decodeCanonical(manifest, &m) {
		t.Fatal("fixture decision chain")
	}
	source, release := pre.Releases[0], m.Releases[0]
	body := jsonObject(t, decision)["records"].([]any)[0].(map[string]any)["body"].(string)
	stable := map[string]any{
		"acceptance_decision": jsonObject(t, decision), "acceptance_facts": jsonObject(t, []byte(document)),
		"archive":           map[string]any{"commit": pre.ArchiveCommit, "remote_commit": pre.ArchiveRemoteCommit, "remote_tag_object": pre.ArchiveRemoteTagObject, "tag_object": pre.ArchiveTagObject, "type": "tag"},
		"burned_identities": []any{}, "candidate_run": map[string]any{"conclusion": "success", "created_at": m.V3Attempt.StartedAt, "event": "workflow_dispatch", "head_sha": m.Workflow.Commit, "id": m.Workflow.RunID, "path": m.Workflow.Path},
		"checklist_sha256": m.AcceptanceVPSChecklistSHA256, "latest_release_id": source.ID, "latest_tag": source.Tag, "manifest_attested": true, "observed_at": "2026-09-02T00:00:00Z",
		"releases":    []any{map[string]any{"assets": release.Assets, "body": body, "commit": release.Commit, "draft": true, "immutable": false, "prerelease": false, "release_id": release.ReleaseID, "release_identity": release.ReleaseIdentity, "sequence": release.Sequence, "tag": release.Tag}},
		"remote_main": m.Workflow.Commit, "schema": qualificationFactsSchema, "signed_manifest": jsonObject(t, manifest), "stage": "stable-preflight", "subscription_history": pre.SubscriptionHistory,
	}
	if out, err := runQualificationCommand(binary, qualificationDocument(t, stable)); err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("ordinary stable gate: %v %s", err, out)
	}
	for name, change := range map[string]func(map[string]any){
		"altered-record": func(v map[string]any) {
			v["releases"].([]any)[0].(map[string]any)["body"] = strings.Replace(body, "Journey: mvp-install ", "Omitted: ", 1)
		},
		"source-drift": func(v map[string]any) {
			v["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["release_identity"].(map[string]any)["commit"] = strings.Repeat("f", 40)
		},
		"failed-candidate": func(v map[string]any) { v["candidate_run"].(map[string]any)["conclusion"] = "failure" },
	} {
		v := jsonObject(t, []byte(qualificationDocument(t, stable)))
		change(v)
		assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
	}
	for name, change := range map[string]func(*v3QualificationAttempt){
		"empty-source":      func(a *v3QualificationAttempt) { a.Sources = nil },
		"additional-source": func(a *v3QualificationAttempt) { a.Sources = append(slices.Clone(a.Sources), a.Sources[0]) },
		"unverified-source": func(a *v3QualificationAttempt) {
			a.Sources = slices.Clone(a.Sources)
			a.Sources[0].PublicVerification = "unknown"
		},
		"changed-source-bytes": func(a *v3QualificationAttempt) {
			a.Sources = slices.Clone(a.Sources)
			a.Sources[0].ReleaseIdentity.Commit = strings.Repeat("f", 40)
		},
	} {
		a := *m.V3Attempt
		change(&a)
		if validV3AttemptDeclaredFields(a, pre) {
			t.Fatalf("%s admitted", name)
		}
	}
	failed := map[string]any{
		"failure":                      map[string]any{"actual_result": "timeout", "attempt_id": m.V3Attempt.AttemptID, "boundary": "unknown", "candidate": release, "expected_result": "expected-safety-and-final-state-proved", "host_state": "Unknown", "observed_at": "2026-09-01T00:32:00Z", "operation_id": "operation-1", "scenario_id": m.V3Attempt.RequiredScenarios[0], "schema": "sbxr-v3-scenario-failure-v3", "vps_id": m.V3Attempt.VPSID},
		"qualification_boundary_facts": jsonObject(t, []byte(boundary)), "qualification_manifest": jsonObject(t, manifest), "qualification_manifest_attested": true,
		"safety_cleanup": map[string]any{"host_state": "Unknown", "status": "not-started"}, "schema": qualificationFactsSchema, "stage": "v3-scenario-failure",
	}
	if out, err := runQualificationCommand(binary, qualificationDocument(t, failed)); err != nil || jsonObject(t, out)["burn_required"] != true || jsonObject(t, out)["stop_test_mutations"] != true {
		t.Fatalf("ordinary failure path: %v %s", err, out)
	}
}
