package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func live89ArchiveFixture(t *testing.T) live89Archive {
	t.Helper()
	b, err := os.ReadFile("testdata/live89-correction.json")
	var a live89Archive
	if err != nil || !decodeCanonical(b, &a) || documentSHA256(b) != live89EvidenceSHA256 {
		t.Fatalf("archival fixture refused: %v", err)
	}
	return a
}

func live89QualificationFixture(t *testing.T, binary string) (qualificationFacts, qualificationManifest, live89CorrectionFacts) {
	t.Helper()
	a := live89ArchiveFixture(t)
	var prefix v3RecurringResultFacts
	for _, e := range a.Evidence {
		if e.Name == "m4-collector-facts.json" {
			if !decodeCanonical([]byte(e.Content), &prefix) {
				t.Fatal("prefix")
			}
		}
	}
	var prior qualificationManifest
	if !decodeCanonical(prefix.QualificationManifest, &prior) {
		t.Fatal("prior manifest")
	}
	pre := candidateFacts("v3")
	pre.Candidate.ATag, pre.Candidate.ASequence = "", 0
	pre.Candidate.BTag, pre.Candidate.BSequence, pre.Candidate.EvidenceVersion = live89CorrectionTag, live89CorrectionSequence, 3
	pre.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallOnly, Sources: []decisionReleaseIdentity{}}
	pre.BurnedIdentities = []burnedIdentity{live89OriginalBurn()}
	source := cleanInstallOnlyBaselineFixture(t)
	pre.Releases, pre.LatestTag = []observedRelease{source}, &source.Tag
	if err := json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &pre.SubscriptionHistory); err != nil {
		t.Fatal(err)
	}
	attempt := *prior.V3Attempt
	attempt.AttemptID, attempt.RunAttempt, attempt.StartedAt = "run-123-attempt-1", 1, "2026-10-04T12:00:00Z"
	attempt.KaringResponseLimitSeconds, attempt.AttendedFinishBy = 0, ""
	baseline := historyBaseline(pre.SubscriptionHistory)
	attempt.Baseline = &baseline
	attempt.Live89CorrectionReview = &live89CorrectionReview{BaseCommit: live89CorrectionBase, EvidenceSHA256: live89EvidenceSHA256, PolicyDiffSHA256: strings.Repeat("b", 64), Reviewer: "Codex source comparison; Owner-approved live89 recording correction", RuntimeTreeSHA256: live89RuntimeTree, TargetCommit: pre.Commit, TargetSequence: live89CorrectionSequence, TargetTag: live89CorrectionTag}
	var assets []softwarelifecycle.LatestAssetProof
	for _, raw := range draftAssets(0) {
		x := raw.(map[string]any)
		if x["name"] != "release-index.json" {
			assets = append(assets, softwarelifecycle.LatestAssetProof{Name: x["name"].(string), Size: int64(x["size"].(int)), SHA256: x["sha256"].(string)})
		}
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(pre.Candidate.BTag, pre.Commit, pre.Candidate.BSequence, assets, pre.Candidate.Support.lifecycle())
	if err != nil {
		t.Fatal(err)
	}
	attempt.CandidateIndex = string(index)
	boundary, encoded := qualificationBoundaryForCandidate(t, binary, pre, jsonObject(t, mustJSON(attempt)))
	var m qualificationManifest
	if !decodeCanonical(encoded, &m) {
		t.Fatal("target manifest")
	}
	return pre, m, live89CorrectionFacts{ArchivedEvidence: a.Evidence, ObservedAt: "2026-10-04T12:01:00Z", QualificationBoundaryFacts: json.RawMessage(boundary), QualificationManifest: encoded, ManifestAttested: true, Schema: qualificationFactsSchema, Stage: live89CorrectionStage}
}

func TestLive89CorrectionUsesAcceptedFactsWithoutRewritingHistory(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	pre, m, f := live89QualificationFixture(t, binary)
	document := qualificationDocument(t, f)
	out, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("correction: %v %s", err, out)
	}
	var d acceptanceVPSResultDecision
	if !decodeCanonical(out, &d) || d.Outcome != "accepted" || d.Stage != live89CorrectionStage || len(d.Records) != 1 || d.FactsSHA256 != documentSHA256([]byte(document)) || d.PriorDecisionSHA256 != documentSHA256(f.QualificationManifest) {
		t.Fatalf("unbound decision: %s", out)
	}
	body := d.Records[0].Body
	for _, text := range []string{"Original qualification: Failed; v3.1.89 remains burned\n", "Fresh live scenarios: Not performed\n", "Original response callback: Not recorded; original unsealed removal record retained\n", "Timely Owner reply (parent-reported approximate): 2026-10-04T10:08:51Z\n", "Scenario: mvp-removal " + live89EvidenceSHA256 + " ", "Acceptance time: 2026-10-04T12:01:00Z\n"} {
		if !strings.Contains(body, text) {
			t.Fatalf("missing disclosure %q", text)
		}
	}
	if strings.Count(body, "\nScenario: ") != 5 || strings.Contains(body, "Owner exception:") {
		t.Fatal("false waiver or missing evidence refs")
	}
	var b qualificationBoundaryFacts
	if !decodeCanonical(f.QualificationBoundaryFacts, &b) {
		t.Fatal("boundary")
	}
	a := *m.V3Attempt
	a.Baseline = nil
	a.CandidateIndex = ""
	var declared bytes.Buffer
	if err := runQualificationDeclaration(strings.NewReader(qualificationDocument(t, qualificationDeclarationFacts{Attempt: a, Preflight: pre})), &declared); err != nil {
		t.Fatalf("unsigned declaration: %v", err)
	}
	r := m.Releases[0]
	support := m.V3Attempt.Support.lifecycle()
	public := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: r.ReleaseIdentity.Repository, Tag: r.Tag, Commit: r.Commit, IndexSHA256: r.ReleaseIdentity.ReleaseIndexSHA256}, Sequence: r.Sequence, Support: &support}
	p := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(p, []byte(qualificationDocument(t, map[string]any{"body": body, "release": public, "assets": r.Assets})), 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("go", "test", "../../internal/softwarelifecycle/adapter/github", "-run", "TestCleanInstallOnlyRecordCompatibility", "-count=1")
	check.Env = append(os.Environ(), "SBXR_TEST_CLEAN_INSTALL_ONLY_RECORD="+p)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("unchanged public/frozen reader: %v %s", err, output)
	}
	stable := map[string]any{"acceptance_decision": jsonObject(t, out), "acceptance_facts": jsonObject(t, []byte(document)), "archive": stableArchiveObservation{Commit: pre.ArchiveCommit, RemoteCommit: pre.ArchiveRemoteCommit, RemoteTagObject: pre.ArchiveRemoteTagObject, TagObject: pre.ArchiveTagObject, Type: "tag"}, "burned_identities": pre.BurnedIdentities, "candidate_run": stableCandidateRun{Conclusion: "success", CreatedAt: m.V3Attempt.StartedAt, Event: "workflow_dispatch", HeadSHA: m.Workflow.Commit, ID: m.Workflow.RunID, Path: m.Workflow.Path}, "checklist_sha256": m.AcceptanceVPSChecklistSHA256, "latest_release_id": pre.Releases[0].ID, "latest_tag": pre.LatestTag, "manifest_attested": true, "observed_at": "2026-10-04T12:02:00Z", "releases": []stableReleaseObservation{{Assets: r.Assets, Body: body, Commit: r.Commit, Draft: true, ReleaseID: r.ReleaseID, ReleaseIdentity: r.ReleaseIdentity, Sequence: r.Sequence, Tag: r.Tag}}, "remote_main": m.Workflow.Commit, "schema": qualificationFactsSchema, "signed_manifest": m, "stage": stablePreflightStage, "subscription_history": pre.SubscriptionHistory}
	if output, err := runQualificationCommand(binary, qualificationDocument(t, stable)); err != nil || jsonObject(t, output)["outcome"] != "actions-required" {
		t.Fatalf("fresh stable gate: %v %s", err, output)
	}
	for name, change := range map[string]func(map[string]any){
		"failed fresh workflow": func(v map[string]any) { v["candidate_run"].(map[string]any)["conclusion"] = "failure" },
		"burn removed":          func(v map[string]any) { v["burned_identities"] = []any{} },
		"immutable failed target": func(v map[string]any) {
			r := v["releases"].([]any)[0].(map[string]any)
			r["draft"] = false
			r["immutable"] = true
			r["prerelease"] = true
		},
		"changed asset": func(v map[string]any) {
			v["releases"].([]any)[0].(map[string]any)["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("f", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := jsonObject(t, []byte(qualificationDocument(t, stable)))
			change(v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
	for name, change := range map[string]func(*v3QualificationAttempt, *qualificationFacts){
		"different target":                   func(a *v3QualificationAttempt, p *qualificationFacts) { p.Candidate.BTag = "v3.1.91" },
		"different sequence":                 func(a *v3QualificationAttempt, p *qualificationFacts) { p.Candidate.BSequence = 169 },
		"deleted original burn":              func(a *v3QualificationAttempt, p *qualificationFacts) { p.BurnedIdentities = nil },
		"fabricated new latest client check": func(a *v3QualificationAttempt, p *qualificationFacts) { a.KaringLatestCheckedAt = a.StartedAt },
		"owner exception": func(a *v3QualificationAttempt, p *qualificationFacts) {
			a.OwnerException = softwarelifecycle.LateConfirmationID
		},
		"wrong source tree": func(a *v3QualificationAttempt, p *qualificationFacts) {
			a.Live89CorrectionReview.RuntimeTreeSHA256 = strings.Repeat("f", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := *m.V3Attempt
			review := *a.Live89CorrectionReview
			a.Live89CorrectionReview = &review
			p := pre
			change(&a, &p)
			if name == "fabricated new latest client check" {
				if live89EnvironmentMatches(a, *m.V3Attempt) {
					t.Fatal("environment drift accepted")
				}
			} else if validV3AttemptDeclaredFields(a, p) {
				t.Fatal("unapproved declaration accepted")
			}
		})
	}
}

func TestLive89CorrectionRefusesAlteredArchiveAndOrdinaryLiveRoutes(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	_, _, f := live89QualificationFixture(t, binary)
	for i, e := range f.ArchivedEvidence {
		t.Run("altered/"+e.Name, func(t *testing.T) {
			v := f
			v.ArchivedEvidence = append([]lateConfirmationEvidence(nil), f.ArchivedEvidence...)
			v.ArchivedEvidence[i].Content += " "
			assertQualificationRefused(t, binary, qualificationDocument(t, v), e.Name)
		})
	}
	for _, stage := range []string{v3PackagedLiveResultStage, "v3-scenario-result", "owner-exception-result", stablePreflightStage} {
		v := f
		v.Stage = stage
		assertQualificationRefused(t, binary, qualificationDocument(t, v), stage)
	}
	for name, change := range map[string]func(*live89CorrectionFacts){"missing archive": func(v *live89CorrectionFacts) { v.ArchivedEvidence = v.ArchivedEvidence[:len(v.ArchivedEvidence)-1] }, "duplicate archive": func(v *live89CorrectionFacts) { v.ArchivedEvidence = append(v.ArchivedEvidence, v.ArchivedEvidence[0]) }, "unattested": func(v *live89CorrectionFacts) { v.ManifestAttested = false }, "backdated new result": func(v *live89CorrectionFacts) { v.ObservedAt = "2026-10-04T10:08:51Z" }, "expired new result": func(v *live89CorrectionFacts) { v.ObservedAt = "2026-10-04T12:30:01Z" }} {
		t.Run(name, func(t *testing.T) {
			v := f
			change(&v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
}
