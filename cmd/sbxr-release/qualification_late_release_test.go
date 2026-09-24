package main

import (
	"encoding/json"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLateConfirmationReleasePath(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	boundary, manifest, _ := mvpQualificationFixtureFor(t, binary, true)
	var m qualificationManifest
	if !decodeCanonical(manifest, &m) {
		t.Fatal("manifest")
	}
	supplement, err := os.ReadFile("testdata/r24-late-confirmation.json")
	if err != nil {
		t.Fatal(err)
	}
	f := ownerExceptionFacts{LateConfirmationSupplement: supplement, ObservedAt: m.V3Attempt.StartedAt, QualificationBoundaryFacts: json.RawMessage(boundary), QualificationManifest: manifest, ManifestAttested: true, Schema: qualificationFactsSchema, Stage: "owner-exception-result"}
	doc := qualificationDocument(t, f)
	out, err := runQualificationCommand(binary, doc)
	if err != nil {
		t.Fatalf("exception result: %v %s", err, out)
	}
	var accepted acceptanceVPSResultDecision
	if !decodeCanonical(out, &accepted) || accepted.Outcome != "accepted" || len(accepted.Records) != 1 {
		t.Fatalf("result: %s", out)
	}
	for _, field := range []string{"packages", "runner", "macos_version", "vps_identity_sha256"} {
		t.Run("prior environment "+field, func(t *testing.T) {
			changed := *m.V3Attempt
			switch field {
			case "packages":
				changed.Packages.Karing.Version = "9.9.9"
			case "runner":
				changed.Runner.GoToolchain = "go1.99.0"
			case "macos_version":
				changed.MacOSVersion = "99.0"
			case "vps_identity_sha256":
				changed.VPSIdentitySHA256 = strings.Repeat("a", 64)
			}
			if lateConfirmationEnvironmentMatches(changed, supplement) {
				t.Fatal("changed environment accepted")
			}
		})
	}
	body := accepted.Records[0].Body
	for _, line := range []string{softwarelifecycle.LateConfirmationLive, "Fresh live scenarios: Not performed", "Original qualification: Failed; v3.1.80 remains burned", softwarelifecycle.LateConfirmationTime} {
		if !strings.Contains(body, line) {
			t.Fatalf("missing disclosure: %s", line)
		}
	}
	if strings.Contains(body, "\nScenario: ") {
		t.Fatal("fabricated fresh live evidence")
	}
	for name, mutate := range map[string]func(*ownerExceptionFacts){
		"unsigned":           func(v *ownerExceptionFacts) { v.ManifestAttested = false },
		"missing supplement": func(v *ownerExceptionFacts) { v.LateConfirmationSupplement = nil },
		"changed supplement": func(v *ownerExceptionFacts) { v.LateConfirmationSupplement = []byte(`{}`) },
		"expired":            func(v *ownerExceptionFacts) { v.ObservedAt = "2030-01-01T00:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := f
			mutate(&changed)
			assertQualificationRefused(t, binary, qualificationDocument(t, changed), name)
		})
	}
	// The target, review and fresh native success are bound by the normal signed
	// boundary; editing any one without its real decision chain refuses.
	for _, field := range []string{"owner_exception", "late_confirmation_review"} {
		changed := jsonObject(t, []byte(doc))
		mm := changed["qualification_manifest"].(map[string]any)
		delete(mm["v3_attempt"].(map[string]any), field)
		assertQualificationRefused(t, binary, qualificationDocument(t, changed), field)
	}
	var bf qualificationBoundaryFacts
	if !decodeCanonical([]byte(boundary), &bf) {
		t.Fatal("boundary")
	}
	// Even an otherwise valid, freshly reconstructed signed boundary cannot
	// transfer the old live observations to a different package declaration.
	changedBoundary := bf
	changedAttempt := *bf.V3Attempt
	changedAttempt.Packages.Karing.Version = "9.9.9"
	changedAttempt.AfterSnapRefresh = changedAttempt.Packages
	changedBoundary.V3Attempt = &changedAttempt
	changedBoundaryBytes := []byte(qualificationDocument(t, changedBoundary))
	changedManifest, err := runQualificationCommand(binary, string(changedBoundaryBytes))
	if err != nil {
		t.Fatalf("otherwise valid changed boundary: %v %s", err, changedManifest)
	}
	changedFacts := f
	changedFacts.QualificationBoundaryFacts, changedFacts.QualificationManifest = changedBoundaryBytes, changedManifest
	assertQualificationRefused(t, binary, qualificationDocument(t, changedFacts), "signed but different historical package")
	var vf candidateDraftVerificationFacts
	if !decodeCanonical(bf.DraftVerificationFacts, &vf) {
		t.Fatal("verification")
	}
	var cf candidateDraftConstructionFacts
	if !decodeCanonical(vf.ConstructionFacts, &cf) {
		t.Fatal("construction")
	}
	var pre qualificationFacts
	if !decodeCanonical(cf.PreflightFacts, &pre) {
		t.Fatal("preflight")
	}
	source := pre.Releases[0]
	release := m.Releases[0]
	stable := map[string]any{
		"acceptance_decision": jsonObject(t, out), "acceptance_facts": jsonObject(t, []byte(doc)),
		"archive":           map[string]any{"commit": pre.ArchiveCommit, "remote_commit": pre.ArchiveRemoteCommit, "remote_tag_object": pre.ArchiveRemoteTagObject, "tag_object": pre.ArchiveTagObject, "type": "tag"},
		"burned_identities": pre.BurnedIdentities, "candidate_run": map[string]any{"conclusion": "success", "created_at": m.V3Attempt.StartedAt, "event": "workflow_dispatch", "head_sha": m.Workflow.Commit, "id": m.Workflow.RunID, "path": m.Workflow.Path},
		"checklist_sha256": m.AcceptanceVPSChecklistSHA256, "latest_release_id": source.ID, "latest_tag": source.Tag, "manifest_attested": true, "observed_at": m.V3Attempt.StartedAt,
		"releases":    []any{map[string]any{"assets": release.Assets, "body": body, "commit": release.Commit, "draft": true, "immutable": false, "prerelease": false, "release_id": release.ReleaseID, "release_identity": release.ReleaseIdentity, "sequence": release.Sequence, "tag": release.Tag}},
		"remote_main": m.Workflow.Commit, "schema": qualificationFactsSchema, "signed_manifest": jsonObject(t, manifest), "stage": "stable-preflight", "subscription_history": pre.SubscriptionHistory,
	}
	stableOut, err := runQualificationCommand(binary, qualificationDocument(t, stable))
	if err != nil {
		t.Fatalf("stable preflight: %v %s", err, stableOut)
	}
	if jsonObject(t, stableOut)["outcome"] != "actions-required" {
		t.Fatalf("stable decision: %s", stableOut)
	}
	start, _ := time.Parse(time.RFC3339, m.V3Attempt.StartedAt)
	action := jsonObject(t, stableOut)["actions"].([]any)[0].(map[string]any)
	observedAssets := make([]any, len(action["assets"].([]any)))
	for index, assetValue := range action["assets"].([]any) {
		asset := assetValue.(map[string]any)
		observedAssets[index] = map[string]any{"id": 100 + index, "name": asset["name"], "sha256": asset["sha256"], "size": asset["size"]}
	}
	publicationFacts := map[string]any{
		"action_index": 0, "approval": map[string]any{"environments": []any{map[string]any{"name": "stable-publication"}}, "state": "approved"},
		"observation": map[string]any{"assets": observedAssets, "attestation": nil, "body": action["body"], "commit": action["commit"], "downloads": action["assets"], "draft": true, "immutable": false, "latest_install_sha256": "", "latest_release_id": source.ID, "prerelease": false, "public_verification": nil, "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"]},
		"observed_at": start.Add(time.Minute).Format(time.RFC3339), "preflight_decision": jsonValue(t, string(stableOut)), "preflight_facts": stable, "prior_decision_sha256": sha256String(string(stableOut)), "prior_verification_decision": nil, "prior_verification_facts": nil, "schema": qualificationFactsSchema, "stage": "stable-publication", "subscription_history": pre.SubscriptionHistory,
	}
	publicationDecision, publicationErr := runQualificationCommand(binary, qualificationDocument(t, publicationFacts))
	if publicationErr != nil || jsonObject(t, publicationDecision)["outcome"] != "actions-required" {
		t.Fatalf("V3 stable publication = %s, %v", publicationDecision, publicationErr)
	}
	public := jsonObject(t, []byte(qualificationDocument(t, publicationFacts["observation"])))
	public["draft"], public["immutable"], public["latest_release_id"] = false, true, action["release_id"]
	public["attestation"] = map[string]any{"commit": action["commit"], "count": 1, "initiator": "github", "predicate_type": "release"}
	public["public_verification"] = map[string]any{"outcome": "accepted", "release_identity": action["release_identity"], "sequence": action["sequence"]}
	public["latest_install_sha256"] = action["assets"].([]any)[0].(map[string]any)["sha256"]
	verification := map[string]any{"attempt": 1, "observation": public, "observed_at": start.Add(70 * time.Second).Format(time.RFC3339), "prior_decision_sha256": sha256String(string(publicationDecision)), "publication_decision": jsonObject(t, publicationDecision), "publication_facts": publicationFacts, "schema": qualificationFactsSchema, "stage": "stable-publication-verification"}
	verified, verifyErr := runQualificationCommand(binary, qualificationDocument(t, verification))
	if verifyErr != nil || jsonObject(t, verified)["outcome"] != "accepted" {
		t.Fatalf("public verification: %s %v", verified, verifyErr)
	}
	finalFacts := map[string]any{"schema": qualificationFactsSchema, "stage": "stable-v3-finalization", "observed_at": start.Add(2 * time.Minute).Format(time.RFC3339), "prior_decision_sha256": sha256String(string(verified)), "publication_verification_decision": jsonObject(t, verified), "publication_verification_facts": verification}
	final, finalErr := runQualificationCommand(binary, qualificationDocument(t, finalFacts))
	wantedLive := softwarelifecycle.LateConfirmationLive
	if finalErr != nil || jsonObject(t, final)["v3_packaged_live"] != wantedLive || jsonObject(t, final)["complete_removal"] != wantedLive {
		t.Fatalf("finalization: %s %v", final, finalErr)
	}

	publicationFacts["approval"].(map[string]any)["state"] = "pending"
	assertQualificationRefused(t, binary, qualificationDocument(t, publicationFacts), "publication still needs approval")
	if _, err := buildStableFailedAcceptanceRecord(m, release, body, "https://github.com/albertloky/SBXR/actions/runs/456"); err != nil {
		t.Fatalf("late exception failure record: %v", err)
	}

	stable["candidate_run"].(map[string]any)["conclusion"] = "failure"
	assertQualificationRefused(t, binary, qualificationDocument(t, stable), "failed fresh automated run")
	stable["candidate_run"].(map[string]any)["conclusion"] = "success"
	stable["burned_identities"] = append(pre.BurnedIdentities, burnedIdentity{Commit: release.Commit, OriginalTag: release.Tag, QualificationRunURL: m.Workflow.RunURL, Reason: "post-sign-qualification-failure", RecordedAt: m.V3Attempt.StartedAt, ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence})
	assertQualificationRefused(t, binary, qualificationDocument(t, stable), "burned fresh target")
}
