package main

import (
	"strings"
	"testing"
)

func mainReviewPreflightFixture(t *testing.T, binary string) map[string]any {
	t.Helper()
	boundary, manifest, evidence := mvpQualificationFixtureForSupport(t, binary, false, true, true)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	accepted, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("acceptance fixture: %v %s", err, accepted)
	}
	var b qualificationBoundaryFacts
	var v candidateDraftVerificationFacts
	var c candidateDraftConstructionFacts
	var pre qualificationFacts
	var m qualificationManifest
	if !decodeCanonical([]byte(boundary), &b) || !decodeCanonical(b.DraftVerificationFacts, &v) || !decodeCanonical(v.ConstructionFacts, &c) || !decodeCanonical(c.PreflightFacts, &pre) || !decodeCanonical(manifest, &m) {
		t.Fatal("invalid qualification fixture")
	}
	r := m.Releases[0]
	body := jsonObject(t, accepted)["records"].([]any)[0].(map[string]any)["body"]
	return map[string]any{
		"acceptance_decision": jsonObject(t, accepted), "acceptance_facts": jsonObject(t, []byte(document)),
		"archive":           stableArchiveObservation{Commit: pre.ArchiveCommit, RemoteCommit: pre.ArchiveRemoteCommit, RemoteTagObject: pre.ArchiveRemoteTagObject, TagObject: pre.ArchiveTagObject, Type: pre.ArchiveType},
		"burned_identities": pre.BurnedIdentities, "candidate_run": stableCandidateRun{Conclusion: "success", CreatedAt: m.V3Attempt.StartedAt, Event: "workflow_dispatch", HeadSHA: m.Workflow.Commit, ID: m.Workflow.RunID, Path: m.Workflow.Path},
		"checklist_sha256": m.AcceptanceVPSChecklistSHA256, "latest_release_id": pre.Releases[0].ID, "latest_tag": pre.LatestTag, "manifest_attested": true, "observed_at": "2026-09-02T00:00:00Z",
		"releases":    []any{map[string]any{"assets": r.Assets, "body": body, "commit": r.Commit, "draft": true, "immutable": false, "prerelease": false, "release_id": r.ReleaseID, "release_identity": r.ReleaseIdentity, "sequence": r.Sequence, "tag": r.Tag}},
		"remote_main": m.Workflow.Commit, "schema": qualificationFactsSchema, "signed_manifest": jsonObject(t, manifest), "stage": stablePreflightStage, "subscription_history": pre.SubscriptionHistory,
	}
}

func TestMainDriftPreservesQualifiedCandidatePendingReview(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	facts := mainReviewPreflightFixture(t, binary)
	facts["remote_main"] = strings.Repeat("e", 40)
	out, err := runQualificationCommand(binary, qualificationDocument(t, facts))
	if err != nil || jsonObject(t, out)["outcome"] != "pending-review" {
		t.Fatalf("main drift must pause rather than fail qualification: %v %s", err, out)
	}
	action := jsonObject(t, out)["actions"].([]any)[0].(map[string]any)
	if action["type"] != "review-stable-release" || action["commit"] != facts["signed_manifest"].(map[string]any)["workflow"].(map[string]any)["commit"] {
		t.Fatalf("pending review lost exact candidate: %s", out)
	}
}

func mainReviewPublicationFixture(t *testing.T, binary string, pre map[string]any) map[string]any {
	t.Helper()
	document := qualificationDocument(t, pre)
	out, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("preflight fixture: %v %s", err, out)
	}
	d := jsonObject(t, out)
	a := d["actions"].([]any)[0].(map[string]any)
	assets := a["assets"].([]any)
	observed := make([]any, len(assets))
	for i, raw := range assets {
		asset := raw.(map[string]any)
		observed[i] = map[string]any{"id": 1000 + i, "name": asset["name"], "sha256": asset["sha256"], "size": asset["size"]}
	}
	return map[string]any{
		"action_index": 0, "approval": map[string]any{"decision_chain": []any{map[string]any{"decision_sha256": sha256String(string(out)), "facts_sha256": sha256String(document), "outcome": d["outcome"], "stage": stablePreflightStage}}, "environments": []any{map[string]any{"name": "stable-publication"}}, "state": "approved"},
		"observation": map[string]any{"assets": observed, "attestation": nil, "body": a["body"], "commit": a["commit"], "downloads": assets, "draft": true, "immutable": false, "latest_install_sha256": "", "latest_release_id": pre["latest_release_id"], "prerelease": false, "public_verification": nil, "release_id": a["release_id"], "release_identity": a["release_identity"], "sequence": a["sequence"], "tag": a["tag"]},
		"observed_at": "2026-09-02T00:01:00Z", "preflight_decision": d, "preflight_facts": pre,
		"prior_decision_sha256": sha256String(string(out)), "prior_verification_decision": nil, "prior_verification_facts": nil,
		"remote_main": pre["remote_main"], "schema": qualificationFactsSchema, "stage": stablePublicationStage, "subscription_history": pre["subscription_history"],
	}
}

func bindPublicationApprovalFixture(t *testing.T, facts map[string]any) {
	t.Helper()
	decision := facts["preflight_decision"].(map[string]any)
	facts["remote_main"] = facts["preflight_facts"].(map[string]any)["remote_main"]
	facts["approval"].(map[string]any)["decision_chain"] = []any{map[string]any{
		"decision_sha256": sha256String(qualificationDocument(t, decision)), "facts_sha256": sha256String(qualificationDocument(t, facts["preflight_facts"])), "outcome": decision["outcome"], "stage": stablePreflightStage,
	}}
}

func TestHistoricalPublicationRecordReplayCannotAuthorizeActions(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	facts := mainReviewPublicationFixture(t, binary, mainReviewPreflightFixture(t, binary))
	delete(facts, "remote_main")
	delete(facts["approval"].(map[string]any), "decision_chain")
	assertQualificationRefused(t, binary, qualificationDocument(t, facts), "historical-shaped publication cannot generate current actions")
	// Reconstruct the original wire record independently of the replay evaluator.
	action := jsonObject(t, []byte(qualificationDocument(t, facts["preflight_decision"].(map[string]any)["actions"].([]any)[0])))
	action["facts_sha256"] = sha256String(qualificationDocument(t, facts))
	action["observed_at"] = facts["observed_at"]
	action["prior_decision_sha256"] = facts["prior_decision_sha256"]
	publication := map[string]any{"actions": []any{action}, "facts_sha256": action["facts_sha256"], "outcome": "actions-required", "prior_decision_sha256": facts["prior_decision_sha256"], "schema": qualificationDecisionSchema, "stage": stablePublicationStage}
	observation := jsonObject(t, []byte(qualificationDocument(t, facts["observation"])))
	observation["draft"], observation["immutable"] = false, true
	observation["attestation"] = map[string]any{"commit": action["commit"], "count": 1, "initiator": "github", "predicate_type": "release"}
	observation["latest_release_id"] = action["release_id"]
	observation["latest_install_sha256"] = action["assets"].([]any)[0].(map[string]any)["sha256"]
	observation["public_verification"] = map[string]any{"outcome": "accepted", "release_identity": action["release_identity"], "sequence": action["sequence"]}
	verified := map[string]any{"attempt": 1, "observation": observation, "observed_at": "2026-09-02T00:01:10Z", "prior_decision_sha256": sha256String(qualificationDocument(t, publication)), "publication_decision": publication, "publication_facts": facts, "schema": qualificationFactsSchema, "stage": stablePublicationVerificationStage}
	assertQualificationRefused(t, binary, qualificationDocument(t, verified), "historical record cannot select current propagation actions")
	decision := map[string]any{"actions": []any{}, "facts_sha256": sha256String(qualificationDocument(t, verified)), "outcome": "accepted", "prior_decision_sha256": verified["prior_decision_sha256"], "schema": qualificationDecisionSchema, "stage": stablePublicationVerificationStage}
	record := map[string]any{"publication_verification_decision": decision, "publication_verification_facts": verified, "schema": qualificationFactsSchema, "stage": stablePublicationRecordStage}
	out, err := runQualificationCommand(binary, qualificationDocument(t, record))
	if err != nil || jsonObject(t, out)["outcome"] != "accepted-record" || len(jsonObject(t, out)["actions"].([]any)) != 0 {
		t.Fatalf("historical read-only replay: %v %s", err, out)
	}
	for name, change := range map[string]func(map[string]any){
		"unpublished record": func(f map[string]any) { f["publication_verification_facts"].(map[string]any)["observation"] = nil },
		"stale recorded decision": func(f map[string]any) {
			f["publication_verification_decision"].(map[string]any)["facts_sha256"] = strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := jsonObject(t, []byte(qualificationDocument(t, record)))
			change(f)
			assertQualificationRefused(t, binary, qualificationDocument(t, f), name)
		})
	}
}

func TestPublicationBindsExactCandidateAssetsMainAndDivergenceReview(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	base := mainReviewPreflightFixture(t, binary)
	copyFacts := func(value map[string]any) map[string]any {
		return jsonObject(t, []byte(qualificationDocument(t, value)))
	}
	assertOutcome := func(t *testing.T, facts map[string]any, want string) {
		t.Helper()
		out, err := runQualificationCommand(binary, qualificationDocument(t, facts))
		if err != nil || jsonObject(t, out)["outcome"] != want {
			t.Fatalf("want %s: %v %s", want, err, out)
		}
		actions := jsonObject(t, out)["actions"].([]any)
		if want == "pending-review" && len(actions) != 0 || want == "actions-required" && (len(actions) != 1 || actions[0].(map[string]any)["type"] != "publish-stable-release") {
			t.Fatalf("unsafe publication actions: %s", out)
		}
	}
	t.Run("unchanged main", func(t *testing.T) {
		assertOutcome(t, mainReviewPublicationFixture(t, binary, copyFacts(base)), "actions-required")
	})
	t.Run("changed remote main pauses publication", func(t *testing.T) {
		f := mainReviewPublicationFixture(t, binary, copyFacts(base))
		f["remote_main"] = strings.Repeat("e", 40)
		assertOutcome(t, f, "pending-review")
	})
	drifted := copyFacts(base)
	drifted["remote_main"] = strings.Repeat("e", 40)
	candidate := drifted["candidate_run"].(map[string]any)["head_sha"]
	drifted["main_review"] = map[string]any{"candidate_commit": candidate, "reviewed_main": drifted["remote_main"], "divergence_sha256": strings.Repeat("7", 64), "security_assessment": "no-security-fixes-missing", "rationale": "Reviewed documentation-only commit; no changed product or evidence inputs."}
	publication := mainReviewPublicationFixture(t, binary, drifted)
	t.Run("documentation-only divergence approved", func(t *testing.T) {
		assertOutcome(t, publication, "actions-required")
	})
	for _, assessment := range []string{"unreviewed", "security-fixes-missing"} {
		t.Run(assessment, func(t *testing.T) {
			pre := copyFacts(drifted)
			pre["main_review"].(map[string]any)["security_assessment"] = assessment
			assertOutcome(t, mainReviewPublicationFixture(t, binary, pre), "pending-review")
		})
	}
	t.Run("missing divergence review", func(t *testing.T) {
		pre := copyFacts(drifted)
		delete(pre, "main_review")
		assertOutcome(t, mainReviewPublicationFixture(t, binary, pre), "pending-review")
	})
	for name, mutate := range map[string]func(map[string]any){
		"stale approval": func(f map[string]any) {
			f["approval"].(map[string]any)["decision_chain"].([]any)[0].(map[string]any)["decision_sha256"] = strings.Repeat("8", 64)
		},
		"missing approval binding": func(f map[string]any) { delete(f["approval"].(map[string]any), "decision_chain") },
		"changed asset approval": func(f map[string]any) {
			f["approval"].(map[string]any)["decision_chain"].([]any)[0].(map[string]any)["facts_sha256"] = strings.Repeat("8", 64)
		},
	} {
		t.Run(name, func(t *testing.T) { f := copyFacts(publication); mutate(f); assertOutcome(t, f, "pending-review") })
	}
	t.Run("repeated drift", func(t *testing.T) {
		for _, sha := range []string{strings.Repeat("f", 40), strings.Repeat("9", 40), candidate.(string)} {
			f := copyFacts(publication)
			f["remote_main"] = sha
			assertOutcome(t, f, "pending-review")
		}
		pre := copyFacts(drifted)
		pre["remote_main"] = strings.Repeat("f", 40)
		assertOutcome(t, mainReviewPublicationFixture(t, binary, pre), "pending-review")
		pre["main_review"].(map[string]any)["reviewed_main"] = pre["remote_main"]
		pre["main_review"].(map[string]any)["divergence_sha256"] = strings.Repeat("6", 64)
		assertOutcome(t, mainReviewPublicationFixture(t, binary, pre), "actions-required")
	})
	for name, mutate := range map[string]func(map[string]any){
		"unapproved":            func(f map[string]any) { f["approval"].(map[string]any)["state"] = "rejected" },
		"substituted candidate": func(f map[string]any) { f["observation"].(map[string]any)["commit"] = strings.Repeat("9", 40) },
		"substituted asset": func(f map[string]any) {
			f["observation"].(map[string]any)["downloads"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := copyFacts(publication)
			mutate(f)
			assertQualificationRefused(t, binary, qualificationDocument(t, f), name)
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"failed qualification still fails": func(f map[string]any) { f["candidate_run"].(map[string]any)["conclusion"] = "failure" },
		"substituted preflight asset": func(f map[string]any) {
			f["releases"].([]any)[0].(map[string]any)["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
		},
		"review of another candidate": func(f map[string]any) {
			f["main_review"].(map[string]any)["candidate_commit"] = strings.Repeat("9", 40)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := copyFacts(drifted)
			mutate(f)
			assertQualificationRefused(t, binary, qualificationDocument(t, f), name)
		})
	}
}
