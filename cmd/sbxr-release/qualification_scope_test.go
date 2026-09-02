package main

import (
	"encoding/json"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestQualificationCommandRequiresExplicitSubscriptionScope(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.0", 18
	source := recurringSourceFixture()
	source.Index.Schema = 1
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	document := jsonObject(t, []byte(canonicalFacts(t, facts)))
	candidate := document["candidate"].(map[string]any)
	candidate["evidence_version"] = 3
	candidate["support"] = map[string]any{"scope": "first-subscription-clean-install", "sources": []any{}, "contract": "sbxr-subscription-update-v1"}
	document["subscription_history"] = scopeHistoryFixture(t, source)
	output, err := runQualificationCommand(binary, qualificationDocument(t, document))
	if err != nil || jsonObject(t, output)["source_state"] != "v3-subscription-clean" {
		t.Fatalf("explicit first subscription preflight: %v\n%s", err, output)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown history":    func(v map[string]any) { delete(v, "subscription_history") },
		"incomplete history": func(v map[string]any) { v["subscription_history"].(map[string]any)["complete"] = false },
		"implicit scope":     func(v map[string]any) { delete(v["candidate"].(map[string]any), "support") },
		"empty recurring sources": func(v map[string]any) {
			v["candidate"].(map[string]any)["support"].(map[string]any)["scope"] = "recurring-subscription-upgrade"
		},
		"unverified baseline": func(v map[string]any) {
			v["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["outcome"] = "unknown"
		},
		"repeat exception": func(v map[string]any) {
			v["subscription_history"].(map[string]any)["releases"].([]any)[0].(map[string]any)["body"] = "Stable result code: RELEASE-V3-SUBSCRIPTION-QUALIFICATION\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := jsonObject(t, []byte(qualificationDocument(t, document)))
			mutate(v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
}

func scopeHistoryFixture(t *testing.T, source observedRelease) map[string]any {
	return map[string]any{"complete": true, "releases": []any{jsonObject(t, []byte(qualificationDocument(t, source)))}, "public_latest": map[string]any{"outcome": "accepted", "release_identity": sourceAction(source).ReleaseIdentity, "sequence": source.Index.Sequence}}
}

func TestQualificationCommandBindsFirstSubscriptionAttempt(t *testing.T) {
	for _, exception := range []string{"", softwarelifecycle.OwnerExceptionID} {
		t.Run("exception="+exception, func(t *testing.T) { testFirstSubscriptionAttempt(t, exception, false) })
	}
}

func TestQualificationCommandBindsCleanInstallRepair(t *testing.T) {
	testFirstSubscriptionAttempt(t, "", true)
}

func TestRepairScopeRequiresExactCompleteUnreusedBaseline(t *testing.T) {
	source := repairBaselineFixture(t)
	var history v3ReleaseHistory
	if err := json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &history); err != nil {
		t.Fatal(err)
	}
	if !validSubscriptionHistory(&history, softwarelifecycle.SubscriptionCleanInstallRepair, nil) {
		t.Fatal("repair baseline refused")
	}
	for name, change := range map[string]func(*v3ReleaseHistory){
		"incomplete":      func(h *v3ReleaseHistory) { h.Complete = false },
		"unverified":      func(h *v3ReleaseHistory) { h.PublicLatest.Outcome = "unknown" },
		"unknown release": func(h *v3ReleaseHistory) { h.Releases[0].Index = nil },
		"previous published repair": func(h *v3ReleaseHistory) {
			var previous observedRelease
			body, _ := json.Marshal(source)
			_ = json.Unmarshal(body, &previous)
			previous.ID++
			previous.Tag, previous.Index.Tag = "v3.1.1", "v3.1.1"
			*previous.Sequence, previous.Index.Sequence = 84, 84
			previous.Index.Support.Scope = softwarelifecycle.SubscriptionCleanInstallRepair
			h.Releases = append(h.Releases, previous)
		},
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(history)
			var changed v3ReleaseHistory
			_ = json.Unmarshal(body, &changed)
			change(&changed)
			if validSubscriptionHistory(&changed, softwarelifecycle.SubscriptionCleanInstallRepair, nil) {
				t.Fatal("unsafe repair history accepted")
			}
		})
	}
	for _, pair := range [][2]string{{source.Commit, strings.Repeat("f", 40)}, {source.Index.SHA256, strings.Repeat("f", 64)}, {source.Tag, "v3.1.2"}} {
		body, _ := json.Marshal(history)
		var changed v3ReleaseHistory
		_ = json.Unmarshal([]byte(strings.ReplaceAll(string(body), pair[0], pair[1])), &changed)
		if validSubscriptionHistory(&changed, softwarelifecycle.SubscriptionCleanInstallRepair, nil) {
			t.Fatal("different repair baseline accepted")
		}
	}
}

func repairBaselineFixture(t *testing.T) observedRelease {
	t.Helper()
	source := recurringSourceFixture()
	commit := "c0667a12ea914f2d0c86d73d52bfb8b40fea054a"
	index := "5e9b25cf2bd5b448c0a833b6420e165bd47a207144bb63330a62e0b9dafc3cd1"
	source.Body = strings.NewReplacer(source.Tag, "v3.1.0", source.Commit, commit, source.Index.SHA256, index,
		"Sequence: 17\n", "Sequence: 83\n", "Status: Qualified\n", "Status: Qualified by Owner exception\n",
		"Codex Live Acceptance: Passed\n", "Codex Live Acceptance: "+softwarelifecycle.OwnerExceptionLive+"\n",
		"Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and outside runner\n", "Integrated Verification: "+softwarelifecycle.OwnerExceptionLive+"\n",
		"Owner Acceptance: Not required\n", "Owner Acceptance: One-release exception approved\n",
		"Secret-safe result: Passed\n", "Secret-safe result: "+softwarelifecycle.OwnerExceptionSecrets+"\n",
		"RELEASE-V3-PACKAGED-LIVE-QUALIFICATION", softwarelifecycle.OwnerExceptionCode,
		"Clean-installed V3 release", "Clean-installed subscription-capable V3 release").Replace(source.Body)
	source.Body += "Owner exception: " + softwarelifecycle.OwnerExceptionID + "\nLive qualification: Incomplete\n"
	source.Tag, source.Index.Tag, source.Commit, source.Index.Commit = "v3.1.0", "v3.1.0", commit, commit
	source.Index.SHA256, source.Assets[1].Digest = index, index
	*source.Sequence, source.Index.Sequence, source.Index.Schema = 83, 83, 2
	source.Index.Support = &v3ReleaseSupport{Scope: softwarelifecycle.FirstSubscriptionCleanInstall, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []decisionReleaseIdentity{}}
	if !qualifiedV3Source(source) {
		t.Fatal("invalid repair baseline fixture")
	}
	return source
}

func testFirstSubscriptionAttempt(t *testing.T, exception string, repair bool) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.0", 83, 3
	source := recurringSourceFixture()
	*source.Sequence, source.Index.Sequence = 82, 82
	source.Body = strings.ReplaceAll(source.Body, "Sequence: 17\n", "Sequence: 82\n")
	source.Index.Schema = 1
	if repair {
		source = repairBaselineFixture(t)
		facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.1", 84
	}
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	facts.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.FirstSubscriptionCleanInstall, Sources: []decisionReleaseIdentity{}}
	if repair {
		facts.Candidate.Support.Scope = "subscription-clean-install-repair"
	}
	if json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &facts.SubscriptionHistory) != nil {
		t.Fatal("history fixture")
	}
	attempt := recurringAttemptFixture(t, source)
	attempt["schema"] = "sbxr-v3-qualification-attempt-v3"
	if repair {
		attempt["evidence_policy"] = softwarelifecycle.RepairEvidencePolicy
		attempt["automated_only_scenarios"] = strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
	}
	if exception != "" {
		attempt["owner_exception"] = exception
	}
	attempt["support"] = facts.Candidate.Support
	attempt["baseline"] = historyBaseline(facts.SubscriptionHistory)
	attempt["sources"] = []any{}
	if repair {
		attempt["required_scenarios"] = strings.Fields(`baseline-clean baseline-refusal baseline-precommit baseline-postcommit baseline-drift baseline-removal
enable-schema1 link-precommit link-postcommit managed-renewal recorder-live recorder-locks snap-refresh unsupported-route
identity-precommit identity-postcommit identity-unavailable identity-absent lifecycle-menu
remove-certbot remove-writer remove-admission-race remove-directory-lock secret-containment karing-final`)
	} else {
		var scenarios []string
		for _, id := range attempt["required_scenarios"].([]string) {
			if strings.HasPrefix(id, "source-") || strings.HasPrefix(id, "update-") {
				continue
			}
			if id == "remove-enable-precommit" {
				scenarios = append(scenarios, "lifecycle-menu")
			}
			scenarios = append(scenarios, id)
		}
		attempt["required_scenarios"] = scenarios
	}
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
	if !repair {
		v := jsonObject(t, []byte(boundary))
		a := v["v3_attempt"].(map[string]any)
		a["evidence_policy"] = softwarelifecycle.RepairEvidencePolicy
		a["automated_only_scenarios"] = strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
		assertQualificationRefused(t, binary, qualificationDocument(t, v), "repair fields on first scope")
	}
	evidence := recurringEvidenceFixture(t, manifest, attempt)
	evidence["schema"] = "sbxr-v3-packaged-live-evidence-v3"
	for _, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		s["schema"] = "sbxr-v3-scenario-evidence-v3"
		var extra []string
		switch s["scenario_id"] {
		case "lifecycle-menu":
			extra = strings.Fields("packaged-zero-argument-menu check-reachable update-reachable recover-reachable explicit-confirmation safe-no-update safe-no-recovery clean-install-target-refused no-replacement-on-refusal")
		case "enable-schema1":
			extra = strings.Fields("candidate-supported-setup-origin no-protected-state-edit no-unsupported-migration")
		}
		for _, check := range extra {
			s["evidence"] = append(s["evidence"].([]any), map[string]any{"record": map[string]any{"check": check, "observed_at": s["completed_at"], "result": "observed"}, "sha256": ""})
		}
	}
	rebindRecurringEvidence(t, evidence)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	if repair {
		for name, mutate := range map[string]func(map[string]any){
			"missing policy": func(v map[string]any) {
				delete(v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any), "evidence_policy")
			},
			"unknown policy": func(v map[string]any) {
				v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)["evidence_policy"] = "unknown"
			},
			"missing automated-only list": func(v map[string]any) {
				delete(v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any), "automated_only_scenarios")
			},
			"reordered automated-only list": func(v map[string]any) {
				ids := v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)["automated_only_scenarios"].([]any)
				ids[0], ids[1] = ids[1], ids[0]
			},
			"extra automated-only list item": func(v map[string]any) {
				a := v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)
				a["automated_only_scenarios"] = append(a["automated_only_scenarios"].([]any), "karing-final")
			},
		} {
			t.Run(name, func(t *testing.T) {
				v := jsonObject(t, []byte(document))
				mutate(v)
				assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
			})
		}
		for name, mutate := range map[string]func(map[string]any){
			"excluded-ID live claim": func(evidence map[string]any) {
				scenarios := evidence["scenarios"].([]any)
				claim := scenarios[0].(map[string]any)
				claim["scenario_id"] = "enable-precommit"
				evidence["scenarios"] = append(scenarios, claim)
			},
			"omitted Karing": func(evidence map[string]any) {
				scenarios := evidence["scenarios"].([]any)
				evidence["scenarios"] = scenarios[:len(scenarios)-1]
			},
			"omitted managed renewal": func(evidence map[string]any) {
				scenarios := evidence["scenarios"].([]any)
				for i, raw := range scenarios {
					if raw.(map[string]any)["scenario_id"] == "managed-renewal" {
						evidence["scenarios"] = append(scenarios[:i], scenarios[i+1:]...)
						return
					}
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				v := jsonObject(t, []byte(document))
				evidence := v["detailed_evidence"].(map[string]any)
				mutate(evidence)
				rebindRecurringEvidence(t, evidence)
				v["detailed_evidence_sha256"] = sha256String(qualificationDocument(t, evidence))
				assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
			})
		}
	}
	if exception != "" {
		assertQualificationRefused(t, binary, document, "exception cannot claim completed live scenarios")
		document = qualificationDocument(t, map[string]any{"schema": qualificationFactsSchema, "stage": "owner-exception-result", "qualification_boundary_facts": jsonValue(t, boundary), "qualification_manifest": jsonObject(t, manifest), "qualification_manifest_attested": true, "observed_at": attempt["started_at"]})
		for name, mutate := range map[string]func(map[string]any){
			"unsigned": func(v map[string]any) { v["qualification_manifest_attested"] = false },
			"unbound manifest": func(v map[string]any) {
				v["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)["owner_exception"] = "other"
			},
			"invented scenarios": func(v map[string]any) { v["scenarios"] = []any{} },
		} {
			v := jsonObject(t, []byte(document))
			mutate(v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		}
	}
	output, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("clean-install evidence: %v\n%s", err, output)
	}
	body := jsonObject(t, output)["records"].([]any)[0].(map[string]any)["body"].(string)
	required := []string{"RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION", "Incoming source upgrades: Not applicable", "Two-release update/recovery: Not applicable", "Release support: ", "Stable baseline: ", "Scenario: lifecycle-menu "}
	if exception != "" {
		required = []string{softwarelifecycle.OwnerExceptionCode, softwarelifecycle.OwnerExceptionLive, softwarelifecycle.OwnerExceptionSecrets, "Live qualification: Incomplete", "Incoming source upgrades: Not applicable"}
		for _, forbidden := range []string{"Karing macOS: Passed", "Codex Live Acceptance: Passed", "Scenario: ", "Integrated Verification: Passed"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("false claim: %s", forbidden)
			}
		}
	}
	for _, line := range required {
		if !strings.Contains(body, line) {
			t.Fatalf("record lacks %q", line)
		}
	}
	if repair {
		for _, line := range []string{"Evidence policy: " + softwarelifecycle.RepairEvidencePolicy, "Automated-only scenarios (not live): " + softwarelifecycle.RepairAutomatedOnlyScenarios, "Automated-only result: Passed in native amd64/arm64 workflow"} {
			if strings.Count(body, line) != 1 {
				t.Fatalf("record disclosure %q", line)
			}
		}
		for _, id := range strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios) {
			if strings.Contains(body, "Scenario: "+id+" ") {
				t.Fatalf("automated-only scenario claimed live: %s", id)
			}
		}
	}
	m := jsonObject(t, manifest)
	target := m["releases"].([]any)[0].(map[string]any)
	stableFacts := map[string]any{
		"acceptance_decision": jsonObject(t, output), "acceptance_facts": jsonValue(t, document),
		"archive":           map[string]any{"commit": facts.ArchiveCommit, "remote_commit": facts.ArchiveRemoteCommit, "remote_tag_object": facts.ArchiveRemoteTagObject, "tag_object": facts.ArchiveTagObject, "type": "tag"},
		"burned_identities": []any{}, "candidate_run": map[string]any{"conclusion": "success", "created_at": "2026-09-01T00:00:00Z", "event": "workflow_dispatch", "head_sha": facts.Commit, "id": "123", "path": ".github/workflows/candidate.yml"},
		"checklist_sha256": facts.ChecklistSHA256, "latest_release_id": source.ID, "latest_tag": source.Tag, "manifest_attested": true, "observed_at": "2026-09-02T00:00:00Z",
		"releases":    []any{map[string]any{"assets": target["assets"], "body": body, "commit": target["commit"], "draft": true, "immutable": false, "prerelease": false, "release_id": target["release_id"], "release_identity": target["release_identity"], "sequence": target["sequence"], "tag": target["tag"]}},
		"remote_main": facts.Commit, "schema": qualificationFactsSchema, "signed_manifest": m, "stage": "stable-preflight", "subscription_history": scopeHistoryFixture(t, source),
	}
	if stable, err := runQualificationCommand(binary, qualificationDocument(t, stableFacts)); err != nil || len(jsonObject(t, stable)["actions"].([]any)) != 1 {
		t.Fatalf("recurring stable gate: %v\n%s", err, stable)
	}
	stableDecision, err := runQualificationCommand(binary, qualificationDocument(t, stableFacts))
	if err != nil {
		t.Fatal(err)
	}
	stable := jsonObject(t, stableDecision)
	action := stable["actions"].([]any)[0].(map[string]any)
	observedAssets := make([]any, len(action["assets"].([]any)))
	for index, assetValue := range action["assets"].([]any) {
		asset := assetValue.(map[string]any)
		observedAssets[index] = map[string]any{"id": 100 + index, "name": asset["name"], "sha256": asset["sha256"], "size": asset["size"]}
	}
	publicationFacts := map[string]any{
		"action_index": 0, "approval": map[string]any{"environments": []any{map[string]any{"name": "stable-publication"}}, "state": "approved"},
		"observation": map[string]any{"assets": observedAssets, "attestation": nil, "body": action["body"], "commit": action["commit"], "downloads": action["assets"], "draft": true, "immutable": false, "latest_install_sha256": "", "latest_release_id": source.ID, "prerelease": false, "public_verification": nil, "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"]},
		"observed_at": "2026-09-02T00:01:00Z", "preflight_decision": jsonValue(t, string(stableDecision)), "preflight_facts": stableFacts, "prior_decision_sha256": sha256String(string(stableDecision)), "prior_verification_decision": nil, "prior_verification_facts": nil, "schema": qualificationFactsSchema, "stage": "stable-publication", "subscription_history": scopeHistoryFixture(t, source),
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
	verification := map[string]any{"attempt": 1, "observation": public, "observed_at": "2026-09-02T00:01:10Z", "prior_decision_sha256": sha256String(string(publicationDecision)), "publication_decision": jsonObject(t, publicationDecision), "publication_facts": publicationFacts, "schema": qualificationFactsSchema, "stage": "stable-publication-verification"}
	verified, verifyErr := runQualificationCommand(binary, qualificationDocument(t, verification))
	if verifyErr != nil || jsonObject(t, verified)["outcome"] != "accepted" {
		t.Fatalf("public verification: %s %v", verified, verifyErr)
	}
	finalFacts := map[string]any{"schema": qualificationFactsSchema, "stage": "stable-v3-finalization", "observed_at": "2026-09-02T00:02:00Z", "prior_decision_sha256": sha256String(string(verified)), "publication_verification_decision": jsonObject(t, verified), "publication_verification_facts": verification}
	final, finalErr := runQualificationCommand(binary, qualificationDocument(t, finalFacts))
	wantedLive := "Passed"
	if exception != "" {
		wantedLive = softwarelifecycle.OwnerExceptionLive
	}
	if finalErr != nil || jsonObject(t, final)["v3_packaged_live"] != wantedLive || jsonObject(t, final)["complete_removal"] != wantedLive {
		t.Fatalf("finalization: %s %v", final, finalErr)
	}

	failure := map[string]any{
		"burned_identities": []any{}, "candidate_commit_ancestor": true, "candidate_run": stableFacts["candidate_run"],
		"finalization_run":  map[string]any{"created_at": "2026-09-02T00:00:00Z", "head_sha": facts.Commit, "id": "456", "path": ".github/workflows/stable.yml", "url": "https://github.com/albertloky/SBXR/actions/runs/456"},
		"manifest_attested": true, "observations": []any{map[string]any{"assets": target["assets"], "body": body, "commit": target["commit"], "draft": true, "immutable": false, "prerelease": false, "release_id": target["release_id"], "release_identity": target["release_identity"], "release_present": true, "sequence": target["sequence"], "tag": target["tag"], "tag_commit": target["commit"]}},
		"observed_at": "2026-09-02T00:01:00Z", "operation": "publish", "publication_stage": "prepublication", "schema": qualificationFactsSchema, "signed_manifest": m, "stage": "stable-failure-finalization",
	}
	failure["observations"].([]any)[0].(map[string]any)["publicly_verified"] = false
	burned, err := runQualificationCommand(binary, qualificationDocument(t, failure))
	if err != nil || jsonObject(t, burned)["outcome"] != "failed-prerelease" || jsonObject(t, burned)["actions"].([]any)[0].(map[string]any)["burn_required"] != true {
		t.Fatalf("recurring stable failure burn: %v\n%s", err, burned)
	}
	for _, stageFacts := range []map[string]any{stableFacts, publicationFacts} {
		for name, mutate := range map[string]func(map[string]any){
			"missing history": func(v map[string]any) { delete(v, "subscription_history") },
			"changed baseline bytes": func(v map[string]any) {
				v["subscription_history"].(map[string]any)["public_latest"].(map[string]any)["release_identity"].(map[string]any)["release_index_sha256"] = strings.Repeat("f", 64)
			},
			"repeat exception": func(v map[string]any) {
				v["subscription_history"].(map[string]any)["releases"].([]any)[0].(map[string]any)["body"] = "Stable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION\n"
			},
		} {
			t.Run(stageFacts["stage"].(string)+"/"+name, func(t *testing.T) {
				v := jsonObject(t, []byte(qualificationDocument(t, stageFacts)))
				mutate(v)
				assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
			})
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown owner exception": func(v map[string]any) { v["v3_attempt"].(map[string]any)["owner_exception"] = "unapproved" },
		"old waiver on repair": func(v map[string]any) {
			if repair {
				v["v3_attempt"].(map[string]any)["owner_exception"] = softwarelifecycle.OwnerExceptionID
			} else {
				v["v3_attempt"].(map[string]any)["owner_exception"] = "unapproved"
			}
		},
		"scope mismatch": func(v map[string]any) {
			v["v3_attempt"].(map[string]any)["support"].(map[string]any)["scope"] = "recurring-subscription-upgrade"
		},
		"baseline mismatch": func(v map[string]any) {
			v["v3_attempt"].(map[string]any)["baseline"].(map[string]any)["commit"] = strings.Repeat("f", 40)
		},
		"index mismatch": func(v map[string]any) { v["v3_attempt"].(map[string]any)["candidate_index"] = "{}" },
		"source mismatch": func(v map[string]any) {
			v["v3_attempt"].(map[string]any)["sources"] = recurringAttemptFixture(t, source)["sources"]
		},
		"missing menu": func(v map[string]any) {
			a := v["v3_attempt"].(map[string]any)
			ids := a["required_scenarios"].([]any)
			for i, id := range ids {
				if id == "lifecycle-menu" {
					a["required_scenarios"] = append(ids[:i], ids[i+1:]...)
					break
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := jsonObject(t, []byte(boundary))
			mutate(v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
	if repair {
		for name, mutate := range map[string]func(map[string]any){
			"missing repair policy":                func(a map[string]any) { delete(a, "evidence_policy") },
			"unknown repair policy":                func(a map[string]any) { a["evidence_policy"] = "unknown" },
			"missing repair automated-only list":   func(a map[string]any) { delete(a, "automated_only_scenarios") },
			"reordered repair automated-only list": func(a map[string]any) { ids := a["automated_only_scenarios"].([]any); ids[0], ids[1] = ids[1], ids[0] },
			"extra repair automated-only list": func(a map[string]any) {
				a["automated_only_scenarios"] = append(a["automated_only_scenarios"].([]any), "karing-final")
			},
		} {
			t.Run(name, func(t *testing.T) {
				v := jsonObject(t, []byte(boundary))
				mutate(v["v3_attempt"].(map[string]any))
				assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
			})
		}
	}
}

func TestQualificationCommandRequiresActualRecurringSubscriptionSources(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build %v %s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.0", 18, 3
	source := recurringSourceFixture()
	source.Index.Schema = 2
	source.Index.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.FirstSubscriptionCleanInstall, Sources: []decisionReleaseIdentity{}}
	source.Body = strings.NewReplacer("RELEASE-V3-PACKAGED-LIVE-QUALIFICATION", "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION", "Clean-installed V3 release", "Clean-installed subscription-capable V3 release", "and outside runner", "and Karing macOS").Replace(source.Body)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	facts.Candidate.Support = &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Sources: []decisionReleaseIdentity{sourceAction(source).ReleaseIdentity}}
	if json.Unmarshal([]byte(qualificationDocument(t, scopeHistoryFixture(t, source))), &facts.SubscriptionHistory) != nil {
		t.Fatal("history fixture")
	}
	attempt := recurringAttemptFixture(t, source)
	attempt["schema"] = "sbxr-v3-qualification-attempt-v3"
	attempt["support"] = facts.Candidate.Support
	attempt["baseline"] = historyBaseline(facts.SubscriptionHistory)
	attempt["sources"].([]any)[0].(map[string]any)["ownership_schema"] = 2
	var assets []softwarelifecycle.LatestAssetProof
	for _, raw := range draftAssets(0) {
		a := raw.(map[string]any)
		if a["name"] != "release-index.json" {
			assets = append(assets, softwarelifecycle.LatestAssetProof{Name: a["name"].(string), Size: int64(a["size"].(int)), SHA256: a["sha256"].(string)})
		}
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(facts.Candidate.BTag, facts.Commit, 18, assets, facts.Candidate.Support.lifecycle())
	if err != nil {
		t.Fatal(err)
	}
	attempt["candidate_index"] = string(index)

	boundary, manifest := qualificationBoundaryForCandidate(t, binary, facts, attempt)
	evidence := recurringEvidenceFixture(t, manifest, attempt)
	evidence["schema"] = "sbxr-v3-packaged-live-evidence-v3"
	for _, raw := range evidence["scenarios"].([]any) {
		scenario := raw.(map[string]any)
		scenario["schema"] = "sbxr-v3-scenario-evidence-v3"
		if scenario["scenario_id"] == "enable-schema1" {
			for _, check := range strings.Fields("candidate-supported-setup-origin no-protected-state-edit no-unsupported-migration") {
				scenario["evidence"] = append(scenario["evidence"].([]any), map[string]any{"record": map[string]any{"check": check, "observed_at": scenario["completed_at"], "result": "observed"}, "sha256": ""})
			}
		}
	}
	rebindRecurringEvidence(t, evidence)
	output, err := runQualificationCommand(binary, recurringResultFixture(t, boundary, manifest, evidence))
	if err != nil {
		t.Fatalf("recurring v3 evidence %v %s", err, output)
	}
	body := jsonObject(t, output)["records"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(body, "RELEASE-V3-SUBSCRIPTION-QUALIFICATION") || !strings.Contains(body, "Scenario: source-v2.0.0-postcommit ") || strings.Contains(body, "Not applicable") {
		t.Fatal("recurring record did not require actual source recovery")
	}
	for name, mutate := range map[string]func(map[string]any){
		"empty sources": func(v map[string]any) { v["v3_attempt"].(map[string]any)["sources"] = []any{} },
		"source identity mismatch": func(v map[string]any) {
			v["v3_attempt"].(map[string]any)["support"].(map[string]any)["sources"].([]any)[0].(map[string]any)["commit"] = strings.Repeat("f", 40)
		},
		"historical schema override": func(v map[string]any) {
			v["v3_attempt"].(map[string]any)["schema"] = "sbxr-v3-qualification-attempt-v2"
		},
		"repair fields on recurring scope": func(v map[string]any) {
			a := v["v3_attempt"].(map[string]any)
			a["evidence_policy"] = softwarelifecycle.RepairEvidencePolicy
			a["automated_only_scenarios"] = strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := jsonObject(t, []byte(boundary))
			mutate(v)
			assertQualificationRefused(t, binary, qualificationDocument(t, v), name)
		})
	}
}

func TestReleaseIndexCommandBindsDeclaredSubscriptionSources(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build %v %s", err, output)
	}
	directory := t.TempDir()
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	supportFile := filepath.Join(t.TempDir(), "support.json")
	outputFile := filepath.Join(t.TempDir(), "release-index.json")
	support := v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Sources: []decisionReleaseIdentity{sourceAction(recurringSourceFixture()).ReleaseIdentity}}
	if err := os.WriteFile(supportFile, []byte(qualificationDocument(t, support)), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "index", "-tag", "v3.1.0", "-commit", strings.Repeat("a", 40), "-sequence", "18", "-directory", directory, "-output", outputFile, "-support", supportFile).CombinedOutput()
	if err != nil {
		t.Fatalf("index command %v %s", err, output)
	}
	body, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Support softwarelifecycle.ReleaseSupport `json:"support"`
	}
	if json.Unmarshal(body, &index) != nil || !reflect.DeepEqual(index.Support, support.lifecycle()) {
		t.Fatalf("source declaration not bound: %s", body)
	}
	if err := os.WriteFile(supportFile, []byte(`{"contract":"sbxr-subscription-update-v1","scope":"recurring-subscription-upgrade","sources":[],"waiver":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Command(binary, "index", "-tag", "v3.1.0", "-commit", strings.Repeat("a", 40), "-sequence", "18", "-directory", directory, "-output", outputFile+".bad", "-support", supportFile).CombinedOutput(); err == nil {
		t.Fatal("unsigned support override admitted")
	}
}
