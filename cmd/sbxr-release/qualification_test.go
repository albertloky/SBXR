package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const initialNormalFacts = `{"archive_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","archive_remote_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","archive_remote_tag_object":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","archive_tag_object":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","archive_type":"tag","burned_identities":[],"candidate":{"a_sequence":17,"a_tag":"v2.0.0","b_sequence":18,"b_tag":"v2.0.1","defect_issue_url":null,"failed_normal_run_id":null,"mode":"normal"},"checklist_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","defect_issue":null,"failed_normal_run":null,"latest_tag":null,"releases":[],"remote_main":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"sbxr-release-qualification-facts-v1","stage":"candidate-preflight","tags":[]}`

const initialNormalDecision = `{"actions":[{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":17,"tag":"v2.0.0","type":"build-release"},{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":18,"tag":"v2.0.1","type":"build-release"}],"facts_sha256":"2e51e83e75a08169f2d6a424ab510f83954bab4e29b35efbfb84e48545f780a3","outcome":"accepted","schema":"sbxr-release-qualification-decision-v1","source_state":"initial-normal","stage":"candidate-preflight"}`

func TestQualificationCommandEvaluatesInitialNormalCandidatePreflight(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	output, err := runQualificationCommand(binary, initialNormalFacts)
	if err != nil {
		t.Fatalf("candidate preflight: %v\n%s", err, output)
	}
	if string(output) != initialNormalDecision {
		t.Fatalf("decision = %s\nwant %s", output, initialNormalDecision)
	}
	retry, err := runQualificationCommand(binary, initialNormalFacts)
	if err != nil || string(retry) != initialNormalDecision {
		t.Fatalf("retry = %s, %v", retry, err)
	}
	changed := strings.Replace(initialNormalFacts, strings.Repeat("c", 64), strings.Repeat("d", 64), 1)
	changedOutput, err := runQualificationCommand(binary, changed)
	if err != nil || string(changedOutput) == initialNormalDecision {
		t.Fatalf("changed facts decision = %s, %v", changedOutput, err)
	}

	for name, document := range map[string]string{
		"missing":        strings.Replace(initialNormalFacts, `,"tags":[]`, "", 1),
		"extra":          strings.Replace(initialNormalFacts, `"stage":"candidate-preflight"`, `"stage":"candidate-preflight","unknown":true`, 1),
		"duplicate key":  strings.Replace(initialNormalFacts, `"stage":"candidate-preflight"`, `"schema":"sbxr-release-qualification-facts-v1","stage":"candidate-preflight"`, 1),
		"non-canonical":  " " + initialNormalFacts,
		"unknown schema": strings.Replace(initialNormalFacts, qualificationFactsSchema, "sbxr-release-qualification-facts-v2", 1),
		"wrong stage":    strings.Replace(initialNormalFacts, candidatePreflightStage, "stable-preflight", 1),
		"contradictory":  strings.Replace(initialNormalFacts, `"tags":[]`, `"tags":["v2.0.0"]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if output, err := runQualificationCommand(binary, document); err == nil {
				t.Fatalf("accepted hostile facts: %s", output)
			}
		})
	}
}

func TestQualificationCommandPreservesLaterNormalAndRescuePreflight(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	later := candidateFacts("normal")
	later.LatestTag = stringPointer("v2.0.0")
	later.Releases = []observedRelease{qualifiedRelease(false)}
	later.Tags = []string{"v2.0.0"}
	laterDocument := canonicalFacts(t, later)
	laterOutput, err := runQualificationCommand(binary, laterDocument)
	if err != nil {
		t.Fatalf("later normal: %v\n%s", err, laterOutput)
	}
	const laterDecision = `{"actions":[{"assets":[{"name":"install.sh","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":10},{"name":"release-index.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size":20},{"name":"sbxr-linux-amd64.tar.gz","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size":30},{"name":"sbxr-linux-arm64.tar.gz","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":40}],"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","draft":false,"immutable":true,"prerelease":false,"release_id":7,"release_identity":{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","release_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222","repository":"albertloky/SBXR","tag":"v2.0.0"},"sequence":17,"tag":"v2.0.0","type":"use-source-release"},{"commit":"dddddddddddddddddddddddddddddddddddddddd","sequence":18,"tag":"v2.0.1","type":"build-release"}],"facts_sha256":"942b30e880e5c69f7e394c2daff89af740cae61676959f12bbf828521b5a6543","outcome":"accepted","schema":"sbxr-release-qualification-decision-v1","source_state":"later-normal","stage":"candidate-preflight"}`
	if string(laterOutput) != laterDecision {
		t.Fatalf("later decision = %s", laterOutput)
	}

	rescue := candidateFacts("rescue")
	rescue.Candidate.DefectIssueURL = stringPointer("https://github.com/albertloky/SBXR/issues/99")
	rescue.Candidate.FailedNormalRunID = stringPointer("123")
	rescue.DefectIssue = &defectIssue{State: "open", URL: *rescue.Candidate.DefectIssueURL}
	rescue.FailedNormalRun = &failedNormalRun{Conclusion: "failure", ID: "123", Mode: "normal", Path: ".github/workflows/candidate.yml"}
	rescue.Releases = []observedRelease{qualifiedRelease(true)}
	rescue.Tags = []string{"v2.0.0"}
	rescue.BurnedIdentities = []burnedIdentity{{Commit: strings.Repeat("e", 40), OriginalTag: "v2.0.0", QualificationRunURL: failedRunURL("123"), Reason: "post-sign-qualification-failure", RecordedAt: "2026-08-23T00:00:00Z", ReleaseIndexSHA256: strings.Repeat("2", 64), Sequence: 17}}
	rescueDocument := canonicalFacts(t, rescue)
	rescueOutput, err := runQualificationCommand(binary, rescueDocument)
	if err != nil {
		t.Fatalf("rescue: %v\n%s", err, rescueOutput)
	}
	const rescueDecision = `{"actions":[{"assets":[{"name":"install.sh","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":10},{"name":"release-index.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size":20},{"name":"sbxr-linux-amd64.tar.gz","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size":30},{"name":"sbxr-linux-arm64.tar.gz","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":40}],"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","draft":false,"immutable":true,"prerelease":true,"release_id":7,"release_identity":{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","release_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222","repository":"albertloky/SBXR","tag":"v2.0.0"},"sequence":17,"tag":"v2.0.0","type":"use-source-release"},{"commit":"dddddddddddddddddddddddddddddddddddddddd","sequence":18,"tag":"v2.0.1","type":"build-release"}],"facts_sha256":"1ee747d980054850a4fd977cf02cd21b1fe82a293a8da27c94382c5525f3c8e6","outcome":"accepted","schema":"sbxr-release-qualification-decision-v1","source_state":"rescue","stage":"candidate-preflight"}`
	if string(rescueOutput) != rescueDecision {
		t.Fatalf("rescue decision = %s", rescueOutput)
	}

	laterBoundaryFacts, laterManifest := qualificationBoundaryForCandidate(t, binary, later)
	rescueBoundaryFacts, rescueManifest := qualificationBoundaryForCandidate(t, binary, rescue)
	if got := sha256String(string(laterManifest)); got != "1e506a2675aab0d4e5f1d8b19178fdd0a15be6843ffb06ea6470f53e127be022" {
		t.Fatalf("later manifest SHA-256 = %s", got)
	}
	if got := sha256String(string(rescueManifest)); got != "a79de11913f4a5aa51b3094cbbb749edf0cd9f49117d5fb9fbbd9801b05a738a" {
		t.Fatalf("rescue manifest SHA-256 = %s", got)
	}
	for name, fixture := range map[string]struct {
		document string
		mutate   func(map[string]any)
	}{
		"stale prior decision digest": {laterBoundaryFacts, func(facts map[string]any) { facts["prior_decision_sha256"] = strings.Repeat("9", 64) }},
		"crossed release": {laterBoundaryFacts, func(facts map[string]any) {
			facts["releases"].([]any)[0].(map[string]any)["tag"] = "v2.0.9"
		}},
		"changed rescue authority": {rescueBoundaryFacts, func(facts map[string]any) {
			facts["rescue"].(map[string]any)["failed_normal_run_id"] = "124"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(fixture.document))
			fixture.mutate(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}

	laterWithDuplicateSequence := candidateFacts("normal")
	laterWithDuplicateSequence.LatestTag = stringPointer("v2.0.0")
	laterWithDuplicateSequence.Releases = []observedRelease{qualifiedRelease(false), {Assets: []observedAsset{}, Body: "historical", Commit: strings.Repeat("f", 40), ID: 8, Sequence: uint64Pointer(17), Tag: "v1.9.0"}}
	laterWithDuplicateSequence.Tags = []string{"v2.0.0"}
	assertQualificationRefused(t, binary, canonicalFacts(t, laterWithDuplicateSequence), "duplicate Release Sequence")

	laterWithBTag := later
	laterWithBTag.Tags = []string{"v2.0.0", "v2.0.1"}
	assertQualificationRefused(t, binary, canonicalFacts(t, laterWithBTag), "existing B tag")

	rescueWithoutBurn := rescue
	rescueWithoutBurn.BurnedIdentities = []burnedIdentity{}
	assertQualificationRefused(t, binary, canonicalFacts(t, rescueWithoutBurn), "missing burned identity")

	rescueAfterRescue := rescue
	latestRescue := qualifiedRelease(false)
	latestRescue.ID = 6
	latestRescue.Tag = "v1.9.0"
	latestRescue.Index.Tag = "v1.9.0"
	latestRescue.Index.Sequence = 16
	latestRescue.Sequence = uint64Pointer(16)
	latestRescue.Body = strings.ReplaceAll(latestRescue.Body, "v2.0.0", "v1.9.0")
	latestRescue.Body = strings.ReplaceAll(latestRescue.Body, "Sequence: 17", "Sequence: 16")
	latestRescue.Body = strings.ReplaceAll(latestRescue.Body, "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION", "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION")
	rescueAfterRescue.LatestTag = stringPointer("v1.9.0")
	rescueAfterRescue.Releases = []observedRelease{latestRescue, qualifiedRelease(true)}
	assertQualificationRefused(t, binary, canonicalFacts(t, rescueAfterRescue), "consecutive rescue")
}

func qualificationBoundaryForCandidate(t *testing.T, binary string, preflightFacts qualificationFacts) (string, []byte) {
	t.Helper()
	preflightDocument := canonicalFacts(t, preflightFacts)
	preflightDecision, err := runQualificationCommand(binary, preflightDocument)
	if err != nil {
		t.Fatalf("candidate preflight: %v\n%s", err, preflightDecision)
	}
	preflight := jsonObject(t, preflightDecision)
	var sources []any
	var builds []map[string]any
	for _, value := range preflight["actions"].([]any) {
		action := value.(map[string]any)
		switch action["type"] {
		case "use-source-release":
			sources = append(sources, map[string]any{"assets": action["assets"], "commit": action["commit"], "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"]})
		case "build-release":
			builds = append(builds, action)
		}
	}
	if len(builds) == 0 {
		t.Fatal("candidate boundary requires a build action")
	}
	targets, observations := make([]any, len(builds)), make([]any, len(builds))
	for index, build := range builds {
		tag, sequence, commit := build["tag"].(string), uint64(build["sequence"].(float64)), build["commit"].(string)
		target := draftTarget(tag, sequence)
		target["commit"] = commit
		target["release_identity"].(map[string]any)["commit"] = commit
		targets[index] = target
		observation := draftObservation(tag, sequence, int64(71+len(sources)+index))
		observation["commit"] = commit
		observation["release_identity"].(map[string]any)["commit"] = commit
		observations[index] = observation
	}
	constructionFacts := qualificationDocument(t, map[string]any{
		"built_releases": targets, "preflight_decision": jsonValue(t, string(preflightDecision)), "preflight_facts": jsonValue(t, preflightDocument),
		"schema": qualificationFactsSchema, "stage": "candidate-draft-construction",
	})
	constructionDecision, err := runQualificationCommand(binary, constructionFacts)
	if err != nil {
		t.Fatalf("draft construction: %v\n%s", err, constructionDecision)
	}
	verificationFacts := qualificationDocument(t, map[string]any{
		"construction_decision": jsonValue(t, string(constructionDecision)), "construction_facts": jsonValue(t, constructionFacts), "observations": observations,
		"schema": qualificationFactsSchema, "stage": "candidate-draft-verification",
	})
	verificationDecision, err := runQualificationCommand(binary, verificationFacts)
	if err != nil {
		t.Fatalf("draft verification: %v\n%s", err, verificationDecision)
	}
	releases := append(sources, jsonObject(t, verificationDecision)["verified_releases"].([]any)...)
	var rescue any
	if preflightFacts.Candidate.Mode == "rescue" {
		rescue = map[string]any{"defect_issue_url": *preflightFacts.Candidate.DefectIssueURL, "failed_normal_run_id": *preflightFacts.Candidate.FailedNormalRunID}
	}
	boundaryFacts := qualificationDocument(t, map[string]any{
		"approval": map[string]any{"environments": []any{map[string]any{"name": "acceptance-vps"}}, "state": "approved"}, "candidate_failure_state_sha256": strings.Repeat("9", 64), "checklist_sha256": preflightFacts.ChecklistSHA256,
		"draft_verification_decision": jsonValue(t, string(verificationDecision)), "draft_verification_facts": jsonValue(t, verificationFacts),
		"native_evidence": func() []any {
			var evidence []any
			for _, build := range builds {
				tag := build["tag"].(string)
				for _, architecture := range []string{"amd64", "arm64"} {
					evidence = append(evidence, map[string]any{"path": "native/native-" + tag + "-" + architecture + "/evidence/native-" + architecture + ".json", "sha256": strings.Repeat(strconv.Itoa(5+len(evidence)), 64)})
				}
			}
			return evidence
		}(),
		"prior_decision_sha256": sha256String(string(verificationDecision)), "releases": releases, "rescue": rescue, "schema": qualificationFactsSchema, "source_state": preflight["source_state"], "stage": "qualification-boundary",
		"workflow": map[string]any{"commit": builds[len(builds)-1]["commit"], "path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123"},
	})
	manifest, err := runQualificationCommand(binary, boundaryFacts)
	if err != nil {
		t.Fatalf("qualification boundary: %v\n%s", err, manifest)
	}
	return boundaryFacts, manifest
}

func TestQualificationCommandConstructsAndVerifiesCandidateDrafts(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	built := []any{draftTarget("v2.0.0", 17), draftTarget("v2.0.1", 18)}
	constructionFacts := qualificationDocument(t, map[string]any{
		"built_releases":     built,
		"preflight_decision": jsonValue(t, initialNormalDecision),
		"preflight_facts":    jsonValue(t, initialNormalFacts),
		"schema":             qualificationFactsSchema,
		"stage":              "candidate-draft-construction",
	})
	constructionOutput, err := runQualificationCommand(binary, constructionFacts)
	if err != nil {
		t.Fatalf("draft construction: %v\n%s", err, constructionOutput)
	}
	construction := jsonObject(t, constructionOutput)
	if construction["outcome"] != "actions-required" || construction["stage"] != "candidate-draft-construction" || len(construction["actions"].([]any)) != 2 {
		t.Fatalf("construction decision = %s", constructionOutput)
	}
	if construction["facts_sha256"] != sha256String(constructionFacts) || construction["prior_decision_sha256"] != sha256String(initialNormalDecision) {
		t.Fatalf("construction decision is not bound to its facts and prior decision: %s", constructionOutput)
	}
	for _, actionValue := range construction["actions"].([]any) {
		action := actionValue.(map[string]any)
		if action["type"] != "construct-draft" || action["facts_sha256"] != construction["facts_sha256"] || action["prior_decision_sha256"] != construction["prior_decision_sha256"] {
			t.Fatalf("unbound construction action: %v", action)
		}
	}

	observations := []any{draftObservation("v2.0.0", 17, 71), draftObservation("v2.0.1", 18, 72)}
	verificationFacts := qualificationDocument(t, map[string]any{
		"construction_decision": jsonValue(t, string(constructionOutput)),
		"construction_facts":    jsonValue(t, constructionFacts),
		"observations":          observations,
		"schema":                qualificationFactsSchema,
		"stage":                 "candidate-draft-verification",
	})
	verificationOutput, err := runQualificationCommand(binary, verificationFacts)
	if err != nil {
		t.Fatalf("draft verification: %v\n%s", err, verificationOutput)
	}
	verification := jsonObject(t, verificationOutput)
	if verification["outcome"] != "accepted" || verification["stage"] != "candidate-draft-verification" || len(verification["verified_releases"].([]any)) != 2 {
		t.Fatalf("verification decision = %s", verificationOutput)
	}
	if verification["facts_sha256"] != sha256String(verificationFacts) || verification["prior_decision_sha256"] != sha256String(string(constructionOutput)) {
		t.Fatalf("verification decision is not bound to its facts and prior decision: %s", verificationOutput)
	}
	retry, err := runQualificationCommand(binary, verificationFacts)
	if err != nil || string(retry) != string(verificationOutput) {
		t.Fatalf("verification retry = %s, %v", retry, err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"partial": func(facts map[string]any) { facts["observations"] = observations[:1] },
		"unexpected": func(facts map[string]any) {
			facts["observations"] = append(observations, draftObservation("v2.0.2", 19, 73))
		},
		"stale": func(facts map[string]any) {
			facts["construction_facts"].(map[string]any)["built_releases"].([]any)[0].(map[string]any)["tag"] = "v2.0.9"
		},
		"crossed journey": func(facts map[string]any) {
			facts["observations"].([]any)[1].(map[string]any)["commit"] = strings.Repeat("b", 40)
		},
		"crossed release ID": func(facts map[string]any) {
			facts["observations"].([]any)[0].(map[string]any)["release_id"] = float64(99)
		},
		"crossed asset ID": func(facts map[string]any) {
			first := facts["observations"].([]any)[0].(map[string]any)["assets"].([]any)[0].(map[string]any)["id"]
			facts["observations"].([]any)[1].(map[string]any)["assets"].([]any)[0].(map[string]any)["id"] = first
			facts["observations"].([]any)[1].(map[string]any)["downloads"].([]any)[0].(map[string]any)["id"] = first
		},
		"unauthenticated": func(facts map[string]any) {
			facts["observations"].([]any)[0].(map[string]any)["downloads"].([]any)[0].(map[string]any)["authenticated"] = false
		},
		"changed bytes": func(facts map[string]any) {
			facts["observations"].([]any)[0].(map[string]any)["downloads"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(verificationFacts))
			mutate(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}

}

func TestQualificationCommandConstructsQualificationManifest(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	constructionFacts := qualificationDocument(t, map[string]any{
		"built_releases":     []any{draftTarget("v2.0.0", 17), draftTarget("v2.0.1", 18)},
		"preflight_decision": jsonValue(t, initialNormalDecision),
		"preflight_facts":    jsonValue(t, initialNormalFacts),
		"schema":             qualificationFactsSchema,
		"stage":              "candidate-draft-construction",
	})
	constructionDecision, err := runQualificationCommand(binary, constructionFacts)
	if err != nil {
		t.Fatalf("draft construction: %v\n%s", err, constructionDecision)
	}
	verificationFacts := qualificationDocument(t, map[string]any{
		"construction_decision": jsonValue(t, string(constructionDecision)),
		"construction_facts":    jsonValue(t, constructionFacts),
		"observations":          []any{draftObservation("v2.0.0", 17, 71), draftObservation("v2.0.1", 18, 72)},
		"schema":                qualificationFactsSchema,
		"stage":                 "candidate-draft-verification",
	})
	verificationDecision, err := runQualificationCommand(binary, verificationFacts)
	if err != nil {
		t.Fatalf("draft verification: %v\n%s", err, verificationDecision)
	}
	boundaryFacts := qualificationDocument(t, map[string]any{
		"approval":                       map[string]any{"environments": []any{map[string]any{"name": "acceptance-vps"}}, "state": "approved"},
		"candidate_failure_state_sha256": strings.Repeat("9", 64),
		"checklist_sha256":               strings.Repeat("c", 64),
		"draft_verification_decision":    jsonValue(t, string(verificationDecision)),
		"draft_verification_facts":       jsonValue(t, verificationFacts),
		"native_evidence": []any{
			map[string]any{"path": "native/native-v2.0.0-amd64/evidence/native-amd64.json", "sha256": strings.Repeat("5", 64)},
			map[string]any{"path": "native/native-v2.0.0-arm64/evidence/native-arm64.json", "sha256": strings.Repeat("6", 64)},
			map[string]any{"path": "native/native-v2.0.1-amd64/evidence/native-amd64.json", "sha256": strings.Repeat("7", 64)},
			map[string]any{"path": "native/native-v2.0.1-arm64/evidence/native-arm64.json", "sha256": strings.Repeat("8", 64)},
		},
		"prior_decision_sha256": sha256String(string(verificationDecision)),
		"releases":              jsonObject(t, verificationDecision)["verified_releases"],
		"rescue":                nil,
		"schema":                qualificationFactsSchema,
		"source_state":          "initial-normal",
		"stage":                 "qualification-boundary",
		"workflow": map[string]any{
			"commit": strings.Repeat("a", 40), "path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main",
			"run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123",
		},
	})
	manifest, err := runQualificationCommand(binary, boundaryFacts)
	if err != nil {
		t.Fatalf("qualification boundary: %v\n%s", err, manifest)
	}
	const expectedManifest = `{"acceptance_vps_checklist_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","approval":{"environments":[{"name":"acceptance-vps"}],"state":"approved"},"candidate_failure_state_sha256":"9999999999999999999999999999999999999999999999999999999999999999","decision_chain":[{"decision_sha256":"c080cc282e985f1e7cda6646d9b47b15b4aa855575d777c582e2cfc1fbda411e","facts_sha256":"2e51e83e75a08169f2d6a424ab510f83954bab4e29b35efbfb84e48545f780a3","outcome":"accepted","stage":"candidate-preflight"},{"decision_sha256":"f259e157613df307ff05e306735181635da422fceecbd7c8a5d732c7b7bf2ec6","facts_sha256":"4190445f74b68e64d8fe93d90cb6fc72b0009b85b8d50cd1defb0e8774af8517","outcome":"actions-required","stage":"candidate-draft-construction"},{"decision_sha256":"fdaa1b143a9eac4a65fc28848966aa5f97b8d13e8e1e56f25dbd3daaeafcc064","facts_sha256":"e4a471efeaf0dbcf03ed384aea69ab3f01c72fc088a3d4e2f1c61b2467866129","outcome":"accepted","stage":"candidate-draft-verification"}],"mode":"normal","native_evidence":[{"path":"native/native-v2.0.0-amd64/evidence/native-amd64.json","sha256":"5555555555555555555555555555555555555555555555555555555555555555"},{"path":"native/native-v2.0.0-arm64/evidence/native-arm64.json","sha256":"6666666666666666666666666666666666666666666666666666666666666666"},{"path":"native/native-v2.0.1-amd64/evidence/native-amd64.json","sha256":"7777777777777777777777777777777777777777777777777777777777777777"},{"path":"native/native-v2.0.1-arm64/evidence/native-arm64.json","sha256":"8888888888888888888888888888888888888888888888888888888888888888"}],"pinned_actions":["actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803","actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16","actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02","actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093","actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661"],"releases":[{"assets":[{"name":"install.sh","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":10},{"name":"release-index.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size":11},{"name":"sbxr-linux-amd64.tar.gz","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size":12},{"name":"sbxr-linux-arm64.tar.gz","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":13}],"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_id":71,"release_identity":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222","repository":"albertloky/SBXR","tag":"v2.0.0"},"sequence":17,"tag":"v2.0.0"},{"assets":[{"name":"install.sh","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":10},{"name":"release-index.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size":11},{"name":"sbxr-linux-amd64.tar.gz","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size":12},{"name":"sbxr-linux-arm64.tar.gz","sha256":"4444444444444444444444444444444444444444444444444444444444444444","size":13}],"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_id":72,"release_identity":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222","repository":"albertloky/SBXR","tag":"v2.0.1"},"sequence":18,"tag":"v2.0.1"}],"repository":"albertloky/SBXR","rescue":null,"schema":"sbxr-qualification-manifest-v1","source_state":"initial-normal","workflow":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":".github/workflows/candidate.yml","ref":"albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main","run_id":"123","run_url":"https://github.com/albertloky/SBXR/actions/runs/123"}}`
	if string(manifest) != expectedManifest {
		t.Fatalf("qualification manifest = %s\nwant %s", manifest, expectedManifest)
	}
	retry, err := runQualificationCommand(binary, boundaryFacts)
	if err != nil || !bytes.Equal(retry, manifest) {
		t.Fatalf("qualification boundary retry = %s, %v", retry, err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"unapproved": func(facts map[string]any) { facts["approval"].(map[string]any)["state"] = "rejected" },
		"refused prior evidence": func(facts map[string]any) {
			facts["draft_verification_decision"].(map[string]any)["outcome"] = "refused"
		},
		"missing native evidence": func(facts map[string]any) { facts["native_evidence"] = facts["native_evidence"].([]any)[:3] },
		"changed source state":    func(facts map[string]any) { facts["source_state"] = "rescue" },
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(boundaryFacts))
			mutate(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}
}

func TestQualificationCommandFinalizesCandidateFailures(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	later := candidateFacts("normal")
	later.LatestTag = stringPointer("v2.0.0")
	later.Releases = []observedRelease{qualifiedRelease(false)}
	later.Tags = []string{"v2.0.0"}
	boundaryDocument, manifest := qualificationBoundaryForCandidate(t, binary, later)
	boundary := jsonValue(t, boundaryDocument).(map[string]any)
	verificationFacts := boundary["draft_verification_facts"].(map[string]any)
	constructionFacts := verificationFacts["construction_facts"]
	constructionDecision := verificationFacts["construction_decision"]
	target := jsonObject(t, manifest)["releases"].([]any)[1].(map[string]any)
	observation := map[string]any{
		"assets": target["assets"], "body": "Qualification pending.", "commit": target["commit"], "created_release_id": target["release_id"], "draft": true, "immutable": false, "prerelease": false,
		"release_id": target["release_id"], "release_identity": target["release_identity"], "release_present": true, "sequence": target["sequence"], "tag": target["tag"], "tag_commit": target["commit"],
	}
	base := map[string]any{
		"burned_identities": []any{}, "candidate_failure_state": nil, "construction_decision": constructionDecision, "construction_facts": constructionFacts,
		"observations": []any{observation}, "observed_at": "2026-08-23T00:00:00Z", "qualification_boundary_facts": nil, "qualification_manifest": nil,
		"prior_decision_sha256": sha256String(qualificationDocument(t, constructionDecision)), "reason": "pre-boundary-failure", "schema": qualificationFactsSchema, "stage": "candidate-failure-finalization",
		"workflow": map[string]any{"commit": strings.Repeat("d", 40), "path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123"},
	}
	preBoundary, err := runQualificationCommand(binary, qualificationDocument(t, base))
	if err != nil {
		t.Fatalf("pre-boundary failure: %v\n%s", err, preBoundary)
	}
	preAction := jsonObject(t, preBoundary)["actions"].([]any)[0].(map[string]any)
	if preAction["type"] != "cleanup-draft" || preAction["release_id"] != target["release_id"] || preAction["tag"] != target["tag"] {
		t.Fatalf("pre-boundary decision = %s", preBoundary)
	}
	retriedCleanup := jsonObject(t, []byte(qualificationDocument(t, base)))
	retriedObservation := retriedCleanup["observations"].([]any)[0].(map[string]any)
	retriedObservation["assets"], retriedObservation["body"], retriedObservation["draft"], retriedObservation["release_present"], retriedObservation["tag_commit"] = []any{}, "", false, false, nil
	retried, err := runQualificationCommand(binary, qualificationDocument(t, retriedCleanup))
	if err != nil {
		t.Fatalf("completed cleanup retry: %v\n%s", err, retried)
	}
	retriedAction := jsonObject(t, retried)["actions"].([]any)[0].(map[string]any)
	if retriedAction["delete_release"] != false || retriedAction["delete_tag"] != false {
		t.Fatalf("completed cleanup retry = %s", retried)
	}
	cleanupVerification := qualificationDocument(t, map[string]any{
		"burned_identities": []any{}, "failure_decision": jsonValue(t, string(preBoundary)), "failure_facts": jsonValue(t, qualificationDocument(t, base)), "observations": []any{retriedObservation},
		"schema": qualificationFactsSchema, "stage": "candidate-failure-verification",
	})
	if verifiedCleanup, err := runQualificationCommand(binary, cleanupVerification); err != nil || jsonObject(t, verifiedCleanup)["outcome"] != "accepted" {
		t.Fatalf("cleanup verification = %s, %v", verifiedCleanup, err)
	}

	failureState := map[string]any{
		"evidence": []any{"https://github.com/albertloky/SBXR/actions/runs/123#artifacts"}, "recorded_at": "2026-08-23T00:00:00Z", "runner": "Ubuntu Server 24.04 linux/amd64",
		"schema": "sbxr-candidate-failure-state-v1", "software": map[string]any{"go_toolchain": "go1.26.6", "public_verifier": "1.3.0 " + strings.Repeat("A", 64)},
		"stages": map[string]any{"codex_live_acceptance": "Failed", "integrated_verification": "Passed"}, "workflow_run": "https://github.com/albertloky/SBXR/actions/runs/123",
	}
	base["candidate_failure_state"] = failureState
	base["qualification_boundary_facts"] = jsonValue(t, boundaryDocument)
	base["qualification_manifest"] = jsonValue(t, string(manifest))
	base["prior_decision_sha256"] = sha256String(string(manifest))
	base["reason"] = "post-sign-qualification-failure"
	postDocument := qualificationDocument(t, base)
	postBoundary, err := runQualificationCommand(binary, postDocument)
	if err != nil {
		t.Fatalf("post-boundary failure: %v\n%s", err, postBoundary)
	}
	post := jsonObject(t, postBoundary)
	postAction := post["actions"].([]any)[0].(map[string]any)
	if post["outcome"] != "failed-prerelease" || postAction["type"] != "finalize-failed-release" || postAction["burn_required"] != true || !strings.Contains(postAction["body"].(string), "Status: Failed prerelease\n") {
		t.Fatalf("post-boundary decision = %s", postBoundary)
	}
	exactRetry, err := runQualificationCommand(binary, postDocument)
	if err != nil || !bytes.Equal(exactRetry, postBoundary) {
		t.Fatalf("post-boundary exact retry = %s, %v", exactRetry, err)
	}
	burn := postAction["burn"].(map[string]any)
	if burn["original_tag"] != target["tag"] || burn["sequence"] != target["sequence"] || burn["commit"] != target["commit"] || burn["release_index_sha256"] != target["release_identity"].(map[string]any)["release_index_sha256"] || burn["qualification_run_url"] != failureState["workflow_run"] || burn["reason"] != base["reason"] || burn["recorded_at"] != base["observed_at"] {
		t.Fatalf("burn evidence = %v", burn)
	}
	verifiedObservation := jsonValue(t, qualificationDocument(t, observation)).(map[string]any)
	verifiedObservation["body"], verifiedObservation["draft"], verifiedObservation["immutable"], verifiedObservation["prerelease"] = postAction["body"], false, true, true
	verificationDocument := qualificationDocument(t, map[string]any{
		"burned_identities": []any{burn}, "failure_decision": jsonValue(t, string(postBoundary)), "failure_facts": jsonValue(t, postDocument), "observations": []any{verifiedObservation},
		"schema": qualificationFactsSchema, "stage": "candidate-failure-verification",
	})
	verified, err := runQualificationCommand(binary, verificationDocument)
	if err != nil || jsonObject(t, verified)["outcome"] != "accepted" || jsonObject(t, verified)["prior_decision_sha256"] != sha256String(string(postBoundary)) {
		t.Fatalf("candidate failure verification = %s, %v", verified, err)
	}
	changedResult := jsonObject(t, []byte(verificationDocument))
	changedResult["observations"].([]any)[0].(map[string]any)["body"] = "changed"
	assertQualificationRefused(t, binary, qualificationDocument(t, changedResult), "changed failed record result")

	base["burned_identities"] = []any{burn}
	retry, err := runQualificationCommand(binary, qualificationDocument(t, base))
	if err != nil || jsonObject(t, retry)["actions"].([]any)[0].(map[string]any)["burn_required"] != false {
		t.Fatalf("exact burn retry = %s, %v", retry, err)
	}
	conflict := jsonObject(t, []byte(qualificationDocument(t, base)))
	conflict["burned_identities"].([]any)[0].(map[string]any)["reason"] = "changed-reason"
	assertQualificationRefused(t, binary, qualificationDocument(t, conflict), "conflicting burn evidence")
	crossed := jsonObject(t, []byte(postDocument))
	crossed["observations"].([]any)[0].(map[string]any)["tag"] = "v2.0.9"
	assertQualificationRefused(t, binary, qualificationDocument(t, crossed), "crossed journey")
	stale := jsonObject(t, []byte(postDocument))
	stale["prior_decision_sha256"] = strings.Repeat("9", 64)
	assertQualificationRefused(t, binary, qualificationDocument(t, stale), "stale decision")

	initialBoundaryDocument, initialManifest := qualificationBoundaryForCandidate(t, binary, candidateFacts("normal"))
	initialBoundary := jsonValue(t, initialBoundaryDocument).(map[string]any)
	initialVerificationFacts := initialBoundary["draft_verification_facts"].(map[string]any)
	initialObservations := []any{}
	for _, value := range jsonObject(t, initialManifest)["releases"].([]any) {
		release := value.(map[string]any)
		initialObservations = append(initialObservations, map[string]any{
			"assets": release["assets"], "body": "Qualification pending.", "commit": release["commit"], "created_release_id": release["release_id"], "draft": true, "immutable": false, "prerelease": false,
			"release_id": release["release_id"], "release_identity": release["release_identity"], "release_present": true, "sequence": release["sequence"], "tag": release["tag"], "tag_commit": nil,
		})
	}
	initialFailure := map[string]any{
		"burned_identities": []any{}, "candidate_failure_state": failureState, "construction_decision": initialVerificationFacts["construction_decision"], "construction_facts": initialVerificationFacts["construction_facts"],
		"observations": initialObservations, "observed_at": "2026-08-23T00:00:00Z", "qualification_boundary_facts": jsonValue(t, initialBoundaryDocument), "qualification_manifest": jsonValue(t, string(initialManifest)),
		"prior_decision_sha256": sha256String(string(initialManifest)), "reason": "post-sign-qualification-failure", "schema": qualificationFactsSchema, "stage": "candidate-failure-finalization",
		"workflow": map[string]any{"commit": strings.Repeat("d", 40), "path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123"},
	}
	initialDecision, err := runQualificationCommand(binary, qualificationDocument(t, initialFailure))
	if err != nil {
		t.Fatalf("initial-normal failure: %v\n%s", err, initialDecision)
	}
	initialActions := jsonObject(t, initialDecision)["actions"].([]any)
	if len(initialActions) != 2 || !strings.Contains(initialActions[0].(map[string]any)["body"].(string), "Qualification role: Clean-installed source release\n") || !strings.Contains(initialActions[1].(map[string]any)["body"].(string), "Qualification role: Discovered, installed, recovered, final latest release\n") {
		t.Fatalf("initial-normal failed records = %s", initialDecision)
	}
}

func TestQualificationCommandFinalizesStableFailures(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}

	_, manifestDocument := qualificationBoundaryForCandidate(t, binary, candidateFacts("normal"))
	manifest := jsonObject(t, manifestDocument)
	observations := make([]any, 0, 2)
	for index, value := range manifest["releases"].([]any) {
		release := value.(map[string]any)
		observations = append(observations, map[string]any{
			"assets": release["assets"], "body": stableQualifiedRecordFixture(t, manifestDocument, index), "commit": release["commit"], "draft": true, "immutable": false, "prerelease": false, "publicly_verified": false,
			"release_id": release["release_id"], "release_identity": release["release_identity"], "release_present": true, "sequence": release["sequence"], "tag": release["tag"], "tag_commit": nil,
		})
	}
	facts := map[string]any{
		"burned_identities": []any{},
		"candidate_run":     map[string]any{"conclusion": "success", "created_at": "2026-08-22T00:00:00Z", "event": "workflow_dispatch", "head_sha": strings.Repeat("d", 40), "id": "123", "path": ".github/workflows/candidate.yml"},
		"finalization_run":  map[string]any{"created_at": "2026-08-23T00:00:00Z", "head_sha": strings.Repeat("d", 40), "id": "456", "path": ".github/workflows/stable.yml", "url": "https://github.com/albertloky/SBXR/actions/runs/456"},
		"manifest_attested": true, "observations": observations, "observed_at": "2026-08-23T00:00:00Z", "operation": "publish", "publication_stage": "prepublication-failure",
		"schema": qualificationFactsSchema, "signed_manifest": manifest, "stage": "stable-failure-finalization",
	}
	document := qualificationDocument(t, facts)
	decision, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("stable prepublication failure: %v\n%s", err, decision)
	}
	result := jsonObject(t, decision)
	if result["outcome"] != "failed-prerelease" || result["reason"] != "prepublication-failure" || len(result["actions"].([]any)) != 2 || result["facts_sha256"] != sha256String(document) {
		t.Fatalf("stable failure decision = %s", decision)
	}
	for _, value := range result["actions"].([]any) {
		action := value.(map[string]any)
		if action["type"] != "finalize-stable-failure" || action["burn_required"] != true || action["publish_failed_prerelease"] != true || action["delete_release"] != false || action["delete_tag"] != false || action["reason"] != "prepublication-failure" || action["observed_at"] != "2026-08-23T00:00:00Z" {
			t.Fatalf("stable failure action = %v", action)
		}
		burn := action["burn"].(map[string]any)
		if burn["qualification_run_url"] != "https://github.com/albertloky/SBXR/actions/runs/123" || burn["recorded_at"] != "2026-08-23T00:00:00Z" {
			t.Fatalf("stable failure burn = %v", burn)
		}
	}
	if retry, retryErr := runQualificationCommand(binary, document); retryErr != nil || !bytes.Equal(retry, decision) {
		t.Fatalf("stable failure exact retry = %s, %v", retry, retryErr)
	}
	rawMarker := jsonObject(t, []byte(document))
	rawMarker["publication_stage"] = "prepublication"
	if rawDecision, rawErr := runQualificationCommand(binary, qualificationDocument(t, rawMarker)); rawErr != nil || jsonObject(t, rawDecision)["outcome"] != "failed-prerelease" {
		t.Fatalf("raw prepublication marker = %s, %v", rawDecision, rawErr)
	}
	laterRetry := jsonObject(t, []byte(document))
	actions := result["actions"].([]any)
	laterRetry["burned_identities"] = []any{actions[0].(map[string]any)["burn"], actions[1].(map[string]any)["burn"]}
	laterRetry["observed_at"] = "2026-08-23T01:00:00Z"
	laterDecision, laterErr := runQualificationCommand(binary, qualificationDocument(t, laterRetry))
	if laterErr != nil {
		t.Fatalf("later exact burn retry: %v\n%s", laterErr, laterDecision)
	}
	for _, value := range jsonObject(t, laterDecision)["actions"].([]any) {
		action := value.(map[string]any)
		if action["burn_required"] != false || action["observed_at"] != "2026-08-23T01:00:00Z" || action["burn"].(map[string]any)["recorded_at"] != "2026-08-23T00:00:00Z" {
			t.Fatalf("later exact burn retry = %s", laterDecision)
		}
	}

	for name, change := range map[string]struct {
		operation, publicationStage, createdAt, outcome, reason string
		actions                                                 int
	}{
		"initial A public verification": {"publish", "initial-a-public-verification-failure", "2026-08-22T00:00:00Z", "withdraw", "initial-a-public-verification-failure", 2},
		"B publication or verification": {"publish", "b-publication-or-verification-failure", "2026-08-22T00:00:00Z", "withdraw", "b-publication-or-verification-failure", 1},
		"stable no-update":              {"publish", "stable-no-update-failure", "2026-08-22T00:00:00Z", "withdraw", "stable-no-update-failure", 1},
		"cancellation":                  {"publish", "prepublication-failure", "2026-08-22T00:00:00Z", "failed-prerelease", "prepublication-failure", 2},
		"owner abandonment":             {"abandon", "prepublication-failure", "2026-08-22T00:00:00Z", "withdraw", "owner-abandoned", 2},
		"90-day expiry":                 {"publish", "prepublication-failure", "2026-05-25T00:00:00Z", "withdraw", "qualification-expired", 2},
	} {
		t.Run(name, func(t *testing.T) {
			variant := jsonObject(t, []byte(document))
			variant["operation"], variant["publication_stage"] = change.operation, change.publicationStage
			variant["candidate_run"].(map[string]any)["created_at"] = change.createdAt
			output, runErr := runQualificationCommand(binary, qualificationDocument(t, variant))
			if runErr != nil {
				t.Fatalf("stable failure: %v\n%s", runErr, output)
			}
			got := jsonObject(t, output)
			if got["outcome"] != change.outcome || got["reason"] != change.reason || len(got["actions"].([]any)) != change.actions {
				t.Fatalf("stable failure decision = %s", output)
			}
		})
	}

	partial := jsonObject(t, []byte(document))
	partial["publication_stage"] = "b-publication-or-verification-failure"
	partial["observations"].([]any)[1].(map[string]any)["tag_commit"] = strings.Repeat("d", 40)
	partialDocument := qualificationDocument(t, partial)
	withdraw, err := runQualificationCommand(binary, partialDocument)
	if err != nil {
		t.Fatalf("withdraw decision: %v\n%s", err, withdraw)
	}
	withdrawAction := jsonObject(t, withdraw)["actions"].([]any)[0].(map[string]any)
	post := jsonValue(t, qualificationDocument(t, partial["observations"].([]any)[1])).(map[string]any)
	post["assets"], post["body"], post["draft"], post["immutable"], post["prerelease"], post["release_present"], post["tag_commit"] = []any{}, "", false, false, false, false, nil
	verificationDocument := qualificationDocument(t, map[string]any{
		"burned_identities": []any{withdrawAction["burn"]}, "failure_decision": jsonValue(t, string(withdraw)), "failure_facts": jsonValue(t, partialDocument), "observations": []any{post},
		"schema": qualificationFactsSchema, "stage": "stable-failure-verification",
	})
	verified, verifyErr := runQualificationCommand(binary, verificationDocument)
	if verifyErr != nil || jsonObject(t, verified)["outcome"] != "accepted" || jsonObject(t, verified)["prior_decision_sha256"] != sha256String(string(withdraw)) {
		t.Fatalf("stable failure verification = %s, %v", verified, verifyErr)
	}
	partial["burned_identities"] = []any{withdrawAction["burn"]}
	partialObservations := partial["observations"].([]any)
	partialTarget := partialObservations[1].(map[string]any)
	partialTarget["assets"], partialTarget["body"], partialTarget["draft"], partialTarget["immutable"], partialTarget["prerelease"], partialTarget["release_present"] = []any{}, "", false, false, false, false
	resubmitted, resubmitErr := runQualificationCommand(binary, qualificationDocument(t, partial))
	if resubmitErr != nil {
		t.Fatalf("partial withdrawal resubmission: %v\n%s", resubmitErr, resubmitted)
	}
	resubmittedAction := jsonObject(t, resubmitted)["actions"].([]any)[0].(map[string]any)
	if resubmittedAction["burn_required"] != false || resubmittedAction["delete_release"] != false || resubmittedAction["delete_tag"] != true {
		t.Fatalf("partial withdrawal resubmission = %s", resubmitted)
	}

	for hostileName, mutate := range map[string]func(map[string]any){
		"crossed Release Identity": func(value map[string]any) {
			value["observations"].([]any)[1].(map[string]any)["release_id"] = float64(999)
		},
		"unattested manifest":     func(value map[string]any) { value["manifest_attested"] = false },
		"unknown failure stage":   func(value map[string]any) { value["publication_stage"] = "unknown" },
		"completed qualification": func(value map[string]any) { value["publication_stage"] = "complete" },
		"changed finalization run": func(value map[string]any) {
			value["finalization_run"].(map[string]any)["url"] = "https://github.com/albertloky/SBXR/actions/runs/999"
		},
	} {
		hostile := jsonObject(t, []byte(document))
		mutate(hostile)
		assertQualificationRefused(t, binary, qualificationDocument(t, hostile), hostileName)
	}

	preserved := jsonObject(t, []byte(document))
	preserved["operation"] = "abandon"
	preservedA := preserved["observations"].([]any)[0].(map[string]any)
	preservedA["draft"], preservedA["immutable"], preservedA["publicly_verified"], preservedA["tag_commit"] = false, true, true, strings.Repeat("d", 40)
	preservedDecision, preservedErr := runQualificationCommand(binary, qualificationDocument(t, preserved))
	if preservedErr != nil || len(jsonObject(t, preservedDecision)["actions"].([]any)) != 1 || jsonObject(t, preservedDecision)["actions"].([]any)[0].(map[string]any)["tag"] != "v2.0.1" {
		t.Fatalf("proven stable A was not preserved = %s, %v", preservedDecision, preservedErr)
	}
	uncertain := jsonObject(t, []byte(qualificationDocument(t, preserved)))
	uncertain["observations"].([]any)[0].(map[string]any)["publicly_verified"] = false
	assertQualificationRefused(t, binary, qualificationDocument(t, uncertain), "uncertain stable A withdrawal")
}

func stableQualifiedRecordFixture(t *testing.T, manifestDocument []byte, releaseIndex int) string {
	t.Helper()
	var manifest qualificationManifest
	if !decodeCanonical(manifestDocument, &manifest) {
		t.Fatal("decode qualification manifest fixture")
	}
	release := manifest.Releases[releaseIndex]
	record := acceptanceRecordJSON{
		AcceptedAt: "2026-08-22T00:00:00Z", Assets: release.Assets, Evidence: []string{manifest.Workflow.RunURL + "#artifacts"}, QualificationRole: "Clean-installed source release",
		ReleaseIdentity: release.ReleaseIdentity, Runner: "Ubuntu Server 24.04 linux/amd64", Schema: "sbxr-acceptance-record-v1", SecretSafeResult: "Passed", Sequence: release.Sequence,
		Software: acceptanceRecordSoftware{GoToolchain: "go1.26.6", PublicVerifier: "1.3.0 " + strings.Repeat("A", 64)}, StableResultCode: "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION",
		Stages: acceptanceRecordStages{CodexLiveAcceptance: "Passed", IntegratedVerification: "Passed", ModuleVerification: "Passed", OwnerAcceptance: "Not required", SeamVerification: "Passed"}, WorkflowRun: manifest.Workflow.RunURL,
	}
	canonical, err := marshalCanonical(record)
	if err != nil {
		t.Fatal(err)
	}
	return "# SBXR Installer-Updater Acceptance Record\nStatus: Qualified\n```json\n" + string(canonical) + "\n```\n"
}

func TestQualificationCommandEvaluatesAcceptanceVPSAndConstructsRecords(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sbxr-release: %v\n%s", err, output)
	}
	later := candidateFacts("normal")
	later.LatestTag = stringPointer("v2.0.0")
	later.Releases = []observedRelease{qualifiedRelease(false)}
	later.Tags = []string{"v2.0.0"}
	boundaryFacts, manifest := qualificationBoundaryForCandidate(t, binary, later)
	facts := map[string]any{
		"evaluation_time":         "2026-08-23T13:00:00Z",
		"github_routing_restored": true,
		"journey": map[string]any{
			"a":                  map[string]any{"release_identity": map[string]any{"commit": strings.Repeat("e", 40), "release_index_sha256": strings.Repeat("2", 64), "repository": "albertloky/SBXR", "tag": "v2.0.0"}, "sequence": 17},
			"activated_rollback": true, "b": map[string]any{"release_identity": map[string]any{"commit": strings.Repeat("d", 40), "release_index_sha256": strings.Repeat("2", 64), "repository": "albertloky/SBXR", "tag": "v2.0.1"}, "sequence": 18}, "check_invalidation": true, "clean_install": true, "committed_forward_recovery": true,
			"concurrency_refusal": true, "lower_sequence_replacement": "Not required - normal authority", "menu_check": true, "mode": "normal",
			"observed_at": "2026-08-23T13:00:00Z", "prepared_rollback": true, "production_update": true, "qualification_manifest_sha256": sha256String(string(manifest)), "schema": "sbxr-acceptance-vps-evidence-v1", "secret_safe": true, "ssh_continuity": true,
		},
		"observed_at":                     "2026-08-23T13:00:00Z",
		"prior_decision_sha256":           sha256String(string(manifest)),
		"qualification_manifest_attested": true,
		"qualification_boundary_facts":    jsonValue(t, boundaryFacts),
		"qualification_manifest":          jsonValue(t, string(manifest)),
		"releases":                        jsonObject(t, manifest)["releases"],
		"runner": map[string]any{
			"architecture": "amd64", "go_toolchain": "go1.26.6", "operating_system": "Ubuntu Server 24.04", "public_verifier": "1.3.0 26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485",
		},
		"schema": qualificationFactsSchema,
		"stage":  "acceptance-vps-result",
	}
	document := qualificationDocument(t, facts)
	decision, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("acceptance VPS result: %v\n%s", err, decision)
	}
	result := jsonObject(t, decision)
	if result["schema"] != qualificationDecisionSchema || result["stage"] != "acceptance-vps-result" || result["outcome"] != "accepted" || result["facts_sha256"] != sha256String(document) || result["prior_decision_sha256"] != sha256String(string(manifest)) {
		t.Fatalf("acceptance decision binding = %s", decision)
	}
	records := result["records"].([]any)
	if len(records) != 2 {
		t.Fatalf("record count = %d", len(records))
	}
	for index, expected := range []struct{ tag, role, sha256 string }{
		{"v2.0.0", "Clean-installed source release", "731e7ba41b933bed30a60f5b0f318eababc210e407427ccbd885b9a48949387f"},
		{"v2.0.1", "Discovered, installed, recovered, final latest release", "7aff098fda09c2ea4693b6187d45f5d6e2a791837d343423b4c56e3b4b019504"},
	} {
		record := records[index].(map[string]any)
		if record["tag"] != expected.tag {
			t.Fatalf("record %d tag = %v", index, record["tag"])
		}
		body := record["body"].(string)
		if sha256String(body) != expected.sha256 {
			t.Fatalf("record %s SHA-256 = %s", expected.tag, sha256String(body))
		}
		for _, required := range []string{"# SBXR Installer-Updater Acceptance Record\n", "Status: Qualified\n", "Tag: " + expected.tag + "\n", "Acceptance time: 2026-08-23T13:00:00Z\n", "Qualification role: " + expected.role + "\n", "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n", "Owner Acceptance: Not required\n", "```json\n{", "\n```\n"} {
			if !strings.Contains(body, required) {
				t.Fatalf("record %s omitted %q\n%s", expected.tag, required, body)
			}
		}
	}
	retry, err := runQualificationCommand(binary, document)
	if err != nil || !bytes.Equal(retry, decision) {
		t.Fatalf("acceptance retry = %s, %v", retry, err)
	}

	manifestObject := jsonObject(t, manifest)
	manifestReleases := manifestObject["releases"].([]any)
	recordsByTag := map[string]string{}
	for _, value := range records {
		record := value.(map[string]any)
		recordsByTag[record["tag"].(string)] = record["body"].(string)
	}
	stableReleases := make([]any, len(manifestReleases))
	for index, value := range manifestReleases {
		release := value.(map[string]any)
		tag := release["tag"].(string)
		body := recordsByTag[tag]
		draft, immutable := true, false
		if index == 0 {
			body, draft, immutable = later.Releases[0].Body, false, true
		}
		stableReleases[index] = map[string]any{
			"assets": release["assets"], "body": body, "commit": release["commit"], "draft": draft, "immutable": immutable, "prerelease": false,
			"release_id": release["release_id"], "release_identity": release["release_identity"], "sequence": release["sequence"], "tag": tag,
		}
	}
	stableFacts := map[string]any{
		"acceptance_decision": jsonValue(t, string(decision)), "acceptance_facts": jsonValue(t, document),
		"archive":           map[string]any{"commit": later.ArchiveCommit, "remote_commit": later.ArchiveRemoteCommit, "remote_tag_object": later.ArchiveRemoteTagObject, "tag_object": later.ArchiveTagObject, "type": later.ArchiveType},
		"burned_identities": []any{},
		"candidate_run":     map[string]any{"conclusion": "success", "created_at": "2026-08-23T12:00:00Z", "event": "workflow_dispatch", "head_sha": strings.Repeat("d", 40), "id": "123", "path": ".github/workflows/candidate.yml"},
		"checklist_sha256":  later.ChecklistSHA256, "latest_tag": "v2.0.0", "manifest_attested": true, "observed_at": "2026-08-23T13:00:00Z", "releases": stableReleases,
		"remote_main": strings.Repeat("d", 40), "schema": qualificationFactsSchema, "signed_manifest": jsonValue(t, string(manifest)), "stage": "stable-preflight",
	}
	stableDocument := qualificationDocument(t, stableFacts)
	stableDecision, err := runQualificationCommand(binary, stableDocument)
	if err != nil {
		t.Fatalf("stable preflight: %v\n%s", err, stableDecision)
	}
	stable := jsonObject(t, stableDecision)
	stableActions := stable["actions"].([]any)
	if stable["outcome"] != "actions-required" || stable["facts_sha256"] != sha256String(stableDocument) || stable["prior_decision_sha256"] != sha256String(string(decision)) || len(stableActions) != 1 || stableActions[0].(map[string]any)["tag"] != "v2.0.1" || stableActions[0].(map[string]any)["body"] != recordsByTag["v2.0.1"] {
		t.Fatalf("stable preflight decision = %s", stableDecision)
	}
	for name, mutate := range map[string]func(map[string]any){
		"90 day qualification": func(value map[string]any) { value["observed_at"] = "2026-11-21T12:00:00Z" },
		"changed draft bytes": func(value map[string]any) {
			value["releases"].([]any)[1].(map[string]any)["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
		},
		"changed acceptance record": func(value map[string]any) {
			value["releases"].([]any)[1].(map[string]any)["body"] = "changed"
		},
		"stale acceptance decision": func(value map[string]any) {
			value["acceptance_decision"].(map[string]any)["facts_sha256"] = strings.Repeat("9", 64)
		},
		"incomplete decision chain": func(value map[string]any) {
			manifest := value["acceptance_facts"].(map[string]any)["qualification_manifest"].(map[string]any)
			manifest["decision_chain"] = manifest["decision_chain"].([]any)[:2]
		},
		"mismatched candidate identity": func(value map[string]any) {
			value["candidate_run"].(map[string]any)["head_sha"] = strings.Repeat("9", 40)
		},
		"changed archive authority": func(value map[string]any) {
			value["archive"].(map[string]any)["remote_commit"] = strings.Repeat("9", 40)
		},
		"different signed manifest": func(value map[string]any) {
			value["signed_manifest"].(map[string]any)["candidate_failure_state_sha256"] = strings.Repeat("8", 64)
		},
		"contradictory source state": func(value map[string]any) { value["latest_tag"] = "v2.0.9" },
		"unsigned manifest":          func(value map[string]any) { value["manifest_attested"] = false },
	} {
		t.Run("stable "+name, func(t *testing.T) {
			hostile := jsonObject(t, []byte(stableDocument))
			mutate(hostile)
			assertQualificationRefused(t, binary, qualificationDocument(t, hostile), name)
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"stale prior decision":   func(value map[string]any) { value["prior_decision_sha256"] = strings.Repeat("9", 64) },
		"stale observation":      func(value map[string]any) { value["observed_at"] = "2026-08-23T12:54:59Z" },
		"future observation":     func(value map[string]any) { value["observed_at"] = "2026-08-23T13:00:01Z" },
		"partial journey":        func(value map[string]any) { delete(value["journey"].(map[string]any), "production_update") },
		"mixed release identity": func(value map[string]any) { value["releases"].([]any)[1].(map[string]any)["tag"] = "v2.0.9" },
		"crossed journey": func(value map[string]any) {
			value["journey"].(map[string]any)["a"].(map[string]any)["sequence"] = float64(16)
		},
		"routing not restored":    func(value map[string]any) { value["github_routing_restored"] = false },
		"unsigned manifest":       func(value map[string]any) { value["qualification_manifest_attested"] = false },
		"secret-bearing evidence": func(value map[string]any) { value["journey"].(map[string]any)["authorization"] = "Bearer secret" },
	} {
		t.Run(name, func(t *testing.T) {
			hostile := jsonObject(t, []byte(document))
			mutate(hostile)
			assertQualificationRefused(t, binary, qualificationDocument(t, hostile), name)
		})
	}

	rescue := candidateFacts("rescue")
	rescue.Candidate.DefectIssueURL = stringPointer("https://github.com/albertloky/SBXR/issues/99")
	rescue.Candidate.FailedNormalRunID = stringPointer("123")
	rescue.DefectIssue = &defectIssue{State: "open", URL: *rescue.Candidate.DefectIssueURL}
	rescue.FailedNormalRun = &failedNormalRun{Conclusion: "failure", ID: "123", Mode: "normal", Path: ".github/workflows/candidate.yml"}
	rescue.Releases = []observedRelease{qualifiedRelease(true)}
	rescue.Tags = []string{"v2.0.0"}
	rescue.BurnedIdentities = []burnedIdentity{{Commit: strings.Repeat("e", 40), OriginalTag: "v2.0.0", QualificationRunURL: failedRunURL("123"), Reason: "post-sign-qualification-failure", RecordedAt: "2026-08-23T00:00:00Z", ReleaseIndexSHA256: strings.Repeat("2", 64), Sequence: 17}}
	rescueBoundaryFacts, rescueManifest := qualificationBoundaryForCandidate(t, binary, rescue)
	rescueFacts := jsonObject(t, []byte(document))
	rescueFacts["prior_decision_sha256"] = sha256String(string(rescueManifest))
	rescueFacts["qualification_boundary_facts"] = jsonValue(t, rescueBoundaryFacts)
	rescueFacts["qualification_manifest"] = jsonValue(t, string(rescueManifest))
	rescueFacts["releases"] = jsonObject(t, rescueManifest)["releases"]
	rescueJourney := rescueFacts["journey"].(map[string]any)
	rescueJourney["a"] = jsonObject(t, rescueManifest)["releases"].([]any)[0].(map[string]any)
	delete(rescueJourney["a"].(map[string]any), "assets")
	delete(rescueJourney["a"].(map[string]any), "commit")
	delete(rescueJourney["a"].(map[string]any), "release_id")
	delete(rescueJourney["a"].(map[string]any), "tag")
	rescueJourney["b"] = jsonObject(t, rescueManifest)["releases"].([]any)[1].(map[string]any)
	delete(rescueJourney["b"].(map[string]any), "assets")
	delete(rescueJourney["b"].(map[string]any), "commit")
	delete(rescueJourney["b"].(map[string]any), "release_id")
	delete(rescueJourney["b"].(map[string]any), "tag")
	rescueJourney["qualification_manifest_sha256"] = sha256String(string(rescueManifest))
	for _, field := range []string{"activated_rollback", "committed_forward_recovery", "menu_check", "prepared_rollback", "production_update"} {
		rescueJourney[field] = "Not required - rescue authority"
	}
	for _, field := range []string{"check_invalidation", "concurrency_refusal"} {
		rescueJourney[field] = "Proved by native automated qualification"
	}
	rescueJourney["lower_sequence_replacement"] = true
	rescueJourney["mode"] = "rescue"
	rescueDecision, err := runQualificationCommand(binary, qualificationDocument(t, rescueFacts))
	if err != nil {
		t.Fatalf("rescue acceptance decision = %s, %v", rescueDecision, err)
	}
	rescueRecords := jsonObject(t, rescueDecision)["records"].([]any)
	for _, value := range rescueRecords {
		body := value.(map[string]any)["body"].(string)
		if !strings.Contains(body, "Stable result code: RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION\n") || !strings.Contains(body, "Qualification role: Rescue direct-install and lower-sequence replacement release\n") || !strings.Contains(body, "Rescue defect evidence: https://github.com/albertloky/SBXR/issues/99\n") {
			t.Fatalf("rescue Acceptance Record = %s", body)
		}
	}
	if len(rescueRecords) != 2 {
		t.Fatalf("rescue acceptance decision = %s, %v", rescueDecision, err)
	}

	stableCase := func(name string, preflightFacts qualificationFacts, acceptanceFacts map[string]any, acceptanceDecision, caseManifest []byte, sourceBody string, wantActions int) {
		t.Helper()
		caseReleases := jsonObject(t, caseManifest)["releases"].([]any)
		caseRecords := map[string]string{}
		for _, value := range jsonObject(t, acceptanceDecision)["records"].([]any) {
			record := value.(map[string]any)
			caseRecords[record["tag"].(string)] = record["body"].(string)
		}
		observations := make([]any, 2)
		for index, value := range caseReleases {
			release := value.(map[string]any)
			tag := release["tag"].(string)
			body, draft, immutable, prerelease := caseRecords[tag], true, false, false
			if index == 0 && preflightFacts.Candidate.Mode == "rescue" {
				body, draft, immutable, prerelease = sourceBody, false, true, true
			}
			observations[index] = map[string]any{"assets": release["assets"], "body": body, "commit": release["commit"], "draft": draft, "immutable": immutable, "prerelease": prerelease, "release_id": release["release_id"], "release_identity": release["release_identity"], "sequence": release["sequence"], "tag": tag}
		}
		facts := map[string]any{
			"acceptance_decision": jsonValue(t, string(acceptanceDecision)), "acceptance_facts": acceptanceFacts,
			"archive":           map[string]any{"commit": preflightFacts.ArchiveCommit, "remote_commit": preflightFacts.ArchiveRemoteCommit, "remote_tag_object": preflightFacts.ArchiveRemoteTagObject, "tag_object": preflightFacts.ArchiveTagObject, "type": preflightFacts.ArchiveType},
			"burned_identities": jsonValue(t, qualificationDocument(t, preflightFacts.BurnedIdentities)),
			"candidate_run":     map[string]any{"conclusion": "success", "created_at": "2026-08-23T12:00:00Z", "event": "workflow_dispatch", "head_sha": strings.Repeat("d", 40), "id": "123", "path": ".github/workflows/candidate.yml"},
			"checklist_sha256":  preflightFacts.ChecklistSHA256, "latest_tag": preflightFacts.LatestTag, "manifest_attested": true, "observed_at": "2026-08-23T13:00:00Z", "releases": observations,
			"remote_main": strings.Repeat("d", 40), "schema": qualificationFactsSchema, "signed_manifest": jsonValue(t, string(caseManifest)), "stage": "stable-preflight",
		}
		result, err := runQualificationCommand(binary, qualificationDocument(t, facts))
		if err != nil || len(jsonObject(t, result)["actions"].([]any)) != wantActions {
			t.Fatalf("%s stable preflight = %s, %v", name, result, err)
		}
		var priorVerificationFacts, priorVerificationDecision any
		for actionIndex, actionValue := range jsonObject(t, result)["actions"].([]any) {
			action := actionValue.(map[string]any)
			assets := action["assets"].([]any)
			observedAssets, downloads := make([]any, len(assets)), make([]any, len(assets))
			for assetIndex, assetValue := range assets {
				asset := assetValue.(map[string]any)
				id := float64(1000 + actionIndex*10 + assetIndex)
				observedAssets[assetIndex] = map[string]any{"id": id, "name": asset["name"], "sha256": asset["sha256"], "size": asset["size"]}
				downloads[assetIndex] = map[string]any{"name": asset["name"], "sha256": asset["sha256"], "size": asset["size"]}
			}
			var latestReleaseID any
			if actionIndex > 0 {
				latestReleaseID = priorVerificationFacts.(map[string]any)["observation"].(map[string]any)["release_id"]
			} else if preflightFacts.LatestTag != nil {
				latestReleaseID = preflightFacts.Releases[0].ID
			}
			observation := map[string]any{
				"assets": observedAssets, "attestation": nil, "body": action["body"], "commit": action["commit"], "downloads": downloads, "draft": true, "immutable": false,
				"latest_install_sha256": "", "latest_release_id": latestReleaseID, "prerelease": false, "public_verification": nil, "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"],
			}
			priorDecisionSHA256 := sha256String(string(result))
			if priorVerificationDecision != nil {
				priorDecisionSHA256 = sha256String(qualificationDocument(t, priorVerificationDecision))
			}
			publicationFacts := map[string]any{
				"action_index": actionIndex, "approval": map[string]any{"environments": []any{map[string]any{"name": "stable-publication"}}, "state": "approved"}, "observation": observation,
				"observed_at": "2026-08-23T13:0" + strconv.Itoa(actionIndex+1) + ":00Z", "preflight_decision": jsonValue(t, string(result)), "preflight_facts": facts,
				"prior_decision_sha256": priorDecisionSHA256, "prior_verification_decision": priorVerificationDecision, "prior_verification_facts": priorVerificationFacts,
				"schema": qualificationFactsSchema, "stage": "stable-publication",
			}
			publicationDocument := qualificationDocument(t, publicationFacts)
			publicationDecision, err := runQualificationCommand(binary, publicationDocument)
			if err != nil {
				t.Fatalf("%s publication %d: %v\n%s", name, actionIndex, err, publicationDecision)
			}
			publication := jsonObject(t, publicationDecision)
			publicationActions := publication["actions"].([]any)
			if publication["outcome"] != "actions-required" || publication["facts_sha256"] != sha256String(publicationDocument) || publication["prior_decision_sha256"] != priorDecisionSHA256 || len(publicationActions) != 1 {
				t.Fatalf("%s publication decision = %s", name, publicationDecision)
			}
			publish := publicationActions[0].(map[string]any)
			if publish["tag"] != action["tag"] || publish["release_id"] != action["release_id"] || publish["commit"] != action["commit"] || publish["release_identity"] == nil || publish["prerelease"] != false || publish["latest"] != true {
				t.Fatalf("%s publication action = %s", name, publicationDecision)
			}

			pendingFacts := map[string]any{
				"attempt": 1, "observation": nil, "observed_at": "2026-08-23T13:0" + strconv.Itoa(actionIndex+1) + ":05Z", "prior_decision_sha256": sha256String(string(publicationDecision)),
				"publication_decision": jsonValue(t, string(publicationDecision)), "publication_facts": publicationFacts, "schema": qualificationFactsSchema, "stage": "stable-publication-verification",
			}
			pendingDecision, err := runQualificationCommand(binary, qualificationDocument(t, pendingFacts))
			if err != nil || jsonObject(t, pendingDecision)["outcome"] != "propagation-pending" || len(jsonObject(t, pendingDecision)["actions"].([]any)) != 1 {
				t.Fatalf("%s pending propagation = %s, %v", name, pendingDecision, err)
			}
			exhaustedFacts := jsonObject(t, []byte(qualificationDocument(t, pendingFacts)))
			exhaustedFacts["attempt"] = float64(60)
			exhaustedDecision, exhaustedErr := runQualificationCommand(binary, qualificationDocument(t, exhaustedFacts))
			if exhaustedErr != nil || jsonObject(t, exhaustedDecision)["outcome"] != "propagation-exhausted" || len(jsonObject(t, exhaustedDecision)["actions"].([]any)) != 0 {
				t.Fatalf("%s exhausted propagation = %s, %v", name, exhaustedDecision, exhaustedErr)
			}

			publicObservation := map[string]any{
				"assets": observedAssets, "attestation": map[string]any{"commit": action["commit"], "count": 1, "initiator": "github", "predicate_type": "release"}, "body": action["body"], "commit": action["commit"], "downloads": downloads,
				"draft": false, "immutable": true, "latest_install_sha256": assets[0].(map[string]any)["sha256"], "latest_release_id": action["release_id"], "prerelease": false,
				"public_verification": map[string]any{"outcome": "accepted", "release_identity": action["release_identity"], "sequence": action["sequence"]}, "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"],
			}
			verificationFacts := map[string]any{
				"attempt": 2, "observation": publicObservation, "observed_at": "2026-08-23T13:0" + strconv.Itoa(actionIndex+1) + ":10Z", "prior_decision_sha256": sha256String(string(publicationDecision)),
				"publication_decision": jsonValue(t, string(publicationDecision)), "publication_facts": publicationFacts, "schema": qualificationFactsSchema, "stage": "stable-publication-verification",
			}
			verificationDocument := qualificationDocument(t, verificationFacts)
			visiblePropagation := jsonObject(t, []byte(verificationDocument))
			visibleObservation := visiblePropagation["observation"].(map[string]any)
			visibleObservation["attestation"] = nil
			visibleObservation["immutable"] = false
			visibleObservation["latest_install_sha256"] = ""
			visibleDecision, visibleErr := runQualificationCommand(binary, qualificationDocument(t, visiblePropagation))
			if visibleErr != nil || jsonObject(t, visibleDecision)["outcome"] != "propagation-pending" {
				t.Fatalf("%s visible propagation = %s, %v", name, visibleDecision, visibleErr)
			}
			mixedPropagation := jsonObject(t, []byte(verificationDocument))
			mixedObservation := mixedPropagation["observation"].(map[string]any)
			mixedObservation["immutable"] = false
			mixedObservation["latest_install_sha256"] = ""
			mixedDecision, mixedErr := runQualificationCommand(binary, qualificationDocument(t, mixedPropagation))
			if mixedErr != nil || jsonObject(t, mixedDecision)["outcome"] != "propagation-pending" {
				t.Fatalf("%s mixed propagation = %s, %v", name, mixedDecision, mixedErr)
			}
			verificationDecision, err := runQualificationCommand(binary, verificationDocument)
			if err != nil || jsonObject(t, verificationDecision)["outcome"] != "accepted" || len(jsonObject(t, verificationDecision)["actions"].([]any)) != 0 {
				t.Fatalf("%s public verification = %s, %v", name, verificationDecision, err)
			}
			if retry, retryErr := runQualificationCommand(binary, verificationDocument); retryErr != nil || !bytes.Equal(retry, verificationDecision) {
				t.Fatalf("%s public verification retry = %s, %v", name, retry, retryErr)
			}
			finalAttempt := jsonObject(t, []byte(verificationDocument))
			finalAttempt["attempt"] = float64(60)
			finalAttemptDecision, finalAttemptErr := runQualificationCommand(binary, qualificationDocument(t, finalAttempt))
			if finalAttemptErr != nil || jsonObject(t, finalAttemptDecision)["outcome"] != "accepted" {
				t.Fatalf("%s final-attempt verification = %s, %v", name, finalAttemptDecision, finalAttemptErr)
			}
			deadline := jsonObject(t, []byte(verificationDocument))
			deadline["observed_at"] = "2026-08-23T13:0" + strconv.Itoa(actionIndex+6) + ":00Z"
			deadlineDecision, deadlineErr := runQualificationCommand(binary, qualificationDocument(t, deadline))
			if deadlineErr != nil || jsonObject(t, deadlineDecision)["outcome"] != "accepted" {
				t.Fatalf("%s deadline verification = %s, %v", name, deadlineDecision, deadlineErr)
			}
			for hostileName, mutate := range map[string]func(map[string]any){
				"wrong Latest selection": func(value map[string]any) { value["observation"].(map[string]any)["latest_release_id"] = float64(999) },
				"changed downloaded bytes": func(value map[string]any) {
					value["observation"].(map[string]any)["downloads"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
				},
				"changed Acceptance Record": func(value map[string]any) { value["observation"].(map[string]any)["body"] = "changed" },
				"wrong attestation": func(value map[string]any) {
					value["observation"].(map[string]any)["attestation"].(map[string]any)["initiator"] = "other"
				},
				"public verifier refusal": func(value map[string]any) {
					value["observation"].(map[string]any)["public_verification"] = map[string]any{"outcome": "refused", "release_identity": nil, "sequence": nil}
				},
				"stale publication decision": func(value map[string]any) { value["prior_decision_sha256"] = strings.Repeat("9", 64) },
			} {
				hostile := jsonObject(t, []byte(verificationDocument))
				mutate(hostile)
				assertQualificationRefused(t, binary, qualificationDocument(t, hostile), hostileName)
			}
			priorVerificationFacts, priorVerificationDecision = verificationFacts, jsonValue(t, string(verificationDecision))
		}
		finalObservation := priorVerificationFacts.(map[string]any)["observation"].(map[string]any)
		identity := finalObservation["release_identity"].(map[string]any)
		noUpdateFacts := map[string]any{
			"observation": map[string]any{
				"after_check_snapshot_sha256": strings.Repeat("8", 64), "after_install_snapshot_sha256": strings.Repeat("8", 64), "after_update_snapshot_sha256": strings.Repeat("8", 64), "before_snapshot_sha256": strings.Repeat("8", 64),
				"check_result": "SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT", "install_result": "SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT",
				"executable_sha256": strings.Repeat("7", 64), "filesystem_layout_exact": true, "snapshots_complete": true,
				"installed_record":        map[string]any{"architecture": "amd64", "commit": identity["commit"], "executable_sha256": strings.Repeat("7", 64), "release_index_sha256": identity["release_index_sha256"], "repository": identity["repository"], "schema": 1, "sequence": finalObservation["sequence"], "tag": identity["tag"]},
				"mutation_lock_available": true, "ssh_continuity": true, "transaction_residue_absent": true, "update_result": "SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT",
			},
			"observed_at": "2026-08-23T13:04:00Z", "prior_decision_sha256": sha256String(qualificationDocument(t, priorVerificationDecision)),
			"publication_verification_decision": priorVerificationDecision, "publication_verification_facts": priorVerificationFacts, "schema": qualificationFactsSchema, "stage": "stable-no-update",
		}
		noUpdateDocument := qualificationDocument(t, noUpdateFacts)
		noUpdateDecision, noUpdateErr := runQualificationCommand(binary, noUpdateDocument)
		if noUpdateErr != nil {
			t.Fatalf("%s stable no-update decision = %s, %v", name, noUpdateDecision, noUpdateErr)
		}
		decision := jsonObject(t, noUpdateDecision)
		if decision["outcome"] != "accepted" || decision["public_verification"] != "Passed" || decision["stable_no_update"] != "Passed" || decision["facts_sha256"] != sha256String(noUpdateDocument) || decision["prior_decision_sha256"] != noUpdateFacts["prior_decision_sha256"] || len(decision["actions"].([]any)) != 0 || decision["release_identity"] == nil || decision["sequence"] != finalObservation["sequence"] {
			t.Fatalf("%s stable no-update decision = %s", name, noUpdateDecision)
		}
		if retry, retryErr := runQualificationCommand(binary, noUpdateDocument); retryErr != nil || !bytes.Equal(retry, noUpdateDecision) {
			t.Fatalf("%s stable no-update retry = %s, %v", name, retry, retryErr)
		}
		for hostileName, mutate := range map[string]func(map[string]any){
			"incomplete observation": func(value map[string]any) { delete(value["observation"].(map[string]any), "update_result") },
			"changed filesystem": func(value map[string]any) {
				value["observation"].(map[string]any)["after_check_snapshot_sha256"] = strings.Repeat("9", 64)
			},
			"stale observation": func(value map[string]any) { value["observed_at"] = "2026-08-23T14:00:00Z" },
			"mixed Release Identity": func(value map[string]any) {
				value["observation"].(map[string]any)["installed_record"].(map[string]any)["tag"] = "v9.9.9"
			},
			"changed installed bytes": func(value map[string]any) {
				value["observation"].(map[string]any)["executable_sha256"] = strings.Repeat("9", 64)
			},
			"contradictory result": func(value map[string]any) {
				value["observation"].(map[string]any)["install_result"] = "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED"
			},
			"transaction residue": func(value map[string]any) {
				value["observation"].(map[string]any)["transaction_residue_absent"] = false
			},
			"incomplete snapshots": func(value map[string]any) { value["observation"].(map[string]any)["snapshots_complete"] = false },
			"wrong prior decision": func(value map[string]any) { value["prior_decision_sha256"] = strings.Repeat("9", 64) },
		} {
			hostile := jsonObject(t, []byte(noUpdateDocument))
			mutate(hostile)
			assertQualificationRefused(t, binary, qualificationDocument(t, hostile), hostileName)
		}
	}

	initialPreflight := candidateFacts("normal")
	initialBoundaryFacts, initialManifest := qualificationBoundaryForCandidate(t, binary, initialPreflight)
	initialAcceptanceFacts := jsonObject(t, []byte(document))
	initialAcceptanceFacts["prior_decision_sha256"] = sha256String(string(initialManifest))
	initialAcceptanceFacts["qualification_boundary_facts"] = jsonValue(t, initialBoundaryFacts)
	initialAcceptanceFacts["qualification_manifest"] = jsonValue(t, string(initialManifest))
	initialAcceptanceFacts["releases"] = jsonObject(t, initialManifest)["releases"]
	initialJourney := initialAcceptanceFacts["journey"].(map[string]any)
	for index, name := range []string{"a", "b"} {
		release := jsonObject(t, initialManifest)["releases"].([]any)[index].(map[string]any)
		initialJourney[name] = map[string]any{"release_identity": release["release_identity"], "sequence": release["sequence"]}
	}
	initialJourney["qualification_manifest_sha256"] = sha256String(string(initialManifest))
	initialDecision, err := runQualificationCommand(binary, qualificationDocument(t, initialAcceptanceFacts))
	if err != nil {
		t.Fatalf("initial acceptance decision = %s, %v", initialDecision, err)
	}
	stableCase("initial-normal", initialPreflight, initialAcceptanceFacts, initialDecision, initialManifest, "", 2)
	stableCase("rescue", rescue, rescueFacts, rescueDecision, rescueManifest, rescue.Releases[0].Body, 1)
}

func draftTarget(tag string, sequence uint64) map[string]any {
	return map[string]any{
		"assets": draftAssets(0), "commit": strings.Repeat("a", 40),
		"release_identity": map[string]any{"commit": strings.Repeat("a", 40), "release_index_sha256": strings.Repeat("2", 64), "repository": "albertloky/SBXR", "tag": tag},
		"sequence":         sequence, "tag": tag,
	}
}

func draftObservation(tag string, sequence uint64, releaseID int64) map[string]any {
	return map[string]any{
		"assets": draftAssets(releaseID * 10), "commit": strings.Repeat("a", 40), "created_release_id": releaseID, "downloads": draftDownloads(releaseID * 10), "draft": true, "immutable": false,
		"prerelease": false, "release_id": releaseID,
		"release_identity": map[string]any{"commit": strings.Repeat("a", 40), "release_index_sha256": strings.Repeat("2", 64), "repository": "albertloky/SBXR", "tag": tag},
		"sequence":         sequence, "tag": tag,
	}
}

func draftAssets(idBase int64) []any {
	names := []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}
	assets := make([]any, len(names))
	for index, name := range names {
		asset := map[string]any{"name": name, "sha256": strings.Repeat(strconv.Itoa(index+1), 64), "size": index + 10}
		if idBase > 0 {
			asset["id"] = idBase + int64(index)
		}
		assets[index] = asset
	}
	return assets
}

func draftDownloads(idBase int64) []any {
	downloads := draftAssets(idBase)
	for _, value := range downloads {
		value.(map[string]any)["authenticated"] = true
	}
	return downloads
}

func qualificationDocument(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func jsonValue(t *testing.T, document string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(document), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func jsonObject(t *testing.T, document []byte) map[string]any {
	t.Helper()
	return jsonValue(t, string(document)).(map[string]any)
}

func sha256String(document string) string {
	digest := sha256.Sum256([]byte(document))
	return hex.EncodeToString(digest[:])
}

func candidateFacts(mode string) qualificationFacts {
	return qualificationFacts{
		ArchiveCommit: strings.Repeat("a", 40), ArchiveRemoteCommit: strings.Repeat("a", 40), ArchiveRemoteTagObject: strings.Repeat("b", 40), ArchiveTagObject: strings.Repeat("b", 40), ArchiveType: "tag",
		BurnedIdentities: []burnedIdentity{}, Candidate: candidateRequest{ASequence: 17, ATag: "v2.0.0", BSequence: 18, BTag: "v2.0.1", Mode: mode}, ChecklistSHA256: strings.Repeat("c", 64), Commit: strings.Repeat("d", 40), Releases: []observedRelease{}, RemoteMain: strings.Repeat("d", 40), Schema: qualificationFactsSchema, Stage: candidatePreflightStage, Tags: []string{},
	}
}

func qualifiedRelease(prerelease bool) observedRelease {
	indexSHA := strings.Repeat("2", 64)
	body := "# SBXR Installer-Updater Acceptance Record\nStatus: Qualified\nRepository: albertloky/SBXR\nTag: v2.0.0\nCommit: " + strings.Repeat("e", 40) + "\nSequence: 17\nRelease index SHA-256: " + indexSHA + "\nModule Verification: Passed\nSeam Verification: Passed\nIntegrated Verification: Passed on live Ubuntu Server 24.04 amd64\nCodex Live Acceptance: Passed\nOwner Acceptance: Not required\nSecret-safe result: Passed\nStable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\nQualification role: Clean-installed source release\nWorkflow evidence: https://github.com/albertloky/SBXR/actions/runs/123\nRunner: Ubuntu Server 24.04 linux/amd64\nGo toolchain: go1.26.6\nPublic verifier: 1.3.0 26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485\nAsset: install.sh 10 " + strings.Repeat("1", 64) + "\nAsset: release-index.json 20 " + indexSHA + "\nAsset: sbxr-linux-amd64.tar.gz 30 " + strings.Repeat("3", 64) + "\nAsset: sbxr-linux-arm64.tar.gz 40 " + strings.Repeat("4", 64) + "\n"
	if prerelease {
		body = "Failed qualification evidence: " + failedRunURL("123") + "\n"
	}
	return observedRelease{
		Assets: []observedAsset{{Digest: strings.Repeat("1", 64), ID: 11, Name: "install.sh", Size: 10}, {Digest: indexSHA, ID: 12, Name: "release-index.json", Size: 20}, {Digest: strings.Repeat("3", 64), ID: 13, Name: "sbxr-linux-amd64.tar.gz", Size: 30}, {Digest: strings.Repeat("4", 64), ID: 14, Name: "sbxr-linux-arm64.tar.gz", Size: 40}},
		Body:   body, Commit: strings.Repeat("e", 40), ID: 7, Immutable: true, Index: &observedIndex{Commit: strings.Repeat("e", 40), Repository: "albertloky/SBXR", Sequence: 17, SHA256: indexSHA, Tag: "v2.0.0"}, Prerelease: prerelease, Sequence: uint64Pointer(17), Tag: "v2.0.0",
	}
}

func canonicalFacts(t *testing.T, facts qualificationFacts) string {
	t.Helper()
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func stringPointer(value string) *string { return &value }

func uint64Pointer(value uint64) *uint64 { return &value }

func runQualificationCommand(binary, document string) ([]byte, error) {
	run := exec.Command(binary, "qualification")
	run.Stdin = strings.NewReader(document)
	return run.CombinedOutput()
}

func assertQualificationRefused(t *testing.T, binary, document, name string) {
	t.Helper()
	if output, err := runQualificationCommand(binary, document); err == nil {
		t.Fatalf("%s accepted: %s", name, output)
	}
}
