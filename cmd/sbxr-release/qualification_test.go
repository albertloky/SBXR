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
	var source, build map[string]any
	for _, value := range preflight["actions"].([]any) {
		action := value.(map[string]any)
		switch action["type"] {
		case "use-source-release":
			source = map[string]any{"assets": action["assets"], "commit": action["commit"], "release_id": action["release_id"], "release_identity": action["release_identity"], "sequence": action["sequence"], "tag": action["tag"]}
		case "build-release":
			build = action
		}
	}
	if source == nil || build == nil {
		t.Fatal("later or rescue boundary requires one source and one build action")
	}
	tag, sequence, commit := build["tag"].(string), uint64(build["sequence"].(float64)), build["commit"].(string)
	target := draftTarget(tag, sequence)
	target["commit"] = commit
	target["release_identity"].(map[string]any)["commit"] = commit
	constructionFacts := qualificationDocument(t, map[string]any{
		"built_releases": []any{target}, "preflight_decision": jsonValue(t, string(preflightDecision)), "preflight_facts": jsonValue(t, preflightDocument),
		"schema": qualificationFactsSchema, "stage": "candidate-draft-construction",
	})
	constructionDecision, err := runQualificationCommand(binary, constructionFacts)
	if err != nil {
		t.Fatalf("draft construction: %v\n%s", err, constructionDecision)
	}
	observation := draftObservation(tag, sequence, 72)
	observation["commit"] = commit
	observation["release_identity"].(map[string]any)["commit"] = commit
	verificationFacts := qualificationDocument(t, map[string]any{
		"construction_decision": jsonValue(t, string(constructionDecision)), "construction_facts": jsonValue(t, constructionFacts), "observations": []any{observation},
		"schema": qualificationFactsSchema, "stage": "candidate-draft-verification",
	})
	verificationDecision, err := runQualificationCommand(binary, verificationFacts)
	if err != nil {
		t.Fatalf("draft verification: %v\n%s", err, verificationDecision)
	}
	releases := []any{source, jsonObject(t, verificationDecision)["verified_releases"].([]any)[0]}
	var rescue any
	if preflightFacts.Candidate.Mode == "rescue" {
		rescue = map[string]any{"defect_issue_url": *preflightFacts.Candidate.DefectIssueURL, "failed_normal_run_id": *preflightFacts.Candidate.FailedNormalRunID}
	}
	boundaryFacts := qualificationDocument(t, map[string]any{
		"approval": map[string]any{"environments": []any{map[string]any{"name": "acceptance-vps"}}, "state": "approved"}, "candidate_failure_state_sha256": strings.Repeat("9", 64), "checklist_sha256": preflightFacts.ChecklistSHA256,
		"draft_verification_decision": jsonValue(t, string(verificationDecision)), "draft_verification_facts": jsonValue(t, verificationFacts),
		"native_evidence":       []any{map[string]any{"path": "native/native-" + tag + "-amd64/evidence/native-amd64.json", "sha256": strings.Repeat("5", 64)}, map[string]any{"path": "native/native-" + tag + "-arm64/evidence/native-arm64.json", "sha256": strings.Repeat("6", 64)}},
		"prior_decision_sha256": sha256String(string(verificationDecision)), "releases": releases, "rescue": rescue, "schema": qualificationFactsSchema, "source_state": preflight["source_state"], "stage": "qualification-boundary",
		"workflow": map[string]any{"commit": commit, "path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123"},
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
