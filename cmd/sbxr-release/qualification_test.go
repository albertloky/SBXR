package main

import (
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
