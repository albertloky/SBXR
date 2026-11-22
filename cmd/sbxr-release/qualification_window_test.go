package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFreshQualificationWindowAcceptsTheExactSignedDraft(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	facts, manifest := freshWindowFixture(t, binary)
	body, err := runQualificationCommand(binary, qualificationDocument(t, facts))
	if err != nil {
		t.Fatalf("fresh window refused: %v %s", err, body)
	}
	decision := jsonObject(t, body)
	if decision["outcome"] != "accepted" || decision["stage"] != "qualification-window" {
		t.Fatalf("unexpected window decision: %s", body)
	}
	want := qualificationDocument(t, facts["window"])
	got := qualificationDocument(t, decision["window"])
	if got != want || !bytes.Equal(manifest, mustJSON(facts["signed_manifest"])) {
		t.Fatal("window decision changed the approved record or its signed source")
	}
}

func TestFreshWindowSigningAdapterReplaysTheOriginalBoundary(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	facts, signed := freshWindowFixture(t, binary)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "fresh-source"), 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, contents string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	manifest := jsonObject(t, signed)
	window := facts["window"].(map[string]any)
	window["karing_checked_at"] = facts["observed_at"]
	origin := manifest["workflow"].(map[string]any)
	next := facts["workflow"].(map[string]any)
	karing := manifest["v3_attempt"].(map[string]any)["packages"].(map[string]any)["karing"].(map[string]any)
	baseline := manifest["v3_attempt"].(map[string]any)["baseline"].(map[string]any)["release_identity"]
	declaration := map[string]any{"origin_run_id": origin["run_id"], "start_unix": window["start_unix"],
		"test_until_unix": window["test_until_unix"], "finish_unix": window["finish_unix"]}
	write("fresh-source/qualification-manifest.json", string(signed), 0600)
	write("fresh-source/qualification-boundary-facts.json", string(facts["qualification_boundary_facts"].(json.RawMessage)), 0600)
	write("fresh-source/draft-observation.json", qualificationDocument(t, facts["draft"]), 0600)
	write("fresh-source/burned-identities.json", "[]", 0600)
	write("origin-run.json", qualificationDocument(t, map[string]any{
		"id": json.Number(origin["run_id"].(string)), "head_sha": origin["commit"], "html_url": origin["run_url"],
		"path": origin["path"], "head_branch": "main", "event": "workflow_dispatch",
		"run_attempt": 1, "status": "completed", "conclusion": "cancelled",
	}), 0600)
	write("origin-jobs.json", `[{"jobs":[{"name":"sign","status":"completed","conclusion":"success","steps":[{"name":"Attest qualification manifest","conclusion":"success"}]},{"name":"acceptance-vps","status":"completed","conclusion":"cancelled","steps":[]}]}]`, 0600)
	write("karing.json", qualificationDocument(t, map[string]any{
		"draft": false, "prerelease": false, "tag_name": "v" + karing["version"].(string),
		"assets": []any{map[string]any{"size": karing["size"], "digest": "sha256:" + karing["sha256"].(string)}},
	}), 0600)
	write("baseline.json", qualificationDocument(t, map[string]any{"outcome": "accepted", "release_identity": baseline}), 0600)
	write("gh", `#!/bin/bash
set -eu
case "$1:$2" in
  "api:repos/albertloky/SBXR/actions/runs/$ORIGIN_RUN") cat origin-run.json;;
  "api:repos/albertloky/SBXR/actions/runs/$ORIGIN_RUN/attempts/1/jobs?per_page=100") cat origin-jobs.json;;
  "api:repos/albertloky/SBXR/actions/runs/$GITHUB_RUN_ID/approvals")
    printf '%s' '[{"state":"approved","environments":[{"name":"acceptance-vps"}]}]';;
  'api:repos/KaringX/karing/releases/latest') cat karing.json;;
  'attestation:verify')
    test "$*" = "attestation verify fresh-source/qualification-manifest.json --repo albertloky/SBXR --signer-workflow albertloky/SBXR/.github/workflows/candidate.yml --source-ref refs/heads/main --source-digest $ORIGIN_SHA --deny-self-hosted-runners --format=json"
    printf '[{"verificationResult":{"signature":{"certificate":{"runInvocationURI":"%s/attempts/1"}}}}]' "$ORIGIN_URL";;
  *) exit 9;;
esac
`, 0700)
	write("date", "#!/bin/sh\nprintf '%s\\n' 2026-11-22T13:10:00Z\n", 0700)
	write("cargo", "#!/bin/bash\n[[ \" $* \" == *' verify-candidate-preflight '* ]] && cat baseline.json\n", 0700)
	write("go", "#!/bin/sh\nexec \"$QUALIFICATION_TEST_BINARY\" qualification\n", 0700)
	script, err := filepath.Abs("../../.github/scripts/fresh-qualification.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", script, "authorize")
	command.Dir = root
	command.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_TOKEN=", "GITHUB_TOKEN=",
		"QUALIFICATION_TEST_BINARY="+binary, "GITHUB_REPOSITORY=albertloky/SBXR", "GITHUB_REF=refs/heads/main",
		"GITHUB_RUN_ATTEMPT=1", "GITHUB_RUN_ID="+next["run_id"].(string), "GITHUB_SHA="+next["commit"].(string),
		"ORIGIN_RUN="+origin["run_id"].(string), "ORIGIN_SHA="+origin["commit"].(string), "ORIGIN_URL="+origin["run_url"].(string),
		"RUNNER_TEMP="+root, "FRESH_WINDOW="+qualificationDocument(t, declaration))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("window signing adapter refused synthetic origin: %v\n%s", err, output)
	}
	decision, err := os.ReadFile(filepath.Join(root, "fresh-window-decision.json"))
	want, wantErr := runQualificationCommand(binary, qualificationDocument(t, facts))
	if err != nil || wantErr != nil || !bytes.Equal(decision, want) {
		t.Fatalf("signing adapter did not produce the exact window decision: %v, %v", err, wantErr)
	}
}

func TestFreshQualificationWindowRefusesSubstitutionOrReplay(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	original, _ := freshWindowFixture(t, binary)
	for name, mutate := range map[string]func(map[string]any){
		"manifest hash": func(f map[string]any) {
			f["window"].(map[string]any)["manifest_sha256"] = strings.Repeat("0", 64)
		},
		"foreign signer": func(f map[string]any) {
			f["origin"].(map[string]any)["signer_workflow"] = "someone/else/.github/workflows/candidate.yml"
		},
		"sign did not succeed": func(f map[string]any) {
			f["origin"].(map[string]any)["sign_conclusion"] = "failure"
		},
		"unsigned draft": func(f map[string]any) {
			f["origin"].(map[string]any)["manifest_attested"] = false
		},
		"wrong observed release": func(f map[string]any) {
			f["draft"].(map[string]any)["release"].(map[string]any)["release_id"] = 454438007
		},
		"already published": func(f map[string]any) {
			f["draft"].(map[string]any)["draft"] = false
		},
		"wrong asset hash": func(f map[string]any) {
			release := f["draft"].(map[string]any)["release"].(map[string]any)
			release["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		},
		"wrong origin attempt": func(f map[string]any) {
			f["origin"].(map[string]any)["run_attempt"] = 2
		},
		"wrong origin run": func(f map[string]any) {
			f["origin"].(map[string]any)["workflow"].(map[string]any)["run_id"] = "45005500246"
		},
		"different fresh run": func(f map[string]any) {
			f["window"].(map[string]any)["workflow"].(map[string]any)["run_id"] = "45005500246"
		},
		"replayed attempt": func(f map[string]any) {
			f["run_attempt"] = 2
		},
		"missing approval": func(f map[string]any) {
			f["approval"].(map[string]any)["state"] = "pending"
		},
		"stale Karing observation": func(f map[string]any) {
			f["window"].(map[string]any)["karing_checked_at"] = "2026-11-22T12:59:59Z"
		},
		"expired": func(f map[string]any) {
			f["observed_at"] = "2026-11-22T15:00:00Z"
		},
		"activity one second short": func(f map[string]any) {
			f["observed_at"] = "2026-11-22T13:10:01Z"
		},
		"restoration one second short": func(f map[string]any) {
			w := f["window"].(map[string]any)
			w["finish_unix"] = w["test_until_unix"].(float64) + 1559
		},
		"burn ref present": func(f map[string]any) {
			f["draft"].(map[string]any)["burn_ref"] = "present"
		},
		"release ref observation absent": func(f map[string]any) {
			delete(f["draft"].(map[string]any), "release_ref")
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(qualificationDocument(t, original)))
			mutate(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}
}

func freshWindowFixture(t *testing.T, binary string) (map[string]any, []byte) {
	t.Helper()
	boundary, manifest, _ := mvpQualificationFixtureForSupport(t, binary, false, true, true)
	signed := jsonObject(t, manifest)
	origin := signed["workflow"]
	workflow := jsonObject(t, []byte(qualificationDocument(t, origin)))
	workflow["run_id"] = "992800"
	workflow["run_url"] = "https://github.com/albertloky/SBXR/actions/runs/992800"
	release := signed["releases"].([]any)[0]
	return map[string]any{
		"schema":                       "sbxr-release-qualification-facts-v1",
		"burned_identities":            []any{},
		"stage":                        "qualification-window",
		"observed_at":                  "2026-11-22T13:10:00Z",
		"run_attempt":                  1,
		"workflow":                     workflow,
		"approval":                     map[string]any{"state": "approved", "environments": []any{map[string]any{"name": "acceptance-vps"}}},
		"signed_manifest":              json.RawMessage(manifest),
		"qualification_boundary_facts": json.RawMessage(boundary),
		"origin": map[string]any{
			"manifest_attested":  true,
			"run_attempt":        1,
			"signer_workflow":    "albertloky/SBXR/.github/workflows/candidate.yml",
			"sign_conclusion":    "success",
			"live_never_started": true,
			"workflow":           origin,
		},
		"draft": map[string]any{
			"draft": true, "immutable": false, "prerelease": false,
			"release_ref": "absent", "burn_ref": "absent", "release": release,
		},
		"window": map[string]any{
			"schema":            "sbxr-qualification-window-v1",
			"manifest_sha256":   sha256String(string(manifest)),
			"origin":            origin,
			"workflow":          workflow,
			"release":           release,
			"run_attempt":       1,
			"start_unix":        1795352400,
			"test_until_unix":   1795354200,
			"finish_unix":       1795355760,
			"karing_checked_at": "2026-11-22T13:05:00Z",
		},
	}, manifest
}

func TestFreshQualificationResultUsesOriginalBytesAndNewRun(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	facts := freshWindowResultFixture(t, binary)
	out, err := runQualificationCommand(binary, qualificationDocument(t, facts))
	if err != nil {
		t.Fatalf("fresh full evidence: %v %s", err, out)
	}
	record := jsonObject(t, out)["records"].([]any)[0].(map[string]any)
	if !strings.Contains(record["body"].(string), "Workflow evidence: https://github.com/albertloky/SBXR/actions/runs/992800\n") {
		t.Fatal("Acceptance Record did not identify the successful fresh attempt")
	}
}

func TestFreshQualificationResultRefusesIncompleteOrBorrowedEvidence(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	base := freshWindowResultFixture(t, binary)
	for name, change := range map[string]func(map[string]any){
		"wrong window signer": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["signer_workflow"] = "other/source"
		},
		"substituted mint evidence": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["window_facts"].(map[string]any)["observed_at"] = "2026-11-22T13:09:59Z"
		},
		"unverified window": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["attested"] = false
		},
		"wrong live job": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["live_job"] = "sign"
		},
		"missing restoration": func(f map[string]any) {
			delete(f["fresh_window"].(map[string]any), "transport_restored_at")
		},
		"late staging": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["admitted_at"] = "2026-11-22T13:10:01Z"
		},
		"wrong live run": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["workflow"].(map[string]any)["run_id"] = "45005500246"
		},
		"window copied into original attempt": func(f map[string]any) {
			e := f["detailed_evidence"].(map[string]any)
			e["attempt_id"] = f["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)["attempt_id"]
			f["detailed_evidence_sha256"] = sha256String(qualificationDocument(t, e))
		},
		"one-node evidence only": func(f map[string]any) {
			e := f["detailed_evidence"].(map[string]any)
			e["scenarios"] = e["scenarios"].([]any)[:1]
			f["detailed_evidence_sha256"] = sha256String(qualificationDocument(t, e))
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(qualificationDocument(t, base)))
			change(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}
}

func freshWindowResultFixture(t *testing.T, binary string) map[string]any {
	t.Helper()
	signedFacts, manifest := freshWindowFixture(t, binary)
	boundary, _, evidence := mvpQualificationFixtureForSupport(t, binary, false, true, true)
	signedWindow, err := runQualificationCommand(binary, qualificationDocument(t, signedFacts))
	if err != nil {
		t.Fatalf("window fixture: %v %s", err, signedWindow)
	}
	windowDigest := sha256String(string(signedWindow))
	evidence["attempt_id"] = "run-992800-attempt-1"
	evidence["observed_at"] = "2026-11-22T13:23:00Z"
	previous := windowDigest
	for index, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		start := time.Date(2026, 11, 22, 13, 11+index*2, 0, 0, time.UTC)
		end := start.Add(time.Minute)
		validated := end
		if index == len(evidence["scenarios"].([]any))-1 {
			validated = end.Add(3 * time.Minute)
		}
		s["attempt_id"] = evidence["attempt_id"]
		s["prior_scenario_sha256"] = previous
		s["started_at"], s["preflight_at"] = start.Format(time.RFC3339), start.Format(time.RFC3339)
		s["completed_at"], s["validated_at"] = end.Format(time.RFC3339), validated.Format(time.RFC3339)
		for _, rawReference := range s["evidence"].([]any) {
			ref := rawReference.(map[string]any)
			record := ref["record"].(map[string]any)
			record["observed_at"] = end.Format(time.RFC3339)
			ref["sha256"] = sha256String(qualificationDocument(t, record))
		}
		previous = sha256String(qualificationDocument(t, s))
	}
	result := jsonObject(t, []byte(recurringResultFixture(t, boundary, manifest, evidence)))
	result["prior_decision_sha256"] = windowDigest
	result["evaluation_time"] = "2026-11-22T13:24:00Z"
	result["fresh_window"] = map[string]any{
		"admitted_at": "2026-11-22T13:10:00Z",
		"attested":    true, "live_job": "acceptance-vps", "live_approved": true,
		"run_attempt": 1, "signer_workflow": "albertloky/SBXR/.github/workflows/candidate.yml",
		"transport_restored_at": "2026-11-22T13:23:10Z",
		"window_facts":          signedFacts, "window_decision": json.RawMessage(signedWindow), "workflow": signedFacts["workflow"],
	}
	return result
}

func TestStablePreflightBindsFreshRunToOriginalSignedRelease(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	result := freshWindowResultFixture(t, binary)
	body, err := runQualificationCommand(binary, qualificationDocument(t, result))
	if err != nil {
		t.Fatalf("fresh acceptance fixture: %v %s", err, body)
	}
	decision := jsonObject(t, body)
	stable := mainReviewPreflightFixture(t, binary)
	origin := stable["candidate_run"].(stableCandidateRun)
	origin.Conclusion = "cancelled"
	live := origin
	live.ID = "992800"
	live.Conclusion = "success"
	live.CreatedAt = "2026-11-22T13:00:03Z"
	stable["candidate_run"] = live
	stable["acceptance_decision"] = decision
	stable["acceptance_facts"] = result
	stable["releases"].([]any)[0].(map[string]any)["body"] = decision["records"].([]any)[0].(map[string]any)["body"]
	stable["observed_at"] = "2026-11-22T13:25:00Z"
	stable["fresh_window"] = map[string]any{
		"origin_run": origin, "run_attempt": 1, "window_attested": true, "acceptance_conclusion": "success",
		"origin_sign_conclusion": "success", "window_sha256": result["prior_decision_sha256"],
	}
	document := qualificationDocument(t, stable)
	out, err := runQualificationCommand(binary, document)
	if err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("stable fresh-window preflight: %v %s", err, out)
	}
	for name, change := range map[string]func(map[string]any){
		"missing independent attestation": func(f map[string]any) { delete(f, "fresh_window") },
		"observed before qualification":   func(f map[string]any) { f["observed_at"] = "2026-11-22T13:00:04Z" },
		"wrong origin": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["origin_run"].(map[string]any)["id"] = "45005500246"
		},
		"wrong live run": func(f map[string]any) {
			f["candidate_run"].(map[string]any)["id"] = "45005500246"
		},
		"skipped live job": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["acceptance_conclusion"] = "skipped"
		},
		"failed live run": func(f map[string]any) {
			f["candidate_run"].(map[string]any)["conclusion"] = "failure"
		},
		"wrong release": func(f map[string]any) {
			f["releases"].([]any)[0].(map[string]any)["release_id"] = 454438007
		},
		"replayed run": func(f map[string]any) {
			f["fresh_window"].(map[string]any)["run_attempt"] = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := jsonObject(t, []byte(document))
			change(facts)
			assertQualificationRefused(t, binary, qualificationDocument(t, facts), name)
		})
	}
}

func TestFreshQualificationFailureBelongsToTheNewAttempt(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	result := freshWindowResultFixture(t, binary)
	fresh := result["fresh_window"].(map[string]any)
	delete(fresh, "transport_restored_at")
	input := map[string]any{
		"schema": qualificationFactsSchema, "stage": "v3-scenario-failure",
		"qualification_boundary_facts": result["qualification_boundary_facts"],
		"qualification_manifest":       result["qualification_manifest"], "qualification_manifest_attested": true,
		"fresh_window":   fresh,
		"safety_cleanup": map[string]any{"host_state": "Unknown", "status": "not-started"},
		"failure": map[string]any{
			"schema": "sbxr-v3-scenario-failure-v3", "actual_result": "unexpected-failure",
			"attempt_id": "run-992800-attempt-1", "boundary": "unknown",
			"candidate": result["releases"].([]any)[0], "expected_result": "expected-safety-and-final-state-proved",
			"host_state": "Unknown", "observed_at": "2026-11-22T13:20:00Z", "operation_id": "operation-1",
			"scenario_id": "mvp-install",
			"vps_id":      result["qualification_manifest"].(map[string]any)["v3_attempt"].(map[string]any)["vps_id"],
		},
	}
	body, err := runQualificationCommand(binary, qualificationDocument(t, input))
	if err != nil {
		t.Fatalf("fresh failure refused: %v %s", err, body)
	}
	decision := jsonObject(t, body)
	if decision["outcome"] != "failed" || decision["stop_test_mutations"] != true ||
		decision["burn_required"] != true ||
		decision["burn"].(map[string]any)["qualification_run_url"] != "https://github.com/albertloky/SBXR/actions/runs/992800" {
		t.Fatalf("unsafe failure decision: %s", body)
	}
	input["failure"].(map[string]any)["attempt_id"] = "run-123-attempt-1"
	assertQualificationRefused(t, binary, qualificationDocument(t, input), "borrowed failure attempt")
}

func TestFreshStableAbandonmentRequiresTheSameVerifiedQualification(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	result := freshWindowResultFixture(t, binary)
	acceptance, err := runQualificationCommand(binary, qualificationDocument(t, result))
	if err != nil {
		t.Fatalf("acceptance fixture: %v %s", err, acceptance)
	}
	baseline := mainReviewPreflightFixture(t, binary)
	origin := baseline["candidate_run"].(stableCandidateRun)
	origin.Conclusion = "cancelled"
	live := origin
	live.ID, live.CreatedAt, live.Conclusion = "992800", "2026-11-22T13:00:03Z", "success"
	target := baseline["releases"].([]any)[0].(map[string]any)
	delete(target, "body")
	target["body"] = jsonObject(t, acceptance)["records"].([]any)[0].(map[string]any)["body"]
	target["release_present"], target["publicly_verified"], target["tag_commit"] = true, false, nil
	observations := []any{target}
	facts := map[string]any{
		"schema": qualificationFactsSchema, "stage": "stable-failure-finalization",
		"candidate_commit_ancestor": true, "burned_identities": []any{}, "candidate_run": live,
		"manifest_attested": true, "signed_manifest": baseline["signed_manifest"], "observations": observations,
		"observed_at": "2026-11-22T14:01:00Z", "operation": "abandon", "publication_stage": "prepublication",
		"finalization_run": map[string]any{"id": "997777", "url": "https://github.com/albertloky/SBXR/actions/runs/997777",
			"head_sha": origin.HeadSHA, "created_at": "2026-11-22T14:00:00Z", "path": ".github/workflows/stable.yml"},
		"fresh_qualification": map[string]any{"acceptance_facts": result, "acceptance_decision": json.RawMessage(acceptance),
			"observation": map[string]any{"origin_run": origin, "origin_sign_conclusion": "success", "run_attempt": 1,
				"acceptance_conclusion": "success", "window_attested": true, "window_sha256": result["prior_decision_sha256"]}},
	}
	body, err := runQualificationCommand(binary, qualificationDocument(t, facts))
	if err != nil {
		t.Fatalf("fresh abandonment preflight: %v %s", err, body)
	}
	action := jsonObject(t, body)["actions"].([]any)[0].(map[string]any)
	if action["reason"] != "owner-abandoned" || action["burn"].(map[string]any)["qualification_run_url"] != "https://github.com/albertloky/SBXR/actions/runs/992800" {
		t.Fatalf("abandonment decision refers to the wrong run: %s", body)
	}
	facts["operation"] = "publish"
	assertQualificationRefused(t, binary, qualificationDocument(t, facts), "a fresh failure must not change the publish retry policy")
}
