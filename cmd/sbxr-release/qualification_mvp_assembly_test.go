package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMVPPythonAssemblerProducesFiveValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, false, false)
}

func TestMVPRecurringPythonAssemblerProducesEightValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, true, false)
}

func TestHTTPPythonAssemblerProducesFiveValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, false, true)
}

func TestHTTPRecurringRecorderAndAssemblerProduceEightValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, true, true)
}

func TestHTTPRecurringAttendedRecorderAndAssemblerProduceEightAcceptedPrefixes(t *testing.T) {
	testMVPAssemblerWithHandoff(t, true, true, true)
}

func testMVPAssembler(t *testing.T, recurring, httpSubscription bool) {
	testMVPAssemblerWithHandoff(t, recurring, httpSubscription, false)
}

func testMVPAssemblerWithHandoff(t *testing.T, recurring, httpSubscription, handoff bool) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	var boundary string
	var manifest []byte
	if recurring {
		boundary, manifest, _ = mvpRecurringQualificationFixtureWithHandoff(t, binary, httpSubscription, handoff)
	} else {
		boundary, manifest, _ = mvpQualificationFixtureWithTransport(t, binary, false, httpSubscription)
	}
	directory := t.TempDir()
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	manifestPath := write("manifest.json", manifest)
	boundaryPath := write("boundary.json", []byte(boundary))
	previousPath := write("previous.json", []byte("[]"))
	manifestValue := jsonObject(t, manifest)
	ids := manifestValue["v3_attempt"].(map[string]any)["required_scenarios"].([]any)
	var lastFacts map[string]any
	var firstSealedDraft []byte
	sharedDraft := filepath.Join(directory, "operator-draft.json")

	for index, rawID := range ids {
		id := rawID.(string)
		now := time.Now().UTC().Truncate(time.Second)
		stamp := now.Format(time.RFC3339)
		limit := 1800
		if id == "mvp-subscription" {
			limit = 7200
		}
		expectedChecks := ordinaryFixtureChecksFor(id, httpSubscription)
		request := map[string]any{
			"deadline_unix": now.Add(time.Duration(limit) * time.Second).Unix(), "not_before": stamp,
			"qualification_manifest_sha256": sha256String(string(manifest)),
			"required_checks":               expectedChecks, "scenario_id": id, "scenario_limit_seconds": limit,
		}
		if handoff {
			request["karing_response_limit_seconds"] = 3600
			request["attended_finish_by"] = manifestValue["v3_attempt"].(map[string]any)["attended_finish_by"]
		}
		checks := make([]any, 0, len(expectedChecks))
		for _, check := range expectedChecks {
			checks = append(checks, map[string]any{"check": check, "observed_at": stamp, "result": "observed"})
		}
		observation := map[string]any{"checks": checks, "completed_at": stamp, "scenario_id": id, "started_at": stamp}
		requestPath := write(fmt.Sprintf("request-%d.json", index), []byte(qualificationDocument(t, request)))
		if handoff {
			write("request.json", []byte(qualificationDocument(t, request)))
			collectorTiming(t, directory, sharedDraft, "clock", true)
			if index > 0 {
				sealed, err := os.ReadFile(sharedDraft)
				if err != nil {
					t.Fatal(err)
				}
				// Ignoring the exact accepted predecessor must not weaken recorder binding.
				command := exec.Command("python3", "../../.github/scripts/mvp-observe.py", "status", "--request", requestPath, "--draft", sharedDraft)
				if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "draft belongs to another collector request") {
					t.Fatalf("recorder accepted predecessor: %v %s", err, output)
				}
				if err := os.WriteFile(sharedDraft, append(append([]byte(nil), sealed...), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
				collectorTiming(t, directory, sharedDraft, "clock", false)
				if index > 1 {
					if err := os.WriteFile(sharedDraft, firstSealedDraft, 0600); err != nil {
						t.Fatal(err)
					}
					collectorTiming(t, directory, sharedDraft, "clock", false)
				}
				if err := os.WriteFile(sharedDraft, sealed, 0600); err != nil {
					t.Fatal(err)
				}
				collectorTiming(t, directory, sharedDraft, "clock", true)
				// A predecessor cannot rescue an expired next request.
				expired := jsonObject(t, []byte(qualificationDocument(t, request)))
				expired["not_before"] = now.Add(-35 * time.Minute).Format(time.RFC3339)
				expired["deadline_unix"] = now.Add(-6 * time.Minute).Unix()
				write("request.json", []byte(qualificationDocument(t, expired)))
				collectorTiming(t, directory, sharedDraft, "clock", false)
				write("request.json", []byte(qualificationDocument(t, request)))
				if err := os.Remove(sharedDraft); err != nil {
					t.Fatal(err)
				}
				collectorTiming(t, directory, sharedDraft, "clock", true)
			}
		}
		pretty, err := json.MarshalIndent(observation, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		observationPath := filepath.Join(directory, fmt.Sprintf("observation-%d.json", index))
		if recurring {
			draft := filepath.Join(directory, fmt.Sprintf("draft-%d.json", index))
			if handoff {
				draft = sharedDraft
			}
			record := func(action string, extra ...string) {
				t.Helper()
				args := append([]string{"../../.github/scripts/mvp-observe.py", action, "--request", requestPath, "--draft", draft}, extra...)
				if output, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
					t.Fatalf("recorder %s: %v %s", action, err, output)
				}
			}
			record("start")
			if handoff && len(karingHandoffPhases(id)) > 0 {
				notified := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
				record("ready", "--phase", karingHandoffPhases(id)[0], "--prepared-at", notified, "--notified-at", notified)
				record("responded")
			}
			for _, check := range expectedChecks {
				record("observe", "--check", check)
			}
			record("finish", "--output", observationPath)
		} else {
			write(fmt.Sprintf("observation-%d.json", index), append(pretty, '\n'))
		}
		factsPath := filepath.Join(directory, fmt.Sprintf("facts-%d.json", index))
		assembler := exec.Command("python3", "../../.github/scripts/v3-mvp-evidence.py",
			"--manifest", manifestPath, "--boundary", boundaryPath, "--request", requestPath,
			"--previous", previousPath, "--observation", observationPath, "--output", factsPath)
		if output, err := assembler.CombinedOutput(); err != nil {
			t.Fatalf("assemble %s: %v\n%s", id, err, output)
		}
		factsBytes, err := os.ReadFile(factsPath)
		if err != nil {
			t.Fatal(err)
		}
		validated, err := runQualificationCommand(binary, string(factsBytes))
		if err != nil || jsonObject(t, validated)["outcome"] != "accepted" || len(jsonObject(t, validated)["records"].([]any)) != 0 {
			t.Fatalf("validator refused %s prefix: %v\n%s", id, err, validated)
		}
		lastFacts = jsonObject(t, factsBytes)
		if handoff {
			write("input.json", factsBytes)
			sealed, err := os.ReadFile(sharedDraft)
			if err != nil {
				t.Fatal(err)
			}
			unsealed := jsonObject(t, sealed)
			unsealed["observation"].(map[string]any)["completed_at"] = nil
			if err := os.WriteFile(sharedDraft, []byte(qualificationDocument(t, unsealed)), 0600); err != nil {
				t.Fatal(err)
			}
			collectorTiming(t, directory, sharedDraft, "retain", false)
			if err := os.WriteFile(sharedDraft, sealed, 0600); err != nil {
				t.Fatal(err)
			}
			collectorTiming(t, directory, sharedDraft, "retain", true)
			if index == 0 {
				firstSealedDraft, err = os.ReadFile(sharedDraft)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		prefix := qualificationDocument(t, lastFacts["detailed_evidence"].(map[string]any)["scenarios"])
		if err := os.WriteFile(previousPath, []byte(prefix), 0600); err != nil {
			t.Fatal(err)
		}
	}

	lastFacts["stage"] = "v3-packaged-live-result"
	lastFacts["evaluation_time"] = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	accepted, err := runQualificationCommand(binary, qualificationDocument(t, lastFacts))
	if err != nil || jsonObject(t, accepted)["outcome"] != "accepted" || len(jsonObject(t, accepted)["records"].([]any)) != 1 {
		t.Fatalf("validator refused assembled final result: %v\n%s", err, accepted)
	}
}

// Execute the collector's real shell blocks across all eight accepted prefixes.
// The subprocess peer changes only fixed host paths; clock/retention code and
// recorder/assembler/Go validation are unchanged. No live evidence is produced.
func collectorTiming(t *testing.T, directory, draft, action string, accept bool) {
	t.Helper()
	raw, err := os.ReadFile("../../.github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	between := func(start, end string) string {
		_, rest, ok := strings.Cut(source, start)
		body, _, done := strings.Cut(rest, end)
		if !ok || !done {
			t.Fatalf("collector block absent: %s", start)
		}
		return start + body
	}
	helpers := between("read_mvp_timing_draft() {", "# Timing transport helpers end.")
	block := between("    active_deadline=$deadline\n", "    sleep 2\n")
	if action == "retain" {
		block = between("  # Retain only a sealed draft", "  # Accepted timing retention ends.")
	}
	request, err := os.ReadFile(filepath.Join(directory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := jsonObject(t, request)["deadline_unix"].(float64)
	script := "set -euo pipefail\numask 077\nremote=(bash -c)\ndirectory=" + shellQuote(directory) + "\ndeadline=" + fmt.Sprintf("%.0f", deadline) + "\n" + helpers + block
	script = strings.ReplaceAll(script, "/root/mvp-observation-draft.json", draft)
	if action == "clock" {
		script += "\ntest \"$active_deadline\" -eq \"$deadline\"\n"
	}
	command := exec.Command("bash", "-c", script)
	command.Dir = "../.."
	output, err := command.CombinedOutput()
	if (err == nil) != accept {
		t.Fatalf("collector %s accepted=%v want %v: %v\n%s", action, err == nil, accept, err, output)
	}
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
