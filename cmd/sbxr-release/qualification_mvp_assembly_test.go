package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMVPPythonAssemblerProducesFiveValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, false)
}

func TestMVPRecurringPythonAssemblerProducesEightValidatorAcceptedPrefixes(t *testing.T) {
	testMVPAssembler(t, true)
}

func testMVPAssembler(t *testing.T, recurring bool) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	fixture := mvpQualificationFixture
	if recurring {
		fixture = mvpRecurringQualificationFixture
	}
	boundary, manifest, _ := fixture(t, binary)
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

	for index, rawID := range ids {
		id := rawID.(string)
		now := time.Now().UTC().Truncate(time.Second)
		stamp := now.Format(time.RFC3339)
		limit := 1800
		if id == "mvp-subscription" {
			limit = 7200
		}
		expectedChecks := ordinaryFixtureChecks(id)
		request := map[string]any{
			"deadline_unix": now.Add(time.Duration(limit) * time.Second).Unix(), "not_before": stamp,
			"qualification_manifest_sha256": sha256String(string(manifest)),
			"required_checks":               expectedChecks, "scenario_id": id, "scenario_limit_seconds": limit,
		}
		checks := make([]any, 0, len(expectedChecks))
		for _, check := range expectedChecks {
			checks = append(checks, map[string]any{"check": check, "observed_at": stamp, "result": "observed"})
		}
		observation := map[string]any{"checks": checks, "completed_at": stamp, "scenario_id": id, "started_at": stamp}
		requestPath := write(fmt.Sprintf("request-%d.json", index), []byte(qualificationDocument(t, request)))
		pretty, err := json.MarshalIndent(observation, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		observationPath := filepath.Join(directory, fmt.Sprintf("observation-%d.json", index))
		if recurring {
			draft := filepath.Join(directory, fmt.Sprintf("draft-%d.json", index))
			record := func(action string, extra ...string) {
				t.Helper()
				args := append([]string{"../../.github/scripts/mvp-observe.py", action, "--request", requestPath, "--draft", draft}, extra...)
				if output, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
					t.Fatalf("recorder %s: %v %s", action, err, output)
				}
			}
			record("start")
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
