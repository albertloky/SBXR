package architecture_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func workflowRun(t *testing.T, path, job, name string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Jobs map[string]struct{ Steps []struct{ Name, Run string } }
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	for _, step := range document.Jobs[job].Steps {
		if step.Name == name {
			return step.Run
		}
	}
	t.Fatalf("step %q missing", name)
	return ""
}

func TestGitHubObservationCommand(t *testing.T) {
	command := exec.Command("python3", ".github/scripts/test_observe_github_resource.py")
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("observation child CLI tests: %v %s", err, output)
	}
}

func TestWorkflowCleanupRefusesUnavailableGitHubObservations(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	candidate := workflowRun(t, ".github/workflows/candidate.yml", "cleanup-unqualified", "Prepare only this run's unsigned failure decision")
	end := strings.Index(candidate, "jq -cnS --slurpfile construction_decision")
	if end < 0 {
		t.Fatal("candidate observation boundary missing")
	}
	candidate = candidate[:end]
	stable := workflowRun(t, ".github/workflows/stable.yml", "finalize-failure", "Recheck the signed qualification and obtain the failure decision")
	start := strings.Index(stable, "printf '[]' > failure/observations.json")
	end = strings.Index(stable, "publication_stage=prepublication-failure")
	if start < 0 || end < start {
		t.Fatal("stable observation boundary missing")
	}
	stable = "set -euo pipefail\nmanifest=failure/qualification-manifest.json\n" + stable[start:end]
	target := map[string]any{"tag": "v2.0.0", "commit": strings.Repeat("a", 40), "release_id": 71, "created_release_id": 71, "sequence": 17, "assets": []any{}, "release_identity": map[string]any{"repository": "albertloky/SBXR", "tag": "v2.0.0", "commit": strings.Repeat("a", 40), "release_index_sha256": strings.Repeat("b", 64)}}
	for name, script := range map[string]string{"candidate observation": candidate, "stable observation": stable} {
		for _, codes := range [][2]string{{"404", "404"}, {"401", "404"}, {"403", "404"}, {"500", "404"}, {"transport", "404"}, {"404", "403"}} {
			// Stable's fetched Git tag observation is separate; only its release
			// classification is under test here.
			if name == "stable observation" && codes[0] == "404" && codes[1] != "404" {
				continue
			}
			t.Run(name+"/"+codes[0]+"-"+codes[1], func(t *testing.T) {
				root := t.TempDir()
				if err := os.MkdirAll(filepath.Join(root, "boundary/unsigned"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "failure"), 0700); err != nil {
					t.Fatal(err)
				}
				write := func(path string, value any) {
					t.Helper()
					body, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, path), body, 0600); err != nil {
						t.Fatal(err)
					}
				}
				write("boundary/unsigned/drafts.json", []any{target})
				write("boundary/unsigned/candidate-failure-facts.json", map[string]any{"observations": []any{target}, "burned_identities": []any{}})
				write("boundary/unsigned/candidate-failure-decision.json", map[string]any{"actions": []any{target}})
				write("failure/qualification-manifest.json", map[string]any{"releases": []any{target}})
				bin := filepath.Join(root, "bin")
				if err := os.Mkdir(bin, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(workflowObservationGHFixture), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
					t.Fatal(err)
				}
				command := exec.Command("bash", "-c", script)
				command.Dir = root
				command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GITHUB_WORKSPACE="+workspace, "GITHUB_REPOSITORY=albertloky/SBXR", "BUILD_RELEASES=[{\"tag\":\"v2.0.0\"}]", "SBXR_RELEASE_STATUS="+codes[0], "SBXR_REF_STATUS="+codes[1])
				output, err := command.CombinedOutput()
				absent := codes == [2]string{"404", "404"}
				if absent && err != nil {
					t.Fatalf("explicit absence refused: %v %s", err, output)
				}
				if !absent && err == nil {
					t.Fatalf("unavailable GitHub observation accepted as cleanup: %s", output)
				}
			})
		}
	}
}

const workflowObservationGHFixture = `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
include=args[:2]==['api','--include']
endpoint=args[2] if include else args[1]
code=os.environ['SBXR_REF_STATUS'] if '/git/ref/' in endpoint else os.environ['SBXR_RELEASE_STATUS']
if code=='transport':
 print('connection failed (HTTP 404)',file=sys.stderr)
 sys.exit(1)
if include: print('HTTP/2.0 '+code+' Fixture\nContent-Type: application/json\n')
print(json.dumps({'message':'fixture error'}))
sys.exit(1)
`
