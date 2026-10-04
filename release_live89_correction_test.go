package architecture_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type live89WorkflowJob struct {
	If    string   `yaml:"if"`
	Needs []string `yaml:"needs"`
}

func live89WorkflowJobs(t *testing.T, workflow string) map[string]live89WorkflowJob {
	t.Helper()
	var document struct {
		Jobs map[string]yaml.Node `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(workflow), &document); err != nil {
		t.Fatal(err)
	}
	jobs := make(map[string]live89WorkflowJob)
	for name, node := range document.Jobs {
		if name != "acceptance-vps" && name != "owner-exception" && name != "live89-correction" && name != "cleanup-unqualified" && name != "attended-1" && name != "attended-4" {
			continue
		}
		var job live89WorkflowJob
		if err := node.Decode(&job); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		jobs[name] = job
	}
	return jobs
}

func assertLive89WorkflowPartition(t *testing.T, workflow string) map[string]live89WorkflowJob {
	t.Helper()
	jobs := live89WorkflowJobs(t, workflow)
	guard := "!fromJSON(inputs.v3_attempt || '{}').owner_exception && !fromJSON(inputs.v3_attempt || '{}').live89_correction_review"
	normal := guard
	needs := []string{"preflight", "drafts", "sign", "acceptance-vps", "owner-exception"}
	condition := "always() && needs.drafts.result != 'skipped' && needs.acceptance-vps.result != 'success' && needs.owner-exception.result != 'success'"
	if attended, present := jobs["attended-1"]; present {
		normal += " && fromJSON(inputs.v3_attempt || '{}').timing_policy != 'sessioned-attended-v1'"
		if attended.If != "${{ "+guard+" && fromJSON(inputs.v3_attempt || '{}').timing_policy == 'sessioned-attended-v1' }}" {
			t.Fatal("attended live entry must exclude archival correction")
		}
		if _, terminal := jobs["attended-4"]; !terminal {
			t.Fatal("declared attended route must have its terminal job")
		}
		needs = append(needs, "attended-4")
		condition += " && needs.attended-4.result != 'success'"
	}
	if jobs["acceptance-vps"].If != "${{ "+normal+" }}" {
		t.Fatal("ordinary live entry must exclude archival correction")
	}
	needs = append(needs, "live89-correction")
	condition += " && needs.live89-correction.result != 'success'"
	actual := slices.Clone(jobs["cleanup-unqualified"].Needs)
	slices.Sort(actual)
	slices.Sort(needs)
	if !slices.Equal(actual, needs) || strings.TrimSpace(jobs["cleanup-unqualified"].If) != condition {
		t.Fatal("failure finalization must wait for all routes and preserve correction success")
	}
	return jobs
}

func TestLive89CorrectionGitAndPayloadBoundary(t *testing.T) {
	if output, err := exec.Command("python3", "-B", ".github/scripts/test_live89_correction_review.py").CombinedOutput(); err != nil {
		t.Fatalf("real Git/archive review: %v\n%s", err, output)
	}
}

func TestLive89CorrectionEvidencePin(t *testing.T) {
	fixture, err := os.ReadFile("cmd/sbxr-release/testdata/live89-correction.json")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(".github/scripts/live89-correction-review.py")
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(fixture))
	if !strings.Contains(string(script), "EVIDENCE = '"+digest+"'") {
		t.Fatal("source review must pin the exact accepted archived evidence bytes")
	}
}

func TestLive89CorrectionWorkflowBinding(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	jobs := assertLive89WorkflowPartition(t, workflow)
	if jobs["live89-correction"].If != "${{ fromJSON(inputs.v3_attempt || '{}').live89_correction_review }}" {
		t.Fatal("correction entry must require its exact declaration")
	}
	if strings.Count(workflow, `python3 .github/scripts/live89-correction-review.py "$GITHUB_SHA"`) != 3 {
		t.Fatal("preflight, signing, and result must independently reproduce the source review")
	}
	for _, required := range []string{
		`.live89_correction_review == $review[0]`,
		`.v3_attempt.live89_correction_review == $review[0]`,
		`stage:"live89-evidence-correction-result"`,
		`archived_evidence:$archived[0].evidence`,
		`karing_latest_checked_at="$(jq -r .karing_latest_checked_at <<<"$V3_ATTEMPT")"`,
		`started_at:$now,karing_latest_checked_at:$karing_latest_checked_at`,
		`python3 .github/scripts/live89-correction-review.py payload "release/sbxr-linux-$target.tar.gz"`,
		`python3 .github/scripts/live89-correction-review.py payload "rechecked/sbxr-linux-$architecture.tar.gz"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("missing correction binding %s", required)
		}
	}
	_, correction, found := strings.Cut(workflow, "  live89-correction:\n")
	if !found {
		t.Fatal("correction job missing")
	}
	if next := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:\n`).FindStringIndex(correction); next != nil {
		correction = correction[:next[0]]
	}
	for _, required := range []string{
		`gh attestation verify qualification-manifest.json`,
		`.github/scripts/recheck-qualified-release.sh expected-release.json rechecked release.json`,
		`.draft == true and .prerelease == false`,
		`.records[0].tag == $tag`,
		`gh release edit "$target_tag" --draft`,
		`name: installer-updater-acceptance-${{ github.run_id }}`,
		`cmd/sbxr-release/testdata/live89-correction.json`,
	} {
		if !strings.Contains(correction, required) {
			t.Fatalf("correction result lost existing trust/record boundary %s", required)
		}
	}
	for _, prohibited := range []string{"ACCEPTANCE_VPS_SSH_PRIVATE_KEY", "ssh -", "v3-qualification-transport.sh", "v3-packaged-live.sh", "git push", "--draft=false"} {
		if strings.Contains(correction, prohibited) {
			t.Fatalf("archival correction must not run live tests or mutate source history: %s", prohibited)
		}
	}
	data, err = os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	stable := string(data)
	for _, required := range []string{
		`python3 .github/scripts/live89-correction-review.py "$run_sha"`,
		`.v3_attempt.live89_correction_review == $review[0]`,
		`python3 .github/scripts/live89-correction-review.py payload "$directory/sbxr-linux-$architecture.tar.gz"`,
		`Prior v3.1.89 live evidence accepted by recording correction; no fresh live run. Original failed workflow and burn preserved.`,
	} {
		if !strings.Contains(stable, required) {
			t.Fatalf("stable correction verification/disclosure missing %s", required)
		}
	}
}

func TestLive89CorrectionWorkflowShellSyntax(t *testing.T) {
	for _, path := range []string{".github/workflows/candidate.yml", ".github/workflows/stable.yml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Jobs map[string]struct {
				Steps []struct {
					Name string `yaml:"name"`
					Run  string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		for job, body := range document.Jobs {
			for _, step := range body.Steps {
				if step.Run == "" {
					continue
				}
				command := exec.Command("bash", "-n")
				command.Stdin = strings.NewReader(step.Run)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("%s/%s/%s: %v\n%s", path, job, step.Name, err, output)
				}
			}
		}
	}
}

func TestLive89CorrectionSkipsOnlyFreshKaringMetadata(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, script, found := strings.Cut(string(data), "            if ! jq -e '.live89_correction_review != null' <<<\"$V3_ATTEMPT\" >/dev/null; then\n")
	if !found {
		t.Fatal("fresh Karing check guard missing")
	}
	script, _, found = strings.Cut(script, "            baseline=")
	if !found {
		t.Fatal("Karing metadata boundary missing")
	}
	script = "if ! jq -e '.live89_correction_review != null' <<<\"$V3_ATTEMPT\" >/dev/null; then\n" + script
	for _, correction := range []bool{false, true} {
		t.Run(fmt.Sprint(correction), func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "gh"), []byte("#!/bin/sh\nprintf called > metadata-called\nexit 41\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			attempt := `{}`
			if correction {
				attempt = `{"live89_correction_review":{"target_tag":"v3.1.90"}}`
			}
			command := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
			command.Dir = directory
			command.Env = append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"), "V3_ATTEMPT="+attempt)
			output, err := command.CombinedOutput()
			_, called := os.Stat(filepath.Join(directory, "metadata-called"))
			if correction && (err != nil || !os.IsNotExist(called)) {
				t.Fatalf("correction performed fresh Karing check: %v %s", err, output)
			}
			if !correction && (err == nil || called != nil || !strings.Contains(string(output), "Official Karing metadata lookup failed.")) {
				t.Fatalf("ordinary fresh qualification lost metadata failure gate: %v %s", err, output)
			}
		})
	}
}
