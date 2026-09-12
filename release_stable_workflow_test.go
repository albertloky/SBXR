package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBurnEvidenceTagCanBeRetriedOnlyWithTheExactPayload(t *testing.T) {
	directory := t.TempDir()
	run := func(arguments ...string) string {
		t.Helper()
		command := exec.Command(arguments[0], arguments[1:]...)
		command.Dir = directory
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", arguments, err, output)
		}
		return string(output)
	}
	run("git", "init", "-q")
	run("git", "config", "user.name", "test")
	run("git", "config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(directory, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "file")
	run("git", "commit", "-qm", "initial")
	if err := os.WriteFile(filepath.Join(directory, "payload.json"), []byte("{\"reason\":\"failure\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(run("git", "rev-parse", "HEAD"))
	script, err := filepath.Abs(".github/scripts/prepare-burn-tag.sh")
	if err != nil {
		t.Fatal(err)
	}
	if first := run(script, "payload.json", "v2.0.0", commit); first != "refs/tags/release-burned/v2.0.0\n" {
		t.Fatalf("first burn tag output = %q", first)
	}
	if retry := run(script, "payload.json", "v2.0.0", commit); retry != "" {
		t.Fatalf("exact retry output = %q", retry)
	}
}

func TestStablePublishesOnlyTheSignedQualifiedDraftsAndProvesStableNoUpdate(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	preflight := workflow[strings.Index(workflow, "  preflight:"):strings.Index(workflow, "  publish:")]
	if !strings.Contains(preflight, "contents: write") {
		t.Fatal("stable preflight cannot read candidate-owned draft releases")
	}
	for _, required := range []string{
		`2> latest-release.error`,
		`jq -e 'type == "object" and (.tag_name | type == "string" and length > 0) and (.id | type == "number" and . > 0 and . == floor)' latest-release.json`,
		`grep -Fxq 'gh: Not Found (HTTP 404)' latest-release.error`,
		`cat latest-release.error >&2`,
		`exit 1`,
	} {
		if !strings.Contains(preflight, required) {
			t.Fatalf("stable preflight does not distinguish absent Latest from observation failure: omitted %q", required)
		}
	}
	if strings.Contains(preflight, `releases/latest" > latest-release.json 2>/dev/null`) {
		t.Fatal("stable preflight maps every Latest observation failure to absence")
	}
	for _, required := range []string{
		"workflow_dispatch:",
		"qualification_run_id:",
		"group: installer-updater-release",
		"cancel-in-progress: false",
		"github.ref == 'refs/heads/main'",
		"environment: acceptance-vps",
		"environment: stable-publication",
		".github/workflows/candidate.yml",
		"conclusion:$candidate_run[0].conclusion",
		"gh attestation verify qualification-manifest.json",
		"archive/full-product-v1.0.15",
		"release-burned/",
		"acceptance-vps-result-facts.json",
		"acceptance-vps-result-decision.json",
		`stage:"stable-preflight"`,
		"stable-preflight-facts.json",
		"stable-preflight-decision.json",
		`stage:"stable-publication"`,
		"stable-publication-facts.json",
		"stable-publication-decision.json",
		`stage:"stable-publication-verification"`,
		"stable-publication-verification-facts.json",
		"stable-publication-verification-decision.json",
		"go run ./cmd/sbxr-release verify-public-latest",
		"stable-publication-decisions-${{ github.run_id }}",
		"path: publication-evidence",
		`type == "observe-stable-release"`,
		`test "$outcome" = "propagation-pending"`,
		"signed_manifest:$signed_manifest[0]",
		`jq -cnS --argjson expected "$release" --slurpfile assets assets.json --slurpfile metadata "$metadata"`,
		"commit:$metadata[0].target_commitish",
		"go run ./cmd/sbxr-release qualification",
		`all(.actions[]; .type == "publish-stable-release" and .facts_sha256 == $facts_sha256 and .prior_decision_sha256 == $prior_decision_sha256)`,
		`gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"`,
		`jq -r .failure_reason`,
		"-F draft=false",
		"-F prerelease=false",
		"-f make_latest=true",
		"for attempt in $(seq 1 60)",
		"check_deadline=$((SECONDS + 600))",
		`test "$SECONDS" -lt "$check_deadline"`,
		"predicate_type=release",
		"Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT",
		"releases/latest/download/install.sh",
		"latest_install_sha256:$latest_install_sha256",
		`stage:"stable-no-update"`,
		"stable-no-update-facts.json",
		"stable-no-update-decision.json",
		"stable_no_update_decision_sha256",
		"find /var/lib/sbxr -mindepth 1 -maxdepth 1 -printf '%f\\n'",
		"StrictHostKeyChecking=yes",
		"rm -f /run/sbxr-stable-original-session",
		"retention-days: 90",
		"contents: write",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("stable.yml omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		"sbxr-components-",
		"acceptance staged-onboarding",
		"validate-package-qualification",
		"inputs.tag",
		"go run ./cmd/sbxr-release -tag",
		"actions/checkout@v",
		"actions/setup-go@v",
		"actions/upload-artifact@v",
		"actions/download-artifact@v",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("stable.yml retained %q", forbidden)
		}
	}
	publication := workflow[strings.Index(workflow, "  publish:"):strings.Index(workflow, "  finalize-failure:")]
	for _, required := range []string{
		`2> "$directory.latest-release.error"`,
		`[[ "$latest" =~ ^[1-9][0-9]*$ ]] || return 1`,
		`grep -Fxq 'gh: Not Found (HTTP 404)' "$directory.latest-release.error"`,
		`cat "$directory.latest-release.error" >&2`,
		`return 1`,
	} {
		if !strings.Contains(publication, required) {
			t.Fatalf("stable publication observer does not distinguish absent Latest from observation failure: omitted %q", required)
		}
	}
	if strings.Contains(publication, `releases/latest" --jq .id 2>/dev/null`) {
		t.Fatal("stable publication observer maps every Latest observation failure to absence")
	}
	for _, forbidden := range []string{`.source_state == "initial-normal"`, `sbxr-acceptance-record-v1`, `test "$((now - created))" -lt "$((90 * 24 * 60 * 60))"`, `.path == ".github/workflows/candidate.yml"`, `test "$run_sha" = "$GITHUB_SHA"`} {
		if strings.Contains(preflight+publication, forbidden) {
			t.Fatalf("stable preflight retained policy %q", forbidden)
		}
	}
	approval := strings.Index(publication, `name == "stable-publication"`)
	recheck := strings.Index(publication, `stage:"stable-publication"`)
	action := strings.Index(publication, `.type == "publish-stable-release"`)
	publish := strings.Index(publication, `gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"`)
	verify := strings.Index(publication, `stage:"stable-publication-verification"`)
	accepted := strings.Index(publication, `.outcome == "accepted"`)
	if approval < 0 || !(approval < recheck && recheck < action && action < publish && publish < verify && verify < accepted) {
		t.Fatal("stable publication does not recheck and verify each approved draft before advancing")
	}
	assertActionsPinned(t, workflow)
}

func TestReleaseFailuresWithdrawOnlyRecheckedTargetsAndBurnQualifiedIdentities(t *testing.T) {
	candidateBody, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	stableBody, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	recheckBody, err := os.ReadFile(".github/scripts/recheck-qualified-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	burnBody, err := os.ReadFile(".github/scripts/prepare-burn-tag.sh")
	if err != nil {
		t.Fatal(err)
	}
	candidate, stable, recheck, burn := string(candidateBody), string(stableBody), string(recheckBody), string(burnBody)
	for _, required := range []string{
		"needs: [preflight, drafts, sign, acceptance-vps, owner-exception]",
		"needs.acceptance-vps.result != 'success'",
		"--draft=false --prerelease --latest=false",
		"post-sign-qualification-failure",
		"defect-issue.json",
		`{is_pull_request:has("pull_request"),state,url:.html_url}`,
		"Publish the rechecked burned releases as failed prereleases",
		"fully recorded unsigned drafts",
		`stage:"candidate-failure-finalization"`,
		"candidate-failure-facts.json",
		"candidate-failure-decision.json",
		`all(.actions[]; .type == "finalize-failed-release" and .facts_sha256 == $facts_sha256 and .prior_decision_sha256 == $prior_decision_sha256)`,
		`jq -jr .body <<<"$action"`,
		`if jq -e .burn_required <<<"$action"`,
		`stage:"candidate-failure-verification"`,
		"candidate-failure-verification-decision.json",
	} {
		if !strings.Contains(candidate, required) {
			t.Fatalf("candidate.yml omitted qualified-failure contract %q", required)
		}
	}
	for _, required := range []string{
		"operation:",
		"- publish",
		"- abandon",
		"finalize-failure:",
		"if: always()",
		"publication-stage",
		"stable-no-update-failure",
		`git merge-base --is-ancestor "$(jq -r .workflow.commit "$manifest")" "$(jq -r .head_sha stable-run.json)"`,
		"candidate_commit_ancestor:true",
		`stage:"stable-failure-finalization"`,
		"stable-failure-facts.json",
		"stable-failure-decision.json",
		`all(.actions[]; .type == "finalize-stable-failure"`,
		"Perform only the decided failure actions",
		`.publish_failed_prerelease`,
		`.delete_release`,
		`.delete_tag`,
		`jq -jr .body <<<"$action"`,
		"gh api --method DELETE \"repos/$GITHUB_REPOSITORY/releases/$release_id\"",
		"gh api --method DELETE \"repos/$GITHUB_REPOSITORY/git/refs/tags/$tag\"",
		"release-burned/$tag",
		"git push --atomic origin",
		`stage:"stable-failure-verification"`,
		"stable-failure-verification-decision.json",
	} {
		if !strings.Contains(stable, required) {
			t.Fatalf("stable.yml omitted withdrawal contract %q", required)
		}
	}
	for _, required := range []string{
		".id == $release_id and .tag_name == $tag and .target_commitish == $commit",
		"$release.release_identity == {repository:$repository,tag:$tag,commit:$commit,release_index_sha256:$index}",
		"sha256sum \"$directory/release-index.json\"",
	} {
		if !strings.Contains(recheck, required) {
			t.Fatalf("release recheck omitted %q", required)
		}
	}
	if strings.Count(candidate, ".github/scripts/recheck-qualified-release.sh") < 2 || strings.Count(stable, ".github/scripts/recheck-qualified-release.sh") < 2 {
		t.Fatal("release mutations do not share the exact qualified-target recheck")
	}
	if !strings.Contains(burn, "git rev-parse -q --verify") || !strings.Contains(burn, "$(cat \"$payload\")") || strings.Count(candidate, ".github/scripts/prepare-burn-tag.sh") < 1 || strings.Count(stable, ".github/scripts/prepare-burn-tag.sh") < 2 {
		t.Fatal("burn evidence is not exact and retry-safe")
	}
	candidateFailure := candidate[strings.Index(candidate, "cleanup-unqualified:"):]
	if !strings.Contains(candidateFailure, "gh attestation verify boundary/qualification-manifest.json") ||
		!strings.Contains(candidateFailure, `.workflow.ref == "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main"`) ||
		strings.Index(candidateFailure, "git push --atomic origin") > strings.Index(candidateFailure, `gh release edit "$tag"`) ||
		strings.Contains(candidateFailure, `jq -nS --arg original_tag`) ||
		strings.Contains(candidateFailure, `write-failed-acceptance-record.sh`) {
		t.Fatal("candidate failure handling does not verify and burn every identity before release mutation")
	}
	stableFailure := stable[strings.Index(stable, "finalize-failure:"):]
	if strings.Index(stableFailure, "git push --atomic origin") > strings.Index(stableFailure, `gh release edit "$tag"`) ||
		strings.Index(stableFailure, "git push --atomic origin") > strings.Index(stableFailure, `gh api --method DELETE "repos/$GITHUB_REPOSITORY/releases/$release_id"`) ||
		!strings.Contains(stableFailure, `jq -S .burn <<<"$action"`) ||
		!strings.Contains(stableFailure, `.github/scripts/prepare-burn-tag.sh "failure/burned/$tag.json" "$tag" "$commit" >/dev/null`) ||
		!strings.Contains(stableFailure, `test "$actual_burn" = "$expected_burn"`) {
		t.Fatal("stable failure Adapter does not attest burns before exact decided mutations and verify their results")
	}
	assertActionsPinned(t, candidate)
	assertActionsPinned(t, stable)
}
