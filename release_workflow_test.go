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

func TestContinuousVerificationBuildsAndRunsTheFourAssetPackageNatively(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/verify.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"pull_request:",
		"cancel-in-progress: true",
		"permissions:\n  contents: read",
		"ubuntu-24.04",
		"ubuntu-24.04-arm",
		"go run ./cmd/sbxr-release",
		"go run ./cmd/sbxr-release bootstrap",
		"go run ./cmd/sbxr-release index",
		"go run ./cmd/sbxr-release verify-package",
		"sbxr-linux-amd64.tar.gz",
		"sbxr-linux-arm64.tar.gz",
		"sudo env TERM=xterm-256color LANG=C.UTF-8",
		"/var/lib/sbxr/installed.json",
		"Update in progress",
		"go test ./internal/softwarelifecycle/adapter/terminal -count=1",
		"go test ./... -count=1",
		"go test -race ./internal/softwarelifecycle",
		"go test -race ./... -count=1",
		"go vet ./...",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("verify.yml omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		"sbxr-components-",
		"acceptance staged-onboarding",
		"validate-package-qualification",
		"package-qualification-",
		"actions/checkout@v7",
		"actions/setup-go@v7",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("verify.yml retained %q", forbidden)
		}
	}
	assertActionsPinned(t, workflow)
}

func TestCandidateConstructsDraftsAndSignsTheQualificationBoundary(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"workflow_dispatch:",
		"type: choice",
		"- normal",
		"- rescue",
		"failed_normal_run_id:",
		"defect_issue_url:",
		"group: installer-updater-release",
		"cancel-in-progress: false",
		"github.ref == 'refs/heads/main'",
		"archive/full-product-v1.0.15",
		"release-burned/",
		"used-sequences.json",
		"qualification_run_url",
		"prepare-burn-tag.sh",
		"git push --atomic origin",
		"releases/latest",
		"gh attestation verify",
		"RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION",
		"ubuntu-24.04",
		"ubuntu-24.04-arm",
		"go run ./cmd/sbxr-release verify-package",
		"sudo env TERM=xterm-256color LANG=C.UTF-8",
		"SBXR requires root authority.",
		"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
		"gh api --method POST \"repos/$GITHUB_REPOSITORY/releases\"",
		"--draft",
		"gh api \"repos/$GITHUB_REPOSITORY/releases/assets/",
		"cmp \"$directory/$name\" \"downloaded/$tag/$name\"",
		"environment: acceptance-vps",
		"actions/runs/$GITHUB_RUN_ID/approvals",
		"qualification-manifest.json",
		"actions/attest-build-provenance@",
		"subject-path: qualification-manifest.json",
		"retention-days: 90",
		"attestations: write",
		"id-token: write",
		"contents: write",
		"cleanup-unqualified:",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("candidate.yml omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		"release:\n    types:",
		"sbxr-components-",
		"acceptance staged-onboarding",
		"actions/checkout@v",
		"actions/setup-go@v",
		"actions/upload-artifact@v",
		"actions/download-artifact@v",
		"actions/attest-build-provenance@v",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("candidate.yml retained %q", forbidden)
		}
	}
	assertActionsPinned(t, workflow)
	sign := workflow[strings.Index(workflow, "  sign:"):strings.Index(workflow, "  acceptance-vps:")]
	attestation := strings.LastIndex(sign, "uses: actions/attest-build-provenance@")
	manifestUpload := strings.LastIndex(sign, "name: signed-qualification-manifest")
	if manifestUpload < 0 || attestation < manifestUpload {
		t.Fatal("qualification attestation is not the final signing step")
	}
	cleanup := workflow[strings.Index(workflow, "cleanup-unqualified:"):]
	if strings.Contains(cleanup, "A_TAG:") || strings.Contains(cleanup, "B_TAG:") || !strings.Contains(cleanup, "BUILD_RELEASES:") {
		t.Fatal("unsigned cleanup is not limited to releases built by this run")
	}
}

func TestCandidateQualifiesTheManifestBoundTwoReleaseJourneyOnTheAcceptanceVPS(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(".github/scripts/installer-updater-vps.sh")
	if err != nil {
		t.Fatal(err)
	}
	acceptanceSources := string(body) + string(script)
	for _, required := range []string{
		"  acceptance-vps:",
		"needs: [preflight, sign]",
		"environment: acceptance-vps",
		"ACCEPTANCE_VPS_HOST",
		"ACCEPTANCE_VPS_HOST_KEY",
		"ACCEPTANCE_VPS_SSH_PRIVATE_KEY",
		"StrictHostKeyChecking=yes",
		"gh attestation verify qualification-manifest.json",
		"go build -o handoff/sbxr-release ./cmd/sbxr-release",
		"install -m 0700 /run/sbxr-qualification/sbxr-release /root/sbxr-qualification-gateway",
		"nohup /root/sbxr-qualification-gateway gateway",
		"/usr/bin/bash /run/sbxr-qualification/installer-updater-vps.sh",
		"command -v strace >/dev/null",
		"printf '\\n127.0.0.1 api.github.com github.com\\n' >> /etc/hosts",
		"rm -f /root/sbxr-qualification-gateway",
		"curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash",
		"SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE",
		"grep -F \"Latest stable version: $B_TAG\" check-b.transcript",
		"start_update \"$transcript\" early",
		"UPDATE_TRACE=\"$transcript.strace\"",
		"menu 2 120 \"$UPDATE_TRACE\"",
		"strace -qq -f -yy -e trace=fsync,rename,renameat,renameat2 -e inject=fsync:delay_exit=100ms",
		"durable_update_count()",
		"durable_activation_count()",
		"usr\\/local\\/bin>.*\"sbxr\"",
		"= 0( \\(DELAYED\\))?$",
		"syncing[$1]=1",
		"<\\.\\.\\. fsync resumed>\\).* = 0( \\(DELAYED\\))?$",
		"current_executable=$(sha256sum /usr/local/bin/sbxr | cut -d' ' -f1)",
		"prepared:Prepared:$A_TAG:$prior_executable:1:0",
		"activated:Prepared:$B_TAG:$candidate_executable:1:1",
		"committed:Committed:$B_TAG:$candidate_executable:2:1",
		"test \"$mode\" = early && return 0",
		"UPDATE_WRAPPER=$(pgrep -P \"$UPDATE_DRIVER\" -x script)",
		"kill -CONT \"$UPDATE_WRAPPER\" 2>/dev/null || true",
		"grep -F 'Checking the qualified latest release' \"$transcript\" >/dev/null 2>&1 && return 0",
		"if test ! -e /var/lib/sbxr/update.json; then",
		"grep -F 'Checking the qualified latest release' \"$transcript\" >/dev/null 2>&1 && break",
		"SOFTWARE-LIFECYCLE-INSTALL-CONCURRENT-MUTATION",
		"SOFTWARE-LIFECYCLE-CHECK-CONCURRENT-CHANGE",
		"prepared:Prepared:$A_TAG",
		"committed:Committed:$B_TAG",
		"/var/lib/sbxr/installed.json",
		"/run/lock/sbxr.lock",
		"update-ca-certificates --fresh",
		"sbxr-acceptance-record-v1",
		"Acceptance time: $accepted_at",
		"RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION",
		"Owner Acceptance: Not required",
		"retention-days: 90",
	} {
		if !strings.Contains(acceptanceSources, required) {
			t.Fatalf("candidate.yml omitted Acceptance VPS contract %q", required)
		}
	}
	if strings.Contains(string(script), "if test ! -e /var/lib/sbxr/update.json; then\n        kill -CONT") {
		t.Fatal("candidate VPS loop signals the updater before a durable record exists")
	}
	assertActionsPinned(t, acceptanceSources)
}

func TestCandidatePreservesFailureEvidenceAndAdvancesAfterBurnedInitialPair(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	acceptance := workflow[strings.Index(workflow, "  acceptance-vps:"):strings.Index(workflow, "  cleanup-unqualified:")]
	checkout := strings.Index(acceptance, "uses: actions/checkout@")
	initialize := strings.Index(acceptance, "name: Initialize exact candidate failure evidence")
	if checkout < 0 || initialize < 0 || checkout > initialize {
		t.Fatal("Acceptance VPS failure evidence is initialized before checkout can clean the workspace")
	}
	sequenceExpression := `[$used[].sequence, $burned[].sequence] | max // 16`
	for _, required := range []string{
		`highest_sequence="$(jq -n --argjson used "$(cat used-sequences.json)" --argjson burned "$burned" '` + sequenceExpression + `')"`,
		`test "$A_SEQUENCE" -eq "$((highest_sequence + 1))"`,
		`test "$B_SEQUENCE" -eq "$((A_SEQUENCE + 1))"`,
		`if test "$highest_sequence" -eq 16; then`,
		`test "$A_TAG" = v2.0.0`,
		`test "$B_TAG" = v2.0.1`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("candidate.yml omitted failed-initial-pair retry contract %q", required)
		}
	}
	command := exec.Command("jq", "-nr", "--argjson", "used", `[{"sequence":16}]`, "--argjson", "burned", `[{"sequence":17},{"sequence":18}]`, sequenceExpression)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("select highest used or burned sequence: %v\n%s", err, output)
	}
	if string(output) != "18\n" {
		t.Fatalf("highest used or burned sequence = %q, want 18", output)
	}
}

func TestStablePublishesOnlyTheSignedQualifiedDraftsAndProvesStableNoUpdate(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"workflow_dispatch:",
		"qualification_run_id:",
		"group: installer-updater-release",
		"cancel-in-progress: false",
		"github.ref == 'refs/heads/main'",
		"environment: acceptance-vps",
		"environment: stable-publication",
		".github/workflows/candidate.yml",
		"conclusion == \"success\"",
		"90 * 24 * 60 * 60",
		"gh attestation verify qualification-manifest.json",
		"archive/full-product-v1.0.15",
		"release-burned/",
		"sbxr-acceptance-record-v1",
		"find \"$directory\" -maxdepth 1 -type f",
		"install.sh",
		"release-index.json",
		"sbxr-linux-amd64.tar.gz",
		"sbxr-linux-arm64.tar.gz",
		"gh release edit",
		"recheck_draft 0",
		"recheck_draft 1",
		"--draft=false",
		"--prerelease=false",
		"--latest",
		"for attempt in $(seq 1 60)",
		"predicate_type=release",
		"Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT",
		"releases/latest/download/install.sh",
		"cmp latest-install.sh pinned-install.sh",
		"SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT",
		"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT",
		"SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT",
		"find /var/lib/sbxr -mindepth 1 -maxdepth 1 -printf '%f\\n'",
		"StrictHostKeyChecking=yes",
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
	approval := strings.Index(workflow, `name == "stable-publication"`)
	recheckA := strings.Index(workflow, "recheck_draft 0")
	publishA := strings.Index(workflow, `gh release edit "$source_tag"`)
	verifyA := strings.Index(workflow, "verify_public 0 true")
	recheckB := strings.Index(workflow, "recheck_draft 1")
	publishB := strings.Index(workflow, `gh release edit "$latest_tag"`)
	if approval < 0 || !(approval < recheckA && recheckA < publishA && publishA < verifyA && verifyA < recheckB && recheckB < publishB) {
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
	recordBody, err := os.ReadFile(".github/scripts/write-failed-acceptance-record.sh")
	if err != nil {
		t.Fatal(err)
	}
	burnBody, err := os.ReadFile(".github/scripts/prepare-burn-tag.sh")
	if err != nil {
		t.Fatal(err)
	}
	candidate, stable, recheck, record, burn := string(candidateBody), string(stableBody), string(recheckBody), string(recordBody), string(burnBody)
	for _, required := range []string{
		"needs: [preflight, drafts, sign, acceptance-vps]",
		"needs.acceptance-vps.result != 'success'",
		"--draft=false --prerelease --latest=false",
		"post-sign-qualification-failure",
		"defect-issue.json",
		".html_url == env.DEFECT_URL and .state == \"open\"",
		"Publish the rechecked burned releases as failed prereleases",
		"fully recorded unsigned drafts",
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
		"initial-a-public-verification-failure",
		"b-publication-or-verification-failure",
		"stable-no-update-failure",
		"qualification-expired",
		"owner-abandoned",
		"Publish prepublication failures as rechecked failed prereleases",
		"gh api --method DELETE \"repos/$GITHUB_REPOSITORY/releases/$release_id\"",
		"gh api --method DELETE \"repos/$GITHUB_REPOSITORY/git/refs/tags/$tag\"",
		"release-burned/$tag",
		"git push --atomic origin",
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
	for _, required := range []string{"Status: Failed prerelease", "Go toolchain:", "Public verifier:", "Qualification role:", "Integrated Verification:", "Codex Live Acceptance:", "evidence:"} {
		if !strings.Contains(record, required) {
			t.Fatalf("failed Acceptance Record omitted %q", required)
		}
	}
	if !strings.Contains(burn, "git rev-parse -q --verify") || !strings.Contains(burn, "$(cat \"$payload\")") || strings.Count(candidate, ".github/scripts/prepare-burn-tag.sh") < 1 || strings.Count(stable, ".github/scripts/prepare-burn-tag.sh") < 2 {
		t.Fatal("burn evidence is not exact and retry-safe")
	}
	candidateFailure := candidate[strings.Index(candidate, "cleanup-unqualified:"):]
	if !strings.Contains(candidateFailure, "gh attestation verify boundary/qualification-manifest.json") ||
		!strings.Contains(candidateFailure, `.workflow.ref == "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main"`) ||
		strings.Index(candidateFailure, "git push --atomic origin") > strings.Index(candidateFailure, `gh release edit "$tag"`) {
		t.Fatal("candidate failure handling does not verify and burn every identity before release mutation")
	}
	stableFailure := stable[strings.Index(stable, "finalize-failure:"):]
	if strings.Index(stableFailure, "git push --atomic origin") > strings.Index(stableFailure, `gh release edit "$tag"`) ||
		!strings.Contains(stableFailure, "if: steps.failure.outputs.outcome == 'withdraw'") ||
		!strings.Contains(stableFailure, "if: steps.failure.outputs.outcome == 'failed-prerelease'") {
		t.Fatal("stable failure handling does not burn before its approved withdrawal or failed-prerelease outcome")
	}
	assertActionsPinned(t, candidate)
	assertActionsPinned(t, stable)
}

func assertActionsPinned(t *testing.T, workflow string) {
	t.Helper()
	for _, line := range strings.Split(workflow, "\n") {
		if strings.Contains(line, "uses: actions/") {
			parts := strings.Split(line, "@")
			if len(parts) != 2 || len(strings.TrimSpace(parts[1])) != 40 {
				t.Fatalf("Action is not pinned to a full commit: %q", line)
			}
		}
	}
}
