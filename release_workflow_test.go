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

func TestReleaseQualificationCutoverRemovedObsoletePolicyHelpers(t *testing.T) {
	for _, path := range []string{
		".github/scripts/release-role.sh",
		".github/scripts/write-failed-acceptance-record.sh",
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("obsolete qualification policy helper remains: %s", path)
		}
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
		"grep -F 'SBXR V3'",
		"grep -F 'Proxy status: Not set up'",
		"grep -F 'Start setup'",
		"grep -F 'Complete removal'",
		"go test ./internal/proxyinstallation/adapter/terminal -count=1",
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
		`gh run download "$FAILED_RUN" --repo "$GITHUB_REPOSITORY" --name signed-qualification-manifest`,
		`gh attestation verify failed-normal-boundary/qualification-manifest.json`,
		`.mode == "normal"`,
		"group: installer-updater-release",
		"cancel-in-progress: false",
		"github.ref == 'refs/heads/main'",
		"archive/full-product-v1.0.15",
		"release-burned/",
		"candidate-preflight-facts.json",
		"go run ./cmd/sbxr-release qualification",
		"candidate-preflight-decision.json",
		`.facts_sha256 == $facts_sha256`,
		`select(.type == "build-release")`,
		`select(.type == "use-source-release")`,
		"prepare-burn-tag.sh",
		"git push --atomic origin",
		"releases/latest",
		"gh attestation verify",
		`stage:"acceptance-vps-result"`,
		"ubuntu-24.04",
		"ubuntu-24.04-arm",
		"go run ./cmd/sbxr-release verify-package",
		"sudo env TERM=xterm-256color LANG=C.UTF-8",
		"SBXR requires root authority.",
		"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
		"environment: acceptance-vps",
		"Verify Acceptance VPS readiness before signing",
		"test ! -e /run/sbxr-qualification",
		"actions/runs/$GITHUB_RUN_ID/approvals",
		`stage:"qualification-boundary"`,
		`go run ./cmd/sbxr-release qualification < qualification-boundary-facts.json > qualification-manifest.json`,
		`[.approval.decision_chain[].stage] == ["candidate-preflight","candidate-draft-construction","candidate-draft-verification"]`,
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
		`gh attestation verify "source-a/$name"`,
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
	for _, forbidden := range []string{`{schema:"sbxr-qualification-manifest-v1"`, `.candidate_failure_state_sha256 = $state`} {
		if strings.Contains(sign, forbidden) {
			t.Fatalf("qualification boundary Adapter retained manifest policy %q", forbidden)
		}
	}
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

func TestCandidateNativelyVerifiesTheMenuForEachMode(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	build := string(body)
	build = build[strings.Index(build, "  build:"):strings.Index(build, "  drafts:")]
	const verification = `          case "$MODE" in
            v3)
              grep -F 'SBXR V3' menu.transcript
              grep -F 'Proxy status: Not set up' menu.transcript
              grep -F 'Code: PROXY-INSTALLATION-STATUS-NOT-SET-UP' menu.transcript
              grep -F 'Start setup' menu.transcript
              ;;
            normal|rescue)
              grep -F 'Recovery required' menu.transcript
              grep -F 'Start recovery' menu.transcript
              ;;
          esac`
	if !strings.Contains(build, "MODE: ${{ inputs.mode }}") || !strings.Contains(build, verification) {
		t.Fatal("candidate native verification is not mode-aware")
	}
}

func TestCandidateDraftAdapterUsesOnlyCanonicalQualificationActionsAndObservations(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	drafts := workflow[strings.Index(workflow, "  drafts:"):strings.Index(workflow, "  sign:")]
	for _, required := range []string{
		`stage:"candidate-draft-construction"`,
		`go run ./cmd/sbxr-release qualification < candidate-draft-construction-facts.json > candidate-draft-construction-decision.json`,
		`.facts_sha256 == $facts_sha256`,
		`.prior_decision_sha256 == $prior_decision_sha256`,
		`gh api --method POST "repos/$repository/releases"`,
		`gh api "repos/$repository/releases/$created_release_id" > observed-release.json`,
		`release_id="$(jq -r .id observed-release.json)"`,
		`gh api "repos/$repository/releases/assets/$id" -H 'Accept: application/octet-stream'`,
		`stage:"candidate-draft-verification"`,
		`go run ./cmd/sbxr-release qualification < candidate-draft-verification-facts.json > candidate-draft-verification-decision.json`,
		`jq -c '.verified_releases' candidate-draft-verification-decision.json > verified-drafts.json`,
		`jq -cnS --argjson source "$SOURCE_A" --slurpfile verified verified-drafts.json`,
	} {
		if !strings.Contains(drafts, required) {
			t.Fatalf("candidate draft Adapter omitted %q", required)
		}
	}
	for _, forbidden := range []string{
		`burned="$(for burned_tag`,
		`cmp "$directory/$name" "$downloaded/$tag/$name"`,
		`jq -cS --argjson source "$SOURCE_A" --slurpfile verified verified-drafts.json`,
	} {
		if strings.Contains(drafts, forbidden) {
			t.Fatalf("candidate draft Adapter retained policy %q", forbidden)
		}
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
		`expected_state="$(jq -c --arg tag "$tag" '.[] | select(.tag == $tag) | {draft,immutable,prerelease}' drafts.json)"`,
		`.draft == $state.draft and .prerelease == $state.prerelease and (.immutable // false) == $state.immutable`,
		"go build -o handoff/sbxr-release ./cmd/sbxr-release",
		"install -m 0700 /run/sbxr-qualification/sbxr-release /root/sbxr-qualification-gateway",
		"nohup /root/sbxr-qualification-gateway gateway",
		"/usr/bin/bash /run/sbxr-qualification/installer-updater-vps.sh",
		"command -v strace >/dev/null",
		"printf '\\n127.0.0.1 api.github.com github.com\\n' >> /etc/hosts",
		"rm -f /root/sbxr-qualification-gateway",
		"acceptance-vps-diagnostics-${{ github.run_id }}",
		"qualification-failure-evidence.tgz",
		"if test -d /var/lib/sbxr; then find /var/lib/sbxr -depth -delete; fi",
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
		`stage:"acceptance-vps-result"`,
		"go run ./cmd/sbxr-release qualification < acceptance-vps-result-facts.json > acceptance-vps-result-decision.json",
		"facts_sha256=\"$(sha256sum acceptance-vps-result-facts.json | cut -d' ' -f1)\"",
		"prior_decision_sha256=\"$(sha256sum handoff/qualification-manifest.json | cut -d' ' -f1)\"",
		`"a": release("A")`,
		`"b": release("B")`,
		`"qualification_manifest_sha256": manifest_sha256`,
		`observed_at="$(jq -r .observed_at handoff/acceptance-vps-evidence.json)"`,
		`jq -jr --arg tag "$tag" '.records[] | select(.tag == $tag) | .body' acceptance-vps-result-decision.json > "$record"`,
		"retention-days: 90",
	} {
		if !strings.Contains(acceptanceSources, required) {
			t.Fatalf("candidate.yml omitted Acceptance VPS contract %q", required)
		}
	}
	if strings.Contains(string(script), "if test ! -e /var/lib/sbxr/update.json; then\n        kill -CONT") {
		t.Fatal("candidate VPS loop signals the updater before a durable record exists")
	}
	acceptance := string(body)[strings.Index(string(body), "  acceptance-vps:"):strings.Index(string(body), "  cleanup-unqualified:")]
	for _, forbidden := range []string{`canonical="$(jq -cnS`, `echo '# SBXR Installer-Updater Acceptance Record'`, `.github/scripts/release-role.sh`, `source_state="$(jq -r .source_state qualification-manifest.json)"`, "              REMOTE\n"} {
		if strings.Contains(acceptance, forbidden) {
			t.Fatalf("candidate Acceptance VPS Adapter retained record policy %q", forbidden)
		}
	}
	assertActionsPinned(t, acceptanceSources)
}

func TestCandidatePreflightUsesOnlyCanonicalQualificationActions(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	preflight := workflow[strings.Index(workflow, "  preflight:"):strings.Index(workflow, "  build:")]
	for _, required := range []string{
		`schema:"sbxr-release-qualification-facts-v1"`,
		`stage:"candidate-preflight"`,
		`go run ./cmd/sbxr-release qualification < candidate-preflight-facts.json > candidate-preflight-decision.json`,
		`.schema == "sbxr-release-qualification-decision-v1"`,
		`if .type == "build-release" then`,
		`elif .type == "use-source-release" then`,
		`else false end`,
		`--slurpfile fact release-fact.json`,
		`--slurpfile releases release-facts.json`,
		`.sequence == (.sequence | floor)`,
		`gh api "repos/$GITHUB_REPOSITORY/releases/$release_id" > source-a-release.json`,
		`test "$(sha256sum "source-a/$name" | cut -d' ' -f1)" = "$(jq -r .sha256 <<<"$expected")"`,
	} {
		if !strings.Contains(preflight, required) {
			t.Fatalf("candidate preflight omitted Adapter contract %q", required)
		}
	}
	for _, forbidden := range []string{
		`highest_sequence=`,
		`source_state=initial-normal`,
		`source_state=later-normal`,
		`source_state=rescue`,
		`test "$B_SEQUENCE" -gt "$A_SEQUENCE"`,
		`--argjson fact "$fact"`,
		`--argjson releases "$(cat release-facts.json)"`,
		`.sequence == floor`,
	} {
		if strings.Contains(preflight, forbidden) {
			t.Fatalf("candidate preflight retained policy %q", forbidden)
		}
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

func TestCandidateRoutesOneV3CandidateThroughPackagedLiveQualification(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	scriptBody, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	v3Path := workflow + "\n" + string(scriptBody)
	stableBody, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	stable := string(stableBody)
	for _, required := range []string{
		"- v3",
		"v3-clean",
		"docs/acceptance/v3-packaged-live.md",
		".github/scripts/v3-packaged-live.sh",
		"v3-packaged-live-evidence.json",
		`stage:"v3-packaged-live-result"`,
		"v3-packaged-live-result-facts.json",
		"v3-packaged-live-result-decision.json",
		"/dev/shm/sbxr-v3-client.json",
		`${RUNNER_TEMP:?}/sbxr-v3-client`,
		"chmod 0600",
		"SIGSTOP",
		"SIGKILL",
		"'Validate configuration'",
		"'Activation committed'",
		"'Removal committed'",
		"fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
		"RELEASE-V3-PACKAGED-LIVE-QUALIFICATION",
		`(.records | length) == 1`,
	} {
		if !strings.Contains(v3Path, required) {
			t.Fatalf("candidate.yml omitted V3 qualification contract %q", required)
		}
	}
	if strings.Contains(v3Path, "client_root=/dev/shm/") {
		t.Fatal("V3 qualification executes the outside client from the runner's noexec /dev/shm mount")
	}
	if strings.Count(v3Path, `test ! -e "$client_root"`) < 2 {
		t.Fatal("V3 qualification does not prove outside-client cleanup on success and failure")
	}
	for _, mode := range []string{"remote-failure-safety", "remote-setup-and-disclose", "remote-secret-safe", "remote-remove"} {
		if !strings.Contains(v3Path, "/usr/bin/bash $WORK/v3-packaged-live.sh "+mode) {
			t.Fatalf("V3 qualification directly executes %s from the noexec /run mount", mode)
		}
	}
	for _, required := range []string{"stable-v3-finalization", "v3-finalization-failure", `v3_packaged_live == "Passed"`, `complete_removal == "Passed"`, "stable-v3-finalization-facts.json", "stable-v3-finalization-decision.json"} {
		if !strings.Contains(stable, required) {
			t.Fatalf("stable.yml omitted V3 finalization contract %q", required)
		}
	}
	for _, forbidden := range []string{"v2.0.43", "pause-v3", "test-mode-v3"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("candidate.yml invented V3 qualification authority %q", forbidden)
		}
	}
	assertActionsPinned(t, workflow)
	assertActionsPinned(t, stable)
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
		"needs: [preflight, drafts, sign, acceptance-vps]",
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
