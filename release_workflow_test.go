package architecture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func TestRecurringV3UsesTheExistingQualificationWorkflow(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"v3_attempt:", "evidence_version:3", "v3-subscription-clean", "sbxr-qualification-manifest-v3", "subscription_history", "release-history.sh", "candidate_index", "-support release-support.json", "v3-recurring", "sbxr-qualification-manifest-v2", "v3-recurring-evidence.sh", "RELEASE-V3-SUBSCRIPTION-QUALIFICATION", "go run ./cmd/sbxr-release verify-public-latest"} {
		if !strings.Contains(string(workflow), required) {
			t.Fatalf("missing recurring workflow contract %q", required)
		}
	}
	stable, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(stable), "bash .github/scripts/release-history.sh current-release-history.json") != 2 || strings.Count(string(stable), "subscription_history:{complete:true") != 2 {
		t.Fatal("publication must recheck history before and after approval")
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/release-history.sh").CombinedOutput(); err != nil {
		t.Fatalf("history collector syntax: %v %s", err, output)
	}
	collector, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"v3-scenario-result", "v3-scenario-failure", "stop_test_mutations", "qualification <", "completed_at", "300", "7200", "STOP", "failure-recorded", "retained-failure.json", ".failure.scenario_id == $scenario"} {
		if !strings.Contains(string(collector), required) {
			t.Fatalf("missing evidence handoff contract %q", required)
		}
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-recurring-evidence.sh").CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v\n%s", err, output)
	}
}

func TestRecurringCollectorPreservesScenarioInputAndLastFailureIdentity(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, loop, found := strings.Cut(string(source), "\nindex=0\n")
	header, _, hasBody := strings.Cut(loop, "  index=$((index + 1))\n")
	_, ending, hasEnd := strings.Cut(loop, "  reason=unexpected-failure\n")
	footer, _, _ := strings.Cut(ending, "\n")
	if !found || !hasBody || !hasEnd || !strings.Contains(footer, ".v3_attempt.required_scenarios[]") {
		t.Fatal("scenario loop boundaries not found")
	}
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"v3_attempt":{"required_scenarios":["baseline-clean","baseline-refusal","karing-final"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{":", "cat >/dev/null"} {
		t.Run(child, func(t *testing.T) {
			// A real child consumes stdin just as ssh does; use the collector's
			// unchanged loop boundaries, without a network or live evidence.
			script := "set -euo pipefail\nmanifest=" + strconv.Quote(manifest) + "\nscenario=baseline-clean\n" + header + child + "\nprintf '%s\\n' \"$scenario\"\n" + footer + "\nprintf 'last=%s\\n' \"$scenario\"\n"
			command := exec.Command("bash", "-c", script)
			command.Stdin = strings.NewReader("ordinary child input\n")
			output, err := command.CombinedOutput()
			if err != nil || string(output) != "baseline-clean\nbaseline-refusal\nkaring-final\nlast=karing-final\n" {
				t.Fatalf("scenario loop lost input or failure identity: %v, output = %q", err, output)
			}
		})
	}
}

func TestSigningUsesVerifiedIndexArtifactWithoutDraftReadPermission(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	sign := workflow[strings.Index(workflow, "  sign:"):strings.Index(workflow, "  acceptance-vps:")]
	if strings.Contains(sign, "candidate-metadata.json") || !strings.Contains(sign, "contents: read") || !strings.Contains(workflow, "downloaded/*/release-index.json") || !strings.Contains(sign, `candidate_index="downloaded/$(jq -r '.[0].tag' drafts.json)/release-index.json"`) || !strings.Contains(sign, `--rawfile candidate_index "$candidate_index"`) {
		t.Fatal("signing must bind the already verified index artifact without reading a private draft")
	}
}

func TestRepairAutomatedEvidenceRunsBeforeNativeAssets(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	build := workflow[strings.Index(workflow, "  build:"):strings.Index(workflow, "  drafts:")]
	assets := strings.Index(build, "mkdir -m 0700 release evidence")
	for _, required := range []string{
		`test "$MODE" = v3 && test "$(jq -r .support.scope <<<"$V3_ATTEMPT")" = subscription-clean-install-repair`,
		"go test -p 1 -timeout 30m ./... -count=1",
		"go test -race -p 1 -timeout 30m ./... -count=1",
		"go vet ./...", "go mod verify",
	} {
		position := strings.Index(build, required)
		if position < 0 || assets < 0 || position >= assets {
			t.Fatalf("repair native evidence lacks pre-build check %q", required)
		}
	}
}

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

func TestContinuousVerificationScansProducedSurfacesAndRefusesSecretsOrMissingFiles(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/verify.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, step, ok := strings.Cut(string(body), "      - name: Refuse secret markers from package surfaces\n")
	if !ok {
		t.Fatal("missing secret scan step")
	}
	_, pattern, ok := strings.Cut(step, "SECRET_PATTERN: '")
	if !ok {
		t.Fatal("missing secret pattern")
	}
	pattern, _, _ = strings.Cut(pattern, "'")
	_, script, ok := strings.Cut(step, "        run: |\n")
	if !ok {
		t.Fatal("missing scan command")
	}
	script, _, _ = strings.Cut(script, "\n      - ")
	lines := strings.Split(script, "\n")
	for index := range lines {
		lines[index] = strings.TrimPrefix(lines[index], "          ")
	}
	script = strings.Join(lines, "\n")
	surfaces := []string{"dist/package", "inspect/sbxr", "non-root.out", "non-root.err", "menu.transcript", "ready.transcript", "summary"}
	for _, fault := range append([]string{"clean", "missing"}, surfaces...) {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			for _, surface := range surfaces {
				if fault == "missing" && surface == "ready.transcript" {
					continue
				}
				path := filepath.Join(directory, surface)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				body := []byte("secret-safe capture\n")
				if fault == surface {
					body = []byte("subscription-secret-marker\n")
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.CommandContext(t.Context(), "bash", "-e", "-c", script)
			command.Dir = directory
			command.Env = append(os.Environ(), "SECRET_PATTERN="+pattern, "GITHUB_STEP_SUMMARY="+filepath.Join(directory, "summary"))
			output, err := command.CombinedOutput()
			if (err == nil) != (fault == "clean") {
				t.Fatalf("scan fault=%s error=%v output=%s", fault, err, output)
			}
		})
	}
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
	readiness, err := os.ReadFile(".github/scripts/qualification-gateway-readiness.sh")
	if err != nil {
		t.Fatal(err)
	}
	acceptanceSources := string(body) + string(script) + string(readiness)
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
		`nohup "$@"`,
		"/usr/bin/bash /run/sbxr-qualification/installer-updater-vps.sh",
		"command -v strace >/dev/null",
		"printf '\\n127.0.0.1 api.github.com github.com\\n' >> /etc/hosts",
		"rm -f /root/sbxr-qualification-gateway",
		"acceptance-vps-diagnostics-${{ github.run_id }}",
		"qualification-failure-evidence.tgz",
		`/usr/bin/bash /run/sbxr-qualification/v3-packaged-live.sh remote-failure-cleanup "$tag" "$sequence" "$commit" "$index"`,
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
	if !strings.Contains(preflight, "bash .github/scripts/release-history.sh release-facts.json") {
		t.Fatal("preflight must invoke the shared history collector")
	}
	history, err := os.ReadFile(".github/scripts/release-history.sh")
	if err != nil {
		t.Fatal(err)
	}
	preflight += string(history)
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
		`curl -fsSL --retry 3 --retry-all-errors https://deb.sagernet.org/files/ver_qb4px/sing-box_1.13.19_linux_amd64.deb -o "$client_deb"`,
		`PACKAGE_SIZE=24597120`,
		`PACKAGE_SHA256=fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf`,
		`test "$(stat -c %s "$client_deb")" -eq "$PACKAGE_SIZE"`,
		`test "$(sha256sum "$client_deb" | cut -d' ' -f1)" = "$PACKAGE_SHA256"`,
		`.inbounds == [{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}] and (.outbounds | length) == 1`,
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
	download := strings.Index(string(scriptBody), `curl -fsSL --retry 3 --retry-all-errors https://deb.sagernet.org/files/ver_qb4px/sing-box_1.13.19_linux_amd64.deb`)
	size := strings.Index(string(scriptBody), `test "$(stat -c %s "$client_deb")" -eq "$PACKAGE_SIZE"`)
	digest := strings.Index(string(scriptBody), `test "$(sha256sum "$client_deb" | cut -d' ' -f1)" = "$PACKAGE_SHA256"`)
	extract := strings.Index(string(scriptBody), `dpkg-deb -x "$client_deb" "$client_root"`)
	if download < 0 || size < 0 || digest < 0 || extract < 0 || !(download < size && size < digest && digest < extract) {
		t.Fatal("V3 qualification does not verify the exact outside-client package before extraction")
	}
	drift := strings.Index(string(scriptBody), "chmod 0600 /etc/sing-box/config.json")
	refusal := strings.Index(string(scriptBody), "run_action 'Complete removal' 'REMOVE SBXR' 'Code: PROXY-INSTALLATION-ACTION-REFUSED'")
	restore := strings.Index(string(scriptBody), "chmod 0640 /etc/sing-box/config.json")
	if drift < 0 || refusal < 0 || restore < 0 || !(drift < refusal && refusal < restore) {
		t.Fatal("V3 qualification does not apply mode 0600 drift before removal refusal and restore canonical mode 0640 after it")
	}
	interruptLaunch := strings.Index(v3Path, `/usr/local/bin/sbxr <"$fifo"`)
	if interruptLaunch < 0 || !strings.Contains(v3Path[:interruptLaunch], `action="$(menu_number "$label")"`) || !strings.Contains(v3Path[:interruptLaunch], `test -n "$action"`) {
		t.Fatal("V3 qualification resolves and validates an interruption action after launching its target process")
	}
	if strings.Count(v3Path, `test ! -e "$client_root"`) < 2 {
		t.Fatal("V3 qualification does not prove outside-client cleanup on success and failure")
	}
	for _, required := range []string{
		".github/scripts/qualification-gateway-readiness.sh",
		`/usr/bin/bash /run/sbxr-qualification/qualification-gateway-readiness.sh https://api.github.com/repos/albertloky/SBXR/releases/latest /run/sbxr-qualification/gateway.log /run/sbxr-qualification/gateway.pid 60 /root/sbxr-qualification-gateway gateway`,
		`-listen 127.0.0.1:8443`,
		`redirect_comment='sbxr-qualification-${{ github.run_id }}-${{ github.run_attempt }}'`,
		`owned_redirect="-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 443 -m comment --comment $redirect_comment -j REDIRECT --to-ports 8443"`,
		`rules="$(iptables -t nat -S OUTPUT)"`,
		`! grep -Eq -- '^-A OUTPUT -d 127\.0\.0\.1/32 .*--dport 443( .*)? -j REDIRECT --to-ports 8443$' <<<"$rules"`,
		`iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 443 -m comment --comment "$redirect_comment" -j REDIRECT --to-ports 8443`,
		`grep -Fqx -- "$owned_redirect" <<<"$rules"`,
		`iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport 443 -m comment --comment "$redirect_comment" -j REDIRECT --to-ports 8443`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("candidate.yml omitted bounded observable gateway readiness %q", required)
		}
	}
	if strings.Count(workflow, `iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport 443 -m comment --comment "$redirect_comment" -j REDIRECT --to-ports 8443`) < 2 {
		t.Fatal("candidate.yml does not remove the qualification redirect on success and failure")
	}
	if strings.Count(workflow, `redirect_comment='sbxr-qualification-${{ github.run_id }}-${{ github.run_attempt }}'`) < 3 || strings.Count(workflow, `rules="$(iptables -t nat -S OUTPUT)"`) < 5 {
		t.Fatal("candidate.yml does not use run-specific ownership with observable setup and cleanup checks")
	}
	if strings.Contains(workflow, `redirect.owned`) {
		t.Fatal("candidate.yml uses a non-atomic filesystem marker for redirect ownership")
	}
	for _, mode := range []string{"remote-failure-safety", "remote-setup-and-disclose", "remote-secret-safe", "remote-remove"} {
		if !strings.Contains(v3Path, "/usr/bin/bash $WORK/v3-packaged-live.sh "+mode) {
			t.Fatalf("V3 qualification directly executes %s from the noexec /run mount", mode)
		}
	}
	for _, required := range []string{"stable-v3-finalization", "v3-finalization-failure", `v3_packaged_live == $live`, `complete_removal == $live`, "live_result=Passed", "owner-approved-v3.1.0-sequence-83", "stable-v3-finalization-facts.json", "stable-v3-finalization-decision.json"} {
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

func TestV3QualificationAcceptsTheCanonicalClientConfiguration(t *testing.T) {
	script, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "jq -e '"
	start := strings.Index(string(script), prefix+`.inbounds ==`)
	if start < 0 {
		t.Fatal("V3 qualification omitted the Client Configuration predicate")
	}
	start += len(prefix)
	end := strings.Index(string(script)[start:], `' "$client_config"`)
	if end < 0 {
		t.Fatal("V3 qualification Client Configuration predicate is malformed")
	}
	predicate := string(script)[start : start+end]
	want := `.inbounds == [{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}] and (.outbounds | length) == 1`
	if predicate != want {
		t.Fatalf("Client Configuration predicate = %q", predicate)
	}

	adapter := singboxadapter.New()
	identity, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := adapter.EncodeServerConfiguration(identity, "microsoft.com:443", "microsoft.com")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.EncodeClientConfiguration(server, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("jq", "-e", predicate)
	command.Stdin = bytes.NewReader(client)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("live Client Configuration predicate rejected the production encoder: %v\n%s", err, output)
	}
}

func TestPackagedActionReadsItsResultNotLifecycleStatus(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "run_action() {")
	if start < 0 {
		t.Fatal("run_action function not found")
	}
	end := strings.Index(string(source)[start:], "\n}\n\nview_details() {")
	if end < 0 {
		t.Fatal("run_action function not found")
	}
	function := string(source)[start : start+end+2]
	const setup = "Code: PROXY-INSTALLATION-SETUP-COMPLETE"
	const removed = "Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
	const initial = "SBXR V3\n" + setup + "\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n"
	for _, test := range []struct {
		name, after, expected string
		want                  bool
	}{
		{"setup with lifecycle status", "SBXR V3\n" + setup + "\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n", setup, true},
		{"real refusal after prior success", "SBXR V3\nCode: PROXY-INSTALLATION-ACTION-REFUSED\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n", setup, false},
		{"missing action result", "", setup, false},
		{"complete removal without another menu", removed + "\n", removed, true},
		{"refused removal", "Code: PROXY-INSTALLATION-ACTION-REFUSED\n", removed, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command("bash", "-c", "set -euo pipefail\nmenu_number() { printf '1\\n'; }\nscan_vps_capture() { return 0; }\nfunction /usr/local/bin/sbxr { cat >/dev/null; printf '%s' \"$ACTION_OUTPUT\"; }\n"+function+"\nrun_action 'Start setup' y \"$EXPECTED\"\n")
			command.Env = append(os.Environ(), "ACTION_OUTPUT="+initial+test.after, "EXPECTED="+test.expected)
			output, err := command.CombinedOutput()
			if (err == nil) != test.want {
				t.Fatalf("action success = %v, want %v; output: %s", err == nil, test.want, output)
			}
		})
	}
}

func TestPackagedInterruptionRequiresObservedEventAndForcedDeath(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "interrupt_at() {")
	if start < 0 {
		t.Fatal("interrupt_at function not found")
	}
	end := strings.Index(string(source)[start:], "\n}\n\ninstall_candidate() {")
	if end < 0 {
		t.Fatal("interrupt_at function not found")
	}
	for _, test := range []struct {
		name, progress string
		signalFailure  bool
		wantSuccess    bool
	}{
		{name: "missing event", wantSuccess: false},
		{name: "observed event", progress: "Progress: Expected event", wantSuccess: true},
		{name: "signal failure after event", progress: "Progress: Expected event", signalFailure: true, wantSuccess: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			work := filepath.Join(directory, "work")
			binary := filepath.Join(directory, "sbxr")
			pidPath := filepath.Join(directory, "pid")
			if err := os.Mkdir(work, 0o700); err != nil {
				t.Fatal(err)
			}
			fake := "#!/bin/sh\nexec 2>/dev/null\nIFS= read -r _\nif test -n \"$FAKE_PROGRESS\"; then printf '%s\\n' \"$FAKE_PROGRESS\"; fi\nwhile IFS= read -r _; do :; done\n"
			if err := os.WriteFile(binary, []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			function := string(source)[start : start+end+2]
			function = strings.ReplaceAll(function, "/usr/local/bin/sbxr", binary)
			if test.progress == "" {
				// Prove repeated missing observations and cleanup, not the production wait duration.
				function = strings.Replace(function, "seq 1 6000", "seq 1 3", 1)
			}
			function = strings.Replace(function, "local process=$!", "local process=$!\nprintf '%s\\n' \"$process\" > "+strconv.Quote(pidPath), 1)
			if test.signalFailure {
				function = strings.Replace(function, `kill -SIGSTOP "$process" 2>/dev/null`, "false", 1)
			}
			sandbox := "set -euo pipefail\nWORK=" + work + "\nmenu_number() { printf '1\\n'; }\nscan_vps_capture() { return 0; }\n" + function + "\ninterrupt_at 'Start setup' y 'Expected event' test\n"
			script := filepath.Join(directory, "test.sh")
			if err := os.WriteFile(script, []byte(sandbox), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", script)
			command.Env = append(os.Environ(), "FAKE_PROGRESS="+test.progress)
			output, runErr := command.CombinedOutput()
			pidBody, readErr := os.ReadFile(pidPath)
			if readErr == nil {
				defer exec.Command("kill", "-KILL", strings.TrimSpace(string(pidBody))).Run()
			}
			if ctx.Err() != nil {
				t.Fatalf("interruption left the child alive: %v, output = %s", ctx.Err(), output)
			}
			if (runErr == nil) != test.wantSuccess {
				t.Fatalf("interruption error = %v, output = %s", runErr, output)
			}
			if readErr != nil {
				t.Fatalf("fake process PID was not recorded: %v", readErr)
			}
			if exec.Command("kill", "-0", strings.TrimSpace(string(pidBody))).Run() == nil {
				t.Fatal("interruption left the child process alive")
			}
			for _, name := range []string{"input-test", "output-test"} {
				if _, err := os.Lstat(filepath.Join(work, name)); !os.IsNotExist(err) {
					t.Fatalf("%s remains: %v", name, err)
				}
			}
		})
	}
}

func TestPackagedSigningKeyDownloadFollowsRedirectAndChecksDigest(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(source), "runner_stage=download-client-signing-key\n")
	download, _, ended := strings.Cut(rest, "runner_stage=download-client-package\n")
	if !found || !ended {
		t.Fatal("signing-key download block not found")
	}
	const key = "public signing key fixture\n"
	for _, body := range []string{key, "changed key\n"} {
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/gpg.key" {
					http.Redirect(w, r, "/key", http.StatusMovedPermanently)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			script := strings.NewReplacer(
				"https://sing-box.app/gpg.key", server.URL+"/gpg.key",
				"/dev/shm/sagernet.asc", filepath.Join(t.TempDir(), "sagernet.asc"),
				"803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", fmt.Sprintf("%x", sha256.Sum256([]byte(key))),
			).Replace(download)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "bash", "-c", "set -euo pipefail\n"+script).CombinedOutput()
			if (err == nil) != (body == key) {
				t.Fatalf("redirected key verification: %v, output = %s", err, output)
			}
		})
	}
}

func TestPackagedRunnerCleanupRetainsOnlyTheFixedFailedStage(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "\ncleanup() {")
	if start < 0 {
		t.Fatal("runner cleanup function not found")
	}
	start++
	end := strings.Index(string(source)[start:], "\n}\ntrap cleanup EXIT")
	if end < 0 {
		t.Fatal("runner cleanup function not found")
	}
	cleanup := string(source)[start : start+end+2]
	for _, test := range []struct {
		name       string
		exitStatus int
		wantStage  bool
	}{
		{name: "failure", exitStatus: 23, wantStage: true},
		{name: "success", wantStage: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stageEvidence := filepath.Join(directory, "failure-evidence", "runner-stage.txt")
			workflowCapture := filepath.Join(directory, "workflow.log")
			secret := "11111111-1111-4111-8111-111111111111"
			body := "safe capture\n"
			if test.wantStage {
				body += secret + "\n"
			}
			if err := os.WriteFile(workflowCapture, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			sandboxCleanup := strings.ReplaceAll(cleanup, "/dev/shm/sagernet.asc", filepath.Join(directory, "sagernet.asc"))
			sandboxCleanup = strings.ReplaceAll(sandboxCleanup, "/dev/shm/sagernet.sources", filepath.Join(directory, "sagernet.sources"))
			sandbox := fmt.Sprintf("set -u\nclient_config=%q\nclient_root=%q\nclient_deb=%q\nclient_log=%q\nworkflow_capture=%q\nclient_uuid=%q\ndownload=\nrunner_stage=measure-proxied-route\nrunner_stage_evidence=%q\n%s\ntrap cleanup EXIT\nexit %d\n", filepath.Join(directory, "client.json"), filepath.Join(directory, "client"), filepath.Join(directory, "client.deb"), filepath.Join(directory, "client.log"), workflowCapture, secret, stageEvidence, sandboxCleanup, test.exitStatus)
			script := filepath.Join(directory, "cleanup.sh")
			if err := os.WriteFile(script, []byte(sandbox), 0o700); err != nil {
				t.Fatal(err)
			}
			output, runErr := exec.Command("bash", script).CombinedOutput()
			if (runErr != nil) != test.wantStage {
				t.Fatalf("cleanup error = %v, output = %s", runErr, output)
			}
			evidence, readErr := os.ReadFile(stageEvidence)
			if test.wantStage {
				if readErr != nil || string(evidence) != "Runner stage: measure-proxied-route\n" || strings.Contains(string(evidence), secret) {
					t.Fatalf("stage evidence = %q, %v", evidence, readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("successful cleanup retained stage evidence: %q, %v", evidence, readErr)
			}
			if _, err := os.Stat(workflowCapture); !os.IsNotExist(err) {
				t.Fatalf("workflow capture remains: %v", err)
			}
		})
	}
}

func TestCandidateFailureCleanupFinishesOnlyThroughThePublicInterface(t *testing.T) {
	workflowBody, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	scriptBody, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	workflow, script := string(workflowBody), string(scriptBody)
	for _, required := range []string{
		"remote-failure-cleanup",
		"Finish cleanup",
		"PROXY-INSTALLATION-SETUP-CLEANED-UP",
		"Finish setup",
		"PROXY-INSTALLATION-SETUP-COMPLETE",
		"Finish removal",
		"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED",
		"Complete removal",
		"prove_not_installed",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("packaged-live failure cleanup omitted %q", required)
		}
	}
	for _, required := range []string{`cleanup_mode='${{ inputs.mode }}'`, `if test "$cleanup_mode" = v3`, `if test -d /var/lib/sbxr; then find /var/lib/sbxr -depth -delete; fi`} {
		if !strings.Contains(workflow, required) {
			t.Errorf("candidate mode-specific failure cleanup omitted %q", required)
		}
	}
	cleanupCall := strings.Index(workflow, "remote-failure-cleanup")
	if cleanupCall < 0 {
		t.Fatal("candidate failure cleanup does not call the packaged public cleanup mode")
	}
	transportCleanup := strings.Index(workflow[cleanupCall:], "hosts.original")
	cleanupResult := strings.Index(workflow[cleanupCall:], `test "$proxy_cleanup_status" -eq 0`)
	if transportCleanup < 0 || cleanupResult < 0 || transportCleanup >= cleanupResult {
		t.Fatal("failure cleanup does not preserve the public cleanup result through qualification transport cleanup")
	}
	failureCleanup := workflow[cleanupCall : cleanupCall+cleanupResult]
	for _, forbidden := range []string{"rm -f /usr/local/bin/sbxr", "find /var/lib/sbxr -depth -delete"} {
		if strings.Contains(failureCleanup, forbidden) {
			t.Fatalf("failure cleanup bypasses public ownership with %q", forbidden)
		}
	}
}

func TestPackagedFailureCleanupHandlesEveryPublicFinishingState(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, state, behavior     string
		wantSuccess, wantRetained bool
	}{
		{"cleanup required", "cleanup", "success", true, false},
		{"setup required", "setup", "success", true, false},
		{"removal required", "removal", "success", true, false},
		{"removal output secret", "removal", "removal-secret", false, false},
		{"inspection failure", "inspection-failure", "failure", false, true},
		{"secret inspection failure", "secret-inspection", "failure", false, true},
		{"unowned mismatch", "problem", "failure", false, true},
		{"finishing failure", "cleanup", "finishing-failure", false, true},
		{"final absence failure", "not-set-up", "final-absence", false, true},
		{"absence inspection failure", "removal", "inspector-failure", false, false},
		{"unit inspection failure", "removal", "systemctl-failure", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			statePath := filepath.Join(directory, "state")
			binary := filepath.Join(directory, "sbxr")
			configuration := filepath.Join(directory, "config.json")
			sandboxScript := filepath.Join(directory, "v3-packaged-live.sh")
			work := filepath.Join(directory, "work")
			bin := filepath.Join(directory, "bin")
			if err := os.MkdirAll(work, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, []byte(test.state+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := `#!/bin/sh
set -eu
state="$(cat "$FAKE_STATE")"
input="$(cat)"
choice="$(printf '%s\n' "$input" | sed -n '1p')"
if test "$state" = inspection-failure; then exit 23; fi
if test "$state" = secret-inspection; then printf '%s\n' "$KNOWN_CLIENT_UUID"; exit 23; fi
# The real terminal prints its initial menu before every submitted action.
if test "$choice" != 0; then printf 'SBXR V3\n0. Exit\n'; fi
case "$state:$choice" in
  cleanup:0) printf 'Proxy status: Setup incomplete\n1. Finish cleanup\n0. Exit\n' ;;
  setup:0) printf 'Proxy status: Setup incomplete\n1. Finish setup\n0. Exit\n' ;;
  removal:0) printf 'Proxy status: Removal incomplete\n1. Finish removal\n0. Exit\n' ;;
  not-set-up:0) printf 'Proxy status: Not set up\n1. Complete removal\n0. Exit\n' ;;
  running:0) printf 'Proxy status: Running\n1. Complete removal\n0. Exit\n' ;;
  problem:0) printf 'Proxy status: Problem detected\n1. View details\n0. Exit\n' ;;
  problem:1) printf 'Detected mismatch: unowned protected resource\nCode: PROXY-INSTALLATION-ACTION-REFUSED\n' ;;
  cleanup:1)
    if test "$FAKE_BEHAVIOR" = finishing-failure; then printf 'Code: PROXY-INSTALLATION-ACTION-REFUSED\n'; exit; fi
    printf 'not-set-up\n' > "$FAKE_STATE"
    printf 'Code: PROXY-INSTALLATION-SETUP-CLEANED-UP\n'
    ;;
  setup:1)
    printf 'running\n' > "$FAKE_STATE"
    printf 'Code: PROXY-INSTALLATION-SETUP-COMPLETE\n'
    ;;
  removal:1)
    rm -f "$0" "${FAKE_CONFIG:-}"
    if test "$FAKE_BEHAVIOR" = removal-secret; then printf '11111111-1111-4111-8111-111111111111\n'; fi
    printf 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED\n'
    ;;
  not-set-up:1|running:1)
    if test "$FAKE_BEHAVIOR" != final-absence; then rm -f "$0"; fi
    printf 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED\n'
    ;;
  *) exit 24 ;;
esac
`
			if err := os.WriteFile(binary, []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			inspectors := map[string]string{
				"dpkg-query": "#!/bin/sh\nif test \"$FAKE_BEHAVIOR\" = inspector-failure; then exit 23; fi\nexit 1\n",
				"apt-mark":   "#!/bin/sh\nexit 0\n",
				"systemctl":  "#!/bin/sh\nif test \"$FAKE_BEHAVIOR\" = systemctl-failure; then printf 'inspection failed\\n' >&2; fi\nexit 1\n",
				"ss":         "#!/bin/sh\nexit 0\n",
				"getent":     "#!/bin/sh\nexit 2\n",
				"stat":       "#!/bin/sh\nprintf 'protected-path 700 0 0 1\\n'\n",
				"sha256sum":  "#!/bin/sh\nif test \"$#\" -eq 0; then cat >/dev/null; fi\nprintf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  -\\n'\n",
			}
			for name, body := range inspectors {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			body := strings.ReplaceAll(string(source), "/usr/local/bin/sbxr", binary)
			body = strings.ReplaceAll(body, "/etc/sing-box/config.json", configuration)
			body = strings.Replace(body, "WORK=/run/sbxr-qualification", "WORK="+work, 1)
			if err := os.WriteFile(sandboxScript, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", sandboxScript, "remote-failure-cleanup", "v3.0.10", "71", strings.Repeat("a", 40), strings.Repeat("b", 64))
			knownClientUUID := "11111111-1111-4111-8111-111111111111"
			if test.behavior == "removal-secret" {
				config := `{"inbounds":[{"tls":{"reality":{"private_key":"known-reality-private-key"}},"users":[{"uuid":"` + knownClientUUID + `"}]}]}`
				if err := os.WriteFile(configuration, []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_STATE="+statePath, "FAKE_BEHAVIOR="+test.behavior, "FAKE_CONFIG="+configuration)
			if test.behavior == "failure" && test.state == "secret-inspection" {
				command.Env = append(command.Env, "KNOWN_CLIENT_UUID="+knownClientUUID)
			}
			output, runErr := command.CombinedOutput()
			if (runErr == nil) != test.wantSuccess {
				t.Fatalf("cleanup error = %v, output = %s", runErr, output)
			}
			if test.wantRetained {
				if _, err := os.Stat(binary); err != nil {
					t.Fatalf("failed cleanup did not retain the inspected executable: %v", err)
				}
			}
			evidence, err := os.ReadFile(filepath.Join(work, "failure-cleanup-evidence.txt"))
			if err != nil || len(evidence) == 0 || strings.Contains(string(evidence), "PRIVATE KEY") || strings.Contains(string(evidence), knownClientUUID) {
				t.Fatalf("cleanup evidence = %q, %v", evidence, err)
			}
			if _, err := os.Stat(filepath.Join(work, "failure-cleanup-evidence.safe")); err != nil {
				t.Fatalf("safe cleanup evidence was not sealed: %v", err)
			}
			if test.state == "problem" && (!strings.Contains(string(evidence), "Detected mismatch: unowned protected resource") || !strings.Contains(string(evidence), "Legal finishing action: Absent") || !strings.Contains(string(evidence), "Protected inventory after:") || !strings.Contains(string(evidence), "Retention: Verified")) {
				t.Fatalf("mismatch evidence = %q", evidence)
			}
		})
	}
}

func TestQualificationGatewayReadinessIsBoundedAndObservable(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/qualification-gateway-readiness.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, child, curl, timeout, want string
		wantSuccess                      bool
	}{
		{name: "delayed healthy gateway", child: "sleep 10", curl: "sleep .2\nexit 0", timeout: "5", wantSuccess: true},
		{name: "exited gateway", child: "exit 23", curl: "while test \"$#\" -gt 0; do if test \"$1\" = --max-time; then shift; sleep \"$1\"; exit 1; fi; shift; done\nexit 1", timeout: "30", want: "qualification gateway exited before readiness\nlistener-fact"},
		{name: "live gateway timeout", child: "sleep 10", curl: "exit 1", timeout: "1", want: "qualification gateway readiness timed out\nlistener-fact"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			bin := filepath.Join(directory, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\n"+test.curl+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "ss"), []byte("#!/bin/sh\nprintf 'listener-fact\\n'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(directory, "gateway.log")
			pidFile := filepath.Join(directory, "gateway.pid")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", script, "https://gateway.test/ready", log, pidFile, test.timeout, "sh", "-c", test.child)
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("readiness exceeded its test deadline: %v\n%s", ctx.Err(), output)
			}
			if pid, readErr := os.ReadFile(pidFile); readErr == nil {
				if value, parseErr := strconv.Atoi(strings.TrimSpace(string(pid))); parseErr == nil {
					_ = exec.Command("kill", strconv.Itoa(value)).Run()
				}
			}
			if (runErr == nil) != test.wantSuccess {
				t.Fatalf("readiness error = %v, output = %s", runErr, output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("readiness output = %q, want %q", output, test.want)
			}
		})
	}
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

func TestSubscriptionQualificationHasIsolatedRebootSafeTransport(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "v3-qualification-transport.sh") {
		t.Fatal("version-3 transport is missing")
	}
	script, err := os.ReadFile(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"127.0.0.1:9443", "127.0.0.2", "--to-ports 9443", "ExecStartPre=", "ExecStopPost=", "WantedBy=multi-user.target", "systemctl enable", "systemctl disable", "cmp -s", "route-down", "update-ca-certificates", "transport-owned"} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("missing transport lifecycle %q", required)
		}
	}
	collector, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(collector), "/root/sbxr-qualification-evidence") || strings.Contains(string(collector), "/run/sbxr-qualification/v3-evidence") {
		t.Fatal("scenario clock handoff cannot survive reboot")
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-qualification-transport.sh").CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v %s", err, output)
	}
}

func TestQualificationRoutingInspectionFailsClosed(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 1, 4} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", status)), 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", "-c", `source "$1"; if has_redirect; then echo present; else echo absent; fi`, "routing-check", script)
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			if status == 4 {
				if err == nil || len(output) != 0 {
					t.Fatalf("inspection error accepted: %v %s", err, output)
				}
				return
			}
			wanted := "present\n"
			if status == 1 {
				wanted = "absent\n"
			}
			if err != nil || string(output) != wanted {
				t.Fatalf("routing result: %v %s", err, output)
			}
		})
	}
}

func TestQualificationHostsRestorationPreservesOriginalAndUnrelatedEdits(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{false, true} {
		t.Run(strconv.FormatBool(changed), func(t *testing.T) {
			dir := t.TempDir()
			before := "127.0.0.1 localhost"
			after := before + "\n127.0.0.2 api.github.com github.com # sbxr-qualification-v3\n"
			current, wanted := after, before
			if changed {
				current += "192.0.2.1 unrelated\n"
				wanted = before + "\n192.0.2.1 unrelated\n"
			}
			for name, body := range map[string]string{"hosts.before": before, "hosts.after": after, "hosts": current, "iptables": "#!/bin/sh\nexit 1\n", "update-ca-certificates": "#!/bin/sh\ntouch \"$SBXR_TEST_ROOT/refreshed\"\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-c", `source "$1"; root="$2"; hosts="$root/hosts"; ca="$root/absent-ca"; route_down`, "hosts-check", script, dir)
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SBXR_TEST_ROOT="+dir)
			// The production runner uses GNU sed; macOS requires its empty suffix.
			if changed {
				if output, err := exec.Command("uname", "-s").Output(); err == nil && strings.TrimSpace(string(output)) == "Darwin" {
					wrapper := "#!/bin/sh\nif test \"$1\" = -i; then shift; exec /usr/bin/sed -i '' \"$@\"; fi\nexec /usr/bin/sed \"$@\"\n"
					if err := os.WriteFile(filepath.Join(dir, "sed"), []byte(wrapper), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("restore: %v %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(dir, "refreshed")); err != nil {
				t.Fatal("absent CA source skipped trust-store refresh", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "hosts"))
			if err != nil || string(got) != wanted {
				t.Fatalf("hosts restore = %q, %v", got, err)
			}
		})
	}
}

func TestQualificationTransportRefusesExistingUnit(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	unit := filepath.Join(dir, "existing-unit")
	if err := os.WriteFile(unit, []byte("unrelated unit"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `source "$1"; root="$2"; unit_path="$root/existing-unit"; ca="$root/absent-ca"; check_start; echo incorrectly-admitted`, "admission-check", script, dir)
	if output, err := command.CombinedOutput(); err == nil || len(output) != 0 {
		t.Fatalf("existing unit admitted: %v %s", err, output)
	}
	got, err := os.ReadFile(unit)
	if err != nil || string(got) != "unrelated unit" {
		t.Fatal("existing unit changed")
	}
}
