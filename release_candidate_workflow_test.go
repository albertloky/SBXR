package architecture_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCandidatePreflightDiagnosticsAtShellBoundary(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, step, found := strings.Cut(string(body), "      - name: Verify source state and unused release authority\n")
	if !found {
		t.Fatal("missing candidate preflight step")
	}
	_, script, found := strings.Cut(step, "        run: |\n")
	if !found {
		t.Fatal("missing candidate preflight shell")
	}
	script, _, _ = strings.Cut(script, "\n      - ")
	lines := strings.Split(script, "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(lines[i], "          ")
	}
	script = strings.Join(lines, "\n")
	prefix, _, found := strings.Cut(script, "git fetch --force --tags origin\n")
	if !found {
		t.Fatal("missing boundary after public verification")
	}
	const refused = `{"outcome":"refused","release_identity":null,"sequence":null}`
	const unavailable = `{"outcome":"unavailable","release_identity":null,"sequence":null}`
	const accepted = `{"outcome":"accepted","release_identity":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_index_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repository":"albertloky/SBXR","tag":"v3.1.0"},"sequence":83}`
	const token = "preflight-test-token-must-stay-private"
	const signedQuery = "sig=preflight-test-signature&token=private-query"
	const declaration = `{"private_fixture":"` + token + ` https://release-assets.githubusercontent.com/fixture?` + signedQuery + `","schema":"sbxr-v3-qualification-attempt-v3","support":{"scope":"subscription-clean-install-repair"}}`
	for _, fixture := range []struct {
		name, result, operation, execution, outcome string
		verifierStatus, wantStatus                  int
	}{
		{"accepted", accepted, "", "completed", "accepted", 0, 0},
		{"clean-install-only", accepted, "", "completed", "accepted", 0, 0},
		{"refused", refused, "require accepted public-latest outcome", "completed", "refused", 0, 1},
		{"unavailable", unavailable, "require accepted public-latest outcome", "completed", "unavailable", 0, 1},
		{"execution-failed", "", "execute verify-public-latest", "did not complete", "empty", 42, 42},
		{"execution-failed-with-result", refused, "execute verify-public-latest", "did not complete", "refused", 42, 42},
		{"execution-failed-with-accepted-result", accepted, "execute verify-public-latest", "did not complete", "accepted", 42, 42},
		{"interrupted", `{"outcome":`, "execute verify-public-latest", "did not complete", "incomplete or invalid", 143, 143},
		{"empty", "", "require accepted public-latest outcome", "completed", "empty", 0, 4},
		{"incomplete", `{"outcome":`, "require accepted public-latest outcome", "completed", "incomplete or invalid", 0, 5},
		{"missing", "", "require accepted public-latest outcome", "completed", "missing", 0, 2},
		{"declaration-missing", "", "require V3 declaration", "not started", "missing", 0, 1},
		{"declaration-noncanonical", "", "check canonical V3 declaration", "not started", "missing", 0, 1},
		{"declaration-scope", accepted, "check V3 declaration scope", "completed", "accepted", 0, 1},
		{"later-failure", accepted, "fetch source tags", "completed", "accepted", 0, 37},
		{"diagnostic-write-failure", refused, "require accepted public-latest outcome", "completed", "refused", 0, 1},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			directory := t.TempDir()
			// Substitute only external commands. Bash, jq, redirection, traps,
			// filesystem writes and the workflow's assertions run unchanged.
			for name, source := range map[string]string{
				"go": `#!/usr/bin/env bash
set -euo pipefail
test "$*" = 'run ./cmd/sbxr-release verify-public-latest'
printf 'called\n' >> verifier-called
if test "$FIXTURE" = missing; then
  rm current-source-verification.json
else
  printf '%s' "$RESULT"
fi
if test "$FIXTURE" = interrupted; then kill -TERM "$$"; fi
exit "$VERIFIER_STATUS"
`,
				"git": "#!/bin/sh\nprintf called > git-called\nexit 37\n",
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.name == "diagnostic-write-failure" {
				if err := os.Mkdir(filepath.Join(directory, "candidate-preflight-diagnostics.txt"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			attempt := declaration
			switch fixture.name {
			case "clean-install-only":
				attempt = strings.ReplaceAll(attempt, "subscription-clean-install-repair", "subscription-clean-install-only")
			case "declaration-missing":
				attempt = ""
			case "declaration-noncanonical":
				attempt += " "
			case "declaration-scope":
				attempt = strings.ReplaceAll(attempt, "subscription-clean-install-repair", "unknown")
			}
			// Success must reach the next operation. The later-failure case
			// runs the full step, stopping at the external git subprocess.
			entry := prefix + "printf reached > continued\n"
			if fixture.name == "later-failure" {
				entry = script
			}
			command := exec.CommandContext(t.Context(), "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", entry)
			command.Dir = directory
			command.Env = []string{
				"PATH=" + directory + ":" + os.Getenv("PATH"),
				"V3_CHECKLIST=unused", "V3_ATTEMPT=" + attempt, "GH_TOKEN=" + token,
				"SIGNED_URL=https://release-assets.githubusercontent.com/fixture?" + signedQuery,
				"RESULT=" + fixture.result, "FIXTURE=" + fixture.name,
				"VERIFIER_STATUS=" + strconv.Itoa(fixture.verifierStatus),
			}
			output, err := command.CombinedOutput()
			status := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				status = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if status != fixture.wantStatus {
				t.Errorf("exit = %d, want %d; output: %s", status, fixture.wantStatus, output)
			}
			_, continuedErr := os.Stat(filepath.Join(directory, "continued"))
			if (continuedErr == nil) != (fixture.wantStatus == 0) {
				t.Errorf("continued after failure or stopped after acceptance: %v", continuedErr)
			}
			calls, _ := os.ReadFile(filepath.Join(directory, "verifier-called"))
			wantCalls := "called\n"
			if fixture.execution == "not started" {
				wantCalls = ""
			}
			if string(calls) != wantCalls {
				t.Errorf("verifier invocations = %q, want %q", calls, wantCalls)
			}
			result, resultErr := os.ReadFile(filepath.Join(directory, "current-source-verification.json"))
			if fixture.execution == "not started" || fixture.name == "missing" {
				if !os.IsNotExist(resultErr) {
					t.Errorf("unexpected result: %v", resultErr)
				}
			} else if resultErr != nil || string(result) != fixture.result {
				t.Errorf("available verification result was not preserved: %v %s", resultErr, result)
			}
			diagnostic, diagnosticErr := os.ReadFile(filepath.Join(directory, "candidate-preflight-diagnostics.txt"))
			if fixture.name != "diagnostic-write-failure" && diagnosticErr != nil {
				t.Errorf("preflight diagnostics were not retained: %v", diagnosticErr)
			}
			for i, text := range []string{string(output), string(diagnostic)} {
				if i == 1 && fixture.name == "diagnostic-write-failure" {
					continue
				}
				for _, want := range []string{fixture.operation, "exit status: " + strconv.Itoa(fixture.wantStatus), "Public-latest verifier: " + fixture.execution, "Public-latest result: " + fixture.outcome} {
					if !strings.Contains(text, want) {
						t.Errorf("diagnostic lacks %q: %q", want, text)
					}
				}
			}
			for _, text := range []string{string(output), string(diagnostic), string(result)} {
				for _, secret := range []string{token, signedQuery, "release-assets.githubusercontent.com/fixture?"} {
					if strings.Contains(text, secret) {
						t.Error("preflight exposed a secret or signed URL query")
					}
				}
			}
		})
	}
}

func TestCandidatePreflightRetainsDiagnosticsWithoutChangingDecisionArtifact(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	preflight, _, _ := strings.Cut(string(body), "\n  build:")
	var diagnosticUpload, decisionUpload string
	for _, step := range strings.Split(preflight, "\n      - ") {
		if strings.Contains(step, "name: candidate-preflight-diagnostics\n") {
			diagnosticUpload = step
		}
		if strings.Contains(step, "name: candidate-preflight-decision-chain\n") {
			decisionUpload = step
		}
	}
	for _, want := range []string{"uses: actions/upload-artifact@", "if: ${{ always() && steps.preflight.outcome == 'failure' }}", "path: |\n            current-source-verification.json\n            candidate-preflight-diagnostics.txt\n", "if-no-files-found: ignore", "retention-days: 1"} {
		if !strings.Contains(diagnosticUpload, want) {
			t.Errorf("early-failure diagnostic upload lacks %q", want)
		}
	}
	if !strings.Contains(decisionUpload, "if-no-files-found: error") || strings.Contains(decisionUpload, "if:") || strings.Contains(decisionUpload, "current-source-verification.json") {
		t.Error("success-only decision-chain artifact contract changed")
	}
	for _, forbidden := range []string{"continue-on-error:", "set -x", "BASH_COMMAND", "printenv"} {
		if strings.Contains(preflight, forbidden) {
			t.Errorf("preflight diagnostics may weaken failure or expose secrets: %s", forbidden)
		}
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

func TestCandidateConstructsDraftsAndSignsTheQualificationBoundary(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"workflow_dispatch:",
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
		"prepare-burn-tag.sh",
		"git push --atomic origin",
		"releases/latest",
		"gh attestation verify",
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
		`python3 "$GITHUB_WORKSPACE/.github/scripts/download-release-asset.py" "$repository" "$id" "downloaded/$tag/$name"`,
		`stage:"candidate-draft-verification"`,
		`go run ./cmd/sbxr-release qualification < candidate-draft-verification-facts.json > candidate-draft-verification-decision.json`,
		`jq -c '.verified_releases' candidate-draft-verification-decision.json > drafts.json`,
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
		`go run ./cmd/sbxr-release qualification-declaration < candidate-declaration-facts.json > candidate-declaration-decision.json`,
		`.schema == "sbxr-release-qualification-decision-v1"`,
		`--slurpfile fact release-fact.json`,
		`--slurpfile releases release-facts.json`,
		`.sequence == (.sequence | floor)`,
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

func TestCandidateRoutesCurrentV3Qualification(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	stableBody, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	stable := string(stableBody)
	for _, required := range []string{
		"docs/acceptance/v3-packaged-live.md",
		"v3-packaged-live-evidence.json",
		"v3-packaged-live-result-facts.json",
		"v3-packaged-live-result-decision.json",
		"RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION",
		`(.records | length) == 1`,
		`tar --no-same-owner -xzf - -C /root/sbxr-qualification-v3`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("candidate.yml omitted V3 qualification contract %q", required)
		}
	}
	if strings.Contains(workflow, `tar -xzf - -C /root/sbxr-qualification-v3`) {
		t.Fatal("V3 transport extraction may restore the runner's archived uid and gid on the root VPS")
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

func TestCandidateV3TransportStagesPrivateManifest(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	const marker = `ssh "${ssh_options[@]}" "root@$ACCEPTANCE_VPS_HOST" 'umask 077; `
	_, remainder, found := strings.Cut(string(body), marker)
	command, _, terminated := strings.Cut(remainder, `' < v3-transport.tgz`)
	if !found || !terminated {
		t.Fatal("V3 transport staging command not found")
	}

	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	remote := filepath.Join(directory, "remote")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(remote, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(source, "qualification-manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"schema":"sbxr-qualification-manifest-v3"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(source, "sbxr-release")
	if err := os.WriteFile(executable, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("tar", "-C", source, "-czf", "-", "qualification-manifest.json", "sbxr-release")
	archiveBytes, err := archive.Output()
	if err != nil {
		t.Fatal(err)
	}

	command = "umask 077; " + strings.ReplaceAll(command, "/root/sbxr-qualification-v3", remote)
	extract := exec.Command("bash", "-c", "set -euo pipefail; "+command)
	extract.Stdin = bytes.NewReader(archiveBytes)
	if output, err := extract.CombinedOutput(); err != nil {
		t.Fatalf("V3 transport staging failed: %v\n%s", err, output)
	}
	for path, want := range map[string]os.FileMode{remote: 0o700, filepath.Join(remote, "qualification-manifest.json"): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
		}
	}
}
