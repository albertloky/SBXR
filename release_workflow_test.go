package architecture_test

import (
	"os"
	"strings"
	"testing"
)

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
		"go test -race ./internal/softwarelifecycle",
		"go vet ./cmd/sbxr-installer-updater",
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
		"git tag -a \"release-burned/$tag\"",
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
		"gh release create",
		"--draft",
		"gh api \"repos/$GITHUB_REPOSITORY/releases/assets/",
		"cmp \"$directory/$name\" \"downloaded/$tag/$name\"",
		"environment: acceptance-vps",
		"actions/runs/$GITHUB_RUN_ID/approvals",
		"attestations/sha256:$manifest_sha256",
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
		"curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash",
		"SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE",
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
	assertActionsPinned(t, acceptanceSources)
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
