package architecture_test

import (
	"os"
	"strings"
	"testing"
)

func TestCandidateWorkflowPublishesOnlyAQualifiedStagedOnboardingAcceptanceRecord(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"git merge-base --is-ancestor b4c2c70 HEAD",
		"RELEASE-STAGED-INSTALL-REVISION-1",
		"RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1",
		"RELEASE-STAGED-ONBOARDING-CHAIN",
		"RELEASE-STAGED-ONBOARDING-SECRET-SCAN",
		"RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT",
		"RELEASE-STAGED-ONBOARDING-TERMINAL",
		"RELEASE-STAGED-ONBOARDING-GUIDE-TEXT",
		"Codex Live Acceptance: Not required — staged-onboarding package and controlled-seam qualification scope.",
		"Owner Acceptance: Not required — staged-onboarding package and controlled-terminal qualification scope.",
		"Required procedures: RELEASE-STAGED-INSTALL-REVISION-1",
		"go run ./cmd/sbxr-release acceptance",
		"-directory dist",
		"-output acceptance-record.md",
		"cat acceptance-record.md >> \"$GITHUB_STEP_SUMMARY\"",
		"rg -a -l \"$pattern\" \"$GITHUB_STEP_SUMMARY\"",
		"name: automated-acceptance-record-${{ github.event.release.tag_name }}",
		"gh release edit \"$RELEASE_TAG\" --notes-file acceptance-record.md",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("candidate workflow omitted %q", required)
		}
	}
	if strings.Contains(workflow, "gh release upload") {
		t.Fatal("Acceptance Record became a seventh release asset")
	}
	if strings.Contains(workflow, "git diff --quiet v1.0.6...HEAD") {
		t.Fatal("staged Connection Profile and Subscription Publication output remained blocked by the root-runtime freeze")
	}
	for _, twice := range []string{
		"go list ./... | grep -v '/internal/ownerconsole$' | xargs go test -count=1",
		"go test ./internal/ownerconsole -count=1",
		"go list ./... | grep -v '/internal/ownerconsole$' | xargs go test -race -p 1 -count=1",
		"go vet ./...",
		"go test ./internal/networkpolicy/adapter/ubuntu -run TestProductionUbuntuSeam -count=1",
		"go test ./internal/systemchanges/adapter/ubuntu -run TestProductionFirewallSeam -count=1",
	} {
		if strings.Count(workflow, twice) < 2 {
			t.Fatalf("candidate workflow must run %q before and after publication", twice)
		}
	}
}

func TestStableWorkflowReverifiesTheExactPublicInstallerBeforeREADMEActivation(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"actions: read",
		"ref: ${{ steps.release.outputs.commit }}",
		"test \"$(git rev-parse HEAD)\" = \"$(jq -r .target_commitish release.json)\"",
		"gh run download \"$record_run_id\" --name \"automated-acceptance-record-$RELEASE_TAG\"",
		"jq -j .body release.json > acceptance-record.md",
		"cmp acceptance-record.md retained-acceptance/acceptance-record.md",
		"go run ./cmd/sbxr-release verify -tag \"$RELEASE_TAG\"",
		"releases/latest/download/install.sh",
		"releases/download/$RELEASE_TAG/install.sh",
		"cmp latest-install.sh pinned-install.sh",
		"Status: Qualified - staged-onboarding package policy",
		"Stable result code: RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION",
		"No live VPS, real Cloudflare, ACME, outside-client, maintained-client, current-documentation, provider mutation, or Owner Acceptance was performed.",
		"Release index SHA-256:",
		"test \"$(jq '.assets | length' release.json)\" = 6",
		"go test ./cmd/sbxr-release -run '^TestGeneratedBootstrap' -count=1",
		"Public bootstrap package gates: Passed",
		"Integrated Ubuntu Verification: Not required",
		"test ! -e /usr/local/bin/sbxr",
		"test ! -e /var/lib/sbxr",
		"MARKER|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer ",
		`rg -a -l "$pattern" "$GITHUB_STEP_SUMMARY"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("stable workflow omitted %q", required)
		}
	}
	if strings.Contains(workflow, "jq -r .body release.json > acceptance-record.md") {
		t.Fatal("stable workflow adds a byte to the retained Acceptance Record")
	}
	if strings.Contains(workflow, "stable_bootstrap.py") || strings.Contains(workflow, "Supported Ubuntu Owner Console launch: Passed") {
		t.Fatal("stable workflow claimed an automated Ubuntu launch")
	}
}

func TestREADMEActivatesOnlyTheVerifiedStableInstaller(t *testing.T) {
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)
	for _, required := range []string{
		"https://github.com/albertloky/SBXR/releases/latest/download/install.sh",
		"https://github.com/albertloky/SBXR/releases/download/v1.0.6/install.sh) --tag v1.0.6",
		"Ubuntu 24.04",
		"GitHub HTTPS",
		"TUI controls",
		"RECLAIM THIS VPS",
		"After it, neither Back nor Cancel is available.",
		"Recovery Required",
		"COMPLETE REMOVAL",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("active README omitted %q", required)
		}
	}
	for _, unavailable := range []string{"Installation remains unavailable", "releases/download/<tag>/install.sh"} {
		if strings.Contains(readme, unavailable) {
			t.Fatalf("active README retained %q", unavailable)
		}
	}
}
