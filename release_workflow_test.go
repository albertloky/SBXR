package architecture_test

import (
	"os"
	"strings"
	"testing"
)

func TestCandidateWorkflowPublishesOnlyAQualifiedInstallerAcceptanceRecord(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"git diff --quiet v1.0.1...HEAD --",
		"internal/connectionprofiles",
		"internal/subscriptionpublication",
		"internal/subscriptionserving",
		"cmd/sbxr/client_access_outcome.go",
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
		"Status: Qualified - installer-only automated exception",
		"Release index SHA-256:",
		"test \"$(jq '.assets | length' release.json)\" = 6",
		"python3 .github/workflows/stable_bootstrap.py",
		"SBXR bootstrap: launching Owner Console",
		"Not installed",
		"test ! -e /usr/local/bin/sbxr",
		"test ! -e /var/lib/sbxr",
		"SECRET-MARKER|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer ",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("stable workflow omitted %q", required)
		}
	}
	if strings.Contains(workflow, "jq -r .body release.json > acceptance-record.md") {
		t.Fatal("stable workflow adds a byte to the retained Acceptance Record")
	}
	driver, err := os.ReadFile(".github/workflows/stable_bootstrap.py")
	if err != nil {
		t.Fatal(err)
	}
	childSize := strings.Index(string(driver), "if pid == 0:\n    fcntl.ioctl(1, termios.TIOCSWINSZ")
	childExec := strings.Index(string(driver), "    os.execve(")
	if childSize < 0 || childExec < 0 || childSize > childExec {
		t.Fatal("stable bootstrap can inspect the PTY before its size is set")
	}
	if !strings.Contains(string(driver), `b"\x1b[?1;2$y`) {
		t.Fatal("stable bootstrap does not prove alternate-screen support")
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
		"https://github.com/albertloky/SBXR/releases/download/v1.0.4/install.sh) --tag v1.0.4",
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
