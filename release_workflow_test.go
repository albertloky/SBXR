package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
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
		"grep -F 'SBXR V3'",
		"grep -F 'Proxy status: Not set up'",
		"grep -F 'Start setup'",
		"grep -F 'Complete removal'",
		"go test ./... -count=1",
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
