package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
	surfaces := []string{"dist/package", "inspect/sbxr", "captures/non-root.out", "captures/non-root.err", "captures/private.out", "captures/private.err", "summary"}
	for _, fault := range append([]string{"clean", "missing"}, surfaces...) {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			for _, surface := range surfaces {
				if fault == "missing" && surface == "captures/private.err" {
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

func TestCandidateWorkflowCleanHostChecksTreatDanglingLinksAsPresent(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(workflow)
	for _, path := range []string{
		"/usr/local/bin/sbxr",
		"/var/lib/sbxr",
		"/run/sbxr-qualification",
		"/root/sbxr-qualification-v3",
		"/root/sbxr-qualification-evidence",
	} {
		guard := `test ! -e ` + path + ` && test ! -L ` + path
		if !strings.Contains(body, guard) {
			t.Errorf("clean-host check can admit dangling link at %s", path)
		}
	}
}

func TestCandidateWorkflowCleanupRefusesDanglingTransportOwnership(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	var cleanup string
	for _, line := range strings.Split(string(workflow), "\n") {
		if !strings.Contains(line, `if ssh "${ssh_options[@]}"`) || !strings.Contains(line, "/transport-owned") {
			continue
		}
		start := strings.Index(line, "'if test")
		end := strings.LastIndex(line, "'; then")
		if start < 0 || end <= start {
			t.Fatal("transport cleanup command boundary changed")
		}
		cleanup = line[start+1 : end]
		break
	}
	if cleanup == "" {
		t.Fatal("transport cleanup command not found")
	}
	root := filepath.Join(t.TempDir(), "transport")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "staging-owned"), []byte("run-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	markerTarget := filepath.Join(root, "missing-owner")
	marker := filepath.Join(root, "transport-owned")
	if err := os.Symlink(markerTarget, marker); err != nil {
		t.Fatal(err)
	}
	cleanup = strings.ReplaceAll(cleanup, "/root/sbxr-qualification-v3", root)
	cleanup = strings.ReplaceAll(cleanup, `${{ github.run_id }}-${{ github.run_attempt }}`, "run-1")
	if output, err := exec.Command("bash", "-c", cleanup).CombinedOutput(); err == nil {
		t.Fatalf("dangling transport ownership admitted: %s", output)
	}
	if target, err := os.Readlink(marker); err != nil || target != markerTarget {
		t.Fatalf("dangling transport marker changed: got %q, %v", target, err)
	}
	body, err := os.ReadFile(filepath.Join(root, "staging-owned"))
	if err != nil || string(body) != "run-1\n" {
		t.Fatalf("owned staging changed: got %q, %v", body, err)
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
