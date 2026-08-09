package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type acceptingValidator struct{ calls int }

func (validator *acceptingValidator) Validate(_ context.Context, metadata softwarelifecycle.PayloadMetadata) error {
	validator.calls++
	if len(metadata.Schemas) != 2 || len(metadata.Migrations) != 1 || len(metadata.Units) != 10 || len(metadata.Artifacts) != 10 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestBuildArchiveProducesOneQualifiedExecutableForBothArchitectures(t *testing.T) {
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		t.Run(string(architecture), func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "sbxr-linux-"+string(architecture)+".tar.gz")
			validator := &acceptingValidator{}
			if err := buildArchive(t.Context(), buildOptions{tag: "v1.0.0", commit: strings.Repeat("a", 40), architecture: architecture, output: output}, validator, currentSource); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			compressed, err := gzip.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			archive := tar.NewReader(compressed)
			header, err := archive.Next()
			if err != nil || header.Name != "sbxr" || header.Mode != 0o755 || header.Uid != 0 || header.Gid != 0 {
				t.Fatalf("archive header = %#v, %v", header, err)
			}
			body, err := io.ReadAll(archive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Next(); err != io.EOF || validator.calls != 1 {
				t.Fatalf("archive entries or validation = %v, %d", err, validator.calls)
			}
			binary := filepath.Join(t.TempDir(), "sbxr")
			if err := os.WriteFile(binary, body, 0o700); err != nil {
				t.Fatal(err)
			}
			metadata, _, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(body), int64(len(body)))
			if err != nil || metadata.Architecture != architecture || metadata.Build.Tag != "v1.0.0" || metadata.Build.PayloadSHA256 == "" {
				t.Fatalf("metadata = %#v, %v", metadata, err)
			}
			elfFile, err := elf.Open(binary)
			if err != nil {
				t.Fatal(err)
			}
			libraries, importErr := elfFile.ImportedLibraries()
			elfFile.Close()
			build, buildErr := buildinfo.ReadFile(binary)
			if importErr != nil || len(libraries) != 0 || buildErr != nil || build.GoVersion != "go1.26.5" {
				t.Fatalf("runtime proof: libraries=%v import=%v build=%v", libraries, importErr, buildErr)
			}
		})
	}
}

func currentSource(_ context.Context, _, _ string) (string, error) {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), nil
}

func TestVerifiedGitSourceBindsTheCleanExactCommit(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "go.mod")
	runGit(t, root, "-c", "user.name=SBXR", "-c", "user.email=sbxr@example.com", "commit", "-m", "source")
	commit := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	destination := filepath.Join(t.TempDir(), "source")
	if got, err := verifiedGitSource(t.Context(), root, commit, destination); err != nil || got != destination {
		t.Fatalf("verified source = %q, %v", got, err)
	}
	if _, err := verifiedGitSource(t.Context(), root, strings.Repeat("a", 40), filepath.Join(t.TempDir(), "wrong")); err == nil {
		t.Fatal("wrong source commit accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedGitSource(t.Context(), root, commit, filepath.Join(t.TempDir(), "dirty")); err == nil {
		t.Fatal("dirty tracked source accepted")
	}
}

func runGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}
