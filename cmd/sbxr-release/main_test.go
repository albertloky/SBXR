package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestBuildCompleteReleaseWritesApplicationAndQualifiedComponentsTogether(t *testing.T) {
	root := t.TempDir()
	application := filepath.Join(root, "sbxr-linux-amd64.tar.gz")
	components := filepath.Join(root, "sbxr-components-linux-amd64.tar.gz")
	options := buildOptions{tag: "v1.0.0", commit: strings.Repeat("a", 40), architecture: softwarelifecycle.AMD64, output: application, componentOutput: components}
	called := false
	err := buildCompleteRelease(t.Context(), options, currentSource, func(_ context.Context, architecture softwarelifecycle.Architecture, metadata softwarelifecycle.PayloadMetadata) ([]byte, error) {
		called = true
		if architecture != softwarelifecycle.AMD64 || metadata.Build.Tag != "v1.0.0" {
			return nil, io.ErrUnexpectedEOF
		}
		return []byte("qualified-components"), nil
	})
	if err != nil || !called {
		t.Fatalf("buildCompleteRelease() = %v, called=%v", err, called)
	}
	if body, err := os.ReadFile(components); err != nil || string(body) != "qualified-components" {
		t.Fatalf("component output = %q, %v", body, err)
	}
	if _, err := os.Stat(application); err != nil {
		t.Fatal(err)
	}

	failedApplication := filepath.Join(root, "failed-application.tar.gz")
	failedComponents := filepath.Join(root, "failed-components.tar.gz")
	options.output, options.componentOutput = failedApplication, failedComponents
	if err := buildCompleteRelease(t.Context(), options, currentSource, func(context.Context, softwarelifecycle.Architecture, softwarelifecycle.PayloadMetadata) ([]byte, error) {
		return nil, errors.New("release qualification refused: mihomo-config")
	}); err == nil || err.Error() != "release qualification refused: mihomo-config" {
		t.Fatalf("component qualification failure = %v", err)
	}
	if _, err := os.Stat(failedApplication); !os.IsNotExist(err) {
		t.Fatalf("partial application output remains: %v", err)
	}

	blockedApplication := filepath.Join(root, "blocked-application.tar.gz")
	blockedComponents := filepath.Join(root, "blocked-components.tar.gz")
	if err := os.WriteFile(blockedComponents, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	options.output, options.componentOutput = blockedApplication, blockedComponents
	if err := buildCompleteRelease(t.Context(), options, currentSource, func(context.Context, softwarelifecycle.Architecture, softwarelifecycle.PayloadMetadata) ([]byte, error) {
		return []byte("qualified-components"), nil
	}); err == nil {
		t.Fatal("occupied component output accepted")
	}
	if _, err := os.Stat(blockedApplication); !os.IsNotExist(err) {
		t.Fatalf("partial application output remains: %v", err)
	}
	if body, err := os.ReadFile(blockedComponents); err != nil || string(body) != "existing" {
		t.Fatalf("existing component output changed: %q, %v", body, err)
	}
}

func TestVerifyCandidateRefusesInvalidTagBeforeExternalVerification(t *testing.T) {
	if err := verifyCandidate(t.Context(), ""); err == nil {
		t.Fatal("empty candidate tag accepted")
	}
}

func TestBuildReleaseIndexFileReadsOnlyInstallAndTheExactFourReleaseArchives(t *testing.T) {
	root := t.TempDir()
	assets := []softwarelifecycle.ReleaseIndexAsset{
		{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Bytes: []byte("amd64 application")},
		{Role: softwarelifecycle.ApplicationARM64, Name: "sbxr-linux-arm64.tar.gz", Bytes: []byte("arm64 application")},
		{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Bytes: []byte("amd64 components")},
		{Role: softwarelifecycle.ComponentsARM64, Name: "sbxr-components-linux-arm64.tar.gz", Bytes: []byte("arm64 components")},
		{Role: softwarelifecycle.Bootstrap, Name: "install.sh", Bytes: []byte("#!/bin/sh\nexit 1\n")},
	}
	for _, asset := range assets {
		if err := os.WriteFile(filepath.Join(root, asset.Name), asset.Bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commit := "0123456789abcdef0123456789abcdef01234567"
	output := filepath.Join(root, "release-index.json")
	if err := os.WriteFile(filepath.Join(root, "unexpected.tar.gz"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err == nil {
		t.Fatal("extra release asset was indexed")
	}
	if err := os.Remove(filepath.Join(root, "unexpected.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err != nil {
		t.Fatal(err)
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: commit}, softwarelifecycle.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	want, err := softwarelifecycle.BuildReleaseIndex(softwarelifecycle.ReleaseIndexRequest{Version: "1.0.0", Sequence: 1, Tag: "v1.0.0", Commit: commit, StateSchema: metadata.StateSchema, MinimumUpdaterSchema: metadata.MinimumUpdaterSchema, Assets: assets})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("release index = %s, %v; want %s", got, err, want)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err == nil {
		t.Fatal("occupied release index was replaced")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "sbxr-components-linux-arm64.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: filepath.Join(root, "missing-index.json")}); err == nil {
		t.Fatal("incomplete release asset set was indexed")
	}
	if err := os.Symlink(filepath.Join(root, "sbxr-components-linux-amd64.tar.gz"), filepath.Join(root, "sbxr-components-linux-arm64.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: filepath.Join(root, "linked-index.json")}); err == nil {
		t.Fatal("linked release asset was indexed")
	}
}

func TestBuildReleaseIndexFileRefusesAnAssetChangedWhileReading(t *testing.T) {
	root := t.TempDir()
	names := []string{"sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "install.sh"}
	for index, name := range names {
		body := []byte("asset")
		if index == 0 {
			body = bytes.Repeat([]byte("a"), 64<<20)
		}
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	changing, err := os.OpenFile(filepath.Join(root, names[0]), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		first := true
		for value := byte('b'); ; value ^= 1 {
			if _, err := changing.WriteAt([]byte{value}, 4<<20); err != nil {
				return
			}
			if first {
				close(started)
				first = false
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started
	err = buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: strings.Repeat("a", 40), directory: root, output: filepath.Join(root, "release-index.json")})
	close(stop)
	<-done
	if closeErr := changing.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil {
		t.Fatal("asset changed during index construction was accepted")
	}
}

func TestBuildReleaseIndexFileRefusesAReplacedAssetPath(t *testing.T) {
	root := t.TempDir()
	names := []string{"sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "install.sh"}
	for index, name := range names {
		body := []byte("asset")
		if index == 1 {
			body = bytes.Repeat([]byte("a"), 128<<20)
		}
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, names[0])
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(replacement, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		time.Sleep(10 * time.Millisecond)
		_ = os.Rename(replacement, target)
		<-stop
	}()
	<-started
	err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: strings.Repeat("a", 40), directory: root, output: filepath.Join(root, "release-index.json")})
	close(stop)
	<-done
	if err == nil {
		t.Fatal("replaced release asset path was accepted")
	}
}

type acceptingValidator struct{ calls int }

func (validator *acceptingValidator) Validate(_ context.Context, metadata softwarelifecycle.PayloadMetadata) error {
	validator.calls++
	if len(metadata.Schemas) != 2 || len(metadata.Migrations) != 1 || len(metadata.Units) != 11 || len(metadata.Artifacts) != 10 {
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
