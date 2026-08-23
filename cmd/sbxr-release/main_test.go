package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestBuildAndVerifyExactFourAssetRelease(t *testing.T) {
	root := t.TempDir()
	tag := "v2.0.0"
	commit := strings.Repeat("a", 40)
	digests := map[softwarelifecycle.Architecture]string{}
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		output := filepath.Join(root, "sbxr-linux-"+string(architecture)+".tar.gz")
		options := buildOptions{tag: tag, commit: commit, sequence: 17, architecture: architecture, output: output}
		if err := buildApplicationRelease(t.Context(), options, currentSource); err != nil {
			t.Fatalf("build %s: %v", architecture, err)
		}
		archive, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		digest, ok := softwarelifecycle.ReleaseArchiveExecutableSHA256(archive)
		if !ok {
			t.Fatal("release archive executable refused")
		}
		digests[architecture] = digest
	}
	if err := buildBootstrapFile(bootstrapOptions{version: "2.0.0", tag: tag, commit: commit, sequence: 17, amd64ExecutableSHA256: digests[softwarelifecycle.AMD64], arm64ExecutableSHA256: digests[softwarelifecycle.ARM64], output: filepath.Join(root, "install.sh")}); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(root, "release-index.json")
	if err := buildReleaseIndexFile(indexOptions{tag: tag, commit: commit, sequence: 17, directory: root, output: index}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 4 {
		t.Fatalf("release assets = %d, %v", len(entries), err)
	}
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		if err := verifyReleasePackage(packageVerificationOptions{directory: root, architecture: architecture}); err != nil {
			t.Fatalf("verify %s: %v", architecture, err)
		}
	}
	bootstrap, err := os.ReadFile(filepath.Join(root, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(bootstrap, []byte(digests[softwarelifecycle.AMD64]), []byte(strings.Repeat("f", 64)), 1)
	if err := os.WriteFile(filepath.Join(root, "install.sh"), changed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleasePackage(packageVerificationOptions{directory: root, architecture: softwarelifecycle.AMD64}); err == nil {
		t.Fatal("changed bootstrap agreement accepted")
	}
}

func TestReleaseBuildAndIndexFailClosed(t *testing.T) {
	root := t.TempDir()
	commit := strings.Repeat("a", 40)
	if err := buildApplicationRelease(t.Context(), buildOptions{tag: "v2.0.0", commit: commit, sequence: 0, architecture: softwarelifecycle.AMD64, output: filepath.Join(root, "sbxr-linux-amd64.tar.gz")}, currentSource); err == nil {
		t.Fatal("zero sequence accepted")
	}
	for name, body := range map[string][]byte{
		"install.sh":              []byte("install"),
		"sbxr-linux-amd64.tar.gz": []byte("amd64"),
		"sbxr-linux-arm64.tar.gz": []byte("arm64"),
		"qualification-only.json": []byte("forbidden"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := buildReleaseIndexFile(indexOptions{tag: "v2.0.0", commit: commit, sequence: 17, directory: root, output: filepath.Join(root, "release-index.json")}); err == nil {
		t.Fatal("extra release asset accepted")
	}
}

func TestReleaseAssetReadRefusesLateReplacement(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = readReleaseFiles(root, []releaseAssetSpec{{name: "first", limit: 100}, {name: "second", limit: 100}}, func(name string) {
		if name == "first" {
			_ = os.Remove(filepath.Join(directory, name))
			_ = os.WriteFile(filepath.Join(directory, name), []byte("changed"), 0o600)
		}
	})
	if err == nil {
		t.Fatal("late release asset replacement accepted")
	}
}

func currentSource(_ context.Context, _ string, _ string) (string, error) {
	return filepath.Abs("../..")
}

func TestReleaseBuildUsesPinnedToolchain(t *testing.T) {
	if runtime.Version() != "go1.26.6" {
		t.Skip("release build is pinned to go1.26.6")
	}
}

func TestPublicLatestVerificationReportsTheProductionGitHubAdapterResult(t *testing.T) {
	latest := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.1", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 18}
	for name, fixture := range map[string]struct {
		outcome softwarelifecycle.LatestReleaseOutcome
		want    string
	}{
		"accepted":    {softwarelifecycle.LatestReleaseAccepted, `{"outcome":"accepted","release_identity":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_index_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repository":"albertloky/SBXR","tag":"v2.0.1"},"sequence":18}`},
		"refused":     {softwarelifecycle.LatestReleaseRefused, `{"outcome":"refused","release_identity":null,"sequence":null}`},
		"unavailable": {softwarelifecycle.LatestReleaseUnavailable, `{"outcome":"unavailable","release_identity":null,"sequence":null}`},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writePublicLatestVerification(t.Context(), &output, latestSource{latest: latest, outcome: fixture.outcome}); err != nil || output.String() != fixture.want {
				t.Fatalf("verification = %s, %v", output.String(), err)
			}
		})
	}
}

type latestSource struct {
	latest  softwarelifecycle.LatestRelease
	outcome softwarelifecycle.LatestReleaseOutcome
}

func (source latestSource) CheckLatest(context.Context) (softwarelifecycle.LatestRelease, softwarelifecycle.LatestReleaseOutcome) {
	return source.latest, source.outcome
}
