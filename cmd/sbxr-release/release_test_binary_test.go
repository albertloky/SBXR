package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var releaseTestBinaryCache struct {
	sync.Mutex
	body []byte
	mode os.FileMode
}

// Cache only immutable bytes. Every caller owns its executable and may change
// or remove it without affecting another test or retaining another test's path.
func buildReleaseTestBinary(t *testing.T) string {
	t.Helper()
	releaseTestBinaryCache.Lock()
	defer releaseTestBinaryCache.Unlock()
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if releaseTestBinaryCache.body == nil {
		if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
			t.Fatalf("build sbxr-release: %v\n%s", err, output)
		}
		body, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(binary)
		if err != nil {
			t.Fatal(err)
		}
		releaseTestBinaryCache.body = body
		releaseTestBinaryCache.mode = info.Mode().Perm()
		return binary
	}
	if err := os.WriteFile(binary, releaseTestBinaryCache.body, releaseTestBinaryCache.mode); err != nil {
		t.Fatal(err)
	}
	return binary
}

// A fresh test process exercises the real compiler once, without depending on
// which other package tests have already requested an executable.
func TestReleaseTestBinaryBuildCache(t *testing.T) {
	const childFlag = "SBXR_RELEASE_CACHE_CHILD"
	if os.Getenv(childFlag) == "1" {
		var first, second string
		var original []byte
		checkCLI := func(t *testing.T, binary string) {
			t.Helper()
			output, err := runQualificationCommand(binary, initialNormalFacts)
			if err != nil || string(output) != initialNormalDecision {
				t.Fatalf("real qualification command: %v\n%s", err, output)
			}
		}
		if !t.Run("independent-files", func(t *testing.T) {
			first, second = buildReleaseTestBinary(t), buildReleaseTestBinary(t)
			a, err := os.Stat(first)
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.Stat(second)
			if err != nil {
				t.Fatal(err)
			}
			if first == second || os.SameFile(a, b) {
				t.Fatal("test executables share a path or inode")
			}
			original, err = os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			checkCLI(t, first)
			checkCLI(t, second)
			if err := os.WriteFile(first, []byte("changed test executable"), 0700); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(second)
			if err != nil || !bytes.Equal(body, original) {
				t.Fatalf("changing one executable affected another: %v", err)
			}
			checkCLI(t, second)
			if err := os.Remove(first); err != nil {
				t.Fatal(err)
			}
		}) {
			return
		}
		for _, path := range []string{first, second} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("subtest executable survived its owner: %s: %v", path, err)
			}
		}
		t.Run("after-owner-cleanup", func(t *testing.T) {
			binary := buildReleaseTestBinary(t)
			body, err := os.ReadFile(binary)
			if err != nil || !bytes.Equal(body, original) {
				t.Fatalf("cached executable changed or depended on retired path: %v", err)
			}
			checkCLI(t, binary)
		})
		return
	}

	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.Abs(realGo)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	log := filepath.Join(directory, "builds.log")
	wrapper := filepath.Join(directory, "go")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SBXR_RELEASE_CACHE_BUILD_LOG\" || exit 91\nexec \"$SBXR_RELEASE_CACHE_REAL_GO\" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), testBinary, "-test.run=^TestReleaseTestBinaryBuildCache$", "-test.count=1", "-test.timeout=60s", "-test.v")
	child.Env = append(os.Environ(), childFlag+"=1", "SBXR_RELEASE_CACHE_REAL_GO="+realGo,
		"SBXR_RELEASE_CACHE_BUILD_LOG="+log, "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("isolated real-build checks: %v\n%s", err, output)
	}
	body, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	builds := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(builds) != 1 || !strings.HasPrefix(builds[0], "build -o ") || !strings.HasSuffix(builds[0], " .") {
		t.Fatalf("expected one unchanged real go build, observed %d: %s", len(builds), body)
	}
}

// A compiler failure must remain visible and leave no fixture directory behind.
func TestReleaseTestBinaryBuildFailurePreservesDiagnosticsAndCleanup(t *testing.T) {
	const childFlag = "SBXR_RELEASE_CACHE_FAILURE_CHILD"
	if os.Getenv(childFlag) == "1" {
		buildReleaseTestBinary(t)
		t.Fatal("forced compiler failure unexpectedly succeeded")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(t.TempDir(), "compiler-temporary")
	if err := os.Mkdir(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), testBinary,
		"-test.run=^TestReleaseTestBinaryBuildFailurePreservesDiagnosticsAndCleanup$",
		"-test.count=1", "-test.timeout=60s", "-test.v")
	child.Env = append(os.Environ(), childFlag+"=1", "TMPDIR="+temporary,
		"GOFLAGS=-sbxr-cache-forced-build-failure")
	output, err := child.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("build sbxr-release:")) ||
		!bytes.Contains(output, []byte("unknown flag -sbxr-cache-forced-build-failure")) {
		t.Fatalf("compiler failure lost its real diagnostic: %v\n%s", err, output)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed compiler left temporary files: %v: %v", entries, err)
	}
}
