package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestPackagedExecutableRunsTheStrictOfflineStagedOnboardingQualification(t *testing.T) {
	binary, components, metadata, manifest, componentSHA256 := packagedQualificationFixture(t)
	temporaryRoot := t.TempDir()
	command := exec.Command(binary, "acceptance", "staged-onboarding", "--components", components, "--json")
	command.Env = append(os.Environ(), "TMPDIR="+temporaryRoot)
	output, err := command.Output()
	if err != nil {
		archive, readErr := os.ReadFile(components)
		if readErr == nil {
			readErr = executePackageQualification(t.Context(), metadata, archive, manifest, componentSHA256, io.Discard)
		}
		t.Fatalf("packaged qualification = %v; direct = %v", err, readErr)
	}
	if err := softwarelifecycle.ValidatePackageQualificationEvidence(output, metadata.Build, metadata.Architecture, manifest, componentSHA256); err != nil {
		t.Fatalf("packaged evidence = %s: %v", output, err)
	}
	entries, err := os.ReadDir(temporaryRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("residual packaged qualification state = %#v, %v", entries, err)
	}
}

func TestPackagedExecutableRefusesArgumentsAndChangedComponentsWithOneSafeCode(t *testing.T) {
	binary, components, metadata, _, _ := packagedQualificationFixture(t)
	changed := filepath.Join(t.TempDir(), "changed.tar.gz")
	body, err := os.ReadFile(components)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if err := os.WriteFile(changed, body, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "components-link.tar.gz")
	if err := os.Symlink(components, symlink); err != nil {
		t.Fatal(err)
	}
	wrongBuild := metadata.Build
	wrongBuild.Commit = strings.Repeat("c", 40)
	files := packageQualificationComponentFiles()
	wrongBuildManifest, err := softwarelifecycle.NewBoundComponentManifest(metadata.Architecture, wrongBuild, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	wrongBuildArchive, err := softwarelifecycle.BuildComponentArchive(wrongBuildManifest, files)
	if err != nil {
		t.Fatal(err)
	}
	wrongBuildPath := filepath.Join(t.TempDir(), "wrong-build.tar.gz")
	if err := os.WriteFile(wrongBuildPath, wrongBuildArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongArchitecture := softwarelifecycle.ARM64
	if metadata.Architecture == softwarelifecycle.ARM64 {
		wrongArchitecture = softwarelifecycle.AMD64
	}
	wrongArchitectureManifest, err := softwarelifecycle.NewBoundComponentManifest(wrongArchitecture, metadata.Build, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	wrongArchitectureArchive, err := softwarelifecycle.BuildComponentArchive(wrongArchitectureManifest, files)
	if err != nil {
		t.Fatal(err)
	}
	wrongArchitecturePath := filepath.Join(t.TempDir(), "wrong-architecture.tar.gz")
	if err := os.WriteFile(wrongArchitecturePath, wrongArchitectureArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	badCoreFiles := packageQualificationComponentFiles()
	badCoreFiles["xray"] = []byte("#!/bin/sh\nexit 1\n")
	badCoreManifest, err := softwarelifecycle.NewBoundComponentManifest(metadata.Architecture, metadata.Build, "5.4.0", badCoreFiles)
	if err != nil {
		t.Fatal(err)
	}
	badCoreArchive, err := softwarelifecycle.BuildComponentArchive(badCoreManifest, badCoreFiles)
	if err != nil {
		t.Fatal(err)
	}
	badCorePath := filepath.Join(t.TempDir(), "bad-core.tar.gz")
	if err := os.WriteFile(badCorePath, badCoreArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	changedValidFiles := packageQualificationComponentFiles()
	changedValidFiles["cloudflared"] = []byte("different controlled cloudflared")
	changedValidManifest, err := softwarelifecycle.NewBoundComponentManifest(metadata.Architecture, metadata.Build, "5.4.0", changedValidFiles)
	if err != nil {
		t.Fatal(err)
	}
	changedValidArchive, err := softwarelifecycle.BuildComponentArchive(changedValidManifest, changedValidFiles)
	if err != nil {
		t.Fatal(err)
	}
	changedValidPath := filepath.Join(t.TempDir(), "changed-valid-components.tar.gz")
	if err := os.WriteFile(changedValidPath, changedValidArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"acceptance", "staged-onboarding", "--components", components},
		{"acceptance", "staged-onboarding", "--components", changed, "--json"},
		{"acceptance", "staged-onboarding", "--components", symlink, "--json"},
		{"acceptance", "staged-onboarding", "--components", wrongBuildPath, "--json"},
		{"acceptance", "staged-onboarding", "--components", wrongArchitecturePath, "--json"},
		{"acceptance", "staged-onboarding", "--components", badCorePath, "--json"},
		{"acceptance", "staged-onboarding", "--components", changedValidPath, "--json"},
		{"acceptance", "staged-onboarding", "--components", components, "--json", "extra"},
	} {
		command := exec.Command(binary, arguments...)
		output, err := command.Output()
		if err == nil || len(output) != 0 {
			t.Fatalf("refused packaged command = output %q, error %v", output, err)
		}
		exit := err.(*exec.ExitError)
		if string(exit.Stderr) != packageQualificationRefusal+"\n" {
			t.Fatalf("refusal = %q", exit.Stderr)
		}
	}
}

func packagedQualificationFixture(t *testing.T) (string, string, softwarelifecycle.PayloadMetadata, softwarelifecycle.ComponentManifest, string) {
	t.Helper()
	binary := buildSBXR(t, runtime.GOOS, runtime.GOARCH)
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	architecture := softwarelifecycle.Architecture(runtime.GOARCH)
	metadata, err := testReleaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40)}, architecture)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(body)
	metadata.Build.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	files := packageQualificationComponentFiles()
	manifest, err := softwarelifecycle.NewBoundComponentManifest(architecture, metadata.Build, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := softwarelifecycle.BuildComponentArchive(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	metadata.ComponentsSHA256 = hex.EncodeToString(digest[:])
	stamped, err := softwarelifecycle.StampPayload(body, metadata)
	if err != nil || os.WriteFile(binary, stamped, 0o700) != nil {
		t.Fatal(err)
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err = softwarelifecycle.ReadPayloadMetadata(file, int64(len(stamped)))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err)
	}
	components := filepath.Join(t.TempDir(), "sbxr-components-linux-"+runtime.GOARCH+".tar.gz")
	if err := os.WriteFile(components, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return binary, components, metadata, manifest, hex.EncodeToString(digest[:])
}

func packageQualificationComponentFiles() map[string][]byte {
	return map[string][]byte{
		"xray":                []byte("#!/bin/sh\ncase \"$1\" in version) printf 'Xray 26.3.27\\n' ;; run) exit 0 ;; *) exit 1 ;; esac\n"),
		"sing-box":            []byte("#!/bin/sh\ncase \"$1\" in version) printf 'sing-box version 1.13.16\\n' ;; check) exit 0 ;; *) exit 1 ;; esac\n"),
		"cloudflared":         []byte("controlled cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(),
		"certbot/pyvenv.cfg":  []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
}
