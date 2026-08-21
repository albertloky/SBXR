package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
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
	applicationBody, err := os.ReadFile(application)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := gzip.NewReader(bytes.NewReader(applicationBody))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(compressed)
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" {
		t.Fatal("application executable unavailable")
	}
	executable, err := io.ReadAll(archive)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(executable), int64(len(executable)))
	digest := sha256.Sum256([]byte("qualified-components"))
	if err != nil || metadata.ComponentsSHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("bound component digest = %q, %v", metadata.ComponentsSHA256, err)
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

func TestValidatePackageQualificationFilesUsesStrictEvidenceAndCanonicalSecretMarkers(t *testing.T) {
	fixture := packageQualificationReleaseFixture(t, "v1.0.0", strings.Repeat("a", 40), softwarelifecycle.AMD64)
	root := t.TempDir()
	options := packageQualificationValidationOptions{application: filepath.Join(root, "application.tar.gz"), components: filepath.Join(root, "components.tar.gz"), evidence: filepath.Join(root, "evidence.json")}
	for name, body := range map[string][]byte{options.application: fixture.application, options.components: fixture.components, options.evidence: fixture.evidence} {
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validatePackageQualificationFiles(options); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(fixture.evidence, []byte(`{"schema":1`), []byte(`{"schema":1,"schema":1`), 1)
	if err := os.WriteFile(options.evidence, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if validatePackageQualificationFiles(options) == nil {
		t.Fatal("duplicate package qualification evidence accepted")
	}
}

type packageQualificationRelease struct{ application, components, evidence []byte }

func packageQualificationReleaseFixture(t *testing.T, tag, commit string, architecture softwarelifecycle.Architecture) packageQualificationRelease {
	t.Helper()
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: tag, Commit: commit}, architecture)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("qualified executable " + architecture)
	stamped, err := softwarelifecycle.StampPayload(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err = softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(stamped), int64(len(stamped)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"xray":                []byte("qualified xray"),
		"sing-box":            []byte("qualified sing-box"),
		"cloudflared":         []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(),
		"certbot/pyvenv.cfg":  []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, err := softwarelifecycle.NewBoundComponentManifest(architecture, metadata.Build, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(components)
	componentSHA256 := fmt.Sprintf("%x", digest)
	metadata.ComponentsSHA256 = componentSHA256
	stamped, err = softwarelifecycle.StampPayload(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	application, err := oneFileArchive(stamped)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := softwarelifecycle.BuildPackageQualificationEvidence(metadata.Build, architecture, manifest, componentSHA256, softwarelifecycle.PackageQualificationProcedureCodes)
	if err != nil {
		t.Fatal(err)
	}
	return packageQualificationRelease{application: application, components: components, evidence: evidence}
}

type acceptanceRecordFixture struct{ root, qualifications, tag, commit string }

func newAcceptanceRecordFixture(t *testing.T) acceptanceRecordFixture {
	t.Helper()
	fixture := acceptanceRecordFixture{root: t.TempDir(), qualifications: t.TempDir(), tag: "v1.0.2", commit: strings.Repeat("a", 40)}
	if err := buildBootstrapFile(bootstrapOptions{version: "1.0.2", sequence: 3, tag: fixture.tag, commit: fixture.commit, output: filepath.Join(fixture.root, "install.sh"), amd64ExecutableSHA256: strings.Repeat("a", 64), arm64ExecutableSHA256: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		qualification := packageQualificationReleaseFixture(t, fixture.tag, fixture.commit, architecture)
		for name, body := range map[string][]byte{
			filepath.Join(fixture.root, "sbxr-linux-"+string(architecture)+".tar.gz"):                    qualification.application,
			filepath.Join(fixture.root, "sbxr-components-linux-"+string(architecture)+".tar.gz"):         qualification.components,
			filepath.Join(fixture.qualifications, "package-qualification-"+string(architecture)+".json"): qualification.evidence,
		} {
			if err := os.WriteFile(name, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.2", sequence: 3, tag: fixture.tag, commit: fixture.commit, directory: fixture.root, output: filepath.Join(fixture.root, "release-index.json")}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestAutomatedAcceptanceRecordBindsOneExactStagedOnboardingRelease(t *testing.T) {
	fixture := newAcceptanceRecordFixture(t)
	commit := fixture.commit
	output := filepath.Join(t.TempDir(), "acceptance-record.md")
	err := writeAutomatedAcceptanceRecord(acceptanceOptions{tag: fixture.tag, commit: fixture.commit, directory: fixture.root, qualificationDirectory: fixture.qualifications, output: output, evidenceURL: "https://github.com/albertloky/SBXR/actions/runs/123456789"}, time.Date(2026, 8, 13, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"# SBXR automated Acceptance Record", "Status: Qualified - staged-onboarding package policy", "Repository: albertloky/SBXR", "Tag: v1.0.2", "Commit: " + commit, "Recorded at: 2026-08-13T03:04:05Z", "Runner: GitHub Actions ubuntu-24.04", "Go toolchain: go1.26.6", "Public verifier: 1.3.0", "Stable result code: RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION", "RELEASE-STAGED-INSTALL-REVISION-1", "RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1", "RELEASE-STAGED-ONBOARDING-CHAIN", "RELEASE-STAGED-ONBOARDING-SECRET-SCAN", "RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT", "RELEASE-STAGED-ONBOARDING-TERMINAL", "RELEASE-STAGED-ONBOARDING-GUIDE-TEXT", "Packaged executable qualification: amd64 Passed; arm64 Passed.", "| Module Verification | Passed |", "| Seam Verification | Passed |", "| Integrated Verification | Passed | Staged Installation, Cloudflare Profile Setup, and chained package composition |", "Codex Live Acceptance: Not required — staged-onboarding package and controlled-seam qualification scope.", "Owner Acceptance: Not required — staged-onboarding package and controlled-terminal qualification scope.", "No live VPS, real Cloudflare, ACME, outside-client, maintained-client, current-documentation, provider mutation, or Owner Acceptance was performed.", "install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "https://github.com/albertloky/SBXR/actions/runs/123456789", "Any changed asset, commit, tag, release-index digest, procedure, guide text, selected output, or required test resets its affected result."} {
		if !strings.Contains(text, want) {
			t.Fatalf("Acceptance Record omitted %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "SECRET-MARKER") {
		t.Fatal("Acceptance Record exposed a secret marker")
	}
	for _, obsolete := range []string{"installer-only automated exception", "ADR-0007 installer-only scope", "root-runtime package policy", "RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION", "ADR-0010 root-runtime package and public-seam scope"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("Acceptance Record retained obsolete %q", obsolete)
		}
	}
}

func TestAutomatedAcceptanceRecordRefusesMissingMismatchedOrExtraPackageEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, acceptanceRecordFixture)
	}{
		{name: "missing architecture", change: func(t *testing.T, fixture acceptanceRecordFixture) {
			t.Helper()
			if err := os.Remove(filepath.Join(fixture.qualifications, "package-qualification-arm64.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mismatched architecture", change: func(t *testing.T, fixture acceptanceRecordFixture) {
			t.Helper()
			body, err := os.ReadFile(filepath.Join(fixture.qualifications, "package-qualification-arm64.json"))
			if err != nil || os.WriteFile(filepath.Join(fixture.qualifications, "package-qualification-amd64.json"), body, 0o600) != nil {
				t.Fatal(err)
			}
		}},
		{name: "extra evidence", change: func(t *testing.T, fixture acceptanceRecordFixture) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(fixture.qualifications, "extra.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "different application build", change: func(t *testing.T, fixture acceptanceRecordFixture) {
			t.Helper()
			different := packageQualificationReleaseFixture(t, "v9.0.0", fixture.commit, softwarelifecycle.AMD64)
			for name, body := range map[string][]byte{
				filepath.Join(fixture.root, "sbxr-linux-amd64.tar.gz"):                    different.application,
				filepath.Join(fixture.root, "sbxr-components-linux-amd64.tar.gz"):         different.components,
				filepath.Join(fixture.qualifications, "package-qualification-amd64.json"): different.evidence,
			} {
				if err := os.WriteFile(name, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(fixture.root, "release-index.json")); err != nil {
				t.Fatal(err)
			}
			if err := buildReleaseIndexFile(indexOptions{version: "1.0.2", sequence: 3, tag: fixture.tag, commit: fixture.commit, directory: fixture.root, output: filepath.Join(fixture.root, "release-index.json")}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAcceptanceRecordFixture(t)
			test.change(t, fixture)
			err := writeAutomatedAcceptanceRecord(acceptanceOptions{tag: fixture.tag, commit: fixture.commit, directory: fixture.root, qualificationDirectory: fixture.qualifications, output: filepath.Join(t.TempDir(), "acceptance-record.md"), evidenceURL: "https://github.com/albertloky/SBXR/actions/runs/123456789"}, time.Now())
			if err == nil {
				t.Fatal("invalid public Package Qualification evidence received an Acceptance Record")
			}
		})
	}
}

func TestControlledStagedOnboardingSecretScanUsesReleaseSurfaces(t *testing.T) {
	fixture := newAcceptanceRecordFixture(t)
	root := fixture.root
	archiveNames := []string{"sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz"}
	acceptance := filepath.Join(t.TempDir(), "acceptance-record.md")
	if err := writeAutomatedAcceptanceRecord(acceptanceOptions{tag: fixture.tag, commit: fixture.commit, directory: root, qualificationDirectory: fixture.qualifications, output: acceptance, evidenceURL: "https://github.com/albertloky/SBXR/actions/runs/123456789"}, time.Date(2026, 8, 13, 3, 4, 5, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	surfaces := map[string][]byte{}
	for name, path := range map[string]string{"acceptance": acceptance, "bootstrap": filepath.Join(root, "install.sh"), "index": filepath.Join(root, "release-index.json")} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		surfaces[name] = body
	}
	for _, name := range archiveNames {
		surfaces["decompressed-"+name] = readControlledArchive(t, filepath.Join(root, name))
	}
	required := []string{"acceptance", "bootstrap", "index", "decompressed-sbxr-linux-amd64.tar.gz", "decompressed-sbxr-linux-arm64.tar.gz", "decompressed-sbxr-components-linux-amd64.tar.gz", "decompressed-sbxr-components-linux-arm64.tar.gz"}
	if err := softwarelifecycle.QualifyControlledStagedOnboardingSurfaces(surfaces, required); err != nil {
		t.Fatal(err)
	}
	for _, marker := range softwarelifecycle.ControlledStagedOnboardingSecretMarkers() {
		for _, name := range required {
			leaked := make(map[string][]byte, len(surfaces))
			for surface, body := range surfaces {
				leaked[surface] = append([]byte(nil), body...)
			}
			leaked[name] = append(leaked[name], marker.Value...)
			if err := softwarelifecycle.QualifyControlledStagedOnboardingSurfaces(leaked, required); err == nil {
				t.Fatalf("%s marker was accepted on %s", marker.Class, name)
			}
		}
	}
}

func readControlledArchive(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var surface bytes.Buffer
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeSymlink {
			t.Fatal("controlled archive surface unavailable")
		}
		if header.Typeflag == tar.TypeSymlink {
			continue
		}
		if _, err := io.Copy(&surface, archive); err != nil {
			t.Fatal(err)
		}
	}
	return surface.Bytes()
}

func TestAutomatedAcceptanceRecordRefusesChangedOrExtraReleaseMaterial(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, string)
	}{
		{name: "changed indexed asset", change: func(t *testing.T, root string) {
			t.Helper()
			mustWrite(t, filepath.Join(root, "install.sh"), "changed")
		}},
		{name: "extra asset", change: func(t *testing.T, root string) { t.Helper(); mustWrite(t, filepath.Join(root, "extra"), "unexpected") }},
		{name: "duplicate index key", change: func(t *testing.T, root string) {
			t.Helper()
			name := filepath.Join(root, "release-index.json")
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, name, strings.Replace(string(body), `"schema":1`, `"schema":1,"schema":1`, 1))
		}},
		{name: "duplicate nested index key", change: func(t *testing.T, root string) {
			t.Helper()
			name := filepath.Join(root, "release-index.json")
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, name, strings.Replace(string(body), `"role":"application-linux-amd64"`, `"role":"application-linux-amd64","role":"application-linux-amd64"`, 1))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAcceptanceRecordFixture(t)
			test.change(t, fixture.root)
			err := writeAutomatedAcceptanceRecord(acceptanceOptions{tag: fixture.tag, commit: fixture.commit, directory: fixture.root, qualificationDirectory: fixture.qualifications, output: filepath.Join(t.TempDir(), "acceptance-record.md"), evidenceURL: "https://github.com/albertloky/SBXR/actions/runs/123456789"}, time.Now())
			if err == nil {
				t.Fatal("changed release material received an Acceptance Record")
			}
		})
	}
}

func TestAutomatedAcceptanceRecordRefusesAnEarlierAssetReplacedAfterItsRead(t *testing.T) {
	fixture := newAcceptanceRecordFixture(t)
	root := fixture.root
	replaced := false
	err := writeAutomatedAcceptanceRecord(acceptanceOptions{tag: fixture.tag, commit: fixture.commit, directory: root, qualificationDirectory: fixture.qualifications, output: filepath.Join(t.TempDir(), "acceptance-record.md"), evidenceURL: "https://github.com/albertloky/SBXR/actions/runs/123456789", afterAssetRead: func(name string) {
		if name == "release-index.json" && !replaced {
			replaced = true
			replacement := filepath.Join(t.TempDir(), "replacement")
			mustWrite(t, replacement, "changed install")
			if err := os.Rename(replacement, filepath.Join(root, "install.sh")); err != nil {
				t.Fatal(err)
			}
		}
	}}, time.Now())
	if err == nil || !replaced {
		t.Fatalf("late asset replacement = %v, replaced=%t", err, replaced)
	}
}

func mustWrite(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
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
			if importErr != nil || len(libraries) != 0 || buildErr != nil || build.GoVersion != "go1.26.6" {
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
