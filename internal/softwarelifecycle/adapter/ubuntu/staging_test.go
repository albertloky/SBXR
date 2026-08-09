package ubuntu_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	ubuntuadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func TestStagerValidatesEmbeddedDocumentsWithoutExecutingTheCandidate(t *testing.T) {
	executable := stampedExecutable(t, "amd64")
	armExecutable := stampedExecutable(t, "arm64")
	archive := releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(executable)), Typeflag: tar.TypeReg}, executable)
	armArchive := releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(armExecutable)), Typeflag: tar.TypeReg}, armExecutable)
	request := stageRequest(t, softwarelifecycle.AMD64, archive, armArchive)
	got, err := ubuntuadapter.NewStager().Stage(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executable)
	if got.Identity != request.Release.Identity || got.Build.PayloadSHA256 == "" || got.Architecture != softwarelifecycle.AMD64 || got.ExecutableSHA256 != hex.EncodeToString(digest[:]) || got.InstallPath != softwarelifecycle.ReleaseInstallPath(request.Release.Identity) || got.StateSchema != 2 {
		t.Fatalf("Stage() = %#v", got)
	}
}

func TestStagerRejectsCallerAuthoredHostileArchitectureRuntimeMetadataAndNativeFailure(t *testing.T) {
	amd64 := stampedExecutable(t, "amd64")
	arm64 := stampedExecutable(t, "arm64")
	valid := releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(amd64)), Typeflag: tar.TypeReg}, amd64)
	validARM64 := releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(arm64)), Typeflag: tar.TypeReg}, arm64)
	if got, err := ubuntuadapter.NewStager().Stage(t.Context(), softwarelifecycle.StageRequest{}); err == nil || got.Identity.Repository != "" {
		t.Fatalf("caller-authored staging request accepted: %#v, %v", got, err)
	}
	tests := []struct {
		name   string
		change func(*softwarelifecycle.StageRequest)
	}{
		{"absolute name", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "/sbxr", Mode: 0o755, Size: int64(len(amd64)), Typeflag: tar.TypeReg}, amd64))
		}},
		{"traversal", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "../sbxr", Mode: 0o755, Size: int64(len(amd64)), Typeflag: tar.TypeReg}, amd64))
		}},
		{"symbolic link", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Typeflag: tar.TypeSymlink, Linkname: "target"}, nil))
		}},
		{"unsafe hard link", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Typeflag: tar.TypeLink, Linkname: "target"}, nil))
		}},
		{"special file", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Typeflag: tar.TypeChar}, nil))
		}},
		{"unsafe ownership", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Uid: 1000, Size: int64(len(amd64)), Typeflag: tar.TypeReg}, amd64))
		}},
		{"unsafe mode", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o777, Size: int64(len(amd64)), Typeflag: tar.TypeReg}, amd64))
		}},
		{"duplicate destination", func(request *softwarelifecycle.StageRequest) { replaceStageArchive(request, duplicateArchive(amd64)) }},
		{"wrong architecture", func(request *softwarelifecycle.StageRequest) {
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(arm64)), Typeflag: tar.TypeReg}, arm64))
		}},
		{"wrong archive digest", func(request *softwarelifecycle.StageRequest) { request.Asset.SHA256 = strings.Repeat("a", 64) }},
		{"non Go executable", func(request *softwarelifecycle.StageRequest) {
			body, _ := os.ReadFile("/usr/bin/env")
			stamped, _ := softwarelifecycle.StampPayload(body, qualificationMetadata(softwarelifecycle.AMD64))
			replaceStageArchive(request, releaseArchive(tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(stamped)), Typeflag: tar.TypeReg}, stamped))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := stageRequest(t, softwarelifecycle.AMD64, valid, validARM64)
			test.change(&request)
			if got, err := ubuntuadapter.NewStager().Stage(t.Context(), request); err == nil || got.Identity.Repository != "" {
				t.Fatalf("hostile payload accepted: %#v, %v", got, err)
			}
		})
	}
}

func stampedExecutable(t *testing.T, architecture string) []byte {
	t.Helper()
	directory := t.TempDir()
	source, binary := filepath.Join(directory, "main.go"), filepath.Join(directory, "sbxr")
	if err := os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-trimpath", "-o", binary, source)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	stamped, err := softwarelifecycle.StampPayload(body, qualificationMetadata(softwarelifecycle.Architecture(architecture)))
	if err != nil {
		t.Fatal(err)
	}
	return stamped
}

func qualificationMetadata(architecture softwarelifecycle.Architecture) softwarelifecycle.PayloadMetadata {
	definitions, _ := state.ReleaseDefinitions()
	units := map[string][]byte{}
	commands := map[string]string{
		"cloudflared.service": "@SBXR_RELEASE_DIR@/cloudflared tunnel --no-autoupdate run --token-file /etc/sbxr/cloudflared/token", "sbxr-cert-renew.service": "/usr/local/bin/sbxr private certificate-renewal", "sbxr-health-check.service": "/usr/local/bin/sbxr private health-check", "sbxr-subscription.service": "/usr/local/bin/sbxr __subscription-serve", "sbxr-update-check.service": "/usr/local/bin/sbxr private update-check", "sing-box.service": "@SBXR_RELEASE_DIR@/sing-box run -c /etc/sbxr/sing-box/config.json", "xray.service": "@SBXR_RELEASE_DIR@/xray run -config /etc/sbxr/xray/config.json",
	}
	for _, name := range softwarelifecycle.ManagedUnitNames() {
		if strings.HasSuffix(name, ".timer") {
			units[name] = []byte("[Timer]\nUnit=" + strings.TrimSuffix(name, ".timer") + ".service\n")
		} else {
			units[name] = []byte("[Service]\nExecStart=" + commands[name] + "\n")
		}
	}
	artifacts, _ := subscriptionpublication.QualificationArtifacts()
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	return softwarelifecycle.PayloadMetadata{Schema: 1, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40)}, Architecture: architecture, StateSchema: 2, MinimumUpdaterSchema: 1, Schemas: definitions, Migrations: []softwarelifecycle.EmbeddedMigration{{Name: "state-v1-to-v2.json", From: 1, To: 2, Document: state.ReleaseMigrations()["state-v1-to-v2.json"]}}, Units: units, Artifacts: artifacts, Baselines: softwarelifecycle.QualifiedComponentBaselines(), Paths: softwarelifecycle.QualifiedPaths()}
}

func stageRequest(t *testing.T, architecture softwarelifecycle.Architecture, amd64Archive, arm64Archive []byte) softwarelifecycle.StageRequest {
	t.Helper()
	amd64Digest, arm64Digest := sha256.Sum256(amd64Archive), sha256.Sum256(arm64Archive)
	amd64Components, arm64Components := stagingComponents(softwarelifecycle.AMD64), stagingComponents(softwarelifecycle.ARM64)
	amd64ComponentsDigest, arm64ComponentsDigest := sha256.Sum256(amd64Components), sha256.Sum256(arm64Components)
	index := []byte(fmt.Sprintf(`{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.0","sequence":1,"tag":"v1.0.0","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state_schema":2,"minimum_updater_schema":1,"assets":[{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"application-linux-arm64","name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":"%s"},{"role":"components-linux-amd64","name":"sbxr-components-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"components-linux-arm64","name":"sbxr-components-linux-arm64.tar.gz","size":%d,"sha256":"%s"}]}`, len(amd64Archive), hex.EncodeToString(amd64Digest[:]), len(arm64Archive), hex.EncodeToString(arm64Digest[:]), len(amd64Components), hex.EncodeToString(amd64ComponentsDigest[:]), len(arm64Components), hex.EncodeToString(arm64ComponentsDigest[:])))
	indexDigest := sha256.Sum256(index)
	evidence := softwarelifecycle.ReleaseEvidence{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), Index: index, Assets: []softwarelifecycle.DownloadedAsset{{Name: "sbxr-linux-amd64.tar.gz", Bytes: amd64Archive}, {Name: "sbxr-linux-arm64.tar.gz", Bytes: arm64Archive}, {Name: "sbxr-components-linux-amd64.tar.gz", Bytes: amd64Components}, {Name: "sbxr-components-linux-arm64.tar.gz", Bytes: arm64Components}}, AttestedAssets: []softwarelifecycle.AttestedAsset{{Name: "release-index.json", SHA256: hex.EncodeToString(indexDigest[:])}, {Name: "sbxr-linux-amd64.tar.gz", SHA256: hex.EncodeToString(amd64Digest[:])}, {Name: "sbxr-linux-arm64.tar.gz", SHA256: hex.EncodeToString(arm64Digest[:])}, {Name: "sbxr-components-linux-amd64.tar.gz", SHA256: hex.EncodeToString(amd64ComponentsDigest[:])}, {Name: "sbxr-components-linux-arm64.tar.gz", SHA256: hex.EncodeToString(arm64ComponentsDigest[:])}}, Verifier: softwarelifecycle.VerifierEvidence{Version: "2.97.0", SigningFingerprint: strings.Repeat("A", 40), OfficialSignedDistribution: true, ReleaseVerified: true, VerifiedAssets: []string{"release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz"}}}
	recorder := &requestRecorder{}
	module := softwarelifecycle.New(staticSource{evidence}, softwarelifecycle.VerifierQualification{Version: "2.97.0", SigningFingerprint: strings.Repeat("A", 40)}, func() time.Time { return time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC) }, recorder)
	_ = module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
	if !recorder.request.Authenticated() {
		t.Fatal("View did not authenticate staging")
	}
	return recorder.request
}

func stagingComponents(architecture softwarelifecycle.Architecture) []byte {
	files := map[string][]byte{
		"xray": []byte("qualified xray"), "sing-box": []byte("qualified sing-box"), "cloudflared": []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, _ := softwarelifecycle.NewComponentManifest(architecture, "5.4.0", files)
	archive, _ := softwarelifecycle.BuildComponentArchive(manifest, files)
	return archive
}

type staticSource struct {
	evidence softwarelifecycle.ReleaseEvidence
}

func (source staticSource) Verify(context.Context, string) (softwarelifecycle.ReleaseEvidence, error) {
	return source.evidence, nil
}

type requestRecorder struct {
	request softwarelifecycle.StageRequest
}

func (recorder *requestRecorder) Stage(_ context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	recorder.request = request
	return softwarelifecycle.StagedRelease{}, errors.New("capture")
}

func releaseArchive(header tar.Header, body []byte) []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	_ = archive.WriteHeader(&header)
	_, _ = archive.Write(body)
	_ = archive.Close()
	_ = compressed.Close()
	return output.Bytes()
}
func duplicateArchive(body []byte) []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for range 2 {
		_ = archive.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = archive.Write(body)
	}
	_ = archive.Close()
	_ = compressed.Close()
	return output.Bytes()
}
func replaceStageArchive(request *softwarelifecycle.StageRequest, archive []byte) {
	digest := sha256.Sum256(archive)
	request.Archive = archive
	request.Asset.Size = int64(len(archive))
	request.Asset.SHA256 = hex.EncodeToString(digest[:])
}
