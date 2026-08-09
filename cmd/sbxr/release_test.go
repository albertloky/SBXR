package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

func TestVersionReportsOnlyEmbeddedBuildFacts(t *testing.T) {
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
	stamped, err := softwarelifecycle.StampPayload(body, metadata)
	if err != nil || os.WriteFile(binary, stamped, 0o700) != nil {
		t.Fatal(err)
	}
	plain, err := exec.Command(binary, "version").Output()
	plainText := string(plain)
	if err != nil || !strings.HasPrefix(plainText, "sbxr "+softwarelifecycle.Repository+" v1.0.0 ("+strings.Repeat("a", 40)+" linux/"+runtime.GOARCH+" payload ") || !strings.Contains(plainText, " state-schema 2)") {
		t.Fatalf("version = %q, %v", plain, err)
	}
	output, err := exec.Command(binary, "version", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var report versionReport
	if json.Unmarshal(output, &report) != nil || report.Build.Repository != softwarelifecycle.Repository || report.Build.PayloadSHA256 == "" || report.StateSchema != 2 {
		t.Fatalf("version JSON = %s", output)
	}
}

func buildSBXR(t *testing.T, operatingSystem, architecture string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "sbxr")
	command := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+operatingSystem, "GOARCH="+architecture)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	return binary
}

func testReleaseMetadata(identity softwarelifecycle.EmbeddedBuildIdentity, architecture softwarelifecycle.Architecture) (softwarelifecycle.PayloadMetadata, error) {
	artifacts, err := subscriptionpublication.QualificationArtifacts()
	if err != nil {
		return softwarelifecycle.PayloadMetadata{}, err
	}
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	definitions, err := state.ReleaseDefinitions()
	if err != nil {
		return softwarelifecycle.PayloadMetadata{}, err
	}
	unitSets := []map[string]string{{"cloudflared.service": cloudflaretunnel.CloudflaredServiceUnit()}, {"sbxr-subscription.service": subscriptionserving.ServiceUnit()}, connectionprofiles.SystemdUnits(), softwarelifecycle.SystemdUnits()}
	for _, read := range []func() (map[string]string, error){certificatelifecycle.SystemdUnits, healthdiagnostics.SystemdUnits} {
		set, err := read()
		if err != nil {
			return softwarelifecycle.PayloadMetadata{}, err
		}
		unitSets = append(unitSets, set)
	}
	return softwarelifecycle.NewPayloadMetadata(identity, architecture, softwarelifecycle.PayloadMaterial{StateDefinitions: definitions, StateMigrations: state.ReleaseMigrations(), UnitSets: unitSets, ArtifactSets: []map[string][]byte{artifacts}})
}
