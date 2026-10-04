package github

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Consumes the actual emitted qualification record. The frozen reader is a
// parser compatibility check, not execution of the released updater.
func TestCleanInstallOnlyRecordCompatibility(t *testing.T) {
	path := os.Getenv("SBXR_TEST_CLEAN_INSTALL_ONLY_RECORD")
	if path == "" {
		t.Skip("exercised with emitted record by cmd/sbxr-release integration test")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body    string                          `json:"body"`
		Release softwarelifecycle.LatestRelease `json:"release"`
		Assets  []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	assets := map[string]assetMetadata{}
	for _, a := range fixture.Assets {
		assets[a.Name] = assetMetadata{Size: a.Size, SHA256: a.SHA256}
	}
	if _, _, ok := latestAcceptanceRecord(fixture.Body, fixture.Release.Identity.Tag, fixture.Release.Identity.Commit, assets); !ok || !qualifiedReleaseSupport(fixture.Body, fixture.Release) {
		t.Fatal("current reader refused clean-install-only record")
	}
	if v3181QualifiedReleaseSupport(fixture.Body, fixture.Release) {
		t.Fatal("frozen v3.1.81 reader accepted unsupported clean-install-only scope")
	}
	for _, prefix := range []string{"Evidence policy: ", "Live acceptance coverage: ", "Karing connectivity evidence: ", "Subscription transport: ", "Release support: ", "Incoming source upgrades: ", "Two-release update/recovery: ", "Scenario: mvp-serving "} {
		for _, bad := range []string{strings.Replace(fixture.Body, prefix, "Omitted: ", 1), fixture.Body + prefix + "invalid\n"} {
			if qualifiedReleaseSupport(bad, fixture.Release) {
				t.Fatalf("missing/duplicate %q accepted", prefix)
			}
		}
	}
	for _, bad := range []string{
		strings.Replace(fixture.Body, "Evidence policy: mvp-http-live-v1", "Evidence policy: mvp-live-v1", 1),
		strings.Replace(fixture.Body, "Scenario: mvp-serving ", "Scenario: mvp-renewal ", 1),
		fixture.Body + "Owner exception: " + softwarelifecycle.LateConfirmationID + "\n",
		fixture.Body + "Automated-only result: Passed in native amd64/arm64 workflow\n",
	} {
		if qualifiedReleaseSupport(bad, fixture.Release) {
			t.Fatal("clean-install-only record accepted incompatible policy or claims")
		}
	}
}
