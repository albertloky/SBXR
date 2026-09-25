package github

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestFrozenV3181ReaderHasOnlyMechanicalRenames(t *testing.T) {
	body, err := os.ReadFile("v3181_reader_test.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(body), "\n", 4)
	want := strings.TrimPrefix(lines[1], "// Original SHA-256: ")
	original := strings.NewReplacer("v3181QualifiedReleaseSupport", "qualifiedReleaseSupport", "v3181QualifiedMVPScenarios", "qualifiedMVPScenarios").Replace(lines[3])
	if fmt.Sprintf("%x", sha256.Sum256([]byte(original))) != want {
		t.Fatal("frozen reader logic changed")
	}
}

// The release-tool integration test supplies its actual emitted record, not a
// second hand-authored record. This checks parsers, not network attestations or
// the released Linux executable's update/recovery execution.
func TestOrdinaryRecordCompatibility(t *testing.T) {
	path := os.Getenv("SBXR_TEST_RECURRING_RECORD")
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
	if _, _, ok := latestAcceptanceRecord(fixture.Body, fixture.Release.Identity.Tag, fixture.Release.Identity.Commit, assets); !ok {
		t.Fatal("public record envelope refused")
	}
	if !v3181QualifiedReleaseSupport(fixture.Body, fixture.Release) {
		t.Fatal("unchanged v3.1.81 support reader refused actual new record")
	}
	if !qualifiedReleaseSupport(fixture.Body, fixture.Release) {
		t.Fatal("current support reader refused actual new record")
	}
	for _, suffix := range []string{"precommit", "upgrade", "postcommit"} {
		line := "Scenario: source-" + fixture.Release.Support.Sources[0].Tag + "-" + suffix + " "
		bad := strings.Replace(fixture.Body, line, "Omitted: ", 1)
		if v3181QualifiedReleaseSupport(bad, fixture.Release) || qualifiedReleaseSupport(bad, fixture.Release) {
			t.Fatalf("missing %s accepted", suffix)
		}
	}
	for _, prefix := range []string{"Recurring evidence policy: ", "Recurring live acceptance coverage: ", "Recurring Karing evidence: ", "Journey: mvp-install "} {
		for _, bad := range []string{strings.Replace(fixture.Body, prefix, "Omitted: ", 1), fixture.Body + prefix + "invalid\n"} {
			if qualifiedReleaseSupport(bad, fixture.Release) {
				t.Fatalf("missing/duplicate scope field %q accepted", prefix)
			}
		}
	}
}
