package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

func TestSourceChecksOnlyTheQualifiedFourAssetLatestRelease(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseAccepted || got.Sequence != 17 || got.Identity.Repository != softwarelifecycle.Repository || got.Identity.Tag != "v2.0.0" || got.Identity.Commit != fixtureCommit {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
	for _, path := range fixture.requests {
		if strings.Contains(path, "/releases/assets/") && !strings.HasSuffix(path, "/2") {
			t.Fatalf("CheckLatest downloaded non-index asset: %s", path)
		}
	}
}

func TestSourceChecksTheCandidateFailureStateBoundQualification(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	assets := make([]map[string]any, 0, len(fixture.release.Assets))
	for _, asset := range fixture.release.Assets {
		assets = append(assets, map[string]any{"name": asset.Name, "size": asset.Size, "sha256": fixture.digests[asset.Name]})
	}
	manifest, err := json.Marshal(map[string]any{
		"schema": "sbxr-qualification-manifest-v1", "repository": softwarelifecycle.Repository,
		"approval": map[string]any{"decision_chain": []map[string]any{
			{"decision_sha256": strings.Repeat("d", 64), "facts_sha256": strings.Repeat("e", 64), "outcome": "accepted", "stage": "candidate-preflight"},
			{"decision_sha256": strings.Repeat("f", 64), "facts_sha256": strings.Repeat("1", 64), "outcome": "actions-required", "stage": "candidate-draft-construction"},
			{"decision_sha256": strings.Repeat("2", 64), "facts_sha256": strings.Repeat("3", 64), "outcome": "accepted", "stage": "candidate-draft-verification"},
		}, "environments": []map[string]any{{"name": "acceptance-vps"}}, "state": "approved"}, "mode": "normal", "source_state": "initial-normal",
		"workflow":        map[string]any{"path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "commit": fixtureCommit, "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123"},
		"releases":        []map[string]any{{"tag": "v2.0.0", "commit": fixtureCommit, "sequence": 17, "release_id": 1, "release_identity": map[string]any{"repository": softwarelifecycle.Repository, "tag": "v2.0.0", "commit": fixtureCommit, "release_index_sha256": fixture.digests["release-index.json"]}, "assets": assets}, {"tag": "v2.0.1", "commit": fixtureCommit, "sequence": 18, "release_id": 2, "release_identity": map[string]any{"repository": softwarelifecycle.Repository, "tag": "v2.0.1", "commit": fixtureCommit, "release_index_sha256": strings.Repeat("a", 64)}, "assets": assets}},
		"native_evidence": []any{}, "acceptance_vps_checklist_sha256": strings.Repeat("b", 64), "pinned_actions": []string{}, "rescue": nil,
		"candidate_failure_state_sha256": strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifest)
	fixture.release.Qualification = &qualificationRelease{Manifest: manifest, Bundle: json.RawMessage(`{"fixture":true}`)}
	verifier := func(body []byte, algorithm, gotDigest string) ([]byte, error) {
		if string(body) != `{"fixture":true}` || algorithm != "sha256" || gotDigest != hex.EncodeToString(digest[:]) {
			return nil, fmt.Errorf("fixture verifier refused")
		}
		return json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []map[string]any{{"name": "qualification-manifest.json", "digest": map[string]string{"sha256": gotDigest}}}})
	}
	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseAccepted || got.Sequence != 17 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

func TestSourceRefusesChangedLatestReleaseFacts(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.release.Assets[1].Digest = "sha256:" + strings.Repeat("a", 64)
	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseRefused || got.Sequence != 0 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

func TestSourceReportsLatestTransportFailureAsUnavailable(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.server.Close()
	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseUnavailable || got.Sequence != 0 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

type latestReleaseFixture struct {
	server   *httptest.Server
	release  githubRelease
	assets   map[string][]byte
	digests  map[string]string
	requests []string
}

func newLatestReleaseFixture(t *testing.T) *latestReleaseFixture {
	t.Helper()
	fixture := &latestReleaseFixture{assets: map[string][]byte{
		"install.sh":              []byte("#!/bin/sh\nexit 1\n"),
		"sbxr-linux-amd64.tar.gz": []byte("amd64 application"),
		"sbxr-linux-arm64.tar.gz": []byte("arm64 application"),
	}, digests: map[string]string{}}
	for name, body := range fixture.assets {
		digest := sha256.Sum256(body)
		fixture.digests[name] = hex.EncodeToString(digest[:])
	}
	index := fmt.Sprintf(`{"schema":1,"repository":%q,"tag":"v2.0.0","commit":%q,"sequence":17,"assets":[{"name":"install.sh","size":%d,"sha256":%q},{"name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":%q},{"name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":%q}]}`,
		softwarelifecycle.Repository, fixtureCommit,
		len(fixture.assets["install.sh"]), fixture.digests["install.sh"],
		len(fixture.assets["sbxr-linux-amd64.tar.gz"]), fixture.digests["sbxr-linux-amd64.tar.gz"],
		len(fixture.assets["sbxr-linux-arm64.tar.gz"]), fixture.digests["sbxr-linux-arm64.tar.gz"])
	fixture.assets["release-index.json"] = []byte(index)
	digest := sha256.Sum256(fixture.assets["release-index.json"])
	fixture.digests["release-index.json"] = hex.EncodeToString(digest[:])
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	fixture.release = githubRelease{Tag: "v2.0.0", TargetCommitish: fixtureCommit, Immutable: true}
	for id, name := range softwarelifecycle.LatestReleaseAssetNames() {
		body := fixture.assets[name]
		fixture.release.Assets = append(fixture.release.Assets, githubAsset{Name: name, Size: int64(len(body)), Digest: "sha256:" + fixture.digests[name], State: "uploaded", URL: fmt.Sprintf("%s/repos/%s/releases/assets/%d", fixture.server.URL, softwarelifecycle.Repository, id+1)})
	}
	fixture.release.Body = fixture.acceptanceRecord()
	return fixture
}

func (fixture *latestReleaseFixture) acceptanceRecord() string {
	lines := []string{
		"# SBXR Installer-Updater Acceptance Record",
		"Status: Qualified",
		"Repository: " + softwarelifecycle.Repository,
		"Tag: v2.0.0",
		"Commit: " + fixtureCommit,
		"Release index SHA-256: " + fixture.digests["release-index.json"],
		"Sequence: 17",
		"Workflow evidence: https://github.com/albertloky/SBXR/actions/runs/123",
		"Runner: Ubuntu Server 24.04 linux/amd64",
		"Go toolchain: go1.26.7",
		"Public verifier: " + Version + " " + SigningFingerprint,
		"Secret-safe result: Passed",
		"Qualification role: Discovered, installed, recovered, final latest release",
		"Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION",
		"Module Verification: Passed",
		"Seam Verification: Passed",
		"Integrated Verification: Passed on live Ubuntu Server 24.04 amd64",
		"Codex Live Acceptance: Passed",
		"Owner Acceptance: Not required",
	}
	for _, asset := range fixture.release.Assets {
		lines = append(lines, fmt.Sprintf("Asset: %s %d %s", asset.Name, asset.Size, fixture.digests[asset.Name]))
	}
	return strings.Join(lines, "\n") + "\n"
}

func (fixture *latestReleaseFixture) verifier(body []byte, algorithm, digest string) ([]byte, error) {
	if string(body) != `{"fixture":true}` || algorithm != "sha1" || digest != fixtureCommit {
		return nil, fmt.Errorf("fixture verifier refused")
	}
	subjects := []map[string]any{{"uri": "pkg:github/" + softwarelifecycle.Repository + "@" + fixture.release.Tag, "digest": map[string]string{"sha1": fixtureCommit}}}
	for _, asset := range fixture.release.Assets {
		subjects = append(subjects, map[string]any{"name": asset.Name, "digest": map[string]string{"sha256": fixture.digests[asset.Name]}})
	}
	return json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://in-toto.io/attestation/release/v0.2", "subject": subjects,
		"predicate": map[string]string{"databaseId": "2", "ownerId": "1", "packageId": "4", "purl": "pkg:github/" + softwarelifecycle.Repository + "@" + fixture.release.Tag, "repository": softwarelifecycle.Repository, "repositoryId": "3", "tag": fixture.release.Tag},
	})
}

func (fixture *latestReleaseFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.requests = append(fixture.requests, request.URL.RequestURI())
	writer.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/repos/" + softwarelifecycle.Repository + "/releases/latest":
		_ = json.NewEncoder(writer).Encode(fixture.release)
	case "/repos/" + softwarelifecycle.Repository + "/attestations/sha1:" + fixtureCommit:
		_ = json.NewEncoder(writer).Encode(map[string]any{"attestations": []map[string]any{{"bundle": map[string]bool{"fixture": true}, "initiator": "github"}}})
	default:
		const prefix = "/repos/" + softwarelifecycle.Repository + "/releases/assets/"
		var id int
		if strings.HasPrefix(request.URL.Path, prefix) {
			_, _ = fmt.Sscanf(strings.TrimPrefix(request.URL.Path, prefix), "%d", &id)
		}
		if id < 1 || id > len(fixture.release.Assets) {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(fixture.assets[fixture.release.Assets[id-1].Name])
	}
}
