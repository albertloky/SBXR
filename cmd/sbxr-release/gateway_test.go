package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestQualificationGatewayServesOnlyManifestBoundReleaseRequests(t *testing.T) {
	root := t.TempDir()
	releases := []map[string]any{}
	for releaseIndex, tag := range []string{"v2.0.0", "v2.0.1"} {
		directory := filepath.Join(root, tag)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		assets := []map[string]any{}
		for _, name := range []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"} {
			body := []byte(tag + " " + name)
			if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			assets = append(assets, map[string]any{"name": name, "size": len(body), "sha256": hex.EncodeToString(digest[:])})
		}
		releases = append(releases, map[string]any{
			"tag": tag, "sequence": 17 + releaseIndex, "commit": strings.Repeat("a", 40), "release_id": 100 + releaseIndex,
			"release_identity": map[string]any{"repository": "albertloky/SBXR", "tag": tag, "commit": strings.Repeat("a", 40), "release_index_sha256": assets[1]["sha256"]},
			"assets":           assets,
		})
	}
	manifest, _ := json.MarshalIndent(map[string]any{"schema": "sbxr-qualification-manifest-v1", "repository": "albertloky/SBXR", "releases": releases}, "", "  ")
	manifest = append(manifest, '\n')
	bundle := json.RawMessage("{\n  \"bundle\": true\n}\n")
	gateway, err := newQualificationGateway(manifest, bundle, root)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/albertloky/SBXR/releases/latest", nil)
	request.Host = "api.github.com"
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"tag_name":"v2.0.1"`) || !strings.Contains(response.Body.String(), `"sbxr_qualification"`) {
		t.Fatalf("latest response = %d %s", response.Code, response.Body.String())
	}
	var latest struct {
		Qualification struct {
			Manifest []byte `json:"manifest"`
			Bundle   []byte `json:"bundle"`
		} `json:"sbxr_qualification"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &latest); err != nil || !bytes.Equal(latest.Qualification.Manifest, manifest) || !bytes.Equal(latest.Qualification.Bundle, bundle) {
		t.Fatal("latest response changed signed qualification bytes")
	}

	request = httptest.NewRequest(http.MethodGet, "https://github.com/albertloky/SBXR/releases/latest/download/install.sh", nil)
	request.Host = "github.com"
	response = httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "v2.0.0 install.sh" {
		t.Fatalf("install response = %d %q", response.Code, response.Body.String())
	}
	if err := os.WriteFile(filepath.Join(root, "v2.0.0", "install.sh"), []byte("changed-content!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "https://github.com/albertloky/SBXR/releases/latest/download/install.sh", nil)
	request.Host = "github.com"
	response = httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || response.Body.Len() != 0 {
		t.Fatalf("changed install response = %d %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/albertloky/SBXR/issues/262", nil)
	request.Host = "api.github.com"
	response = httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
		t.Fatalf("unlisted response = %d %q", response.Code, response.Body.String())
	}
}

func TestQualificationGatewayServesOneV3Candidate(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "v3.0.0")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	assets := []map[string]any{}
	for _, name := range gatewayAssetNames {
		body := []byte("v3 " + name)
		if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		assets = append(assets, map[string]any{"name": name, "size": len(body), "sha256": hex.EncodeToString(digest[:])})
	}
	release := map[string]any{"tag": "v3.0.0", "sequence": 17, "commit": strings.Repeat("a", 40), "release_identity": map[string]any{"repository": "albertloky/SBXR", "tag": "v3.0.0", "commit": strings.Repeat("a", 40), "release_index_sha256": assets[1]["sha256"]}, "assets": assets}
	manifest, _ := json.Marshal(map[string]any{"schema": "sbxr-qualification-manifest-v1", "repository": "albertloky/SBXR", "releases": []any{release}})
	gateway, err := newQualificationGateway(manifest, json.RawMessage(`{"bundle":true}`), root)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.close()
	request := httptest.NewRequest(http.MethodGet, "https://github.com/albertloky/SBXR/releases/latest/download/install.sh", nil)
	request.Host = "github.com"
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "v3 install.sh" {
		t.Fatalf("V3 install = %d %q", response.Code, response.Body.String())
	}
}

func TestQualificationGatewayServesBoundSubscriptionCandidate(t *testing.T) {
	for _, scope := range []string{softwarelifecycle.FirstSubscriptionCleanInstall, softwarelifecycle.SubscriptionCleanInstallRepair, softwarelifecycle.RecurringSubscriptionUpgrade} {
		t.Run(scope, func(t *testing.T) { testQualificationGatewaySubscriptionCandidate(t, scope) })
	}
}

func testQualificationGatewaySubscriptionCandidate(t *testing.T, scope string) {
	root := t.TempDir()
	tag, commit := "v3.1.0", strings.Repeat("a", 40)
	directory := filepath.Join(root, tag)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	var assets []decisionAsset
	var proofs []softwarelifecycle.LatestAssetProof
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		body := []byte(name)
		digest := sha256.Sum256(body)
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		asset := decisionAsset{Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
		assets = append(assets, asset)
		proofs = append(proofs, softwarelifecycle.LatestAssetProof{Name: name, Size: asset.Size, SHA256: asset.SHA256})
	}
	support := v3ReleaseSupport{Scope: scope, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []decisionReleaseIdentity{}}
	var sources = []v3QualificationSource{}
	sourceState := "v3-subscription-clean"
	if scope == softwarelifecycle.RecurringSubscriptionUpgrade {
		support.Scope, sourceState = scope, "v3-recurring"
		source := decisionReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.1", Commit: strings.Repeat("b", 40), ReleaseIndexSHA256: strings.Repeat("c", 64)}
		support.Sources = append(support.Sources, source)
		sources = append(sources, v3QualificationSource{ReleaseIdentity: source})
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(tag, commit, 18, proofs, support.lifecycle())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "release-index.json"), index, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(index)
	assets = append(assets, decisionAsset{Name: "release-index.json", Size: int64(len(index)), SHA256: hex.EncodeToString(digest[:])})
	slices.SortFunc(assets, func(a, b decisionAsset) int { return strings.Compare(a.Name, b.Name) })
	release := qualificationRelease{Tag: tag, Commit: commit, Sequence: 18, ReleaseID: 123, Assets: assets, ReleaseIdentity: decisionReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: tag, Commit: commit, ReleaseIndexSHA256: hex.EncodeToString(digest[:])}}
	attempt := &v3QualificationAttempt{Schema: "sbxr-v3-qualification-attempt-v3", CandidateIndex: string(index), Support: &support, Sources: sources, Baseline: &qualificationRelease{}}
	attempt.RequiredScenarios = attemptScenarios(*attempt)
	manifest := qualificationManifest{Schema: "sbxr-qualification-manifest-v3", Repository: softwarelifecycle.Repository, Mode: "v3", SourceState: "v3-subscription-clean", Releases: []qualificationRelease{release}, V3Attempt: attempt, AcceptanceVPSChecklistSHA256: strings.Repeat("a", 64), CandidateFailureStateSHA256: strings.Repeat("b", 64), Approval: qualificationApproval{State: "approved", Environments: []approvalEnvironment{{Name: "acceptance-vps"}}}, Workflow: qualificationWorkflow{Commit: commit, Path: ".github/workflows/candidate.yml", Ref: softwarelifecycle.Repository + "/.github/workflows/candidate.yml@refs/heads/main", RunID: "123", RunURL: "https://github.com/albertloky/SBXR/actions/runs/123"}}
	for i, stage := range []string{candidatePreflightStage, candidateDraftConstructionStage, candidateDraftVerificationStage} {
		outcome := "accepted"
		if i == 1 {
			outcome = "actions-required"
		}
		manifest.Approval.DecisionChain = append(manifest.Approval.DecisionChain, decisionChainEntry{Stage: stage, Outcome: outcome, FactsSHA256: strings.Repeat("c", 64), DecisionSHA256: strings.Repeat("d", 64)})
	}
	manifest.SourceState = sourceState
	encoded, _ := json.MarshalIndent(manifest, "", "  ")
	bundle := json.RawMessage(`{"bundle":true}`)
	gateway, err := newQualificationGateway(encoded, bundle, root)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.close()
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/albertloky/SBXR/releases/latest", nil))
	var latest struct {
		Qualification struct{ Manifest, Bundle []byte } `json:"sbxr_qualification"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &latest) != nil || !bytes.Equal(latest.Qualification.Manifest, encoded) || !bytes.Equal(latest.Qualification.Bundle, bundle) {
		t.Fatal("signed bytes changed")
	}
	response = httptest.NewRecorder()
	gateway.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://github.com/albertloky/SBXR/releases/download/"+tag+"/release-index.json", nil))
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), index) {
		t.Fatal("bound index unavailable")
	}
	for _, mutate := range []func(*qualificationManifest){
		func(m *qualificationManifest) { m.Schema = "sbxr-qualification-manifest-v4" },
		func(m *qualificationManifest) { m.Approval.State = "pending" },
		func(m *qualificationManifest) { m.SourceState = "unknown" },
		func(m *qualificationManifest) {
			if m.SourceState == "v3-recurring" {
				m.SourceState = "v3-subscription-clean"
			} else {
				m.SourceState = "v3-recurring"
			}
		},
		func(m *qualificationManifest) { m.V3Attempt.Support.Sources = nil },
		func(m *qualificationManifest) { m.V3Attempt.Sources = nil },
		func(m *qualificationManifest) { m.V3Attempt.CandidateIndex += "\n" },
	} {
		var changed qualificationManifest
		if json.Unmarshal(encoded, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		body, _ := json.Marshal(changed)
		if gateway, err := newQualificationGateway(body, bundle, root); err == nil {
			gateway.close()
			t.Fatal("unbound manifest accepted")
		}
	}
}
