package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
