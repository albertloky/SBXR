package github

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestSourceChecksTheExactPublicTagWithoutChangingLatestDiscovery(t *testing.T) {
	tagged := newLatestReleaseFixture(t)
	canonical := newLatestReleaseFixture(t)
	retagPublicReleaseFixture(t, canonical, "v2.0.1", 18)
	for i, asset := range canonical.release.Assets {
		canonical.release.Assets[i].URL = strings.Replace(asset.URL, canonical.server.URL, tagged.server.URL, 1)
	}
	var active *latestReleaseFixture
	var requests []string
	client := *tagged.server.Client()
	client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.RequestURI())
		switch {
		case strings.Contains(request.URL.Path, "/releases/tags/"):
			active = tagged
			body, err := json.Marshal(tagged.release)
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
		case request.URL.Path == "/repos/"+softwarelifecycle.Repository+"/releases/latest":
			active = canonical
		}
		if active == nil {
			return nil, fmt.Errorf("request before release metadata: %s", request.URL.Path)
		}
		endpoint, err := url.Parse(active.server.URL)
		if err != nil {
			return nil, err
		}
		rewritten := request.Clone(request.Context())
		rewritten.URL.Scheme, rewritten.URL.Host = endpoint.Scheme, endpoint.Host
		return active.server.Client().Transport.RoundTrip(rewritten)
	})
	verifier := func(body []byte, algorithm, digest string) ([]byte, error) {
		if active == nil {
			return nil, fmt.Errorf("verification before metadata")
		}
		return active.verifier(body, algorithm, digest)
	}
	source := NewWithEndpoint(&client, tagged.server.URL, verifier)
	if release, outcome := source.CheckRelease(t.Context(), "v2.0.0"); outcome != softwarelifecycle.LatestReleaseAccepted || release.Identity.Tag != "v2.0.0" || release.Sequence != 17 {
		t.Fatalf("tagged release = %#v, %v", release, outcome)
	}
	exactPath := "/repos/" + softwarelifecycle.Repository + "/releases/tags/v2.0.0"
	if len(requests) != 3 || requests[0] != exactPath {
		t.Fatalf("tagged discovery requests = %v; want exact tag, attestation and index", requests)
	}
	for _, request := range requests {
		if strings.Contains(request, "/releases/latest") {
			t.Fatalf("tagged verification read canonical Latest: %s", request)
		}
	}
	before := len(requests)
	if latest, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseAccepted || latest.Identity.Tag != "v2.0.1" || latest.Sequence != 18 {
		t.Fatalf("canonical Latest = %#v, %v; want the independently newer release", latest, outcome)
	}
	if requests[before] != "/repos/"+softwarelifecycle.Repository+"/releases/latest" {
		t.Fatalf("Latest discovery used %s", requests[before])
	}
	before = len(requests)
	if _, outcome := source.CheckRelease(t.Context(), "v2.0.2"); outcome != softwarelifecycle.LatestReleaseRefused {
		t.Fatalf("mismatched response tag = %v", outcome)
	}
	if len(requests) != before+1 || requests[before] != "/repos/"+softwarelifecycle.Repository+"/releases/tags/v2.0.2" {
		t.Fatalf("mismatched tag requests = %v; want metadata refusal before proof or asset fetch", requests[before:])
	}
	for _, tag := range []string{"", "latest", "v2.0.0/../../latest", "v2.0.0?draft=true", "v2.0.0#fragment"} {
		before = len(requests)
		if _, outcome := source.CheckRelease(t.Context(), tag); outcome != softwarelifecycle.LatestReleaseRefused || len(requests) != before {
			t.Fatalf("unsafe tag %q = %v, requests %d -> %d", tag, outcome, before, len(requests))
		}
	}
	tagged.release.Qualification = &qualificationRelease{}
	before = len(requests)
	if _, outcome := source.CheckRelease(t.Context(), "v2.0.0"); outcome != softwarelifecycle.LatestReleaseRefused {
		t.Fatalf("tagged qualification channel = %v", outcome)
	}
	if len(requests) != before+1 || requests[before] != exactPath {
		t.Fatalf("qualification channel requests = %v; want metadata refusal", requests[before:])
	}
}

func retagPublicReleaseFixture(t *testing.T, fixture *latestReleaseFixture, tag string, sequence uint64) {
	t.Helper()
	var index map[string]any
	if err := json.Unmarshal(fixture.assets["release-index.json"], &index); err != nil {
		t.Fatal(err)
	}
	index["tag"], index["sequence"] = tag, sequence
	body, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	fixture.release.Tag = tag
	fixture.assets["release-index.json"] = body
	digest := sha256.Sum256(body)
	fixture.digests["release-index.json"] = hex.EncodeToString(digest[:])
	for i, asset := range fixture.release.Assets {
		if asset.Name == "release-index.json" {
			fixture.release.Assets[i].Digest = "sha256:" + fixture.digests[asset.Name]
			fixture.release.Assets[i].Size = int64(len(body))
		}
	}
	fixture.release.Body = strings.NewReplacer("Tag: v2.0.0", "Tag: "+tag, "Sequence: 17", fmt.Sprintf("Sequence: %d", sequence)).Replace(fixture.acceptanceRecord())
}

func TestSourceNativeReleaseVerifierChecksRealOfflineBundle(t *testing.T) {
	body, err := os.ReadFile("testdata/github_release_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	// This real native GitHub proof belongs to another repository. Its valid
	// signature cannot make its release claims qualify an SBXR release.
	const commit = "c5e17a62e06a1d201570249c61fae531e9244e1b"
	source := New()
	if source.verifier == nil {
		t.Fatal("pinned production trust roots did not initialize")
	}
	statement, err := source.verifier(body, "sha1", commit)
	if err != nil {
		t.Fatalf("real native GitHub signature refused: %v", err)
	}
	if _, _, err := parseReleaseStatement(statement, commit); err == nil {
		t.Fatal("cryptographically valid foreign release claims admitted as SBXR")
	}
	if _, err := source.verifier(body, "sha1", strings.Repeat("a", 40)); err == nil {
		t.Fatal("real native proof admitted for another commit")
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	signatureEntry := envelope["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)
	signature, err := base64.StdEncoding.DecodeString(signatureEntry["sig"].(string))
	if err != nil || len(signature) == 0 {
		t.Fatal("invalid signed fixture signature")
	}
	signature[len(signature)-1] ^= 1
	signatureEntry["sig"] = base64.StdEncoding.EncodeToString(signature)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.verifier(tampered, "sha1", commit); err == nil {
		t.Fatal("tampered real native signature accepted")
	}
}
