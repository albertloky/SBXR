package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

func TestSourcePubliclyVerifiesTheExactSixAssetReleaseWithoutCredentials(t *testing.T) {
	fixture := newReleaseFixture(t)
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)

	got, err := source.Verify(t.Context(), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Repository != softwarelifecycle.Repository || got.Tag != "v1.0.0" || got.Commit != fixtureCommit || len(got.Assets) != 5 || len(got.AttestedAssets) != 6 {
		t.Fatalf("Verify() = %#v", got)
	}
	if got.Verifier.Version != Version || got.Verifier.SigningFingerprint != SigningFingerprint || !got.Verifier.ReleaseVerified || !got.Verifier.OfficialSignedDistribution ||
		!reflect.DeepEqual(got.Verifier.VerifiedAssets, fixedAssetNames()) {
		t.Fatalf("verifier evidence = %#v", got.Verifier)
	}
	for _, request := range fixture.requests {
		if request.authorization != "" {
			t.Fatalf("credential sent to public GitHub seam: %q", request.authorization)
		}
		if strings.Contains(request.path, "/releases/assets/") && request.accept != "application/octet-stream" {
			t.Fatalf("release asset requested as %q instead of bytes", request.accept)
		}
	}
}

func TestSourceRefusesHostilePublicReleaseFactsWithOneSafeError(t *testing.T) {
	tests := []struct {
		name   string
		change func(*releaseFixture)
	}{
		{"mutable release", func(f *releaseFixture) { f.release.Immutable = false }},
		{"changed commit", func(f *releaseFixture) { f.release.TargetCommitish = strings.Repeat("b", 40) }},
		{"missing asset", func(f *releaseFixture) { f.release.Assets = f.release.Assets[:5] }},
		{"duplicate asset", func(f *releaseFixture) { f.release.Assets[5] = f.release.Assets[0] }},
		{"changed API digest", func(f *releaseFixture) { f.release.Assets[0].Digest = "sha256:" + strings.Repeat("a", 64) }},
		{"changed signed digest", func(f *releaseFixture) { f.attested["install.sh"] = strings.Repeat("a", 64) }},
		{"unverified bundle", func(f *releaseFixture) { f.verifyErr = errors.New("PRIVATE-MARKER") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReleaseFixture(t)
			test.change(fixture)
			source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
			got, err := source.Verify(t.Context(), "v1.0.0")
			if err == nil || got.Repository != "" || strings.Contains(err.Error(), "PRIVATE-MARKER") {
				t.Fatalf("Verify() = %#v, %v", got, err)
			}
			view := softwarelifecycle.New(source, softwarelifecycle.VerifierQualification{Version: Version, SigningFingerprint: SigningFingerprint}, time.Now).View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
			if view.Refusal == nil || view.Refusal.Code != softwarelifecycle.ReleaseVerificationRefused || view.VerifiedCandidate != nil {
				t.Fatalf("View() = %#v, want only %s", view, softwarelifecycle.ReleaseVerificationRefused)
			}
		})
	}
}

func TestReleaseStatementRefusesAMissingRequiredV02PredicateField(t *testing.T) {
	fixture := newReleaseFixture(t)
	body, err := fixture.verifier([]byte(`{"fixture":true}`), "sha1", fixtureCommit)
	if err != nil {
		t.Fatal(err)
	}
	var statement map[string]any
	if json.Unmarshal(body, &statement) != nil {
		t.Fatal("fixture statement refused")
	}
	delete(statement["predicate"].(map[string]any), "packageId")
	body, _ = json.Marshal(statement)
	if _, err := parseReleaseStatement(body, "v1.0.0", fixtureCommit); err == nil {
		t.Fatal("release/v0.2 statement without packageId accepted")
	}
}

func TestSourceDiscoversStableAndReviewedReleasesThroughPublicHTTPS(t *testing.T) {
	fixture := newReleaseFixture(t)
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	for _, test := range []struct {
		reviewed string
		want     softwarelifecycle.ReleaseListing
	}{
		{"", softwarelifecycle.ReleaseListing{Tag: "v1.0.0"}},
		{"v1.0.0", softwarelifecycle.ReleaseListing{Tag: "v1.0.0"}},
	} {
		got, err := source.Discover(t.Context(), test.reviewed)
		if err != nil || got != test.want {
			t.Fatalf("Discover(%q) = %#v, %v", test.reviewed, got, err)
		}
	}
}

func TestSourceRefusesAutomaticStableDiscoveryUntilTheAcceptanceRecordAgrees(t *testing.T) {
	for _, change := range []func(*releaseFixture){
		func(f *releaseFixture) { f.release.Body = "" },
		func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "Status: Qualified - root-runtime package policy", "Status: Qualified - installer-only automated exception", 1)
		},
		func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "Integrated Ubuntu Verification: Not required", "Integrated Ubuntu Verification: Passed", 1)
		},
		func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, fixtureCommit, strings.Repeat("b", 40), 1)
		},
		func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, f.attested["release-index.json"], strings.Repeat("b", 64), 1)
		},
	} {
		fixture := newReleaseFixture(t)
		change(fixture)
		source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
		if got, err := source.Discover(t.Context(), ""); err == nil || got.Tag != "" {
			t.Fatalf("Discover() = %#v, %v", got, err)
		}
	}
}

func TestSourceBindsAStableAcceptanceRecordToTheDownloadedIndex(t *testing.T) {
	fixture := newReleaseFixture(t)
	fixture.release.Body = strings.Replace(fixture.release.Body, fixture.attested["release-index.json"], strings.Repeat("b", 64), 1)
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	if got, err := source.Verify(t.Context(), "v1.0.0"); err == nil || got.Repository != "" {
		t.Fatalf("Verify() = %#v, %v", got, err)
	}
}

func TestSourceStillVerifiesAReviewedPrereleaseBeforeItsAcceptanceRecordExists(t *testing.T) {
	fixture := newReleaseFixture(t)
	fixture.release.Prerelease = true
	fixture.release.Body = ""
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	if _, err := source.Verify(t.Context(), "v1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func TestSigstoreVerifierAuthenticatesTheOfficialGitHubReleaseFixture(t *testing.T) {
	if source := New(); source.client == nil || source.verifier == nil {
		t.Fatal("compiled GitHub trust root disagrees with its reviewed digest")
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("testdata/github_release_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	statement, err := sigstoreVerifier(trustedRoot)(body, "sha1", "c5e17a62e06a1d201570249c61fae531e9244e1b")
	if err != nil || !strings.Contains(string(statement), `"repository":"bdehamer/delme"`) {
		t.Fatalf("official release bundle = %s, %v", statement, err)
	}
	changed := append([]byte(nil), body...)
	changed[len(changed)/2] ^= 1
	if _, err := sigstoreVerifier(trustedRoot)(changed, "sha1", "c5e17a62e06a1d201570249c61fae531e9244e1b"); err == nil {
		t.Fatal("changed signed bundle accepted")
	}
}

type recordedRequest struct {
	path, authorization, accept string
}

type releaseFixture struct {
	server    *httptest.Server
	release   githubRelease
	assets    map[string][]byte
	attested  map[string]string
	requests  []recordedRequest
	verifyErr error
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	fixture := &releaseFixture{assets: map[string][]byte{
		"install.sh":                         []byte("#!/bin/sh\nexit 1\n"),
		"release-index.json":                 []byte(`{"schema":1}`),
		"sbxr-components-linux-amd64.tar.gz": []byte("amd64 components"),
		"sbxr-components-linux-arm64.tar.gz": []byte("arm64 components"),
		"sbxr-linux-amd64.tar.gz":            []byte("amd64 application"),
		"sbxr-linux-arm64.tar.gz":            []byte("arm64 application"),
	}, attested: map[string]string{}}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	fixture.release = githubRelease{Tag: "v1.0.0", TargetCommitish: fixtureCommit, Immutable: true}
	for index, name := range fixedAssetNames() {
		body := fixture.assets[name]
		digest := sha256.Sum256(body)
		fixture.attested[name] = hex.EncodeToString(digest[:])
		fixture.release.Assets = append(fixture.release.Assets, githubAsset{
			Name: name, Size: int64(len(body)), Digest: "sha256:" + hex.EncodeToString(digest[:]), State: "uploaded",
			URL: fmt.Sprintf("%s/repos/%s/releases/assets/%d", fixture.server.URL, softwarelifecycle.Repository, index+1),
		})
	}
	fixture.release.Body = stableAcceptanceFixture(fixture.attested["release-index.json"])
	return fixture
}

func stableAcceptanceFixture(indexSHA256 string) string {
	return "# SBXR automated Acceptance Record\n\n" +
		"Status: Qualified - root-runtime package policy\n" +
		"Repository: " + softwarelifecycle.Repository + "\n" +
		"Tag: v1.0.0\n" +
		"Commit: " + fixtureCommit + "\n" +
		"Release index SHA-256: " + indexSHA256 + "\n" +
		"Stable result code: RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION\n\n" +
		"| Module Verification | Passed | exact |\n" +
		"| Seam Verification | Passed | exact |\n" +
		"| Integrated Verification | Passed | exact |\n" +
		"| Codex Live Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no live VPS evidence claimed |\n" +
		"| Owner Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no maintained-client evidence claimed |\n\n" +
		"Integrated Ubuntu Verification: Not required - ADR-0010 root-runtime package and public-seam scope; no automated Ubuntu integration evidence claimed.\n" +
		"No Integrated Ubuntu Verification, live VPS, provider, maintained-client, or Owner evidence was performed.\n\n" +
		"Any asset, attestation, repository, tag, commit, release-index digest, qualification scope, required check, or client-facing change invalidates this record.\n"
}

func (fixture *releaseFixture) verifier(body []byte, algorithm, digest string) ([]byte, error) {
	if fixture.verifyErr != nil {
		return nil, fixture.verifyErr
	}
	if string(body) != `{"fixture":true}` || algorithm != "sha1" || digest != fixtureCommit {
		return nil, errors.New("fixture verifier refused")
	}
	subjects := []map[string]any{{"uri": "pkg:github/" + softwarelifecycle.Repository + "@v1.0.0", "digest": map[string]string{"sha1": fixtureCommit}}}
	for _, name := range fixedAssetNames() {
		subjects = append(subjects, map[string]any{"name": name, "digest": map[string]string{"sha256": fixture.attested[name]}})
	}
	return json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://in-toto.io/attestation/release/v0.2", "subject": subjects,
		"predicate": map[string]string{"databaseId": "2", "ownerId": "1", "packageId": "4", "purl": "pkg:github/" + softwarelifecycle.Repository + "@v1.0.0", "repository": softwarelifecycle.Repository, "repositoryId": "3", "tag": "v1.0.0"},
	})
}

func (fixture *releaseFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.requests = append(fixture.requests, recordedRequest{request.URL.RequestURI(), request.Header.Get("Authorization"), request.Header.Get("Accept")})
	writer.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/repos/" + softwarelifecycle.Repository + "/git/ref/tags/v1.0.0":
		_ = json.NewEncoder(writer).Encode(map[string]any{"object": map[string]string{"sha": fixtureCommit, "type": "commit"}})
	case "/repos/" + softwarelifecycle.Repository + "/releases/tags/v1.0.0", "/repos/" + softwarelifecycle.Repository + "/releases/latest":
		_ = json.NewEncoder(writer).Encode(fixture.release)
	case "/repos/" + softwarelifecycle.Repository + "/attestations/sha1:" + fixtureCommit:
		_ = json.NewEncoder(writer).Encode(map[string]any{"attestations": []map[string]any{{"bundle": map[string]bool{"fixture": true}, "initiator": "github"}}})
	default:
		const prefix = "/repos/" + softwarelifecycle.Repository + "/releases/assets/"
		if strings.HasPrefix(request.URL.Path, prefix) {
			if request.Header.Get("Accept") != "application/octet-stream" {
				_ = json.NewEncoder(writer).Encode(map[string]string{"name": "asset metadata"})
				return
			}
			var id int
			_, _ = fmt.Sscanf(strings.TrimPrefix(request.URL.Path, prefix), "%d", &id)
			names := fixedAssetNames()
			if id > 0 && id <= len(names) {
				_, _ = writer.Write(fixture.assets[names[id-1]])
				return
			}
		}
		http.NotFound(writer, request)
	}
}
