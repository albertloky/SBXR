package github

import (
	"bytes"
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

func TestSourceChecksOnlyTheQualifiedFourAssetLatestRelease(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)

	got, outcome := source.CheckLatest(t.Context())

	if outcome != softwarelifecycle.LatestReleaseAccepted || got.Sequence != 17 || got.Identity.Repository != softwarelifecycle.Repository || got.Identity.Tag != "v2.0.0" || got.Identity.Commit != fixtureCommit {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
	for _, request := range fixture.requests {
		if strings.Contains(request.path, "/releases/assets/") && !strings.HasSuffix(request.path, "/2") {
			t.Fatalf("CheckLatest downloaded non-index asset: %s", request.path)
		}
	}
}

func TestSourceChecksAManifestBoundQualificationReleaseWithoutAStableRecord(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.release.Body = ""
	assets := make([]map[string]any, 0, len(fixture.release.Assets))
	for _, asset := range fixture.release.Assets {
		assets = append(assets, map[string]any{"name": asset.Name, "size": asset.Size, "sha256": strings.TrimPrefix(asset.Digest, "sha256:")})
	}
	manifest, err := json.Marshal(map[string]any{
		"schema":     "sbxr-qualification-manifest-v1",
		"repository": softwarelifecycle.Repository,
		"workflow": map[string]any{
			"path": ".github/workflows/candidate.yml", "ref": "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main",
			"commit": fixtureCommit, "run_id": "123", "run_url": "https://github.com/albertloky/SBXR/actions/runs/123",
		},
		"releases": []any{map[string]any{
			"tag": "v1.9.9", "sequence": 16, "commit": fixtureCommit, "release_id": 6,
			"release_identity": map[string]any{"repository": softwarelifecycle.Repository, "tag": "v1.9.9", "commit": fixtureCommit, "release_index_sha256": strings.Repeat("a", 64)},
			"assets":           assets,
		}, map[string]any{
			"tag": "v2.0.0", "sequence": 17, "commit": fixtureCommit, "release_id": 7,
			"release_identity": map[string]any{"repository": softwarelifecycle.Repository, "tag": "v2.0.0", "commit": fixtureCommit, "release_index_sha256": fixture.attested["release-index.json"]},
			"assets":           assets,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.release.Qualification = &qualificationRelease{Manifest: manifest, Bundle: json.RawMessage(`{"fixture":true}`)}
	digest := sha256.Sum256(manifest)
	verifier := func(body []byte, algorithm, gotDigest string) ([]byte, error) {
		if string(body) != `{"fixture":true}` || algorithm != "sha256" || gotDigest != hex.EncodeToString(digest[:]) {
			return nil, errors.New("qualification verifier refused")
		}
		return json.Marshal(map[string]any{
			"_type":   "https://in-toto.io/Statement/v1",
			"subject": []any{map[string]any{"name": "qualification-manifest.json", "digest": map[string]string{"sha256": gotDigest}}},
		})
	}

	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, verifier).CheckLatest(t.Context())

	if outcome != softwarelifecycle.LatestReleaseAccepted || got.Sequence != 17 || got.Identity.Tag != "v2.0.0" {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

func TestSourceCheckLatestRefusesHostileOrChangedReleaseFacts(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*releaseFixture)
	}{
		{"draft", func(f *releaseFixture) { f.release.Draft = true }},
		{"prerelease", func(f *releaseFixture) { f.release.Prerelease = true }},
		{"mutable", func(f *releaseFixture) { f.release.Immutable = false }},
		{"extra asset", func(f *releaseFixture) { f.release.Assets = append(f.release.Assets, f.release.Assets[0]) }},
		{"changed metadata digest", func(f *releaseFixture) { f.release.Assets[1].Digest = "sha256:" + strings.Repeat("a", 64) }},
		{"changed attestation", func(f *releaseFixture) { f.attested["release-index.json"] = strings.Repeat("a", 64) }},
		{"different acceptance binding", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, fixtureCommit, strings.Repeat("b", 40), 1)
		}},
		{"missing runner facts", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "Runner: Ubuntu Server 24.04 linux/amd64\n", "", 1)
		}},
		{"changed verifier", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, SigningFingerprint, strings.Repeat("A", 64), 1)
		}},
		{"pending secret scan", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "Secret-safe result: Passed", "Secret-safe result: Pending", 1)
		}},
		{"rescue without authority", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION", "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION", 1)
			f.release.Body = strings.Replace(f.release.Body, "Discovered, installed, recovered, final latest release", "Rescue direct-install and lower-sequence replacement release", 1)
		}},
		{"normal code with rescue role", func(f *releaseFixture) {
			f.release.Body = strings.Replace(f.release.Body, "Discovered, installed, recovered, final latest release", "Rescue direct-install and lower-sequence replacement release", 1)
		}},
		{"oversized index", func(f *releaseFixture) { f.release.Assets[1].Size = softwarelifecycle.MaxIndexBytes + 1 }},
		{"missing index response", func(f *releaseFixture) {
			f.release.Assets[1].URL = f.server.URL + "/repos/" + softwarelifecycle.Repository + "/releases/assets/999"
		}},
		{"unknown index field", func(f *releaseFixture) {
			rebindLatestIndex(f, bytes.Replace(f.assets["release-index.json"], []byte(`{"schema":1`), []byte(`{"schema":1,"unknown":true`), 1))
		}},
		{"duplicate index field", func(f *releaseFixture) {
			rebindLatestIndex(f, bytes.Replace(f.assets["release-index.json"], []byte(`{"schema":1`), []byte(`{"schema":1,"schema":1`), 1))
		}},
		{"zero sequence", func(f *releaseFixture) {
			rebindLatestIndex(f, bytes.Replace(f.assets["release-index.json"], []byte(`"sequence":17`), []byte(`"sequence":0`), 1))
		}},
		{"late index replacement", func(f *releaseFixture) {
			f.beforeAsset = func(name string) {
				if name == "release-index.json" {
					f.assets[name] = append(f.assets[name], '\n')
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			test.change(fixture)
			got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
			if outcome != softwarelifecycle.LatestReleaseRefused || got.Sequence != 0 {
				t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
			}
		})
	}
}

func TestSourceCheckLatestReportsTransportFailureAsUnavailable(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.server.Close()
	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseUnavailable || got.Sequence != 0 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

func TestSourceCheckLatestRefusesUnsafeRedirect(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.redirectAsset = true
	client := fixture.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirectRefused }
	got, outcome := NewWithEndpoint(client, fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseRefused || got.Sequence != 0 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
	}
}

func TestSourceCheckLatestAcceptsQualifiedRescueRecord(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	fixture.release.Body = strings.Replace(fixture.release.Body, "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION", "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION", 1)
	fixture.release.Body = strings.Replace(fixture.release.Body, "Discovered, installed, recovered, final latest release", "Rescue direct-install and lower-sequence replacement release", 1)
	fixture.release.Body += "Rescue defect evidence: https://github.com/albertloky/SBXR/issues/123\n" +
		"Failed normal run evidence: https://github.com/albertloky/SBXR/actions/runs/122\n" +
		"Normal journey waiver: Reproducible installed-source defect made the normal menu journey impossible\n"

	got, outcome := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier).CheckLatest(t.Context())
	if outcome != softwarelifecycle.LatestReleaseAccepted || got.Sequence != 17 {
		t.Fatalf("CheckLatest() = %#v, %v", got, outcome)
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

func TestSourceAcceptsOnlyOneExactStableAcceptanceRecordPolicy(t *testing.T) {
	for _, record := range []func(string) string{stableAcceptanceFixture, stagedAcceptanceFixture} {
		fixture := newReleaseFixture(t)
		fixture.release.Body = record(fixture.attested["release-index.json"])
		source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
		if got, err := source.Discover(t.Context(), ""); err != nil || got.Tag != "v1.0.0" {
			t.Fatalf("Discover() = %#v, %v", got, err)
		}
	}

	for _, change := range []func(string) string{
		func(body string) string {
			return strings.Replace(body, "Packaged executable qualification: amd64 Passed; arm64 Passed.\n", "", 1)
		},
		func(body string) string {
			return strings.Replace(body, "Packaged executable qualification: ", "Packaged executable qualification: amd64 Passed; arm64 Passed.\nPackaged executable qualification: ", 1)
		},
		func(body string) string {
			return strings.Replace(body, "Packaged executable qualification: amd64 Passed; arm64 Passed.", "Packaged executable qualification: amd64 Passed; arm64 Pending.", 1)
		},
		func(body string) string {
			return strings.Replace(body, "Status: Qualified - staged-onboarding package policy\n", "Status: Qualified - staged-onboarding package policy\nStatus: Qualified - root-runtime package policy\n", 1)
		},
		func(body string) string {
			return strings.Replace(body, "RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION", "RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION", 1)
		},
		func(body string) string {
			return strings.Replace(body, "Repository: ", "Repository: "+softwarelifecycle.Repository+"\nRepository: ", 1)
		},
		func(body string) string {
			return strings.Replace(body, "| External check | Status |\n", "| External check | Status |\n| External check | Status |\n", 1)
		},
		func(body string) string { return strings.Replace(body, "\n\n", "\r\n", 1) },
		func(body string) string { return strings.Replace(body, "\n\n", "\x00\n", 1) },
		func(body string) string {
			return strings.Replace(body, "Any changed asset", "hostile line\nAny changed asset", 1)
		},
		func(body string) string { return body + "hostile trailing line\n" },
		func(body string) string { return body + strings.Repeat("x", 64<<10) },
	} {
		fixture := newReleaseFixture(t)
		fixture.release.Body = change(stagedAcceptanceFixture(fixture.attested["release-index.json"]))
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
	server        *httptest.Server
	release       githubRelease
	assets        map[string][]byte
	attested      map[string]string
	requests      []recordedRequest
	verifyErr     error
	beforeAsset   func(string)
	redirectAsset bool
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

func newLatestReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	fixture := newReleaseFixture(t)
	fixture.release.Tag = "v2.0.0"
	index := fmt.Sprintf(`{"schema":1,"repository":%q,"tag":"v2.0.0","commit":%q,"sequence":17,"assets":[{"name":"install.sh","size":%d,"sha256":%q},{"name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":%q},{"name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":%q}]}`,
		softwarelifecycle.Repository, fixtureCommit,
		len(fixture.assets["install.sh"]), fixture.attested["install.sh"],
		len(fixture.assets["sbxr-linux-amd64.tar.gz"]), fixture.attested["sbxr-linux-amd64.tar.gz"],
		len(fixture.assets["sbxr-linux-arm64.tar.gz"]), fixture.attested["sbxr-linux-arm64.tar.gz"])
	fixture.assets["release-index.json"] = []byte(index)
	names := []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}
	fixture.release.Assets = nil
	fixture.attested = map[string]string{}
	for id, name := range names {
		body := fixture.assets[name]
		digest := sha256.Sum256(body)
		fixture.attested[name] = hex.EncodeToString(digest[:])
		fixture.release.Assets = append(fixture.release.Assets, githubAsset{Name: name, Size: int64(len(body)), Digest: "sha256:" + fixture.attested[name], State: "uploaded", URL: fmt.Sprintf("%s/repos/%s/releases/assets/%d", fixture.server.URL, softwarelifecycle.Repository, id+1)})
	}
	fixture.release.Body = latestAcceptanceFixture(fixture)
	return fixture
}

func latestAcceptanceFixture(fixture *releaseFixture) string {
	lines := []string{
		"# SBXR Installer-Updater Acceptance Record",
		"Status: Qualified",
		"Repository: " + softwarelifecycle.Repository,
		"Tag: v2.0.0",
		"Commit: " + fixtureCommit,
		"Release index SHA-256: " + fixture.attested["release-index.json"],
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
		lines = append(lines, fmt.Sprintf("Asset: %s %d %s", asset.Name, asset.Size, fixture.attested[asset.Name]))
	}
	return strings.Join(lines, "\n") + "\n"
}

func rebindLatestIndex(fixture *releaseFixture, body []byte) {
	fixture.assets["release-index.json"] = body
	digest := sha256.Sum256(body)
	fixture.attested["release-index.json"] = hex.EncodeToString(digest[:])
	for index := range fixture.release.Assets {
		if fixture.release.Assets[index].Name == "release-index.json" {
			fixture.release.Assets[index].Size = int64(len(body))
			fixture.release.Assets[index].Digest = "sha256:" + fixture.attested["release-index.json"]
		}
	}
	fixture.release.Body = latestAcceptanceFixture(fixture)
}

func stableAcceptanceFixture(indexSHA256 string) string {
	return "# SBXR automated Acceptance Record\n\n" +
		"Status: Qualified - root-runtime package policy\n" +
		"Repository: " + softwarelifecycle.Repository + "\n" +
		"Tag: v1.0.0\n" +
		"Commit: " + fixtureCommit + "\n" +
		"Release index SHA-256: " + indexSHA256 + "\n" +
		"Stable result code: RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION\n\n" +
		"| Module Verification | Passed | Package suites at the Pasteable Install Command and owning Module Interfaces |\n" +
		"| Seam Verification | Passed | Exact public HTTPS release verification, Sigstore attestations, and package seam checks |\n" +
		"| Integrated Verification | Passed | Package composition through existing product Interfaces |\n" +
		"| Codex Live Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no live VPS evidence claimed |\n" +
		"| Owner Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no maintained-client evidence claimed |\n\n" +
		"Integrated Ubuntu Verification: Not required - ADR-0010 root-runtime package and public-seam scope; no automated Ubuntu integration evidence claimed.\n" +
		"No Integrated Ubuntu Verification, live VPS, provider, maintained-client, or Owner evidence was performed.\n\n" +
		"Any asset, attestation, repository, tag, commit, release-index digest, qualification scope, required check, or client-facing change invalidates this record.\n"
}

func stagedAcceptanceFixture(indexSHA256 string) string {
	return "# SBXR automated Acceptance Record\n\n" +
		"Status: Qualified - staged-onboarding package policy\n" +
		"Repository: " + softwarelifecycle.Repository + "\n" +
		"Tag: v1.0.0\n" +
		"Commit: " + fixtureCommit + "\n" +
		"Release index SHA-256: " + indexSHA256 + "\n" +
		"Stable result code: RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION\n" +
		"Qualified procedures: RELEASE-STAGED-INSTALL-REVISION-1, RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1, RELEASE-STAGED-ONBOARDING-CHAIN, RELEASE-STAGED-ONBOARDING-SECRET-SCAN, RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT, RELEASE-STAGED-ONBOARDING-TERMINAL, RELEASE-STAGED-ONBOARDING-GUIDE-TEXT\n" +
		"Packaged executable qualification: amd64 Passed; arm64 Passed.\n\n" +
		"| Module Verification | Passed | Package suites at the Pasteable Install Command and owning Module Interfaces |\n" +
		"| Seam Verification | Passed | Exact public HTTPS release verification, Sigstore attestations, and package seam checks |\n" +
		"| Integrated Verification | Passed | Staged Installation, Cloudflare Profile Setup, and chained package composition |\n" +
		"| External check | Status |\n" +
		"|---|---|\n" +
		"| Codex Live Acceptance | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Real VPS | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Real Cloudflare | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| ACME | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Outside-client | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Maintained-client | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Current-documentation | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Provider mutation | Not required — staged-onboarding package and controlled-seam qualification scope |\n" +
		"| Owner Acceptance | Not required — staged-onboarding package and controlled-terminal qualification scope |\n\n" +
		"Codex Live Acceptance: Not required — staged-onboarding package and controlled-seam qualification scope.\n" +
		"Owner Acceptance: Not required — staged-onboarding package and controlled-terminal qualification scope.\n" +
		"No live VPS, real Cloudflare, ACME, outside-client, maintained-client, current-documentation, provider mutation, or Owner Acceptance was performed.\n\n" +
		"Any changed asset, commit, tag, release-index digest, procedure, guide text, selected output, or required test resets its affected result.\n"
}

func (fixture *releaseFixture) verifier(body []byte, algorithm, digest string) ([]byte, error) {
	if fixture.verifyErr != nil {
		return nil, fixture.verifyErr
	}
	if string(body) != `{"fixture":true}` || algorithm != "sha1" || digest != fixtureCommit {
		return nil, errors.New("fixture verifier refused")
	}
	subjects := []map[string]any{{"uri": "pkg:github/" + softwarelifecycle.Repository + "@" + fixture.release.Tag, "digest": map[string]string{"sha1": fixtureCommit}}}
	for _, asset := range fixture.release.Assets {
		name := asset.Name
		subjects = append(subjects, map[string]any{"name": name, "digest": map[string]string{"sha256": fixture.attested[name]}})
	}
	return json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://in-toto.io/attestation/release/v0.2", "subject": subjects,
		"predicate": map[string]string{"databaseId": "2", "ownerId": "1", "packageId": "4", "purl": "pkg:github/" + softwarelifecycle.Repository + "@" + fixture.release.Tag, "repository": softwarelifecycle.Repository, "repositoryId": "3", "tag": fixture.release.Tag},
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
			if id > 0 && id <= len(fixture.release.Assets) {
				name := fixture.release.Assets[id-1].Name
				if fixture.redirectAsset && name == "release-index.json" {
					http.Redirect(writer, request, "http://example.com/changed", http.StatusFound)
					return
				}
				if fixture.beforeAsset != nil {
					fixture.beforeAsset(name)
				}
				_, _ = writer.Write(fixture.assets[name])
				return
			}
		}
		http.NotFound(writer, request)
	}
}
