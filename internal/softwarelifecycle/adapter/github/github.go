// Package github supplies Software Lifecycle's public GitHub release seam.
package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	Version            = "1.3.0"
	SigningFingerprint = "26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485"
	apiBaseURL         = "https://api.github.com"
	maxBundleBytes     = 8 << 20
)

//go:embed trusted_root.json
var trustedRootJSON []byte

type BundleVerifier func([]byte, string, string) ([]byte, error)

type Source struct {
	client   *http.Client
	baseURL  string
	verifier BundleVerifier
}

func New() Source {
	digest := sha256.Sum256(trustedRootJSON)
	if strings.ToUpper(hex.EncodeToString(digest[:])) != SigningFingerprint {
		return Source{}
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return Source{}
	}
	return NewWithEndpoint(publicClient(), apiBaseURL, sigstoreVerifier(trustedRoot))
}

// NewWithEndpoint replaces only the public HTTPS and bundle-verification boundaries for Seam Verification.
func NewWithEndpoint(client *http.Client, baseURL string, verifier BundleVerifier) Source {
	return Source{client: client, baseURL: strings.TrimSuffix(baseURL, "/"), verifier: verifier}
}

func publicClient() *http.Client {
	return &http.Client{CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 4 || request.URL.Scheme != "https" {
			return errors.New("release redirect refused")
		}
		host := request.URL.Hostname()
		if host != "release-assets.githubusercontent.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
			return errors.New("release redirect refused")
		}
		return nil
	}}
}

func (source Source) Discover(ctx context.Context, reviewedTag string) (softwarelifecycle.ReleaseListing, error) {
	if source.client == nil || reviewedTag != "" && !safeTag(reviewedTag) {
		return softwarelifecycle.ReleaseListing{}, errors.New("GitHub release discovery unavailable")
	}
	path := "/repos/" + softwarelifecycle.Repository + "/releases/latest"
	if reviewedTag != "" {
		path = "/repos/" + softwarelifecycle.Repository + "/releases/tags/" + url.PathEscape(reviewedTag)
	}
	var release githubRelease
	if source.getJSON(ctx, source.baseURL+path, 1<<20, &release) != nil || !safeTag(release.Tag) {
		return softwarelifecycle.ReleaseListing{}, errors.New("GitHub release discovery refused")
	}
	if reviewedTag == "" {
		assets, err := exactReleaseAssets(source.baseURL, release.Assets)
		if err != nil || release.Draft || release.Prerelease || !release.Immutable || !commitPattern.MatchString(release.TargetCommitish) ||
			!stableAcceptanceRecord(release.Body, release.Tag, release.TargetCommitish, assets["release-index.json"].SHA256) {
			return softwarelifecycle.ReleaseListing{}, errors.New("GitHub stable release discovery refused")
		}
	}
	return softwarelifecycle.ReleaseListing{Tag: release.Tag, Draft: release.Draft, Prerelease: release.Prerelease}, nil
}

func (source Source) Verify(ctx context.Context, tag string) (softwarelifecycle.ReleaseEvidence, error) {
	if source.client == nil || source.verifier == nil || source.baseURL == "" || !safeTag(tag) {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub verifier unavailable")
	}
	var ref githubRef
	if source.getJSON(ctx, source.baseURL+"/repos/"+softwarelifecycle.Repository+"/git/ref/tags/"+url.PathEscape(tag), 64<<10, &ref) != nil ||
		ref.Object.Type != "commit" || !commitPattern.MatchString(ref.Object.SHA) {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release ref refused")
	}
	commit := ref.Object.SHA
	var release githubRelease
	if source.getJSON(ctx, source.baseURL+"/repos/"+softwarelifecycle.Repository+"/releases/tags/"+url.PathEscape(tag), 1<<20, &release) != nil ||
		release.Tag != tag || release.TargetCommitish != commit || release.Draft || !release.Immutable || len(release.Assets) != 6 {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub immutable release refused")
	}
	recordIndexSHA256 := ""
	if !release.Prerelease {
		var ok bool
		recordIndexSHA256, ok = acceptanceRecordIndexSHA256(release.Body, tag, commit)
		if !ok {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub stable acceptance record refused")
		}
	}
	metadata, err := exactReleaseAssets(source.baseURL, release.Assets)
	if err != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release asset set refused")
	}
	var response attestationResponse
	attestationURL := source.baseURL + "/repos/" + softwarelifecycle.Repository + "/attestations/sha1:" + commit + "?predicate_type=release&per_page=100"
	if source.getJSON(ctx, attestationURL, maxBundleBytes, &response) != nil || len(response.Attestations) != 1 || response.Attestations[0].Initiator != "github" {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release attestation refused")
	}
	bundleBody, err := source.bundle(ctx, response.Attestations[0])
	if err != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release bundle refused")
	}
	statementBody, err := source.verifier(bundleBody, "sha1", commit)
	if err != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release signature refused")
	}
	attested, err := parseReleaseStatement(statementBody, tag, commit)
	if err != nil || !sameAssetDigests(metadata, attested) {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release statement refused")
	}
	names := fixedAssetNames()
	downloaded := make([]softwarelifecycle.DownloadedAsset, 0, 5)
	var index []byte
	for _, name := range names {
		asset := metadata[name]
		body, err := source.get(ctx, asset.URL, assetLimit(name), "application/octet-stream")
		if err != nil || int64(len(body)) != asset.Size {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("bounded release download failed")
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != asset.SHA256 {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("downloaded release asset changed")
		}
		if name == "release-index.json" {
			index = body
		} else {
			downloaded = append(downloaded, softwarelifecycle.DownloadedAsset{Name: name, Bytes: body})
		}
	}
	if recordIndexSHA256 != "" {
		digest := sha256.Sum256(index)
		if hex.EncodeToString(digest[:]) != recordIndexSHA256 {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub stable acceptance record refused")
		}
	}
	proofs := make([]softwarelifecycle.AttestedAsset, 0, len(names))
	for _, name := range names {
		proofs = append(proofs, softwarelifecycle.AttestedAsset{Name: name, SHA256: metadata[name].SHA256})
	}
	return softwarelifecycle.ReleaseEvidence{
		Repository: softwarelifecycle.Repository, Tag: tag, Commit: commit, Index: index, Assets: downloaded, AttestedAssets: proofs,
		Verifier: softwarelifecycle.VerifierEvidence{Version: Version, SigningFingerprint: SigningFingerprint, OfficialSignedDistribution: true, ReleaseVerified: true, VerifiedAssets: names},
	}, nil
}

type githubRef struct {
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

type githubRelease struct {
	Tag             string        `json:"tag_name"`
	TargetCommitish string        `json:"target_commitish"`
	Body            string        `json:"body"`
	Draft           bool          `json:"draft"`
	Prerelease      bool          `json:"prerelease"`
	Immutable       bool          `json:"immutable"`
	Assets          []githubAsset `json:"assets"`
}

func stableAcceptanceRecord(body, tag, commit, indexSHA256 string) bool {
	recorded, ok := acceptanceRecordIndexSHA256(body, tag, commit)
	return ok && (indexSHA256 == "" || recorded == indexSHA256)
}

func acceptanceRecordIndexSHA256(body, tag, commit string) (string, bool) {
	if len(body) == 0 || len(body) > 64<<10 || strings.ContainsAny(body, "\r\x00") {
		return "", false
	}
	required := []string{
		"# SBXR automated Acceptance Record",
		"Repository: " + softwarelifecycle.Repository,
		"Tag: " + tag,
		"Commit: " + commit,
	}
	for _, line := range required {
		if strings.Count(body, line+"\n") != 1 {
			return "", false
		}
	}
	rootRuntime := []string{
		"Status: Qualified - root-runtime package policy",
		"Stable result code: RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION",
		"| Module Verification | Passed | Package suites at the Pasteable Install Command and owning Module Interfaces |",
		"| Seam Verification | Passed | Exact public HTTPS release verification, Sigstore attestations, and package seam checks |",
		"| Integrated Verification | Passed | Package composition through existing product Interfaces |",
		"Integrated Ubuntu Verification: Not required - ADR-0010 root-runtime package and public-seam scope; no automated Ubuntu integration evidence claimed.",
		"| Codex Live Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no live VPS evidence claimed |",
		"| Owner Acceptance | Not required | ADR-0010 root-runtime package and public-seam scope; no maintained-client evidence claimed |",
		"No Integrated Ubuntu Verification, live VPS, provider, maintained-client, or Owner evidence was performed.",
		"Any asset, attestation, repository, tag, commit, release-index digest, qualification scope, required check, or client-facing change invalidates this record.",
	}
	stagedOnboarding := []string{
		"Status: Qualified - staged-onboarding package policy",
		"Stable result code: RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION",
		"Qualified procedures: RELEASE-STAGED-INSTALL-REVISION-1, RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1, RELEASE-STAGED-ONBOARDING-CHAIN, RELEASE-STAGED-ONBOARDING-SECRET-SCAN, RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT, RELEASE-STAGED-ONBOARDING-TERMINAL, RELEASE-STAGED-ONBOARDING-GUIDE-TEXT",
		"Packaged executable qualification: amd64 Passed; arm64 Passed.",
		"| Module Verification | Passed | Package suites at the Pasteable Install Command and owning Module Interfaces |",
		"| Seam Verification | Passed | Exact public HTTPS release verification, Sigstore attestations, and package seam checks |",
		"| Integrated Verification | Passed | Staged Installation, Cloudflare Profile Setup, and chained package composition |",
		"| Codex Live Acceptance | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Real VPS | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Real Cloudflare | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| ACME | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Outside-client | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Maintained-client | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Current-documentation | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Provider mutation | Not required — staged-onboarding package and controlled-seam qualification scope |",
		"| Owner Acceptance | Not required — staged-onboarding package and controlled-terminal qualification scope |",
		"Codex Live Acceptance: Not required — staged-onboarding package and controlled-seam qualification scope.",
		"Owner Acceptance: Not required — staged-onboarding package and controlled-terminal qualification scope.",
		"No live VPS, real Cloudflare, ACME, outside-client, maintained-client, current-documentation, provider mutation, or Owner Acceptance was performed.",
		"Any changed asset, commit, tag, release-index digest, procedure, guide text, selected output, or required test resets its affected result.",
	}
	policy := rootRuntime
	forbiddenPolicyLines := stagedOnboarding[:4]
	if strings.Count(body, stagedOnboarding[0]+"\n") == 1 {
		policy, forbiddenPolicyLines = stagedOnboarding, rootRuntime[:2]
	}
	for _, line := range policy {
		if strings.Count(body, line+"\n") != 1 {
			return "", false
		}
	}
	for _, line := range forbiddenPolicyLines {
		if strings.Contains(body, line) {
			return "", false
		}
	}
	if !strings.HasSuffix(body, policy[len(policy)-1]+"\n") {
		return "", false
	}
	known := append(append([]string{}, required...), policy...)
	known = append(known, "| Stage | Status | Evidence |", "|---|---|---|", "| External check | Status |", "|---|---|", "| Exact asset | Bytes | SHA-256 |", "|---|---:|---|")
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if line == "" {
			continue
		}
		if seen[line] || !slices.Contains(known, line) && !acceptanceRecordVariableLinePattern.MatchString(line) {
			return "", false
		}
		seen[line] = true
	}
	prefix := "Release index SHA-256: "
	var digest string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			if digest != "" {
				return "", false
			}
			digest = strings.TrimPrefix(line, prefix)
		}
	}
	return digest, hashPattern.MatchString(digest)
}

type githubAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	State  string `json:"state"`
	URL    string `json:"url"`
}

type attestationResponse struct {
	Attestations []githubAttestation `json:"attestations"`
}

type githubAttestation struct {
	Bundle    json.RawMessage `json:"bundle"`
	BundleURL string          `json:"bundle_url"`
	Initiator string          `json:"initiator"`
}

type assetMetadata struct {
	URL, SHA256 string
	Size        int64
}

func exactReleaseAssets(baseURL string, assets []githubAsset) (map[string]assetMetadata, error) {
	expected := map[string]bool{}
	for _, name := range fixedAssetNames() {
		expected[name] = true
	}
	result := make(map[string]assetMetadata, len(assets))
	for _, asset := range assets {
		digest, ok := strings.CutPrefix(asset.Digest, "sha256:")
		parsed, parseErr := url.Parse(asset.URL)
		if !expected[asset.Name] || result[asset.Name].URL != "" || !ok || !hashPattern.MatchString(digest) || asset.State != "uploaded" ||
			asset.Size <= 0 || asset.Size > assetLimit(asset.Name) || parseErr != nil || parsed.Scheme != "https" && !strings.HasPrefix(baseURL, "http://") ||
			!strings.HasPrefix(asset.URL, baseURL+"/repos/"+softwarelifecycle.Repository+"/releases/assets/") {
			return nil, errors.New("release asset refused")
		}
		result[asset.Name] = assetMetadata{URL: asset.URL, SHA256: digest, Size: asset.Size}
	}
	if len(result) != len(expected) {
		return nil, errors.New("release asset refused")
	}
	return result, nil
}

func (source Source) bundle(ctx context.Context, attestation githubAttestation) ([]byte, error) {
	if len(attestation.Bundle) != 0 && string(attestation.Bundle) != "null" {
		if len(attestation.Bundle) > maxBundleBytes || softwarelifecycle.ValidateUniqueJSON(attestation.Bundle) != nil {
			return nil, errors.New("bundle refused")
		}
		return append([]byte(nil), attestation.Bundle...), nil
	}
	parsed, err := url.Parse(attestation.BundleURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "tmaproduction.blob.core.windows.net" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("bundle URL refused")
	}
	compressed, err := source.get(ctx, attestation.BundleURL, maxBundleBytes, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	body, err := snappy.Decode(nil, compressed)
	if err != nil || len(body) == 0 || len(body) > maxBundleBytes || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return nil, errors.New("bundle refused")
	}
	return body, nil
}

func sigstoreVerifier(trustedRoot *root.TrustedRoot) BundleVerifier {
	return func(body []byte, algorithm, digest string) ([]byte, error) {
		if trustedRoot == nil || algorithm != "sha1" || !commitPattern.MatchString(digest) || len(body) == 0 || len(body) > maxBundleBytes {
			return nil, errors.New("bundle verification refused")
		}
		var releaseBundle bundle.Bundle
		if err := releaseBundle.UnmarshalJSON(body); err != nil {
			return nil, fmt.Errorf("bundle verification refused: %w", err)
		}
		verifier, err := verify.NewVerifier(trustedRoot, verify.WithSignedTimestamps(1))
		if err != nil {
			return nil, errors.New("bundle verification refused")
		}
		identity, err := verify.NewShortCertificateIdentity("", ".*", "https://dotcom.releases.github.com", "")
		digestBytes, decodeErr := hex.DecodeString(digest)
		if err != nil || decodeErr != nil {
			return nil, errors.New("bundle verification refused")
		}
		if _, err := verifier.Verify(&releaseBundle, verify.NewPolicy(verify.WithArtifactDigest(algorithm, digestBytes), verify.WithCertificateIdentity(identity))); err != nil {
			return nil, fmt.Errorf("bundle verification refused: %w", err)
		}
		return append([]byte(nil), releaseBundle.GetDsseEnvelope().Payload...), nil
	}
}

type releaseStatement struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []releaseSubject `json:"subject"`
	Predicate     releasePredicate `json:"predicate"`
}

type releaseSubject struct {
	Name   string            `json:"name"`
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type releasePredicate struct {
	DatabaseID, OwnerID, PackageID, PURL, Repository, RepositoryID, Tag string
}

func (p *releasePredicate) UnmarshalJSON(body []byte) error {
	var value struct {
		DatabaseID   string `json:"databaseId"`
		OwnerID      string `json:"ownerId"`
		PackageID    string `json:"packageId"`
		PURL         string `json:"purl"`
		Repository   string `json:"repository"`
		RepositoryID string `json:"repositoryId"`
		Tag          string `json:"tag"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("release predicate refused")
	}
	*p = releasePredicate{value.DatabaseID, value.OwnerID, value.PackageID, value.PURL, value.Repository, value.RepositoryID, value.Tag}
	return nil
}

func parseReleaseStatement(body []byte, tag, commit string) (map[string]string, error) {
	if softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return nil, errors.New("release statement refused")
	}
	var statement releaseStatement
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&statement) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("release statement refused")
	}
	purl := "pkg:github/" + softwarelifecycle.Repository + "@" + tag
	if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != "https://in-toto.io/attestation/release/v0.2" ||
		statement.Predicate.DatabaseID == "" || statement.Predicate.OwnerID == "" || statement.Predicate.PackageID == "" || statement.Predicate.RepositoryID == "" ||
		statement.Predicate.Repository != softwarelifecycle.Repository || statement.Predicate.Tag != tag || statement.Predicate.PURL != purl || len(statement.Subject) != 7 {
		return nil, errors.New("release statement refused")
	}
	release := statement.Subject[0]
	if release.Name != "" || release.URI != purl || len(release.Digest) != 1 || release.Digest["sha1"] != commit {
		return nil, errors.New("release statement refused")
	}
	assets := map[string]string{}
	for _, subject := range statement.Subject[1:] {
		if subject.Name == "" || subject.URI != "" || len(subject.Digest) != 1 || !hashPattern.MatchString(subject.Digest["sha256"]) || assets[subject.Name] != "" {
			return nil, errors.New("release statement refused")
		}
		assets[subject.Name] = subject.Digest["sha256"]
	}
	return assets, nil
}

func sameAssetDigests(metadata map[string]assetMetadata, attested map[string]string) bool {
	if len(metadata) != len(attested) {
		return false
	}
	for name, asset := range metadata {
		if attested[name] != asset.SHA256 {
			return false
		}
	}
	return true
}

func fixedAssetNames() []string {
	return []string{"install.sh", "release-index.json", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}
}

func assetLimit(name string) int64 {
	if name == "release-index.json" {
		return softwarelifecycle.MaxIndexBytes
	}
	return softwarelifecycle.MaxAssetBytes
}

func (source Source) getJSON(ctx context.Context, address string, limit int64, target any) error {
	body, err := source.get(ctx, address, limit, "application/vnd.github+json")
	if err != nil || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return errors.New("GitHub JSON refused")
	}
	if json.Unmarshal(body, target) != nil {
		return errors.New("GitHub JSON refused")
	}
	return nil
}

func (source Source) get(ctx context.Context, address string, limit int64, accept string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("GitHub request refused")
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	request.Header.Set("User-Agent", "SBXR/"+Version)
	response, err := source.client.Do(request)
	if err != nil {
		return nil, errors.New("GitHub request failed")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil || response.StatusCode != http.StatusOK || len(body) == 0 || int64(len(body)) > limit {
		return nil, fmt.Errorf("GitHub response refused")
	}
	return body, nil
}

var (
	commitPattern                       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern                         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagPattern                          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	acceptanceRecordVariableLinePattern = regexp.MustCompile(`^(Release index SHA-256: [0-9a-f]{64}|Recorded at: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|Runner: GitHub Actions ubuntu-24\.04 linux/(amd64|arm64)|Go toolchain: go[0-9]+\.[0-9]+\.[0-9]+|Public verifier: [0-9]+\.[0-9]+\.[0-9]+ [A-F0-9]{64}|Workflow evidence: https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*|\| (install\.sh|release-index\.json|sbxr-linux-amd64\.tar\.gz|sbxr-linux-arm64\.tar\.gz|sbxr-components-linux-amd64\.tar\.gz|sbxr-components-linux-arm64\.tar\.gz) \| [1-9][0-9]* \| [0-9a-f]{64} \|)$`)
)

func safeTag(tag string) bool { return tagPattern.MatchString(tag) }
