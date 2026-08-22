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
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	Version                         = "1.3.0"
	SigningFingerprint              = "26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485"
	qualificationSigningFingerprint = "3C2CC7F357DC064EC527FDCD78DA6E9245C21A381E1ABAA0F2B62B186BCAC1A1"
	apiBaseURL                      = "https://api.github.com"
	maxBundleBytes                  = 8 << 20
)

var (
	errUnavailable     = errors.New("GitHub unavailable")
	errRedirectRefused = errors.New("release redirect refused")
)

//go:embed trusted_root.json
var trustedRootJSON []byte

//go:embed qualification_trusted_root.json
var qualificationTrustedRootJSON []byte

type BundleVerifier func([]byte, string, string) ([]byte, error)

type Source struct {
	client   *http.Client
	baseURL  string
	verifier BundleVerifier
}

func New() Source {
	digest := sha256.Sum256(trustedRootJSON)
	qualificationDigest := sha256.Sum256(qualificationTrustedRootJSON)
	if strings.ToUpper(hex.EncodeToString(digest[:])) != SigningFingerprint || strings.ToUpper(hex.EncodeToString(qualificationDigest[:])) != qualificationSigningFingerprint {
		return Source{}
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return Source{}
	}
	qualificationTrustedRoot, err := root.NewTrustedRootFromJSON(qualificationTrustedRootJSON)
	if err != nil {
		return Source{}
	}
	return NewWithEndpoint(publicClient(), apiBaseURL, sigstoreVerifier(trustedRoot, qualificationTrustedRoot))
}

// NewWithEndpoint replaces only the public HTTPS and bundle-verification boundaries for Seam Verification.
func NewWithEndpoint(client *http.Client, baseURL string, verifier BundleVerifier) Source {
	return Source{client: client, baseURL: strings.TrimSuffix(baseURL, "/"), verifier: verifier}
}

func publicClient() *http.Client {
	return &http.Client{CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 4 || request.URL.Scheme != "https" {
			return errRedirectRefused
		}
		host := request.URL.Hostname()
		if host != "release-assets.githubusercontent.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
			return errRedirectRefused
		}
		return nil
	}}
}

func (source Source) CheckLatest(ctx context.Context) (softwarelifecycle.LatestRelease, softwarelifecycle.LatestReleaseOutcome) {
	latest, _, outcome := source.latest(ctx, "")
	return latest, outcome
}

func (source Source) PrepareLatest(ctx context.Context, architecture softwarelifecycle.Architecture) (softwarelifecycle.UpdateCandidate, softwarelifecycle.LatestReleaseOutcome) {
	name := "sbxr-linux-amd64.tar.gz"
	if architecture == softwarelifecycle.ARM64 {
		name = "sbxr-linux-arm64.tar.gz"
	} else if architecture != softwarelifecycle.AMD64 {
		return softwarelifecycle.UpdateCandidate{}, softwarelifecycle.LatestReleaseRefused
	}
	latest, archive, outcome := source.latest(ctx, name)
	if outcome != softwarelifecycle.LatestReleaseAccepted {
		return softwarelifecycle.UpdateCandidate{}, outcome
	}
	candidate, ok := softwarelifecycle.VerifyLatestUpdateArchive(latest, architecture, archive)
	if !ok {
		return softwarelifecycle.UpdateCandidate{}, softwarelifecycle.LatestReleaseRefused
	}
	return candidate, softwarelifecycle.LatestReleaseAccepted
}

func (source Source) latest(ctx context.Context, archiveName string) (softwarelifecycle.LatestRelease, []byte, softwarelifecycle.LatestReleaseOutcome) {
	if source.client == nil || source.verifier == nil || source.baseURL == "" {
		return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
	}
	var release githubRelease
	if err := source.latestJSON(ctx, source.baseURL+"/repos/"+softwarelifecycle.Repository+"/releases/latest", 1<<20, &release); err != nil {
		latest, outcome := latestFailure(err)
		return latest, nil, outcome
	}
	metadata, err := exactLatestAssets(source.baseURL, release.Assets)
	if err != nil || release.Draft || release.Prerelease || !release.Immutable || !immutableTagPattern.MatchString(release.Tag) || !commitPattern.MatchString(release.TargetCommitish) {
		return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
	}
	recordIndex, recordSequence, qualified := latestAcceptanceRecord(release.Body, release.Tag, release.TargetCommitish, metadata)
	if release.Qualification != nil {
		if recordIndex, recordSequence, qualified = source.qualificationLatest(release, metadata); !qualified {
			return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
		}
	} else {
		if !qualified {
			return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
		}
		var response attestationResponse
		attestationURL := source.baseURL + "/repos/" + softwarelifecycle.Repository + "/attestations/sha1:" + release.TargetCommitish + "?predicate_type=release&per_page=100"
		if err := source.latestJSON(ctx, attestationURL, maxBundleBytes, &response); err != nil {
			latest, outcome := latestFailure(err)
			return latest, nil, outcome
		}
		if len(response.Attestations) != 1 || response.Attestations[0].Initiator != "github" {
			return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
		}
		bundleCtx, cancelBundle := context.WithTimeout(ctx, 30*time.Second)
		bundleBody, err := source.bundle(bundleCtx, response.Attestations[0])
		cancelBundle()
		if err != nil {
			latest, outcome := latestFailure(err)
			return latest, nil, outcome
		}
		statementBody, err := source.verifier(bundleBody, "sha1", release.TargetCommitish)
		if err != nil {
			return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
		}
		attested, err := parseReleaseStatementWithAssets(statementBody, release.Tag, release.TargetCommitish, 4)
		if err != nil || !sameAssetDigests(metadata, attested) {
			return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
		}
	}
	indexMetadata := metadata["release-index.json"]
	indexCtx, cancelIndex := context.WithTimeout(ctx, 30*time.Second)
	index, err := source.get(indexCtx, indexMetadata.URL, softwarelifecycle.MaxIndexBytes, "application/octet-stream")
	cancelIndex()
	if err != nil {
		latest, outcome := latestFailure(err)
		return latest, nil, outcome
	}
	digest := sha256.Sum256(index)
	if int64(len(index)) != indexMetadata.Size || hex.EncodeToString(digest[:]) != indexMetadata.SHA256 || indexMetadata.SHA256 != recordIndex {
		return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
	}
	proofs := make([]softwarelifecycle.LatestAssetProof, 0, 4)
	for _, name := range latestAssetNames() {
		asset := metadata[name]
		proofs = append(proofs, softwarelifecycle.LatestAssetProof{Name: name, Size: asset.Size, SHA256: asset.SHA256})
	}
	latest, valid := softwarelifecycle.VerifyLatestReleaseIndex(softwarelifecycle.Repository, release.Tag, release.TargetCommitish, index, proofs)
	if !valid || latest.Sequence != recordSequence {
		return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
	}
	if archiveName == "" {
		return latest, nil, softwarelifecycle.LatestReleaseAccepted
	}
	asset := metadata[archiveName]
	archiveCtx, cancelArchive := context.WithTimeout(ctx, 2*time.Minute)
	archive, err := source.get(archiveCtx, asset.URL, softwarelifecycle.MaxAssetBytes, "application/octet-stream")
	cancelArchive()
	digest = sha256.Sum256(archive)
	if err != nil {
		failed, failedOutcome := latestFailure(err)
		return failed, nil, failedOutcome
	}
	if int64(len(archive)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 {
		return softwarelifecycle.LatestRelease{}, nil, softwarelifecycle.LatestReleaseRefused
	}
	return latest, archive, softwarelifecycle.LatestReleaseAccepted
}

func latestFailure(err error) (softwarelifecycle.LatestRelease, softwarelifecycle.LatestReleaseOutcome) {
	if errors.Is(err, errUnavailable) {
		return softwarelifecycle.LatestRelease{}, softwarelifecycle.LatestReleaseUnavailable
	}
	return softwarelifecycle.LatestRelease{}, softwarelifecycle.LatestReleaseRefused
}

type githubRelease struct {
	Tag             string                `json:"tag_name"`
	TargetCommitish string                `json:"target_commitish"`
	Body            string                `json:"body"`
	Draft           bool                  `json:"draft"`
	Prerelease      bool                  `json:"prerelease"`
	Immutable       bool                  `json:"immutable"`
	Assets          []githubAsset         `json:"assets"`
	Qualification   *qualificationRelease `json:"sbxr_qualification,omitempty"`
}

type qualificationRelease struct {
	Manifest []byte `json:"manifest"`
	Bundle   []byte `json:"bundle"`
}

type qualificationManifest struct {
	Schema      string          `json:"schema"`
	Repository  string          `json:"repository"`
	Approval    json.RawMessage `json:"approval"`
	Mode        string          `json:"mode"`
	SourceState string          `json:"source_state"`
	Workflow    struct {
		Path   string `json:"path"`
		Ref    string `json:"ref"`
		Commit string `json:"commit"`
		RunID  string `json:"run_id"`
		RunURL string `json:"run_url"`
	} `json:"workflow"`
	Releases []struct {
		Tag       string `json:"tag"`
		Commit    string `json:"commit"`
		Sequence  uint64 `json:"sequence"`
		ReleaseID uint64 `json:"release_id"`
		Identity  struct {
			Repository  string `json:"repository"`
			Tag         string `json:"tag"`
			Commit      string `json:"commit"`
			IndexSHA256 string `json:"release_index_sha256"`
		} `json:"release_identity"`
		Assets []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}
	}
	NativeEvidence               json.RawMessage `json:"native_evidence"`
	AcceptanceVPSChecklistSHA256 string          `json:"acceptance_vps_checklist_sha256"`
	CandidateFailureStateSHA256  string          `json:"candidate_failure_state_sha256"`
	PinnedActions                []string        `json:"pinned_actions"`
	Rescue                       json.RawMessage `json:"rescue"`
}

func (source Source) qualificationLatest(release githubRelease, metadata map[string]assetMetadata) (string, uint64, bool) {
	proof := release.Qualification
	if proof == nil || len(proof.Manifest) == 0 || len(proof.Manifest) > 1<<20 || len(proof.Bundle) == 0 || len(proof.Bundle) > maxBundleBytes || softwarelifecycle.ValidateUniqueJSON(proof.Manifest) != nil || softwarelifecycle.ValidateUniqueJSON(proof.Bundle) != nil {
		return "", 0, false
	}
	var manifest qualificationManifest
	decoder := json.NewDecoder(bytes.NewReader(proof.Manifest))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.Schema != "sbxr-qualification-manifest-v1" || manifest.Repository != softwarelifecycle.Repository || manifest.Workflow.Path != ".github/workflows/candidate.yml" || manifest.Workflow.Ref != "albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main" || !commitPattern.MatchString(manifest.Workflow.Commit) || !workflowEvidencePattern.MatchString(manifest.Workflow.RunURL) || manifest.Workflow.RunID == "" || !strings.HasSuffix(manifest.Workflow.RunURL, "/"+manifest.Workflow.RunID) || !hashPattern.MatchString(manifest.CandidateFailureStateSHA256) || len(manifest.Releases) != 2 {
		return "", 0, false
	}
	digest := sha256.Sum256(proof.Manifest)
	digestText := hex.EncodeToString(digest[:])
	statement, err := source.verifier(proof.Bundle, "sha256", digestText)
	if err != nil || !qualificationStatementBinds(statement, digestText) {
		return "", 0, false
	}
	for _, candidate := range manifest.Releases {
		if candidate.Tag != release.Tag {
			continue
		}
		if candidate.Sequence == 0 || candidate.ReleaseID == 0 || candidate.Commit != release.TargetCommitish || candidate.Identity.Repository != softwarelifecycle.Repository || candidate.Identity.Tag != release.Tag || candidate.Identity.Commit != release.TargetCommitish || !hashPattern.MatchString(candidate.Identity.IndexSHA256) || len(candidate.Assets) != len(metadata) {
			return "", 0, false
		}
		seen := map[string]bool{}
		for _, asset := range candidate.Assets {
			got, ok := metadata[asset.Name]
			if !ok || seen[asset.Name] || asset.Size != got.Size || asset.SHA256 != got.SHA256 {
				return "", 0, false
			}
			seen[asset.Name] = true
		}
		return candidate.Identity.IndexSHA256, candidate.Sequence, candidate.Identity.IndexSHA256 == metadata["release-index.json"].SHA256
	}
	return "", 0, false
}

func qualificationStatementBinds(body []byte, digest string) bool {
	if len(body) == 0 || len(body) > maxBundleBytes || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return false
	}
	var statement struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	return json.Unmarshal(body, &statement) == nil && statement.Type == "https://in-toto.io/Statement/v1" && len(statement.Subject) == 1 && statement.Subject[0].Name == "qualification-manifest.json" && len(statement.Subject[0].Digest) == 1 && statement.Subject[0].Digest["sha256"] == digest
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

func latestAssetNames() []string {
	return []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}
}

func exactLatestAssets(baseURL string, assets []githubAsset) (map[string]assetMetadata, error) {
	expected := map[string]bool{}
	for _, name := range latestAssetNames() {
		expected[name] = true
	}
	result := make(map[string]assetMetadata, len(assets))
	for _, asset := range assets {
		digest, ok := strings.CutPrefix(asset.Digest, "sha256:")
		limit := int64(softwarelifecycle.MaxAssetBytes)
		if asset.Name == "install.sh" || asset.Name == "release-index.json" {
			limit = softwarelifecycle.MaxIndexBytes
		}
		if !expected[asset.Name] || result[asset.Name].URL != "" || !ok || !hashPattern.MatchString(digest) || asset.State != "uploaded" || asset.Size <= 0 || asset.Size > limit || !validLatestAssetURL(baseURL, asset.URL) {
			return nil, errors.New("latest release asset refused")
		}
		result[asset.Name] = assetMetadata{URL: asset.URL, SHA256: digest, Size: asset.Size}
	}
	if len(result) != len(expected) {
		return nil, errors.New("latest release asset refused")
	}
	return result, nil
}

func validLatestAssetURL(baseURL, address string) bool {
	base, baseErr := url.Parse(baseURL)
	parsed, parseErr := url.Parse(address)
	prefix := "/repos/" + softwarelifecycle.Repository + "/releases/assets/"
	id := strings.TrimPrefix(parsed.Path, prefix)
	assetID, idErr := strconv.ParseUint(id, 10, 64)
	return baseErr == nil && parseErr == nil && parsed.Scheme == base.Scheme && parsed.Host == base.Host && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == parsed.EscapedPath() && idErr == nil && assetID > 0 && strconv.FormatUint(assetID, 10) == id
}

func latestAcceptanceRecord(body, tag, commit string, assets map[string]assetMetadata) (string, uint64, bool) {
	if len(body) == 0 || len(body) > 64<<10 || strings.ContainsAny(body, "\r\x00") || !strings.HasSuffix(body, "\n") {
		return "", 0, false
	}
	if strings.Count(body, "# SBXR Installer-Updater Acceptance Record\n") != 1 {
		return "", 0, false
	}
	required := map[string]string{
		"Status: ":                  "Qualified",
		"Repository: ":              softwarelifecycle.Repository,
		"Tag: ":                     tag,
		"Commit: ":                  commit,
		"Module Verification: ":     "Passed",
		"Seam Verification: ":       "Passed",
		"Integrated Verification: ": "Passed on live Ubuntu Server 24.04 amd64",
		"Codex Live Acceptance: ":   "Passed",
		"Owner Acceptance: ":        "Not required",
	}
	for prefix, expected := range required {
		if value, ok := uniqueRecordValue(body, prefix); !ok || value != expected {
			return "", 0, false
		}
	}
	resultCode, resultOK := uniqueRecordValue(body, "Stable result code: ")
	workflow, workflowOK := uniqueRecordValue(body, "Workflow evidence: ")
	runner, runnerOK := uniqueRecordValue(body, "Runner: ")
	toolchain, toolchainOK := uniqueRecordValue(body, "Go toolchain: ")
	verifier, verifierOK := uniqueRecordValue(body, "Public verifier: ")
	secretSafe, secretSafeOK := uniqueRecordValue(body, "Secret-safe result: ")
	role, roleOK := uniqueRecordValue(body, "Qualification role: ")
	if !resultOK || resultCode != "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION" && resultCode != "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION" || !workflowOK || !workflowEvidencePattern.MatchString(workflow) || !runnerOK || !acceptanceRunnerPattern.MatchString(runner) || !toolchainOK || !goToolchainPattern.MatchString(toolchain) || !verifierOK || verifier != Version+" "+SigningFingerprint || !secretSafeOK || secretSafe != "Passed" || !roleOK || !qualificationRolePattern.MatchString(role) {
		return "", 0, false
	}
	if resultCode == "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION" {
		defect, defectOK := uniqueRecordValue(body, "Rescue defect evidence: ")
		failedRun, failedRunOK := uniqueRecordValue(body, "Failed normal run evidence: ")
		waiver, waiverOK := uniqueRecordValue(body, "Normal journey waiver: ")
		if role != "Rescue direct-install and lower-sequence replacement release" || !defectOK || !issueEvidencePattern.MatchString(defect) || !failedRunOK || !workflowEvidencePattern.MatchString(failedRun) || !waiverOK || waiver != "Reproducible installed-source defect made the normal menu journey impossible" {
			return "", 0, false
		}
	} else if role == "Rescue direct-install and lower-sequence replacement release" {
		return "", 0, false
	}
	for _, name := range latestAssetNames() {
		asset := assets[name]
		value, ok := uniqueRecordValue(body, "Asset: "+name+" ")
		if !ok || value != fmt.Sprintf("%d %s", asset.Size, asset.SHA256) {
			return "", 0, false
		}
	}
	indexSHA256, ok := uniqueRecordValue(body, "Release index SHA-256: ")
	if !ok || !hashPattern.MatchString(indexSHA256) || indexSHA256 != assets["release-index.json"].SHA256 {
		return "", 0, false
	}
	sequenceText, ok := uniqueRecordValue(body, "Sequence: ")
	sequence, parseErr := strconv.ParseUint(sequenceText, 10, 64)
	return indexSHA256, sequence, ok && parseErr == nil && sequence > 0
}

func uniqueRecordValue(body, prefix string) (string, bool) {
	value := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			if value != "" {
				return "", false
			}
			value = strings.TrimPrefix(line, prefix)
		}
	}
	return value, value != ""
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

func sigstoreVerifier(trustedRoot, qualificationTrustedRoot *root.TrustedRoot) BundleVerifier {
	return func(body []byte, algorithm, digest string) ([]byte, error) {
		if trustedRoot == nil || algorithm != "sha1" && algorithm != "sha256" || algorithm == "sha1" && !commitPattern.MatchString(digest) || algorithm == "sha256" && !hashPattern.MatchString(digest) || len(body) == 0 || len(body) > maxBundleBytes {
			return nil, errors.New("bundle verification refused")
		}
		var releaseBundle bundle.Bundle
		if err := releaseBundle.UnmarshalJSON(body); err != nil {
			return nil, fmt.Errorf("bundle verification refused: %w", err)
		}
		verifierRoot := trustedRoot
		verifierOptions := []verify.VerifierOption{verify.WithSignedTimestamps(1)}
		if algorithm == "sha256" {
			verifierRoot = qualificationTrustedRoot
			verifierOptions = []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
		}
		verifier, err := verify.NewVerifier(verifierRoot, verifierOptions...)
		if err != nil {
			return nil, errors.New("bundle verification refused")
		}
		identity, err := verify.NewShortCertificateIdentity("", ".*", "https://dotcom.releases.github.com", "")
		if algorithm == "sha256" {
			identity, err = verify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", "https://github.com/albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main", "")
		}
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

func parseReleaseStatementWithAssets(body []byte, tag, commit string, assetCount int) (map[string]string, error) {
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
		statement.Predicate.Repository != softwarelifecycle.Repository || statement.Predicate.Tag != tag || statement.Predicate.PURL != purl || len(statement.Subject) != assetCount+1 {
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

func (source Source) latestJSON(ctx context.Context, address string, limit int64, target any) error {
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := source.get(requestCtx, address, limit, "application/vnd.github+json")
	if err != nil {
		return err
	}
	if softwarelifecycle.ValidateUniqueJSON(body) != nil || json.Unmarshal(body, target) != nil {
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
		if errors.Is(err, errRedirectRefused) {
			return nil, errors.New("GitHub redirect refused")
		}
		return nil, errUnavailable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil || response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return nil, errUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("GitHub response refused")
	}
	if len(body) == 0 || int64(len(body)) > limit {
		return nil, fmt.Errorf("GitHub response refused")
	}
	return body, nil
}

var (
	commitPattern            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern              = regexp.MustCompile(`^[0-9a-f]{64}$`)
	immutableTagPattern      = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	workflowEvidencePattern  = regexp.MustCompile(`^https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*$`)
	issueEvidencePattern     = regexp.MustCompile(`^https://github\.com/albertloky/SBXR/issues/[1-9][0-9]*$`)
	acceptanceRunnerPattern  = regexp.MustCompile(`^Ubuntu Server 24\.04 linux/amd64$`)
	goToolchainPattern       = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
	qualificationRolePattern = regexp.MustCompile(`^(Clean-installed source release|Discovered, installed, recovered, final latest release|Rescue direct-install and lower-sequence replacement release)$`)
)
