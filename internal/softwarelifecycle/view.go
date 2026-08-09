package softwarelifecycle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Repository = "albertloky/SBXR"

const (
	MaxIndexBytes = 1 << 20
	MaxAssetBytes = 256 << 20
)

type InstallationStatus string

const (
	NotInstalled     InstallationStatus = "Not installed"
	Managed          InstallationStatus = "Managed"
	ChangeInProgress InstallationStatus = "Change in progress"
	RecoveryRequired InstallationStatus = "Recovery Required"
)

type Action string

const (
	ReviewInstall          Action = "Review install"
	ReviewUpdate           Action = "Review update"
	ReviewDowngrade        Action = "Review downgrade"
	ReviewRepair           Action = "Review repair"
	RetryAutomaticRollback Action = "Retry automatic rollback"
	CompleteRemoval        Action = "Complete removal"
)

type Component string

const (
	ApplicationAMD64 Component = "application-linux-amd64"
	ApplicationARM64 Component = "application-linux-arm64"
	ComponentsAMD64  Component = "components-linux-amd64"
	ComponentsARM64  Component = "components-linux-arm64"
)

type RefusalCode string

const ReleaseVerificationRefused RefusalCode = "SOFTWARE-LIFECYCLE-RELEASE-REFUSED"

type ReleaseIdentity struct {
	Repository, Tag, Commit, IndexSHA256 string
}

type AssetProof struct {
	Role   Component
	Name   string
	Size   int64
	SHA256 string
}

type VerifiedRelease struct {
	Identity                          ReleaseIdentity
	Version                           string
	Sequence                          uint64
	StateSchema, MinimumUpdaterSchema uint64
	VerifiedAt                        time.Time
	Assets                            []AssetProof
	Migrations                        []EmbeddedMigration
}

type Refusal struct {
	Code       RefusalCode
	NextAction string
}

type ViewRequest struct {
	Tag                string
	Architecture       Architecture
	InstallationStatus InstallationStatus
	Installed          *VerifiedRelease
	UpdateDiscovery    *UpdateDiscovery
}

type ViewResult struct {
	InstallationStatus  InstallationStatus
	Installed           *ReleaseIdentity
	VerifiedCandidate   *VerifiedRelease
	StagedCandidate     *StagedRelease
	MigrationSummary    string
	UpdateEligible      bool
	DowngradeCompatible bool
	AffectedComponents  []Component
	PermittedActions    []Action
	Refusal             *Refusal
	installCandidate    InstallCandidate
}

func (result ViewResult) InstallCandidate() InstallCandidate { return result.installCandidate }
func (result ViewResult) UpdateCandidate() InstallCandidate  { return result.installCandidate }

type DownloadedAsset struct {
	Name  string
	Bytes []byte
}

type AttestedAsset struct {
	Name, SHA256 string
}

type VerifierEvidence struct {
	Version, SigningFingerprint string
	OfficialSignedDistribution  bool
	ReleaseVerified             bool
	VerifiedAssets              []string
}

type ReleaseEvidence struct {
	Repository, Tag, Commit string
	Index                   []byte
	Assets                  []DownloadedAsset
	AttestedAssets          []AttestedAsset
	Verifier                VerifierEvidence
}

type ReleaseSource interface {
	Verify(context.Context, string) (ReleaseEvidence, error)
}

type VerifierQualification struct {
	Version, SigningFingerprint string
}

type Interface struct {
	source        ReleaseSource
	discovery     ReleaseDiscovery
	candidates    CandidateStore
	stager        ReleaseStager
	qualification VerifierQualification
	now           func() time.Time
}

func NewWithCandidateRetention(source ReleaseSource, qualification VerifierQualification, now func() time.Time, candidates CandidateStore, stager ...ReleaseStager) Interface {
	module := New(source, qualification, now, stager...)
	module.discovery, _ = source.(ReleaseDiscovery)
	module.candidates = candidates
	return module
}

func New(source ReleaseSource, qualification VerifierQualification, now func() time.Time, stager ...ReleaseStager) Interface {
	if now == nil {
		now = time.Now
	}
	var selected ReleaseStager
	if len(stager) == 1 {
		selected = stager[0]
	}
	return Interface{source: source, stager: selected, qualification: qualification, now: now}
}

func (module Interface) View(ctx context.Context, request ViewRequest) ViewResult {
	result := ViewResult{InstallationStatus: request.InstallationStatus}
	if request.Installed != nil && validInstalled(*request.Installed) {
		identity := request.Installed.Identity
		result.Installed = &identity
	}
	if module.source == nil || !validRequest(request) || !validQualification(module.qualification) {
		return refuse(result)
	}
	if request.UpdateDiscovery != nil {
		return module.discoverUpdate(ctx, request, result)
	}
	evidence, err := module.source.Verify(ctx, request.Tag)
	if err != nil {
		return refuse(result)
	}
	candidate, archives, err := verify(evidence, request.Tag, module.qualification, module.now().UTC())
	if err != nil {
		return refuse(result)
	}
	result.VerifiedCandidate = &candidate
	if request.Architecture != "" {
		applicationRole, componentsRole := componentsForArchitecture(request.Architecture)
		asset, archive, ok := selectedArchive(candidate, archives, applicationRole)
		componentAsset, componentArchive, componentOK := selectedArchive(candidate, archives, componentsRole)
		if module.stager == nil || !ok || !componentOK {
			return refuse(result)
		}
		stageRequest := newStageRequest(candidate, request.Architecture, asset, archive, componentAsset, componentArchive)
		staged, err := module.stager.Stage(ctx, stageRequest)
		if err != nil || !validStagedRelease(staged, stageRequest) {
			return refuse(result)
		}
		result.StagedCandidate = &staged
		result.installCandidate = InstallCandidate{cell: &installCandidateCell{verified: candidate, staged: staged, archive: append([]byte(nil), archive...), components: append([]byte(nil), componentArchive...)}}
	}
	result.MigrationSummary = migrationSummary(candidate)
	result.AffectedComponents = []Component{ApplicationAMD64, ApplicationARM64, ComponentsAMD64, ComponentsARM64}
	switch request.InstallationStatus {
	case NotInstalled:
		result.PermittedActions = []Action{ReviewInstall}
	case Managed:
		if request.Installed != nil && eligibleUpdate(*request.Installed, candidate) {
			result.UpdateEligible = true
			result.PermittedActions = []Action{ReviewUpdate}
		} else if request.Installed != nil && eligibleDowngrade(*request.Installed, candidate) {
			result.DowngradeCompatible = true
			result.PermittedActions = []Action{ReviewDowngrade}
		}
	}
	return result
}

func validRequest(request ViewRequest) bool {
	if request.UpdateDiscovery != nil {
		return request.Tag == "" && request.Architecture == "" && request.InstallationStatus == Managed && request.Installed != nil && validInstalled(*request.Installed) && request.Installed.StateSchema > 0 && request.UpdateDiscovery.valid()
	}
	if !safeTag(request.Tag) {
		return false
	}
	switch request.InstallationStatus {
	case NotInstalled:
		return request.Installed == nil
	case Managed:
		return request.Installed != nil && validInstalled(*request.Installed)
	case ChangeInProgress, RecoveryRequired:
		return request.Installed == nil || validInstalled(*request.Installed)
	default:
		return false
	}
}

func validInstalled(release VerifiedRelease) bool {
	return release.Identity.Repository == Repository && safeTag(release.Identity.Tag) && commitPattern.MatchString(release.Identity.Commit) && hashPattern.MatchString(release.Identity.IndexSHA256) && release.Sequence > 0
}

func validQualification(value VerifierQualification) bool {
	return regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(value.Version) && regexp.MustCompile(`^[0-9A-F]{40,64}$`).MatchString(value.SigningFingerprint)
}

func refuse(result ViewResult) ViewResult {
	result.VerifiedCandidate = nil
	result.StagedCandidate = nil
	result.installCandidate = InstallCandidate{}
	result.MigrationSummary = ""
	result.UpdateEligible = false
	result.DowngradeCompatible = false
	result.AffectedComponents = nil
	result.PermittedActions = nil
	result.Refusal = &Refusal{Code: ReleaseVerificationRefused, NextAction: "Check the selected immutable release again"}
	return result
}

type releaseIndex struct {
	Schema               int          `json:"schema"`
	Product              string       `json:"product"`
	Repository           string       `json:"repository"`
	Version              string       `json:"version"`
	Sequence             uint64       `json:"sequence"`
	Tag                  string       `json:"tag"`
	Commit               string       `json:"commit"`
	StateSchema          uint64       `json:"state_schema"`
	MinimumUpdaterSchema uint64       `json:"minimum_updater_schema"`
	Assets               []indexAsset `json:"assets"`
}

type indexAsset struct {
	Role   Component `json:"role"`
	Name   string    `json:"name"`
	Size   int64     `json:"size"`
	SHA256 string    `json:"sha256"`
}

var (
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	tagPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func safeTag(value string) bool { return tagPattern.MatchString(value) }

func verify(evidence ReleaseEvidence, requestedTag string, qualification VerifierQualification, at time.Time) (VerifiedRelease, map[string][]byte, error) {
	if evidence.Repository != Repository || evidence.Tag != requestedTag || !commitPattern.MatchString(evidence.Commit) || len(evidence.Index) == 0 || len(evidence.Index) > MaxIndexBytes || at.IsZero() || at.Location() != time.UTC {
		return VerifiedRelease{}, nil, errors.New("release identity refused")
	}
	if evidence.Verifier.Version != qualification.Version || evidence.Verifier.SigningFingerprint != qualification.SigningFingerprint || !evidence.Verifier.OfficialSignedDistribution || !evidence.Verifier.ReleaseVerified {
		return VerifiedRelease{}, nil, errors.New("verifier refused")
	}
	if err := ValidateUniqueJSON(evidence.Index); err != nil {
		return VerifiedRelease{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(evidence.Index))
	decoder.DisallowUnknownFields()
	var index releaseIndex
	if decoder.Decode(&index) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedRelease{}, nil, errors.New("index refused")
	}
	if index.Schema != 1 || index.Product != "sbxr" || index.Repository != Repository || !versionPattern.MatchString(index.Version) || index.Sequence == 0 || index.Tag != requestedTag || index.Commit != evidence.Commit || index.StateSchema == 0 || index.MinimumUpdaterSchema == 0 || len(index.Assets) != 4 {
		return VerifiedRelease{}, nil, errors.New("index identity refused")
	}
	downloads := make(map[string][]byte, len(evidence.Assets))
	for _, asset := range evidence.Assets {
		if _, duplicate := downloads[asset.Name]; duplicate || !safeName(asset.Name) || len(asset.Bytes) == 0 || len(asset.Bytes) > MaxAssetBytes {
			return VerifiedRelease{}, nil, errors.New("download refused")
		}
		downloads[asset.Name] = asset.Bytes
	}
	attested := make(map[string]string, len(evidence.AttestedAssets))
	for _, asset := range evidence.AttestedAssets {
		if _, duplicate := attested[asset.Name]; duplicate || !safeName(asset.Name) || !hashPattern.MatchString(asset.SHA256) {
			return VerifiedRelease{}, nil, errors.New("attestation refused")
		}
		attested[asset.Name] = asset.SHA256
	}
	indexDigest := sha256.Sum256(evidence.Index)
	if attested["release-index.json"] != hex.EncodeToString(indexDigest[:]) || !exactNames(evidence.Verifier.VerifiedAssets, attested) || len(attested) != 5 || len(downloads) != 4 {
		return VerifiedRelease{}, nil, errors.New("asset set refused")
	}
	seenRoles := map[Component]bool{}
	proofs := make([]AssetProof, 0, 4)
	var migrations []EmbeddedMigration
	migrationProofs := 0
	for _, asset := range index.Assets {
		if asset.Role != ApplicationAMD64 && asset.Role != ApplicationARM64 && asset.Role != ComponentsAMD64 && asset.Role != ComponentsARM64 || seenRoles[asset.Role] || !safeName(asset.Name) || asset.Name == "release-index.json" || asset.Size <= 0 || asset.Size > MaxAssetBytes || !hashPattern.MatchString(asset.SHA256) {
			return VerifiedRelease{}, nil, errors.New("indexed asset refused")
		}
		seenRoles[asset.Role] = true
		body, ok := downloads[asset.Name]
		digest := sha256.Sum256(body)
		validArchive := oneExecutableArchive(body)
		if validArchive && index.StateSchema > 1 && (asset.Role == ApplicationAMD64 || asset.Role == ApplicationARM64) {
			executable, ok := executableArchiveBytes(body)
			metadata, _, metadataErr := ReadPayloadMetadata(bytes.NewReader(executable), int64(len(executable)))
			architecture := AMD64
			if asset.Role == ApplicationARM64 {
				architecture = ARM64
			}
			validArchive = ok && metadataErr == nil && metadata.Build.Repository == Repository && metadata.Build.Tag == requestedTag && metadata.Build.Commit == evidence.Commit && metadata.Architecture == architecture && metadata.StateSchema == index.StateSchema && metadata.MinimumUpdaterSchema == index.MinimumUpdaterSchema
			if validArchive {
				if migrationProofs == 0 {
					migrations = cloneMigrations(metadata.Migrations)
				} else {
					validArchive = reflect.DeepEqual(migrations, metadata.Migrations)
				}
				migrationProofs++
			}
		}
		if asset.Role == ComponentsAMD64 {
			_, validErr := ValidateComponentArchive(body, AMD64)
			validArchive = validErr == nil
		} else if asset.Role == ComponentsARM64 {
			_, validErr := ValidateComponentArchive(body, ARM64)
			validArchive = validErr == nil
		}
		if !ok || !strings.HasSuffix(asset.Name, ".tar.gz") || int64(len(body)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 || attested[asset.Name] != asset.SHA256 || !validArchive {
			return VerifiedRelease{}, nil, errors.New("asset disagreement")
		}
		proofs = append(proofs, AssetProof{Role: asset.Role, Name: asset.Name, Size: asset.Size, SHA256: asset.SHA256})
	}
	if !seenRoles[ApplicationAMD64] || !seenRoles[ApplicationARM64] || !seenRoles[ComponentsAMD64] || !seenRoles[ComponentsARM64] {
		return VerifiedRelease{}, nil, errors.New("role refused")
	}
	if index.StateSchema > 1 && migrationProofs != 2 {
		return VerifiedRelease{}, nil, errors.New("migration path refused")
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].Role < proofs[j].Role })
	return VerifiedRelease{
		Identity: ReleaseIdentity{Repository: Repository, Tag: requestedTag, Commit: evidence.Commit, IndexSHA256: hex.EncodeToString(indexDigest[:])},
		Version:  index.Version, Sequence: index.Sequence, StateSchema: index.StateSchema, MinimumUpdaterSchema: index.MinimumUpdaterSchema,
		VerifiedAt: at, Assets: proofs, Migrations: migrations,
	}, downloads, nil
}

func componentsForArchitecture(architecture Architecture) (Component, Component) {
	switch architecture {
	case AMD64:
		return ApplicationAMD64, ComponentsAMD64
	case ARM64:
		return ApplicationARM64, ComponentsARM64
	default:
		return "", ""
	}
}

func selectedArchive(release VerifiedRelease, archives map[string][]byte, component Component) (AssetProof, []byte, bool) {
	for _, asset := range release.Assets {
		if asset.Role == component {
			archive, ok := archives[asset.Name]
			return asset, archive, ok
		}
	}
	return AssetProof{}, nil, false
}

func oneExecutableArchive(body []byte) bool {
	_, ok := executableArchiveBytes(body)
	return ok
}

func executableArchiveBytes(body []byte) ([]byte, bool) {
	input := bytes.NewReader(body)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return nil, false
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, MaxAssetBytes+1))
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > MaxAssetBytes || header.Mode != 0o755 {
		return nil, false
	}
	executable, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(executable)) != header.Size {
		return nil, false
	}
	if _, err := archive.Next(); err != io.EOF {
		return nil, false
	}
	remaining, err := io.Copy(io.Discard, compressed)
	if err != nil || remaining != 0 || compressed.Close() != nil || input.Len() != 0 {
		return nil, false
	}
	return executable, true
}

func safeName(value string) bool {
	return namePattern.MatchString(value) && value != "." && value != ".." && !strings.HasSuffix(strings.ToLower(value), ".zip")
}

func exactNames(verified []string, attested map[string]string) bool {
	if len(verified) != len(attested) {
		return false
	}
	seen := make(map[string]bool, len(verified))
	for _, name := range verified {
		if seen[name] || attested[name] == "" {
			return false
		}
		seen[name] = true
	}
	return true
}

func migrationSummary(release VerifiedRelease) string {
	summary := "State schema " + strconv.FormatUint(release.StateSchema, 10) + "; minimum updater schema " + strconv.FormatUint(release.MinimumUpdaterSchema, 10)
	if len(release.Migrations) > 0 {
		summary += "; complete migration path 1 -> " + strconv.FormatUint(release.StateSchema, 10)
	}
	return summary
}

// ValidateUniqueJSON rejects duplicate object keys at every nesting level.
// The GitHub Adapter uses the same rule for the signed release statement.
func ValidateUniqueJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON key")
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
