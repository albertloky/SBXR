package softwarelifecycle

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var ErrCandidateNotFound = errors.New("verified update candidate not found")

var immutableReleaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type InputGuidance struct {
	Purpose, AcceptedFormat, Recovery, Example, URL string
	Instructions, CommonMistakes                    []string
}

func DowngradeInputGuidance() InputGuidance {
	return InputGuidance{
		Purpose:        "Select one older compatible SBXR release.",
		Instructions:   []string{"Open official SBXR Releases and copy one immutable tag; SBXR refuses unproved compatibility."},
		AcceptedFormat: "One exact immutable vX.Y.Z tag with no spaces or suffix.",
		CommonMistakes: []string{"vX.Y.Z is tutorial only; malformed, current, newer, incompatible, branch, commit, URL, or prerelease values are refused."},
		Recovery:       "Choose another official tag; no Plan or host change exists until compatibility passes.",
		Example:        "vX.Y.Z",
		URL:            "https://github.com/albertloky/SBXR/releases",
	}
}

func ValidDowngradeTag(tag string) bool { return immutableReleaseTag.MatchString(tag) }

type ReleaseListing struct {
	Tag        string
	Draft      bool
	Prerelease bool
}

type ReleaseDiscovery interface {
	Discover(context.Context, string) (ReleaseListing, error)
}

type UpdateDiscovery struct {
	reviewedTag string
	reviewed    bool
}

func StableUpdateDiscovery() UpdateDiscovery { return UpdateDiscovery{reviewed: true} }

func ReviewedAlternateUpdateDiscovery(tag string) (UpdateDiscovery, error) {
	if !safeTag(tag) {
		return UpdateDiscovery{}, errors.New("reviewed alternate release refused")
	}
	return UpdateDiscovery{reviewedTag: tag, reviewed: true}, nil
}

func (selection UpdateDiscovery) valid() bool {
	return selection.reviewed && (selection.reviewedTag == "" || safeTag(selection.reviewedTag))
}

type CandidateRecord struct {
	Sequence   uint64
	Evidence   ReleaseEvidence
	VerifiedAt time.Time
}

type CandidateStore interface {
	Load() (CandidateRecord, error)
	RetainNewest(CandidateRecord) error
}

func (module Interface) discoverUpdate(ctx context.Context, request ViewRequest, result ViewResult) ViewResult {
	if module.discovery == nil || module.candidates == nil {
		return refuse(result)
	}
	retained, retainedOK, err := module.loadCandidate()
	if err != nil {
		return refuse(result)
	}
	listing, err := module.discovery.Discover(ctx, request.UpdateDiscovery.reviewedTag)
	if err != nil {
		if retainedOK && eligibleUpdate(*request.Installed, retained) {
			return reportUpdate(result, retained)
		}
		return refuse(result)
	}
	if !safeTag(listing.Tag) || listing.Draft || request.UpdateDiscovery.reviewedTag == "" && listing.Prerelease || request.UpdateDiscovery.reviewedTag != "" && listing.Tag != request.UpdateDiscovery.reviewedTag {
		if retainedOK && eligibleUpdate(*request.Installed, retained) {
			return reportUpdate(result, retained)
		}
		return result
	}
	evidence, err := module.source.Verify(ctx, listing.Tag)
	if err != nil {
		if retainedOK && eligibleUpdate(*request.Installed, retained) {
			return reportUpdate(result, retained)
		}
		return refuse(result)
	}
	at := module.now().UTC()
	candidate, _, err := verify(evidence, listing.Tag, module.qualification, at)
	if err != nil || !eligibleUpdate(*request.Installed, candidate) {
		if retainedOK && eligibleUpdate(*request.Installed, retained) {
			return reportUpdate(result, retained)
		}
		return result
	}
	if module.candidates.RetainNewest(CandidateRecord{Sequence: candidate.Sequence, Evidence: cloneReleaseEvidence(evidence), VerifiedAt: at}) != nil {
		return refuse(result)
	}
	newest, newestOK, err := module.loadCandidate()
	if err != nil || !newestOK || !eligibleUpdate(*request.Installed, newest) {
		return refuse(result)
	}
	return reportUpdate(result, newest)
}

func (module Interface) loadCandidate() (VerifiedRelease, bool, error) {
	record, err := module.candidates.Load()
	if errors.Is(err, ErrCandidateNotFound) {
		return VerifiedRelease{}, false, nil
	}
	if err != nil || record.Sequence == 0 || record.VerifiedAt.IsZero() || record.VerifiedAt.Location() != time.UTC {
		return VerifiedRelease{}, false, errors.New("retained candidate unavailable")
	}
	candidate, _, verifyErr := verify(record.Evidence, record.Evidence.Tag, module.qualification, record.VerifiedAt)
	if verifyErr != nil || candidate.Sequence != record.Sequence {
		return VerifiedRelease{}, false, errors.New("retained candidate refused")
	}
	return candidate, true, nil
}

func eligibleUpdate(installed, candidate VerifiedRelease) bool {
	return validInstalled(installed) && installed.Identity.Tag != "v1.0.6" && validInstalled(candidate) && candidate.Identity != installed.Identity && candidate.Sequence > installed.Sequence && candidate.MinimumUpdaterSchema <= 1 && compatibleStateSchemas(installed.StateSchema, candidate)
}

func eligibleDowngrade(installed, candidate VerifiedRelease) bool {
	return validInstalled(installed) && validInstalled(candidate) && ValidDowngradeTag(candidate.Identity.Tag) && candidate.Identity != installed.Identity && candidate.Sequence < installed.Sequence && candidate.MinimumUpdaterSchema <= 1 && candidate.StateSchema == 2 && candidate.StateSchema == installed.StateSchema
}

func compatibleStateSchemas(installed uint64, candidate VerifiedRelease) bool {
	if candidate.StateSchema == installed {
		return true
	}
	if installed == 0 || candidate.StateSchema <= installed || len(candidate.Migrations) != int(candidate.StateSchema-1) {
		return false
	}
	for schema := installed; schema < candidate.StateSchema; schema++ {
		migration := candidate.Migrations[schema-1]
		if migration.From != schema || migration.To != schema+1 || migration.NetworkAccess || len(migration.Document) == 0 {
			return false
		}
	}
	return true
}

func reportUpdate(result ViewResult, candidate VerifiedRelease) ViewResult {
	result.VerifiedCandidate = &candidate
	result.MigrationSummary = migrationSummary(candidate)
	result.UpdateEligible = true
	result.AffectedComponents = []Component{ApplicationAMD64, ApplicationARM64, ComponentsAMD64, ComponentsARM64}
	result.PermittedActions = []Action{ReviewUpdate}
	return result
}

func cloneReleaseEvidence(value ReleaseEvidence) ReleaseEvidence {
	result := value
	result.Index = append([]byte(nil), value.Index...)
	result.Assets = make([]DownloadedAsset, len(value.Assets))
	for index, asset := range value.Assets {
		result.Assets[index] = DownloadedAsset{Name: asset.Name, Bytes: append([]byte(nil), asset.Bytes...)}
	}
	result.AttestedAssets = append([]AttestedAsset(nil), value.AttestedAssets...)
	result.Verifier.VerifiedAssets = append([]string(nil), value.Verifier.VerifiedAssets...)
	return result
}

func cloneMigrations(value []EmbeddedMigration) []EmbeddedMigration {
	result := make([]EmbeddedMigration, len(value))
	for index, migration := range value {
		result[index] = migration
		result[index].Document = append([]byte(nil), migration.Document...)
	}
	return result
}
