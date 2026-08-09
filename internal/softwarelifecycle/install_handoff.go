package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// InstallCandidateHandoff carries only the already-reviewed selected payload
// bytes to the verified root child for independent staging without network I/O.
type InstallCandidateHandoff struct {
	Verified           VerifiedRelease `json:"verified"`
	Staged             StagedRelease   `json:"staged"`
	ApplicationAsset   AssetProof      `json:"application_asset"`
	ComponentAsset     AssetProof      `json:"component_asset"`
	ApplicationArchive []byte          `json:"application_archive"`
	ComponentArchive   []byte          `json:"component_archive"`
}

func (InstallCandidateHandoff) String() string {
	return "verified install candidate handoff: protected"
}
func (InstallCandidateHandoff) GoString() string {
	return "verified install candidate handoff: protected"
}

func (handoff InstallCandidateHandoff) Valid() bool {
	if !validInstalled(handoff.Verified) || handoff.Staged.Identity != handoff.Verified.Identity || handoff.Staged.Architecture != AMD64 && handoff.Staged.Architecture != ARM64 {
		return false
	}
	applicationRole, componentRole := componentsForArchitecture(handoff.Staged.Architecture)
	application, applicationOK := installHandoffAsset(handoff.Verified.Assets, applicationRole)
	component, componentOK := installHandoffAsset(handoff.Verified.Assets, componentRole)
	request := newStageRequest(handoff.Verified, handoff.Staged.Architecture, application, handoff.ApplicationArchive, component, handoff.ComponentArchive)
	return applicationOK && componentOK && application == handoff.ApplicationAsset && component == handoff.ComponentAsset && assetBytesMatch(application, handoff.ApplicationArchive) && assetBytesMatch(component, handoff.ComponentArchive) && validStagedRelease(handoff.Staged, request)
}

func (candidate InstallCandidate) InstallHandoff() (InstallCandidateHandoff, bool) {
	if !validInstallCandidate(candidate) || !validInstalled(candidate.cell.verified) {
		return InstallCandidateHandoff{}, false
	}
	applicationRole, componentRole := componentsForArchitecture(candidate.cell.staged.Architecture)
	application, applicationOK := installHandoffAsset(candidate.cell.verified.Assets, applicationRole)
	component, componentOK := installHandoffAsset(candidate.cell.verified.Assets, componentRole)
	if !applicationOK || !componentOK || !assetBytesMatch(application, candidate.cell.archive) || !assetBytesMatch(component, candidate.cell.components) {
		return InstallCandidateHandoff{}, false
	}
	return InstallCandidateHandoff{
		Verified: candidate.cell.verified, Staged: candidate.cell.staged, ApplicationAsset: application, ComponentAsset: component,
		ApplicationArchive: append([]byte(nil), candidate.cell.archive...), ComponentArchive: append([]byte(nil), candidate.cell.components...),
	}, true
}

func RebuildInstallCandidate(ctx context.Context, handoff InstallCandidateHandoff, stager ReleaseStager) (InstallCandidate, error) {
	if ctx == nil || stager == nil || !handoff.Valid() {
		return InstallCandidate{}, errors.New("install candidate handoff refused")
	}
	applicationRole, componentRole := componentsForArchitecture(handoff.Staged.Architecture)
	application, applicationOK := installHandoffAsset(handoff.Verified.Assets, applicationRole)
	component, componentOK := installHandoffAsset(handoff.Verified.Assets, componentRole)
	if !applicationOK || !componentOK || application != handoff.ApplicationAsset || component != handoff.ComponentAsset {
		return InstallCandidate{}, errors.New("install candidate bytes changed")
	}
	request := newStageRequest(handoff.Verified, handoff.Staged.Architecture, application, handoff.ApplicationArchive, component, handoff.ComponentArchive)
	staged, err := stager.Stage(ctx, request)
	if err != nil || staged != handoff.Staged || !validStagedRelease(staged, request) {
		return InstallCandidate{}, errors.New("install candidate staging refused")
	}
	return InstallCandidate{cell: &installCandidateCell{verified: handoff.Verified, staged: staged, archive: append([]byte(nil), handoff.ApplicationArchive...), components: append([]byte(nil), handoff.ComponentArchive...)}}, nil
}

func installHandoffAsset(assets []AssetProof, role Component) (AssetProof, bool) {
	var result AssetProof
	for _, asset := range assets {
		if asset.Role != role {
			continue
		}
		if result.Role != "" {
			return AssetProof{}, false
		}
		result = asset
	}
	return result, result.Role == role && safeName(result.Name) && result.Size > 0 && result.Size <= MaxAssetBytes && hashPattern.MatchString(result.SHA256)
}

func assetBytesMatch(asset AssetProof, body []byte) bool {
	if int64(len(body)) != asset.Size {
		return false
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]) == asset.SHA256
}
