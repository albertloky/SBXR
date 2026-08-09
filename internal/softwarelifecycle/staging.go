package softwarelifecycle

import (
	"context"
	"path/filepath"
)

type Architecture string

const (
	AMD64 Architecture = "amd64"
	ARM64 Architecture = "arm64"
)

type StageRequest struct {
	Release          VerifiedRelease
	Architecture     Architecture
	Asset            AssetProof
	Archive          []byte
	ComponentAsset   AssetProof
	ComponentArchive []byte
	authenticated    bool
}

func (request StageRequest) Authenticated() bool { return request.authenticated }

func newStageRequest(release VerifiedRelease, architecture Architecture, asset AssetProof, archive []byte, componentAsset AssetProof, componentArchive []byte) StageRequest {
	return StageRequest{Release: release, Architecture: architecture, Asset: asset, Archive: archive, ComponentAsset: componentAsset, ComponentArchive: componentArchive, authenticated: true}
}

type StagedRelease struct {
	Identity         ReleaseIdentity
	Build            EmbeddedBuildIdentity
	Architecture     Architecture
	ExecutableSHA256 string
	ComponentsSHA256 string
	InstallPath      string
	StateSchema      uint64
}

type ReleaseStager interface {
	Stage(context.Context, StageRequest) (StagedRelease, error)
}

func ReleaseInstallPath(identity ReleaseIdentity) string {
	return filepath.Join("/opt/sbxr/releases", identity.Tag+"-"+identity.Commit+"-"+identity.IndexSHA256, "sbxr")
}

func validStagedRelease(staged StagedRelease, request StageRequest) bool {
	return staged.Identity == request.Release.Identity && staged.Build.Repository == request.Release.Identity.Repository && staged.Build.Tag == request.Release.Identity.Tag && staged.Build.Commit == request.Release.Identity.Commit && hashPattern.MatchString(staged.Build.PayloadSHA256) && staged.Architecture == request.Architecture && hashPattern.MatchString(staged.ExecutableSHA256) && hashPattern.MatchString(staged.ComponentsSHA256) && staged.InstallPath == ReleaseInstallPath(request.Release.Identity) && staged.StateSchema == request.Release.StateSchema
}
