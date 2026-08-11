package softwarelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type ReleaseIndexAsset struct {
	Role  Component
	Name  string
	Bytes []byte
}

type ReleaseIndexRequest struct {
	Version              string
	Sequence             uint64
	Tag, Commit          string
	StateSchema          uint64
	MinimumUpdaterSchema uint64
	Assets               []ReleaseIndexAsset
}

func BuildReleaseIndex(request ReleaseIndexRequest) ([]byte, error) {
	if !versionPattern.MatchString(request.Version) || request.Tag != "v"+request.Version || !commitPattern.MatchString(request.Commit) || request.Sequence == 0 || request.StateSchema == 0 || request.MinimumUpdaterSchema == 0 || request.MinimumUpdaterSchema > request.StateSchema || len(request.Assets) != 4 {
		return nil, errors.New("release index refused")
	}
	assets := make(map[Component]ReleaseIndexAsset, len(request.Assets))
	for _, asset := range request.Assets {
		if _, duplicate := assets[asset.Role]; duplicate || len(asset.Bytes) == 0 || len(asset.Bytes) > MaxAssetBytes {
			return nil, errors.New("release index asset refused")
		}
		assets[asset.Role] = asset
	}
	index := releaseIndex{Schema: 1, Product: "sbxr", Repository: Repository, Version: request.Version, Sequence: request.Sequence, Tag: request.Tag, Commit: request.Commit, StateSchema: request.StateSchema, MinimumUpdaterSchema: request.MinimumUpdaterSchema}
	for _, expected := range []struct {
		role Component
		name string
	}{{ApplicationAMD64, "sbxr-linux-amd64.tar.gz"}, {ApplicationARM64, "sbxr-linux-arm64.tar.gz"}, {ComponentsAMD64, "sbxr-components-linux-amd64.tar.gz"}, {ComponentsARM64, "sbxr-components-linux-arm64.tar.gz"}} {
		asset, ok := assets[expected.role]
		if !ok || asset.Name != expected.name {
			return nil, errors.New("release index role refused")
		}
		digest := sha256.Sum256(asset.Bytes)
		index.Assets = append(index.Assets, indexAsset{Role: expected.role, Name: expected.name, Size: int64(len(asset.Bytes)), SHA256: hex.EncodeToString(digest[:])})
	}
	return json.Marshal(index)
}
