package softwarelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

type LatestAssetProof struct {
	Name   string
	Size   int64
	SHA256 string
}

type latestReleaseIndex struct {
	Schema     int                `json:"schema"`
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Commit     string             `json:"commit"`
	Sequence   uint64             `json:"sequence"`
	Assets     []LatestAssetProof `json:"assets"`
}

func VerifyLatestReleaseIndex(repository, tag, commit string, index []byte, proofs []LatestAssetProof) (LatestRelease, bool) {
	if repository != Repository || !immutableReleaseTag.MatchString(tag) || !commitPattern.MatchString(commit) || len(index) == 0 || len(index) > MaxIndexBytes || ValidateUniqueJSON(index) != nil {
		return LatestRelease{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(index))
	decoder.DisallowUnknownFields()
	var document latestReleaseIndex
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != 1 || document.Repository != repository || document.Tag != tag || document.Commit != commit || document.Sequence == 0 || len(document.Assets) != 3 || len(proofs) != 4 {
		return LatestRelease{}, false
	}
	expected := []string{"install.sh", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}
	byName := make(map[string]LatestAssetProof, len(proofs))
	for _, proof := range proofs {
		if byName[proof.Name].Name != "" || proof.Size <= 0 || !hashPattern.MatchString(proof.SHA256) {
			return LatestRelease{}, false
		}
		byName[proof.Name] = proof
	}
	indexDigest := sha256.Sum256(index)
	indexSHA256 := hex.EncodeToString(indexDigest[:])
	if proof := byName["release-index.json"]; proof.Name == "" || proof.Size != int64(len(index)) || proof.SHA256 != indexSHA256 || len(byName) != 4 {
		return LatestRelease{}, false
	}
	for position, asset := range document.Assets {
		proof := byName[asset.Name]
		limit := int64(MaxAssetBytes)
		if asset.Name == "install.sh" {
			limit = MaxIndexBytes
		}
		if asset.Name != expected[position] || asset.Size <= 0 || asset.Size > limit || !hashPattern.MatchString(asset.SHA256) || proof != asset {
			return LatestRelease{}, false
		}
	}
	return LatestRelease{Identity: ReleaseIdentity{Repository: repository, Tag: tag, Commit: commit, IndexSHA256: indexSHA256}, Sequence: document.Sequence}, true
}
