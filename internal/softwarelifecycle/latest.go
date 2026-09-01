package softwarelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

type LatestAssetProof struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type latestReleaseIndex struct {
	Schema     int                `json:"schema"`
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Commit     string             `json:"commit"`
	Sequence   uint64             `json:"sequence"`
	Assets     []LatestAssetProof `json:"assets"`
	Support    *ReleaseSupport    `json:"support,omitempty"`
}

var latestIndexedAssetNames = []string{"install.sh", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}

func LatestReleaseIndexedAssetNames() []string {
	return append([]string(nil), latestIndexedAssetNames...)
}

func LatestReleaseAssetNames() []string {
	names := make([]string, 0, len(latestIndexedAssetNames)+1)
	for _, name := range latestIndexedAssetNames {
		names = append(names, name)
		if name == "install.sh" {
			names = append(names, "release-index.json")
		}
	}
	return names
}

// BuildLatestReleaseIndex creates the strict index consumed by VerifyLatestReleaseIndex.
func BuildLatestReleaseIndex(tag, commit string, sequence uint64, assets []LatestAssetProof) ([]byte, error) {
	if !immutableReleaseTag.MatchString(tag) || !commitPattern.MatchString(commit) || sequence == 0 || len(assets) != 3 {
		return nil, io.ErrUnexpectedEOF
	}
	expected := LatestReleaseIndexedAssetNames()
	for index, asset := range assets {
		limit := int64(MaxAssetBytes)
		if asset.Name == "install.sh" {
			limit = MaxIndexBytes
		}
		if asset.Name != expected[index] || asset.Size <= 0 || asset.Size > limit || !hashPattern.MatchString(asset.SHA256) {
			return nil, io.ErrUnexpectedEOF
		}
	}
	document := latestReleaseIndex{Schema: 1, Repository: Repository, Tag: tag, Commit: commit, Sequence: sequence, Assets: assets}
	body, err := json.Marshal(document)
	if err != nil || len(body) == 0 || len(body) > MaxIndexBytes {
		return nil, io.ErrUnexpectedEOF
	}
	return body, nil
}

func VerifyLatestReleaseIndex(repository, tag, commit string, index []byte, proofs []LatestAssetProof) (LatestRelease, bool) {
	if repository != Repository || !immutableReleaseTag.MatchString(tag) || !commitPattern.MatchString(commit) || len(index) == 0 || len(index) > MaxIndexBytes || ValidateUniqueJSON(index) != nil {
		return LatestRelease{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(index))
	decoder.DisallowUnknownFields()
	var document latestReleaseIndex
	var fields map[string]json.RawMessage
	if json.Unmarshal(index, &fields) != nil {
		return LatestRelease{}, false
	}
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || (document.Schema != 1 && document.Schema != 2) || (document.Schema == 1 && (document.Support != nil || len(fields) != 6)) || (document.Schema == 2 && !document.Support.valid()) || document.Repository != repository || document.Tag != tag || document.Commit != commit || document.Sequence == 0 || len(document.Assets) != 3 || len(proofs) != 4 {
		return LatestRelease{}, false
	}
	expected := LatestReleaseIndexedAssetNames()
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
	return LatestRelease{Identity: ReleaseIdentity{Repository: repository, Tag: tag, Commit: commit, IndexSHA256: indexSHA256}, Sequence: document.Sequence, Support: document.Support}, true
}
