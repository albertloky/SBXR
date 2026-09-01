package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

var gatewayAssetNames = []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}

type gatewayManifest struct {
	Schema     string `json:"schema"`
	Repository string `json:"repository"`
	Releases   []struct {
		Tag      string `json:"tag"`
		Sequence uint64 `json:"sequence"`
		Commit   string `json:"commit"`
		Identity struct {
			Repository  string `json:"repository"`
			Tag         string `json:"tag"`
			Commit      string `json:"commit"`
			IndexSHA256 string `json:"release_index_sha256"`
		} `json:"release_identity"`
		Assets []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"assets"`
	} `json:"releases"`
}

type gatewayAsset struct {
	name, digest string
	size         int64
	file         *os.File
	identity     fs.FileInfo
}

type gatewayRelease struct {
	tag, commit string
	sequence    uint64
	assets      map[string]*gatewayAsset
}

type qualificationGateway struct {
	manifest json.RawMessage
	bundle   json.RawMessage
	releases []gatewayRelease
	control  string
}

func runQualificationGateway(options gatewayOptions) error {
	if options.manifest == "" || options.bundle == "" || options.assets == "" || options.certificate == "" || options.key == "" || options.listen == "" {
		return errors.New("qualification gateway refused")
	}
	manifest, err := os.ReadFile(options.manifest)
	if err != nil {
		return err
	}
	bundle, err := os.ReadFile(options.bundle)
	if err != nil {
		return err
	}
	gateway, err := newQualificationGateway(manifest, bundle, options.assets)
	if err != nil {
		return err
	}
	defer gateway.close()
	gateway.control = options.control
	server := &http.Server{Addr: options.listen, Handler: gateway, ReadHeaderTimeout: 10 * time.Second}
	return server.ListenAndServeTLS(options.certificate, options.key)
}

func newQualificationGateway(manifest, bundle json.RawMessage, assetRoot string) (*qualificationGateway, error) {
	if len(manifest) == 0 || len(manifest) > 1<<20 || len(bundle) == 0 || len(bundle) > 8<<20 || softwarelifecycle.ValidateUniqueJSON(manifest) != nil || softwarelifecycle.ValidateUniqueJSON(bundle) != nil {
		return nil, errors.New("qualification authority refused")
	}
	var document gatewayManifest
	if json.Unmarshal(manifest, &document) != nil || document.Repository != softwarelifecycle.Repository || len(document.Releases) < 1 || len(document.Releases) > 2 || document.Releases[0].Sequence == 0 || len(document.Releases) == 2 && (document.Releases[0].Tag == document.Releases[1].Tag || document.Releases[1].Sequence <= document.Releases[0].Sequence) {
		return nil, errors.New("qualification manifest refused")
	}
	if document.Schema != "sbxr-qualification-manifest-v1" {
		var scoped qualificationManifest
		decoder := json.NewDecoder(bytes.NewReader(manifest))
		decoder.DisallowUnknownFields()
		if document.Schema != "sbxr-qualification-manifest-v3" || decoder.Decode(&scoped) != nil || decoder.Decode(&struct{}{}) != io.EOF || scoped.SourceState != "v3-subscription-clean" || !validStableFailureManifest(scoped) {
			return nil, errors.New("qualification manifest refused")
		}
	}
	gateway := &qualificationGateway{manifest: append(json.RawMessage(nil), manifest...), bundle: append(json.RawMessage(nil), bundle...), releases: make([]gatewayRelease, len(document.Releases))}
	for index, release := range document.Releases {
		if !validTag(release.Tag) || !validCommit(release.Commit) || release.Identity.Repository != softwarelifecycle.Repository || release.Identity.Tag != release.Tag || release.Identity.Commit != release.Commit || !validSHA256(release.Identity.IndexSHA256) || len(release.Assets) != len(gatewayAssetNames) {
			gateway.close()
			return nil, errors.New("qualification release refused")
		}
		names := make([]string, 0, len(release.Assets))
		bound := gatewayRelease{tag: release.Tag, commit: release.Commit, sequence: release.Sequence, assets: map[string]*gatewayAsset{}}
		for _, asset := range release.Assets {
			names = append(names, asset.Name)
			if !validSHA256(asset.SHA256) || asset.Size <= 0 || asset.Size > gatewayAssetLimit(asset.Name) || bound.assets[asset.Name] != nil {
				gateway.close()
				return nil, errors.New("qualification asset refused")
			}
			file, err := os.Open(path.Join(assetRoot, release.Tag, asset.Name))
			if err != nil {
				gateway.close()
				return nil, err
			}
			identity, statErr := file.Stat()
			digest := sha256.New()
			copied, copyErr := io.Copy(digest, file)
			_, seekErr := file.Seek(0, io.SeekStart)
			if statErr != nil || !identity.Mode().IsRegular() || copied != asset.Size || identity.Size() != asset.Size || copyErr != nil || seekErr != nil || hex.EncodeToString(digest.Sum(nil)) != asset.SHA256 {
				_ = file.Close()
				gateway.close()
				return nil, errors.New("qualification asset changed")
			}
			bound.assets[asset.Name] = &gatewayAsset{name: asset.Name, digest: asset.SHA256, size: asset.Size, file: file, identity: identity}
		}
		slices.Sort(names)
		if !slices.Equal(names, gatewayAssetNames) || bound.assets["release-index.json"].digest != release.Identity.IndexSHA256 {
			gateway.close()
			return nil, errors.New("qualification asset set refused")
		}
		gateway.releases[index] = bound
	}
	return gateway, nil
}

func (gateway *qualificationGateway) close() {
	if gateway == nil {
		return
	}
	for _, release := range gateway.releases {
		for _, asset := range release.assets {
			_ = asset.file.Close()
		}
	}
}

func (gateway *qualificationGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	host := request.Host
	if name, ok := strings.CutSuffix(host, ":443"); ok {
		host = name
	}
	if host == "github.com" {
		if request.URL.Path == "/"+softwarelifecycle.Repository+"/releases/latest/download/install.sh" {
			gateway.serveAsset(response, gateway.installRelease().assets["install.sh"])
			return
		}
		for _, release := range gateway.releases {
			prefix := "/" + softwarelifecycle.Repository + "/releases/download/" + release.tag + "/"
			if strings.HasPrefix(request.URL.Path, prefix) {
				gateway.serveAsset(response, release.assets[strings.TrimPrefix(request.URL.Path, prefix)])
				return
			}
		}
	} else if host == "api.github.com" {
		if request.URL.Path == "/repos/"+softwarelifecycle.Repository+"/releases/latest" {
			gateway.waitForLatestRelease()
			gateway.serveLatest(response)
			return
		}
		prefix := "/repos/" + softwarelifecycle.Repository + "/releases/assets/"
		if strings.HasPrefix(request.URL.Path, prefix) {
			id := strings.TrimPrefix(request.URL.Path, prefix)
			if len(id) == 1 && id[0] >= '1' && id[0] <= '4' {
				gateway.serveAsset(response, gateway.releases[len(gateway.releases)-1].assets[gatewayAssetNames[id[0]-'1']])
				return
			}
		}
	}
	response.WriteHeader(http.StatusNotFound)
}

func (gateway *qualificationGateway) installRelease() gatewayRelease {
	if gateway.control != "" {
		if selected, err := os.ReadFile(path.Join(gateway.control, "install-tag")); err == nil {
			tag := strings.TrimSpace(string(selected))
			for _, release := range gateway.releases {
				if release.tag == tag {
					return release
				}
			}
		}
	}
	return gateway.releases[0]
}

func (gateway *qualificationGateway) waitForLatestRelease() {
	if gateway.control == "" {
		return
	}
	_ = os.WriteFile(path.Join(gateway.control, "latest-requested"), []byte("requested\n"), 0o600)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path.Join(gateway.control, "hold-latest")); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (gateway *qualificationGateway) serveLatest(response http.ResponseWriter) {
	release := gateway.releases[len(gateway.releases)-1]
	assets := make([]map[string]any, 0, len(gatewayAssetNames))
	for index, name := range gatewayAssetNames {
		asset := release.assets[name]
		assets = append(assets, map[string]any{"name": name, "size": asset.size, "digest": "sha256:" + asset.digest, "state": "uploaded", "url": "https://api.github.com/repos/" + softwarelifecycle.Repository + "/releases/assets/" + string(rune('1'+index))})
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"tag_name": release.tag, "target_commitish": release.commit, "body": "", "draft": false, "prerelease": false, "immutable": true, "assets": assets,
		"sbxr_qualification": map[string]any{"manifest": []byte(gateway.manifest), "bundle": []byte(gateway.bundle)},
	})
}

func (gateway *qualificationGateway) serveAsset(response http.ResponseWriter, asset *gatewayAsset) {
	if asset == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	before, err := asset.file.Stat()
	if err != nil || !os.SameFile(asset.identity, before) || before.Mode() != asset.identity.Mode() || before.Size() != asset.size || before.ModTime() != asset.identity.ModTime() {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(io.NewSectionReader(asset.file, 0, asset.size))
	after, statErr := asset.file.Stat()
	digest := sha256.Sum256(body)
	if err != nil || statErr != nil || int64(len(body)) != asset.size || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hex.EncodeToString(digest[:]) != asset.digest {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.FormatInt(asset.size, 10))
	_, _ = response.Write(body)
}

func gatewayAssetLimit(name string) int64 {
	if name == "install.sh" || name == "release-index.json" {
		return softwarelifecycle.MaxIndexBytes
	}
	return softwarelifecycle.MaxAssetBytes
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
