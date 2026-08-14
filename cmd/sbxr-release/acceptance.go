package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
)

type acceptanceOptions struct {
	tag, commit, directory, output, evidenceURL string
	afterAssetRead                              func(string)
}

type acceptanceIndex struct {
	Schema               uint64                 `json:"schema"`
	Product              string                 `json:"product"`
	Repository           string                 `json:"repository"`
	Version              string                 `json:"version"`
	Sequence             uint64                 `json:"sequence"`
	Tag                  string                 `json:"tag"`
	Commit               string                 `json:"commit"`
	StateSchema          uint64                 `json:"state_schema"`
	MinimumUpdaterSchema uint64                 `json:"minimum_updater_schema"`
	Assets               []acceptanceIndexAsset `json:"assets"`
}

type acceptanceIndexAsset struct {
	Role   string `json:"role"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type acceptanceAsset struct {
	Size   int64
	SHA256 string
}

var (
	acceptanceCommit      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	acceptanceHash        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	acceptanceEvidenceURL = regexp.MustCompile(`^https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*$`)
)

func writeAutomatedAcceptanceRecord(options acceptanceOptions, recordedAt time.Time) error {
	if options.directory == "" || options.output == "" || !acceptanceCommit.MatchString(options.commit) || !acceptanceEvidenceURL.MatchString(options.evidenceURL) || recordedAt.IsZero() {
		return errors.New("acceptance record refused")
	}
	rootPath, rootErr := filepath.Abs(options.directory)
	outputPath, outputErr := filepath.Abs(options.output)
	relative, relativeErr := filepath.Rel(rootPath, outputPath)
	if rootErr != nil || outputErr != nil || relativeErr != nil || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("acceptance record location refused")
	}
	root, err := os.OpenRoot(options.directory)
	if err != nil {
		return errors.New("acceptance assets unavailable")
	}
	defer root.Close()
	names := []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz"}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != len(names) {
		return errors.New("acceptance asset set refused")
	}
	assets := make(map[string]acceptanceAsset, len(names))
	identities := make(map[string]fs.FileInfo, len(names))
	var indexBody []byte
	for _, name := range names {
		limit := int64(softwarelifecycle.MaxAssetBytes)
		if name == "release-index.json" {
			limit = softwarelifecycle.MaxIndexBytes
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
			return errors.New("acceptance asset refused")
		}
		file, err := root.Open(name)
		if err != nil {
			return errors.New("acceptance asset unavailable")
		}
		opened, statErr := file.Stat()
		var body bytes.Buffer
		hash := sha256.New()
		destination := io.Writer(hash)
		if name == "release-index.json" {
			destination = io.MultiWriter(hash, &body)
		}
		read, readErr := io.Copy(destination, io.LimitReader(file, limit+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		pathAfter, pathErr := root.Lstat(name)
		if statErr != nil || readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || !unchangedFile(info, opened) || !unchangedFile(opened, after) || !unchangedFile(opened, pathAfter) || read != info.Size() {
			return errors.New("acceptance asset changed")
		}
		assets[name] = acceptanceAsset{Size: read, SHA256: hex.EncodeToString(hash.Sum(nil))}
		identities[name] = opened
		if name == "release-index.json" {
			indexBody = body.Bytes()
		}
		if options.afterAssetRead != nil {
			options.afterAssetRead(name)
		}
	}
	entries, err = fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != len(names) {
		return errors.New("acceptance asset set changed")
	}
	for _, name := range names {
		current, statErr := root.Lstat(name)
		if statErr != nil || !unchangedFile(identities[name], current) {
			return errors.New("acceptance asset changed")
		}
	}
	index, err := decodeAcceptanceIndex(indexBody)
	if err != nil || index.Repository != softwarelifecycle.Repository || index.Tag != options.tag || index.Commit != options.commit {
		return errors.New("acceptance identity refused")
	}
	indexed := make(map[string]acceptanceIndexAsset, len(index.Assets))
	for _, asset := range index.Assets {
		indexed[asset.Name] = asset
	}
	for _, name := range names {
		if name == "release-index.json" {
			continue
		}
		asset, ok := indexed[name]
		if !ok || asset.Size != assets[name].Size || asset.SHA256 != assets[name].SHA256 {
			return errors.New("acceptance index agreement refused")
		}
	}
	var record strings.Builder
	fmt.Fprintln(&record, "# SBXR automated Acceptance Record")
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "Status: Qualified - root-runtime package policy")
	fmt.Fprintln(&record, "Repository:", softwarelifecycle.Repository)
	fmt.Fprintln(&record, "Tag:", index.Tag)
	fmt.Fprintln(&record, "Commit:", index.Commit)
	fmt.Fprintln(&record, "Release index SHA-256:", assets["release-index.json"].SHA256)
	fmt.Fprintln(&record, "Recorded at:", recordedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&record, "Runner: GitHub Actions ubuntu-24.04 %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(&record, "Go toolchain:", runtime.Version())
	fmt.Fprintf(&record, "Public verifier: %s %s\n", githubadapter.Version, githubadapter.SigningFingerprint)
	fmt.Fprintln(&record, "Stable result code: RELEASE-ROOT-RUNTIME-PACKAGE-QUALIFICATION")
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "| Stage | Status | Evidence |")
	fmt.Fprintln(&record, "|---|---|---|")
	fmt.Fprintln(&record, "| Module Verification | Passed | Package suites at the Pasteable Install Command and owning Module Interfaces |")
	fmt.Fprintln(&record, "| Seam Verification | Passed | Exact public HTTPS release verification, Sigstore attestations, and package seam checks |")
	fmt.Fprintln(&record, "| Integrated Verification | Passed | Package composition through existing product Interfaces |")
	fmt.Fprintln(&record, "| Codex Live Acceptance | Not required | ADR-0010 privilege and service-identity scope; no live VPS evidence claimed |")
	fmt.Fprintln(&record, "| Owner Acceptance | Not required | ADR-0010 privilege and service-identity scope; no maintained-client evidence claimed |")
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "Integrated Ubuntu Verification: Not required - ADR-0010 privilege and service-identity scope; no automated Ubuntu integration evidence claimed.")
	fmt.Fprintln(&record, "No Integrated Ubuntu Verification, live VPS, provider, maintained-client, or Owner evidence was performed.")
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "| Exact asset | Bytes | SHA-256 |")
	fmt.Fprintln(&record, "|---|---:|---|")
	for _, name := range names {
		fmt.Fprintf(&record, "| %s | %d | %s |\n", name, assets[name].Size, assets[name].SHA256)
	}
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "Workflow evidence:", options.evidenceURL)
	fmt.Fprintln(&record)
	fmt.Fprintln(&record, "Any asset, attestation, repository, tag, commit, release-index digest, qualification scope, required check, or client-facing change invalidates this record.")
	return writeExclusive(options.output, []byte(record.String()))
}

func decodeAcceptanceIndex(body []byte) (acceptanceIndex, error) {
	if softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return acceptanceIndex{}, errors.New("acceptance index refused")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var index acceptanceIndex
	if err := decoder.Decode(&index); err != nil || decoder.Decode(&struct{}{}) != io.EOF || index.Schema != 1 || index.Product != "sbxr" || index.Repository != softwarelifecycle.Repository || index.Version == "" || index.Tag != "v"+index.Version || index.Sequence == 0 || index.StateSchema == 0 || index.MinimumUpdaterSchema == 0 || index.MinimumUpdaterSchema > index.StateSchema || len(index.Assets) != 5 {
		return acceptanceIndex{}, errors.New("acceptance index refused")
	}
	expected := map[string]string{"application-linux-amd64": "sbxr-linux-amd64.tar.gz", "application-linux-arm64": "sbxr-linux-arm64.tar.gz", "components-linux-amd64": "sbxr-components-linux-amd64.tar.gz", "components-linux-arm64": "sbxr-components-linux-arm64.tar.gz", "bootstrap": "install.sh"}
	seen := make(map[string]bool, len(index.Assets))
	for _, asset := range index.Assets {
		if expected[asset.Role] != asset.Name || asset.Size <= 0 || !acceptanceHash.MatchString(asset.SHA256) || seen[asset.Name] {
			return acceptanceIndex{}, errors.New("acceptance index refused")
		}
		seen[asset.Name] = true
	}
	return index, nil
}
