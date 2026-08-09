// Package github supplies Software Lifecycle's official GitHub CLI release seam.
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	Version            = "2.97.0"
	SigningFingerprint = "7F38BBB59D064DBCB3D84D725612B36462313325"
	amd64BinarySHA256  = "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
	arm64BinarySHA256  = "ccbb0f14178faefac1cb0f336a853071fa63a1d0df23ef5ab7a304fe3859e082"
)

type CommandRunner func(context.Context, string, []string, int64) ([]byte, error)

type Source struct {
	run CommandRunner
}

func New() Source {
	return NewWithRunner(func(ctx context.Context, name string, arguments []string, limit int64) ([]byte, error) {
		command := exec.CommandContext(ctx, name, arguments...)
		command.Env = []string{"GH_REPO=" + softwarelifecycle.Repository, "NO_COLOR=1"}
		for _, variable := range []string{"HOME", "XDG_CONFIG_HOME", "GH_CONFIG_DIR"} {
			if value := os.Getenv(variable); value != "" {
				command.Env = append(command.Env, variable+"="+value)
			}
		}
		output, err := command.StdoutPipe()
		if err != nil || command.Start() != nil {
			return nil, errors.New("command start failed")
		}
		body, readErr := io.ReadAll(io.LimitReader(output, limit+1))
		if readErr != nil || int64(len(body)) > limit {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, errors.New("command output limit exceeded")
		}
		if command.Wait() != nil {
			return nil, errors.New("command failed")
		}
		return body, nil
	})
}

// NewWithRunner replaces only the external command boundary for Seam Verification.
func NewWithRunner(runner CommandRunner) Source {
	return Source{run: runner}
}

func (source Source) Verify(ctx context.Context, tag string) (softwarelifecycle.ReleaseEvidence, error) {
	if source.run == nil || !safeTag(tag) {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub verifier unavailable")
	}
	if source.qualifyDistribution(ctx) != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub verifier qualification failed")
	}
	releaseOutput, err := source.run(ctx, "/usr/bin/gh", []string{"release", "verify", tag, "--repo", softwarelifecycle.Repository, "--format", "json"}, 8<<20)
	if err != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release verification failed")
	}
	repository, attestedTag, commit, attested, err := parseReleaseVerification(releaseOutput)
	if err != nil || repository != softwarelifecycle.Repository || attestedTag != tag || len(attested) != 5 {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub release attestation refused")
	}
	sort.Slice(attested, func(i, j int) bool { return attested[i].Name < attested[j].Name })
	directory, err := os.MkdirTemp("", "sbxr-release-")
	if err != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("release staging unavailable")
	}
	defer os.RemoveAll(directory)
	if os.Chmod(directory, 0o700) != nil {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("release staging unavailable")
	}
	var index []byte
	assets := make([]softwarelifecycle.DownloadedAsset, 0, 4)
	verifiedNames := make([]string, 0, 5)
	for _, asset := range attested {
		if !safeAssetName(asset.Name) {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("attested release name refused")
		}
		limit := int64(softwarelifecycle.MaxAssetBytes)
		if asset.Name == "release-index.json" {
			limit = softwarelifecycle.MaxIndexBytes
		}
		body, err := source.run(ctx, "/usr/bin/gh", []string{"release", "download", tag, "--repo", softwarelifecycle.Repository, "--pattern", asset.Name, "--output", "-", "--allow-escape-sequences"}, limit)
		if err != nil || len(body) == 0 || int64(len(body)) > limit {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("bounded release download failed")
		}
		path := filepath.Join(directory, asset.Name)
		if os.WriteFile(path, body, 0o600) != nil {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("release staging failed")
		}
		if _, err := source.run(ctx, "/usr/bin/gh", []string{"release", "verify-asset", tag, path}, 1<<20); err != nil {
			return softwarelifecycle.ReleaseEvidence{}, errors.New("GitHub asset verification failed")
		}
		verifiedNames = append(verifiedNames, asset.Name)
		if asset.Name == "release-index.json" {
			index = body
		} else {
			assets = append(assets, softwarelifecycle.DownloadedAsset{Name: asset.Name, Bytes: body})
		}
	}
	if len(index) == 0 {
		return softwarelifecycle.ReleaseEvidence{}, errors.New("release index missing")
	}
	return softwarelifecycle.ReleaseEvidence{
		Repository: repository, Tag: attestedTag, Commit: commit, Index: index, Assets: assets, AttestedAssets: attested,
		Verifier: softwarelifecycle.VerifierEvidence{
			Version: Version, SigningFingerprint: SigningFingerprint, OfficialSignedDistribution: true,
			ReleaseVerified: true, VerifiedAssets: verifiedNames,
		},
	}, nil
}

func (source Source) qualifyDistribution(ctx context.Context) error {
	checks := []struct {
		name      string
		arguments []string
		accept    func(string) bool
	}{
		{"/usr/bin/gh", []string{"--version"}, func(output string) bool { return strings.HasPrefix(output, "gh version "+Version+" ") }},
		{"/usr/bin/dpkg-query", []string{"-W", "-f=${Version}\\n", "gh"}, func(output string) bool { return packageVersion(strings.TrimSpace(output), Version) }},
		{"/usr/bin/apt-cache", []string{"policy", "gh"}, func(output string) bool { return officialInstalledPolicy(output, Version) }},
		{"/usr/bin/dpkg", []string{"--verify", "gh"}, func(output string) bool { return strings.TrimSpace(output) == "" }},
		{"/usr/bin/gpg", []string{"--show-keys", "--with-colons", "/etc/apt/keyrings/githubcli-archive-keyring.gpg"}, func(output string) bool { return strings.Contains(output, "fpr:::::::::"+SigningFingerprint+":") }},
		{"/usr/bin/cat", []string{"/etc/apt/sources.list.d/github-cli.list"}, func(output string) bool {
			return strings.Contains(output, "signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg") && strings.Contains(output, "https://cli.github.com/packages stable main")
		}},
		{"/usr/bin/dpkg", []string{"--print-architecture"}, func(output string) bool {
			return strings.TrimSpace(output) == "amd64" || strings.TrimSpace(output) == "arm64"
		}},
	}
	architecture := ""
	for _, check := range checks {
		output, err := source.run(ctx, check.name, check.arguments, 1<<20)
		if err != nil || !check.accept(string(output)) {
			return errors.New("official signed distribution refused")
		}
		if len(check.arguments) == 1 && check.arguments[0] == "--print-architecture" {
			architecture = strings.TrimSpace(string(output))
		}
	}
	wantDigest := amd64BinarySHA256
	if architecture == "arm64" {
		wantDigest = arm64BinarySHA256
	}
	output, err := source.run(ctx, "/usr/bin/sha256sum", []string{"/usr/bin/gh"}, 1<<20)
	if err != nil || !strings.HasPrefix(string(output), wantDigest+"  /usr/bin/gh") {
		return errors.New("official GitHub CLI bytes refused")
	}
	return nil
}

func packageVersion(installed, qualified string) bool {
	return installed == qualified || strings.HasPrefix(installed, qualified+"-")
}

func officialInstalledPolicy(output, version string) bool {
	lines := strings.Split(output, "\n")
	installed := ""
	for _, line := range lines {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "Installed: "); found {
			installed = value
			break
		}
	}
	if !packageVersion(installed, version) {
		return false
	}
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "***" && fields[1] == installed {
			for _, origin := range lines[index+1:] {
				origin = strings.TrimSpace(origin)
				if origin == "" {
					continue
				}
				return strings.Contains(origin, "https://cli.github.com/packages")
			}
		}
	}
	return false
}

func safeTag(tag string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`).MatchString(tag)
}

func safeAssetName(name string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(name) && name != "." && name != ".."
}

type verificationOutput struct {
	Attestation struct {
		Bundle struct {
			Envelope struct {
				Payload string `json:"payload"`
			} `json:"dsseEnvelope"`
		} `json:"bundle"`
	} `json:"attestation"`
}

type releaseStatement struct {
	Subject []struct {
		Name   string            `json:"name"`
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"predicate"`
}

func parseReleaseVerification(document []byte) (string, string, string, []softwarelifecycle.AttestedAsset, error) {
	if len(document) == 0 || len(document) > 8<<20 || softwarelifecycle.ValidateUniqueJSON(document) != nil {
		return "", "", "", nil, errors.New("malformed release verification")
	}
	var output verificationOutput
	if json.Unmarshal(document, &output) != nil || output.Attestation.Bundle.Envelope.Payload == "" {
		return "", "", "", nil, errors.New("malformed release verification")
	}
	payload, err := base64.StdEncoding.DecodeString(output.Attestation.Bundle.Envelope.Payload)
	if err != nil || softwarelifecycle.ValidateUniqueJSON(payload) != nil {
		return "", "", "", nil, errors.New("malformed release attestation")
	}
	var statement releaseStatement
	if json.Unmarshal(payload, &statement) != nil || len(statement.Subject) < 2 {
		return "", "", "", nil, errors.New("malformed release attestation")
	}
	releaseURI := "pkg:github/" + statement.Predicate.Repository + "@" + statement.Predicate.Tag
	commit := ""
	attested := make([]softwarelifecycle.AttestedAsset, 0, len(statement.Subject)-1)
	seen := map[string]bool{}
	for _, subject := range statement.Subject {
		switch {
		case subject.URI == releaseURI && subject.Name == "" && len(subject.Digest) == 1:
			if commit != "" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(subject.Digest["sha1"]) {
				return "", "", "", nil, errors.New("ambiguous release identity")
			}
			commit = subject.Digest["sha1"]
		case subject.URI == "" && subject.Name != "" && len(subject.Digest) == 1:
			digest := subject.Digest["sha256"]
			if seen[subject.Name] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
				return "", "", "", nil, errors.New("ambiguous release asset")
			}
			seen[subject.Name] = true
			attested = append(attested, softwarelifecycle.AttestedAsset{Name: subject.Name, SHA256: digest})
		default:
			return "", "", "", nil, errors.New("unknown release subject")
		}
	}
	if commit == "" {
		return "", "", "", nil, errors.New("release identity missing")
	}
	return statement.Predicate.Repository, statement.Predicate.Tag, commit, attested, nil
}
