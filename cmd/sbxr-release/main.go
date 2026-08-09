// Command sbxr-release builds one qualified immutable SBXR architecture archive.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	ubuntuadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

type payloadValidator interface {
	Validate(context.Context, softwarelifecycle.PayloadMetadata) error
}

type sourceVerifier func(context.Context, string, string) (string, error)

type buildOptions struct {
	tag, commit, output string
	architecture        softwarelifecycle.Architecture
}

func main() {
	var options buildOptions
	var certbot string
	flag.StringVar(&options.tag, "tag", "", "immutable release tag")
	flag.StringVar(&options.commit, "commit", "", "40-character commit SHA")
	flag.StringVar(&options.output, "output", "", "output .tar.gz path")
	flag.StringVar(&certbot, "certbot", "/snap/bin/certbot", "supported snap or proved pip-venv Certbot path")
	flag.Func("architecture", "amd64 or arm64", func(value string) error {
		options.architecture = softwarelifecycle.Architecture(value)
		return nil
	})
	flag.Parse()
	validator, err := ubuntuadapter.NewNativeValidatorAt(nil, certbot)
	if err != nil || buildArchive(context.Background(), options, validator, verifiedModuleSource) != nil {
		fmt.Fprintln(os.Stderr, "sbxr release build refused")
		os.Exit(1)
	}
}

func buildArchive(ctx context.Context, options buildOptions, validator payloadValidator, verifySource sourceVerifier) error {
	if ctx == nil || validator == nil || verifySource == nil || runtime.Version() != "go1.26.5" || options.output == "" || options.architecture != softwarelifecycle.AMD64 && options.architecture != softwarelifecycle.ARM64 {
		return errors.New("release build refused")
	}
	directory, err := os.MkdirTemp("", "sbxr-release-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	executablePath := directory + "/sbxr"
	sourceRoot, err := verifySource(ctx, options.commit, filepath.Join(directory, "source"))
	if err != nil {
		return errors.New("release source refused")
	}
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", executablePath, "./cmd/sbxr")
	command.Dir = sourceRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+string(options.architecture))
	if output, err := command.CombinedOutput(); err != nil || len(output) != 0 {
		return errors.New("release executable build refused")
	}
	executable, err := os.ReadFile(executablePath)
	if err != nil {
		return err
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: options.tag, Commit: options.commit}, options.architecture)
	if err != nil || validator.Validate(ctx, metadata) != nil {
		return errors.New("release qualification refused")
	}
	stamped, err := softwarelifecycle.StampPayload(executable, metadata)
	if err != nil {
		return err
	}
	archive, err := oneFileArchive(stamped)
	if err != nil || len(archive) > softwarelifecycle.MaxAssetBytes {
		return errors.New("release archive refused")
	}
	output, err := os.OpenFile(options.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("release output refused")
	}
	_, writeErr := output.Write(archive)
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(options.output)
		return errors.New("release output unavailable")
	}
	return nil
}

func verifiedModuleSource(ctx context.Context, commit, destination string) (string, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOMOD")
	output, err := command.Output()
	moduleFile := strings.TrimSpace(string(output))
	if err != nil || filepath.Base(moduleFile) != "go.mod" {
		return "", errors.New("release module unavailable")
	}
	return verifiedGitSource(ctx, filepath.Dir(moduleFile), commit, destination)
}

func verifiedGitSource(ctx context.Context, root, commit, destination string) (string, error) {
	head, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", "HEAD^{commit}").Output()
	if err != nil || strings.TrimSpace(string(head)) != commit {
		return "", errors.New("release commit mismatch")
	}
	if exec.CommandContext(ctx, "git", "-C", root, "diff", "--quiet", "HEAD", "--").Run() != nil {
		return "", errors.New("tracked release source is dirty")
	}
	archive, err := exec.CommandContext(ctx, "git", "-C", root, "archive", "--format=tar", "HEAD").Output()
	if err != nil || len(archive) == 0 || len(archive) > softwarelifecycle.MaxAssetBytes {
		return "", errors.New("release source unavailable")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", err
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		clean := filepath.Clean(header.Name)
		path := filepath.Join(destination, clean)
		if err != nil || clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !strings.HasPrefix(path, destination+string(filepath.Separator)) {
			return "", errors.New("release source archive refused")
		}
		switch header.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		case tar.TypeDir:
			if os.MkdirAll(path, 0o700) != nil {
				return "", errors.New("release source unavailable")
			}
		case tar.TypeReg, tar.TypeRegA:
			if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
				return "", errors.New("release source unavailable")
			}
			file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(header.Mode)&0o755)
			if openErr != nil {
				return "", errors.New("release source unavailable")
			}
			copied, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || copied != header.Size {
				return "", errors.New("release source unavailable")
			}
		default:
			return "", errors.New("release source archive refused")
		}
	}
	return destination, nil
}

func releaseMetadata(identity softwarelifecycle.EmbeddedBuildIdentity, architecture softwarelifecycle.Architecture) (softwarelifecycle.PayloadMetadata, error) {
	artifacts, err := subscriptionpublication.QualificationArtifacts()
	if err != nil {
		return softwarelifecycle.PayloadMetadata{}, err
	}
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	definitions, err := state.ReleaseDefinitions()
	if err != nil {
		return softwarelifecycle.PayloadMetadata{}, err
	}
	unitSets := []map[string]string{{"cloudflared.service": cloudflaretunnel.CloudflaredServiceUnit()}, {"sbxr-subscription.service": subscriptionserving.ServiceUnit()}, connectionprofiles.SystemdUnits(), softwarelifecycle.SystemdUnits()}
	for _, read := range []func() (map[string]string, error){certificatelifecycle.SystemdUnits, healthdiagnostics.SystemdUnits} {
		set, err := read()
		if err != nil {
			return softwarelifecycle.PayloadMetadata{}, err
		}
		unitSets = append(unitSets, set)
	}
	return softwarelifecycle.NewPayloadMetadata(identity, architecture, softwarelifecycle.PayloadMaterial{StateDefinitions: definitions, UnitSets: unitSets, ArtifactSets: []map[string][]byte{artifacts}})
}

func oneFileArchive(body []byte) ([]byte, error) {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := archive.Write(body); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
