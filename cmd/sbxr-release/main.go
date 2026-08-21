// Command sbxr-release builds one qualified immutable SBXR architecture archive.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	ubuntuadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type payloadValidator interface {
	Validate(context.Context, softwarelifecycle.PayloadMetadata) error
}

type sourceVerifier func(context.Context, string, string) (string, error)
type componentBuilder func(context.Context, softwarelifecycle.Architecture, softwarelifecycle.PayloadMetadata) ([]byte, error)

type buildOptions struct {
	tag, commit, output, componentOutput string
	architecture                         softwarelifecycle.Architecture
}

type indexOptions struct {
	version, tag, commit, directory, output string
	sequence                                uint64
}

type bootstrapOptions struct {
	version, tag, commit, output                 string
	amd64ExecutableSHA256, arm64ExecutableSHA256 string
	sequence                                     uint64
	root                                         string
}

type packageQualificationValidationOptions struct {
	application, components, evidence string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "validate-package-qualification" {
		flags := flag.NewFlagSet("validate-package-qualification", flag.ContinueOnError)
		var options packageQualificationValidationOptions
		flags.StringVar(&options.application, "application", "", "exact application archive")
		flags.StringVar(&options.components, "components", "", "exact component archive")
		flags.StringVar(&options.evidence, "evidence", "", "strict package qualification JSON")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || validatePackageQualificationFiles(options) != nil {
			fmt.Fprintln(os.Stderr, "sbxr package qualification validation refused")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "acceptance" {
		flags := flag.NewFlagSet("acceptance", flag.ContinueOnError)
		var options acceptanceOptions
		flags.StringVar(&options.tag, "tag", "", "immutable release tag")
		flags.StringVar(&options.commit, "commit", "", "40-character commit SHA")
		flags.StringVar(&options.directory, "directory", "", "directory containing the exact six release assets")
		flags.StringVar(&options.qualificationDirectory, "qualification-directory", "", "directory containing both strict Package Qualification results")
		flags.StringVar(&options.output, "output", "", "redacted Acceptance Record output path")
		flags.StringVar(&options.evidenceURL, "evidence-url", "", "GitHub Actions evidence URL")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || writeAutomatedAcceptanceRecord(options, time.Now()) != nil {
			fmt.Fprintln(os.Stderr, "sbxr acceptance record refused")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		tag := flags.String("tag", "", "immutable release tag")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || verifyCandidate(context.Background(), *tag) != nil {
			fmt.Fprintln(os.Stderr, "sbxr release verification refused")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "index" {
		flags := flag.NewFlagSet("index", flag.ContinueOnError)
		var options indexOptions
		flags.StringVar(&options.version, "version", "", "release version")
		flags.Uint64Var(&options.sequence, "sequence", 0, "release sequence")
		flags.StringVar(&options.tag, "tag", "", "immutable release tag")
		flags.StringVar(&options.commit, "commit", "", "40-character commit SHA")
		flags.StringVar(&options.directory, "directory", "", "directory containing install.sh and the four release archives")
		flags.StringVar(&options.output, "output", "", "release-index.json output path")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || buildReleaseIndexFile(options) != nil {
			fmt.Fprintln(os.Stderr, "sbxr release index refused")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
		var options bootstrapOptions
		flags.StringVar(&options.version, "version", "", "release version")
		flags.Uint64Var(&options.sequence, "sequence", 0, "release sequence")
		flags.StringVar(&options.tag, "tag", "", "immutable release tag")
		flags.StringVar(&options.commit, "commit", "", "40-character commit SHA")
		flags.StringVar(&options.amd64ExecutableSHA256, "amd64-executable-sha256", "", "amd64 executable SHA-256")
		flags.StringVar(&options.arm64ExecutableSHA256, "arm64-executable-sha256", "", "arm64 executable SHA-256")
		flags.StringVar(&options.output, "output", "", "install.sh output path")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || buildBootstrapFile(options) != nil {
			fmt.Fprintln(os.Stderr, "sbxr bootstrap build refused")
			os.Exit(1)
		}
		return
	}
	var options buildOptions
	flag.StringVar(&options.tag, "tag", "", "immutable release tag")
	flag.StringVar(&options.commit, "commit", "", "40-character commit SHA")
	flag.StringVar(&options.output, "output", "", "output .tar.gz path")
	flag.StringVar(&options.componentOutput, "component-output", "", "qualified component output .tar.gz path")
	flag.Func("architecture", "amd64 or arm64", func(value string) error {
		options.architecture = softwarelifecycle.Architecture(value)
		return nil
	})
	flag.Parse()
	if err := buildCompleteRelease(context.Background(), options, verifiedModuleSource, ubuntuadapter.BuildReleaseComponentArchive); err != nil {
		fmt.Fprintln(os.Stderr, "sbxr release build refused:", err)
		os.Exit(1)
	}
}

func validatePackageQualificationFiles(options packageQualificationValidationOptions) error {
	application, err := readQualificationFile(options.application, softwarelifecycle.MaxAssetBytes)
	if err != nil {
		return err
	}
	components, err := readQualificationFile(options.components, softwarelifecycle.MaxAssetBytes)
	if err != nil {
		return err
	}
	evidence, err := readQualificationFile(options.evidence, softwarelifecycle.MaxPackageQualificationEvidenceBytes)
	if err != nil {
		return err
	}
	_, _, err = softwarelifecycle.ValidatePackagedQualificationEvidence(application, components, evidence)
	return err
}

func readQualificationFile(name string, maximum int) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, errors.New("package qualification input unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, errors.New("package qualification input refused")
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, errors.New("package qualification input unavailable")
	}
	return body, nil
}

func verifyCandidate(ctx context.Context, tag string) error {
	module := softwarelifecycle.New(
		githubadapter.New(),
		softwarelifecycle.VerifierQualification{Version: githubadapter.Version, SigningFingerprint: githubadapter.SigningFingerprint},
		time.Now,
		ubuntuadapter.NewStager(),
	)
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		result := module.View(ctx, softwarelifecycle.ViewRequest{Tag: tag, Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
		if result.Refusal != nil || result.VerifiedCandidate == nil || result.StagedCandidate == nil || result.StagedCandidate.Architecture != architecture {
			return errors.New("candidate verification refused")
		}
	}
	return nil
}

func buildReleaseIndexFile(options indexOptions) error {
	if options.directory == "" || options.output == "" {
		return errors.New("release index refused")
	}
	root, err := os.OpenRoot(options.directory)
	if err != nil {
		return errors.New("release assets unavailable")
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != 5 {
		return errors.New("release asset set refused")
	}
	exact := map[string]bool{"install.sh": true, "sbxr-linux-amd64.tar.gz": true, "sbxr-linux-arm64.tar.gz": true, "sbxr-components-linux-amd64.tar.gz": true, "sbxr-components-linux-arm64.tar.gz": true}
	for _, entry := range entries {
		if !exact[entry.Name()] {
			return errors.New("release asset set refused")
		}
	}
	assets := make([]softwarelifecycle.ReleaseIndexAsset, 0, 5)
	expectedAssets := []struct {
		role softwarelifecycle.Component
		name string
	}{{softwarelifecycle.ApplicationAMD64, "sbxr-linux-amd64.tar.gz"}, {softwarelifecycle.ApplicationARM64, "sbxr-linux-arm64.tar.gz"}, {softwarelifecycle.ComponentsAMD64, "sbxr-components-linux-amd64.tar.gz"}, {softwarelifecycle.ComponentsARM64, "sbxr-components-linux-arm64.tar.gz"}, {softwarelifecycle.Bootstrap, "install.sh"}}
	openedAssets := make(map[string]fs.FileInfo, len(expectedAssets))
	for _, expected := range expectedAssets {
		info, err := root.Lstat(expected.name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > softwarelifecycle.MaxAssetBytes {
			return errors.New("release asset refused")
		}
		file, err := root.Open(expected.name)
		if err != nil {
			return errors.New("release asset unavailable")
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
			file.Close()
			return errors.New("release asset changed")
		}
		body, readErr := io.ReadAll(io.LimitReader(file, softwarelifecycle.MaxAssetBytes+1))
		after, statErr := file.Stat()
		closeErr := file.Close()
		pathAfter, pathErr := root.Lstat(expected.name)
		if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil || !unchangedFile(opened, after) || !unchangedFile(opened, pathAfter) || int64(len(body)) != info.Size() {
			return errors.New("release asset unavailable")
		}
		openedAssets[expected.name] = opened
		assets = append(assets, softwarelifecycle.ReleaseIndexAsset{Role: expected.role, Name: expected.name, Bytes: body})
	}
	entries, err = fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != len(expectedAssets) {
		return errors.New("release asset set changed")
	}
	for _, expected := range expectedAssets {
		current, statErr := root.Lstat(expected.name)
		if statErr != nil || !unchangedFile(openedAssets[expected.name], current) {
			return errors.New("release asset changed")
		}
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: options.tag, Commit: options.commit}, softwarelifecycle.AMD64)
	if err != nil {
		return errors.New("release metadata unavailable")
	}
	index, err := softwarelifecycle.BuildReleaseIndex(softwarelifecycle.ReleaseIndexRequest{Version: options.version, Sequence: options.sequence, Tag: options.tag, Commit: options.commit, StateSchema: metadata.StateSchema, MinimumUpdaterSchema: metadata.MinimumUpdaterSchema, Assets: assets})
	if err != nil {
		return err
	}
	return writeExclusive(options.output, index)
}

func unchangedFile(before, after fs.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func buildArchive(ctx context.Context, options buildOptions, validator payloadValidator, verifySource sourceVerifier) error {
	if validator == nil {
		return errors.New("release build refused")
	}
	archive, metadata, err := buildApplicationArchive(ctx, options, verifySource)
	if err != nil || validator.Validate(ctx, metadata) != nil {
		return errors.New("release qualification refused")
	}
	return writeExclusive(options.output, archive)
}

func buildCompleteRelease(ctx context.Context, options buildOptions, verifySource sourceVerifier, buildComponents componentBuilder) error {
	if options.componentOutput == "" || options.componentOutput == options.output || buildComponents == nil {
		return errors.New("complete release build refused")
	}
	application, metadata, err := buildApplicationArchive(ctx, options, verifySource)
	if err != nil {
		return err
	}
	components, err := buildComponents(ctx, options.architecture, metadata)
	if err != nil {
		return err
	}
	if len(components) == 0 || len(components) > softwarelifecycle.MaxAssetBytes {
		return errors.New("component release qualification refused")
	}
	componentDigest := sha256.Sum256(components)
	metadata.ComponentsSHA256 = hex.EncodeToString(componentDigest[:])
	application, err = bindApplicationComponents(application, metadata)
	if err != nil {
		return err
	}
	return writePairExclusive(options.output, application, options.componentOutput, components)
}

func bindApplicationComponents(application []byte, metadata softwarelifecycle.PayloadMetadata) ([]byte, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(application))
	if err != nil {
		return nil, errors.New("release application archive refused")
	}
	archive := tar.NewReader(compressed)
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > softwarelifecycle.MaxAssetBytes {
		return nil, errors.New("release application archive refused")
	}
	stamped, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(stamped)) != header.Size {
		return nil, errors.New("release application archive refused")
	}
	if _, err := archive.Next(); err != io.EOF || compressed.Close() != nil {
		return nil, errors.New("release application archive refused")
	}
	_, payload, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(stamped), int64(len(stamped)))
	if err != nil {
		return nil, errors.New("release application identity refused")
	}
	stamped, err = softwarelifecycle.StampPayload(payload, metadata)
	if err != nil {
		return nil, err
	}
	return oneFileArchive(stamped)
}

func buildApplicationArchive(ctx context.Context, options buildOptions, verifySource sourceVerifier) ([]byte, softwarelifecycle.PayloadMetadata, error) {
	if ctx == nil || verifySource == nil || runtime.Version() != "go1.26.6" || options.output == "" || options.architecture != softwarelifecycle.AMD64 && options.architecture != softwarelifecycle.ARM64 {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release build refused")
	}
	directory, err := os.MkdirTemp("", "sbxr-release-build-")
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, err
	}
	defer os.RemoveAll(directory)
	executablePath := directory + "/sbxr"
	sourceRoot, err := verifySource(ctx, options.commit, filepath.Join(directory, "source"))
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release source refused")
	}
	command := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-trimpath", "-o", executablePath, "./cmd/sbxr")
	command.Dir = sourceRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+string(options.architecture))
	if _, err := command.CombinedOutput(); err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release executable build refused")
	}
	executable, err := os.ReadFile(executablePath)
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, err
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: options.tag, Commit: options.commit}, options.architecture)
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release qualification refused")
	}
	stamped, err := softwarelifecycle.StampPayload(executable, metadata)
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, err
	}
	metadata, _, err = softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(stamped), int64(len(stamped)))
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release payload identity unavailable")
	}
	archive, err := oneFileArchive(stamped)
	if err != nil || len(archive) > softwarelifecycle.MaxAssetBytes {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("release archive refused")
	}
	return archive, metadata, nil
}

func writeExclusive(name string, body []byte) error {
	output, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("release output refused")
	}
	_, writeErr := output.Write(body)
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(name)
		return errors.New("release output unavailable")
	}
	return nil
}

func writePairExclusive(firstName string, firstBody []byte, secondName string, secondBody []byte) error {
	first, err := os.OpenFile(firstName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("release output refused")
	}
	second, err := os.OpenFile(secondName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = first.Close()
		_ = os.Remove(firstName)
		return errors.New("release output refused")
	}
	failed := false
	for _, output := range []struct {
		file *os.File
		body []byte
	}{{first, firstBody}, {second, secondBody}} {
		written, writeErr := output.file.Write(output.body)
		syncErr := output.file.Sync()
		if writeErr != nil || written != len(output.body) || syncErr != nil {
			failed = true
		}
	}
	firstCloseErr, secondCloseErr := first.Close(), second.Close()
	if firstCloseErr != nil || secondCloseErr != nil {
		failed = true
	}
	if failed {
		_ = os.Remove(firstName)
		_ = os.Remove(secondName)
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
	unitSets := []map[string]string{{"cloudflared.service": cloudflaretunnel.CloudflaredServiceUnit()}, {"sbxr-subscription.service": subscriptionserving.ServiceUnit()}, connectionprofiles.SystemdUnits(), softwarelifecycle.SystemdUnits(), systemchanges.SystemdUnits()}
	for _, read := range []func() (map[string]string, error){certificatelifecycle.SystemdUnits, healthdiagnostics.SystemdUnits} {
		set, err := read()
		if err != nil {
			return softwarelifecycle.PayloadMetadata{}, err
		}
		unitSets = append(unitSets, set)
	}
	return softwarelifecycle.NewPayloadMetadata(identity, architecture, softwarelifecycle.PayloadMaterial{StateDefinitions: definitions, StateMigrations: state.ReleaseMigrations(), UnitSets: unitSets, ArtifactSets: []map[string][]byte{artifacts}})
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
