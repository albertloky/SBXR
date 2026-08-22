// Command sbxr-release builds and verifies Installer-Updater release assets.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type sourceVerifier func(context.Context, string, string) (string, error)

type buildOptions struct {
	tag, commit, output string
	sequence            uint64
	architecture        softwarelifecycle.Architecture
}

type indexOptions struct {
	tag, commit, directory, output string
	sequence                       uint64
}

type bootstrapOptions struct {
	version, tag, commit, output                 string
	amd64ExecutableSHA256, arm64ExecutableSHA256 string
	sequence                                     uint64
	root                                         string
}

type packageVerificationOptions struct {
	directory    string
	architecture softwarelifecycle.Architecture
}

type gatewayOptions struct {
	manifest, bundle, assets, certificate, key, listen, control string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gateway" {
		flags := flag.NewFlagSet("gateway", flag.ContinueOnError)
		var options gatewayOptions
		flags.StringVar(&options.manifest, "manifest", "", "signed qualification manifest")
		flags.StringVar(&options.bundle, "bundle", "", "qualification attestation bundle")
		flags.StringVar(&options.assets, "assets", "", "manifest-bound A and B asset directories")
		flags.StringVar(&options.certificate, "certificate", "", "TLS certificate")
		flags.StringVar(&options.key, "key", "", "TLS private key")
		flags.StringVar(&options.listen, "listen", ":443", "TLS listen address")
		flags.StringVar(&options.control, "control", "", "root-only external timing controls")
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || runQualificationGateway(options) != nil {
			fmt.Fprintln(os.Stderr, "sbxr qualification gateway refused")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "index" {
		flags := flag.NewFlagSet("index", flag.ContinueOnError)
		var options indexOptions
		flags.Uint64Var(&options.sequence, "sequence", 0, "release sequence")
		flags.StringVar(&options.tag, "tag", "", "immutable release tag")
		flags.StringVar(&options.commit, "commit", "", "40-character commit SHA")
		flags.StringVar(&options.directory, "directory", "", "directory containing install.sh and both application archives")
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
	if len(os.Args) > 1 && os.Args[1] == "verify-package" {
		flags := flag.NewFlagSet("verify-package", flag.ContinueOnError)
		var options packageVerificationOptions
		flags.StringVar(&options.directory, "directory", "", "directory containing the exact four release assets")
		flags.Func("architecture", "amd64 or arm64", func(value string) error {
			options.architecture = softwarelifecycle.Architecture(value)
			return nil
		})
		if flags.Parse(os.Args[2:]) != nil || flags.NArg() != 0 || verifyReleasePackage(options) != nil {
			fmt.Fprintln(os.Stderr, "sbxr release package refused")
			os.Exit(1)
		}
		return
	}
	var options buildOptions
	flag.StringVar(&options.tag, "tag", "", "immutable release tag")
	flag.StringVar(&options.commit, "commit", "", "40-character commit SHA")
	flag.Uint64Var(&options.sequence, "sequence", 0, "release sequence")
	flag.StringVar(&options.output, "output", "", "application archive output path")
	flag.Func("architecture", "amd64 or arm64", func(value string) error {
		options.architecture = softwarelifecycle.Architecture(value)
		return nil
	})
	flag.Parse()
	if flag.NArg() != 0 || buildApplicationRelease(context.Background(), options, verifiedModuleSource) != nil {
		fmt.Fprintln(os.Stderr, "sbxr release build refused")
		os.Exit(1)
	}
}

func buildApplicationRelease(ctx context.Context, options buildOptions, source sourceVerifier) error {
	archive, err := buildApplicationArchive(ctx, options, source)
	if err != nil {
		return err
	}
	return writeExclusive(options.output, archive, 0o600)
}

func buildApplicationArchive(ctx context.Context, options buildOptions, source sourceVerifier) ([]byte, error) {
	if ctx == nil || source == nil || runtime.Version() != "go1.26.6" || options.output == "" || options.sequence == 0 || !validTag(options.tag) || !validCommit(options.commit) || options.architecture != softwarelifecycle.AMD64 && options.architecture != softwarelifecycle.ARM64 {
		return nil, errors.New("release build refused")
	}
	directory, err := os.MkdirTemp("", "sbxr-release-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	sourceRoot, err := source(ctx, options.commit, filepath.Join(directory, "source"))
	if err != nil {
		return nil, errors.New("release source refused")
	}
	executablePath := filepath.Join(directory, "sbxr")
	command := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-trimpath", "-o", executablePath, "./cmd/sbxr")
	command.Dir = sourceRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+string(options.architecture))
	if _, err := command.CombinedOutput(); err != nil {
		return nil, errors.New("release executable build refused")
	}
	payload, err := os.ReadFile(executablePath)
	if err != nil || len(payload) == 0 || len(payload) > softwarelifecycle.MaxAssetBytes {
		return nil, errors.New("release executable unavailable")
	}
	executable, err := softwarelifecycle.StampReleaseExecutable(payload, options.tag, options.commit, options.sequence, options.architecture)
	if err != nil {
		return nil, err
	}
	archive, err := oneFileArchive(executable)
	if err != nil || len(archive) > softwarelifecycle.MaxAssetBytes {
		return nil, errors.New("release archive refused")
	}
	return archive, nil
}

func buildReleaseIndexFile(options indexOptions) error {
	if options.directory == "" || options.output == "" || options.sequence == 0 || !validTag(options.tag) || !validCommit(options.commit) {
		return errors.New("release index refused")
	}
	root, err := os.OpenRoot(options.directory)
	if err != nil {
		return errors.New("release assets unavailable")
	}
	defer root.Close()
	names := softwarelifecycle.LatestReleaseIndexedAssetNames()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != len(names) {
		return errors.New("release asset set refused")
	}
	specs := releaseAssetSpecs(names)
	bodies, err := readReleaseFiles(root, specs, nil)
	if err != nil {
		return err
	}
	assets := make([]softwarelifecycle.LatestAssetProof, 0, len(names))
	for _, name := range names {
		body := bodies[name]
		digest := sha256.Sum256(body)
		assets = append(assets, softwarelifecycle.LatestAssetProof{Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])})
	}
	body, err := softwarelifecycle.BuildLatestReleaseIndex(options.tag, options.commit, options.sequence, assets)
	if err != nil {
		return errors.New("release index refused")
	}
	return writeExclusive(options.output, body, 0o600)
}

func verifyReleasePackage(options packageVerificationOptions) error {
	if options.directory == "" || options.architecture != softwarelifecycle.AMD64 && options.architecture != softwarelifecycle.ARM64 {
		return errors.New("release package refused")
	}
	root, err := os.OpenRoot(options.directory)
	if err != nil {
		return errors.New("release package unavailable")
	}
	defer root.Close()
	names := softwarelifecycle.LatestReleaseAssetNames()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != len(names) {
		return errors.New("release package refused")
	}
	bodies, err := readReleaseFiles(root, releaseAssetSpecs(names), nil)
	if err != nil {
		return err
	}
	proofs := make([]softwarelifecycle.LatestAssetProof, 0, len(names))
	for _, name := range names {
		body := bodies[name]
		digest := sha256.Sum256(body)
		proofs = append(proofs, softwarelifecycle.LatestAssetProof{Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])})
	}
	var index struct {
		Tag, Commit string
	}
	if json.Unmarshal(bodies["release-index.json"], &index) != nil {
		return errors.New("release index refused")
	}
	release, ok := softwarelifecycle.VerifyLatestReleaseIndex(softwarelifecycle.Repository, index.Tag, index.Commit, bodies["release-index.json"], proofs)
	archiveName := "sbxr-linux-" + string(options.architecture) + ".tar.gz"
	if !ok {
		return errors.New("release index refused")
	}
	candidate, ok := softwarelifecycle.VerifyLatestUpdateArchive(release, options.architecture, bodies[archiveName])
	if !ok {
		return errors.New("release archive refused")
	}
	executableSHA256, ok := candidate.ExecutableSHA256()
	if !ok {
		return errors.New("release archive refused")
	}
	bootstrap := string(bodies["install.sh"])
	required := []string{
		"REPOSITORY='" + softwarelifecycle.Repository + "'",
		"TAG='" + release.Identity.Tag + "'",
		"COMMIT='" + release.Identity.Commit + "'",
		fmt.Sprintf("SEQUENCE='%d'", release.Sequence),
		strings.ToUpper(string(options.architecture)) + "_EXECUTABLE_SHA256='" + executableSHA256 + "'",
	}
	for _, line := range required {
		if strings.Count(bootstrap, line+"\n") != 1 {
			return errors.New("release bootstrap refused")
		}
	}
	return nil
}

type releaseAssetSpec struct {
	name  string
	limit int64
}

func releaseAssetSpecs(names []string) []releaseAssetSpec {
	specs := make([]releaseAssetSpec, 0, len(names))
	for _, name := range names {
		limit := int64(softwarelifecycle.MaxAssetBytes)
		if name == "install.sh" || name == "release-index.json" {
			limit = softwarelifecycle.MaxIndexBytes
		}
		specs = append(specs, releaseAssetSpec{name: name, limit: limit})
	}
	return specs
}

func readReleaseFiles(root *os.Root, specs []releaseAssetSpec, afterRead func(string)) (map[string][]byte, error) {
	bodies := make(map[string][]byte, len(specs))
	identities := make(map[string]fs.FileInfo, len(specs))
	for _, spec := range specs {
		body, identity, err := readRootFile(root, spec.name, spec.limit)
		if err != nil {
			return nil, err
		}
		bodies[spec.name], identities[spec.name] = body, identity
		if afterRead != nil {
			afterRead(spec.name)
		}
	}
	for name, identity := range identities {
		current, err := root.Lstat(name)
		if err != nil || !unchangedFile(identity, current) {
			return nil, errors.New("release asset changed")
		}
	}
	return bodies, nil
}

func readRootFile(root *os.Root, name string, limit int64) ([]byte, fs.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, nil, errors.New("release asset refused")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, errors.New("release asset unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, nil, errors.New("release asset changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	pathAfter, pathErr := root.Lstat(name)
	if err != nil || statErr != nil || pathErr != nil || int64(len(body)) != before.Size() || !unchangedFile(opened, after) || !unchangedFile(opened, pathAfter) {
		return nil, nil, errors.New("release asset changed")
	}
	return body, opened, nil
}

func unchangedFile(before, after fs.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func writeExclusive(name string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("release output refused")
	}
	written, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(body) {
		_ = os.Remove(name)
		return errors.New("release output unavailable")
	}
	return nil
}

func verifiedModuleSource(ctx context.Context, commit, destination string) (string, error) {
	moduleFile, err := exec.CommandContext(ctx, "go", "env", "GOMOD").Output()
	if err != nil || filepath.Base(strings.TrimSpace(string(moduleFile))) != "go.mod" {
		return "", errors.New("release module unavailable")
	}
	return verifiedGitSource(ctx, filepath.Dir(strings.TrimSpace(string(moduleFile))), commit, destination)
}

func verifiedGitSource(ctx context.Context, root, commit, destination string) (string, error) {
	head, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", "HEAD^{commit}").Output()
	if err != nil || strings.TrimSpace(string(head)) != commit || exec.CommandContext(ctx, "git", "-C", root, "diff", "--quiet", "HEAD", "--").Run() != nil {
		return "", errors.New("release source refused")
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

func validTag(value string) bool {
	var major, minor, patch uint64
	var extra string
	_, err := fmt.Sscanf(value, "v%d.%d.%d%s", &major, &minor, &patch, &extra)
	return err == io.EOF && value == fmt.Sprintf("v%d.%d.%d", major, minor, patch)
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
