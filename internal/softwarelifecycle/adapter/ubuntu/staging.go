package ubuntu

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type Stager struct{}

func NewStager() Stager { return Stager{} }

func (Stager) Stage(_ context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	if !validRequest(request) {
		return softwarelifecycle.StagedRelease{}, errors.New("release staging refused")
	}
	directory, err := os.MkdirTemp("", "sbxr-payload-")
	if err != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("release staging unavailable")
	}
	defer os.RemoveAll(directory)
	if os.Chmod(directory, 0o700) != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("release staging unavailable")
	}
	path := directory + "/sbxr"
	if err := extractExecutable(request.Archive, path); err != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("release extraction refused")
	}
	if err := validateELF(path, request.Architecture); err != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("release executable refused")
	}
	file, err := os.Open(path)
	if err != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("release metadata unavailable")
	}
	info, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return softwarelifecycle.StagedRelease{}, errors.New("release metadata unavailable")
	}
	metadata, _, metadataErr := softwarelifecycle.ReadPayloadMetadata(file, info.Size())
	closeErr := file.Close()
	if metadataErr != nil || closeErr != nil || metadata.Architecture != request.Architecture || metadata.Build.Repository != request.Release.Identity.Repository || metadata.Build.Tag != request.Release.Identity.Tag || metadata.Build.Commit != request.Release.Identity.Commit || metadata.StateSchema != request.Release.StateSchema || metadata.MinimumUpdaterSchema != request.Release.MinimumUpdaterSchema {
		return softwarelifecycle.StagedRelease{}, errors.New("release metadata refused")
	}
	executable, err := os.ReadFile(path)
	if err != nil {
		return softwarelifecycle.StagedRelease{}, errors.New("staged executable unavailable")
	}
	digest := sha256.Sum256(executable)
	return softwarelifecycle.StagedRelease{
		Identity: request.Release.Identity, Build: metadata.Build, Architecture: request.Architecture, ExecutableSHA256: hex.EncodeToString(digest[:]),
		InstallPath: softwarelifecycle.ReleaseInstallPath(request.Release.Identity), StateSchema: metadata.StateSchema,
	}, nil
}

func validRequest(request softwarelifecycle.StageRequest) bool {
	if !request.Authenticated() {
		return false
	}
	digest := sha256.Sum256(request.Archive)
	role := softwarelifecycle.ApplicationAMD64
	if request.Architecture == softwarelifecycle.ARM64 {
		role = softwarelifecycle.ApplicationARM64
	} else if request.Architecture != softwarelifecycle.AMD64 {
		return false
	}
	return request.Release.Identity.Repository == softwarelifecycle.Repository && request.Asset.Role == role && request.Asset.Size == int64(len(request.Archive)) && request.Asset.Size > 0 && request.Asset.Size <= softwarelifecycle.MaxAssetBytes && request.Asset.SHA256 == hex.EncodeToString(digest[:])
}

func extractExecutable(body []byte, destination string) error {
	input := bytes.NewReader(body)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, softwarelifecycle.MaxAssetBytes+1))
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Size <= 0 || header.Size > softwarelifecycle.MaxAssetBytes || header.Mode != 0o755 || header.Uid != 0 || header.Gid != 0 || (header.Uname != "" && header.Uname != "root") || (header.Gname != "" && header.Gname != "root") {
		return errors.New("unsafe archive entry")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	copied, copyErr := io.Copy(file, archive)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || copied != header.Size {
		return errors.New("truncated archive entry")
	}
	if _, err := archive.Next(); err != io.EOF {
		return errors.New("extra archive entry")
	}
	remaining, err := io.Copy(io.Discard, compressed)
	if err != nil || remaining != 0 || compressed.Close() != nil || input.Len() != 0 {
		return errors.New("trailing archive content")
	}
	return nil
}

func validateELF(path string, architecture softwarelifecycle.Architecture) error {
	file, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	wantMachine := elf.EM_X86_64
	if architecture == softwarelifecycle.ARM64 {
		wantMachine = elf.EM_AARCH64
	}
	if file.FileHeader.Class != elf.ELFCLASS64 || file.FileHeader.Machine != wantMachine || file.Section(".gopclntab") == nil {
		return errors.New("wrong executable architecture")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("language runtime dependency")
		}
	}
	libraries, err := file.ImportedLibraries()
	if err != nil || len(libraries) != 0 {
		return errors.New("native runtime dependency")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.GoVersion != "go1.26.5" {
		return errors.New("wrong Go toolchain")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return errors.New("ambiguous Go build setting")
		}
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != string(architecture) || settings["CGO_ENABLED"] != "0" {
		return errors.New("unsafe Go build settings")
	}
	return nil
}
