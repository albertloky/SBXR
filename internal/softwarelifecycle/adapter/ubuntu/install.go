package ubuntu

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type Installer struct {
	staged             softwarelifecycle.StagedRelease
	archive            []byte
	components         []byte
	manifest           softwarelifecycle.ComponentManifest
	manageRecoveryUnit bool
	enableRecovery     func() error
	disableRecovery    func() error
}

func NewInstaller(candidate softwarelifecycle.InstallCandidate) (Installer, error) {
	staged, archive, components, valid := candidate.SoftwareLifecyclePreparedArchive()
	if !valid {
		return Installer{}, errors.New("verified install candidate unavailable")
	}
	installer, err := newInstaller(staged, archive, components)
	installer.manageRecoveryUnit = err == nil
	installer.enableRecovery = enableInstallRecovery
	installer.disableRecovery = disableInstallRecovery
	return installer, err
}

func newInstaller(staged softwarelifecycle.StagedRelease, archive []byte, components ...[]byte) (Installer, error) {
	var componentArchive []byte
	if len(components) == 1 {
		componentArchive = components[0]
	}
	installer := Installer{staged: staged, archive: append([]byte(nil), archive...), components: append([]byte(nil), componentArchive...)}
	digest := sha256.Sum256(componentArchive)
	manifest, err := softwarelifecycle.ValidateComponentArchive(componentArchive, staged.Architecture)
	if err != nil || hex.EncodeToString(digest[:]) != staged.ComponentsSHA256 {
		return Installer{}, errors.New("prepared component archive refused")
	}
	installer.manifest = manifest
	if _, _, err := installer.material(); err != nil {
		return Installer{}, err
	}
	return installer, nil
}

type installRollback struct {
	Schema     int                             `json:"schema"`
	Created    []string                        `json:"created"`
	Staged     softwarelifecycle.StagedRelease `json:"staged"`
	Archive    []byte                          `json:"archive"`
	Components []byte                          `json:"components"`
}

func (installer Installer) CaptureRollback(rootPath string, step systemchanges.Step, write func(io.Reader) error) error {
	if !softwareStep(step) || write == nil {
		return errors.New("Software Lifecycle rollback capture unavailable")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range installer.installedFiles() {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("an SBXR install target already exists")
		}
	}
	document, _ := json.Marshal(installRollback{Schema: 1, Created: installer.installedFiles(), Staged: installer.staged, Archive: installer.archive, Components: installer.components})
	return write(bytes.NewReader(document))
}

func NewRecoveryInstaller() Installer {
	return Installer{manageRecoveryUnit: true, enableRecovery: enableInstallRecovery, disableRecovery: disableInstallRecovery}
}

func (installer Installer) Activate(rootPath string, step systemchanges.Step, _ time.Duration) (systemchanges.StepEvidence, error) {
	if !softwareStep(step) {
		return systemchanges.StepEvidence{}, errors.New("Software Lifecycle install step invalid")
	}
	executable, metadata, err := installer.material()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	units, err := softwarelifecycle.RenderManagedUnits(metadata, installer.staged.Identity)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	directories := []struct {
		name string
		mode fs.FileMode
	}{{"opt", 0o755}, {"opt/sbxr", 0o755}, {"opt/sbxr/releases", 0o755}, {path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/")), 0o755}, {"var", 0o755}, {"var/lib", 0o755}, {"var/lib/sbxr", 0o700}, {"etc", 0o755}, {"etc/sbxr", 0o755}, {"etc/systemd", 0o755}, {"etc/systemd/system", 0o755}, {"usr", 0o755}, {"usr/local", 0o755}, {"usr/local/bin", 0o755}}
	for _, directory := range directories {
		if err := ensureInstallDirectory(root, directory.name, directory.mode); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := writeInstallFile(root, strings.TrimPrefix(installer.staged.InstallPath, "/"), executable, 0o755); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := installer.installComponents(root); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	for _, name := range softwarelifecycle.ManagedUnitNames() {
		if err := writeInstallFile(root, path.Join("etc/systemd/system", name), units[name], 0o644); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := root.Symlink(installer.staged.InstallPath, "usr/local/bin/sbxr"); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := syncInstallDirectories(root, path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/")), "etc/systemd/system", "usr/local/bin"); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := installer.verify(root, metadata); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if installer.manageRecoveryUnit && (installer.enableRecovery == nil || installer.enableRecovery() != nil) {
		return systemchanges.StepEvidence{}, errors.New("restart recovery enablement failed")
	}
	digest := sha256.Sum256(executable)
	return systemchanges.StepEvidence{Code: "software-release-installed", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (installer Installer) Reverse(rootPath string, step systemchanges.Step, source io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	if !softwareStep(step) || source == nil {
		return systemchanges.StepEvidence{}, errors.New("Software Lifecycle rollback unavailable")
	}
	rebuilt, rollback, err := installer.fromRollback(source)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	installer = rebuilt
	_, metadata, err := installer.material()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	if err := installer.verifyRollbackTargets(root, metadata); err != nil {
		return systemchanges.StepEvidence{}, errors.New("installed release changed before rollback")
	}
	if installer.manageRecoveryUnit && (installer.disableRecovery == nil || installer.disableRecovery() != nil) {
		return systemchanges.StepEvidence{}, errors.New("restart recovery disablement failed")
	}
	for _, name := range reverseStrings(rollback.Created) {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	}
	for _, name := range installer.componentDirectories() {
		_ = root.Remove(name)
	}
	_ = root.Remove(path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/")))
	_ = root.Remove("etc/sbxr")
	if err := syncInstallDirectories(root, "opt/sbxr/releases", "etc/systemd/system", "usr/local/bin"); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256([]byte("not-installed"))
	return systemchanges.StepEvidence{Code: "software-release-removed", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (installer Installer) fromRollback(source io.Reader) (Installer, installRollback, error) {
	var rollback installRollback
	decoder := json.NewDecoder(io.LimitReader(source, int64(softwarelifecycle.MaxAssetBytes*3)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&rollback) != nil || rollback.Schema != 1 {
		return Installer{}, installRollback{}, errors.New("Software Lifecycle rollback proof invalid")
	}
	rebuilt, err := newInstaller(rollback.Staged, rollback.Archive, rollback.Components)
	if err != nil {
		return Installer{}, installRollback{}, errors.New("Software Lifecycle rollback proof invalid")
	}
	rebuilt.manageRecoveryUnit, rebuilt.disableRecovery = installer.manageRecoveryUnit, installer.disableRecovery
	if !equalStrings(rollback.Created, rebuilt.installedFiles()) {
		return Installer{}, installRollback{}, errors.New("Software Lifecycle rollback proof invalid")
	}
	return rebuilt, rollback, nil
}

func enableInstallRecovery() error  { return setInstallRecovery("enable") }
func disableInstallRecovery() error { return setInstallRecovery("disable") }

func setInstallRecovery(action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", action, "sbxr-recovery.service")
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(nil), io.Discard, io.Discard
	if command.Run() != nil {
		return errors.New("restart recovery unit change failed")
	}
	return nil
}

func (installer Installer) verifyRollbackTargets(root *os.Root, metadata softwarelifecycle.PayloadMetadata) error {
	units, err := softwarelifecycle.RenderManagedUnits(metadata, installer.staged.Identity)
	if err != nil {
		return err
	}
	for _, name := range installer.installedFiles() {
		info, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if name == "usr/local/bin/sbxr" || installer.componentSymlink(name) {
			target, readErr := root.Readlink(name)
			want := installer.staged.InstallPath
			if name != "usr/local/bin/sbxr" {
				want = "/usr/bin/python3"
			}
			if readErr != nil || target != want {
				return errors.New("active executable link mismatch")
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("installed file type mismatch")
		}
		body, readErr := root.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		if name == strings.TrimPrefix(installer.staged.InstallPath, "/") {
			digest := sha256.Sum256(body)
			if hex.EncodeToString(digest[:]) != installer.staged.ExecutableSHA256 {
				return errors.New("installed executable digest mismatch")
			}
			continue
		}
		if component, ok := installer.componentFile(name); ok {
			digest := sha256.Sum256(body)
			if hex.EncodeToString(digest[:]) != component.SHA256 || info.Mode().Perm() != fs.FileMode(component.Mode) {
				return errors.New("managed component mismatch")
			}
			continue
		}
		if !bytes.Equal(body, units[path.Base(name)]) {
			return errors.New("managed unit mismatch")
		}
	}
	return nil
}

func (installer Installer) Inspect(rootPath string, step systemchanges.Step, source io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	if !softwareStep(step) || source == nil {
		return "", errors.New("Software Lifecycle inspection unavailable")
	}
	var err error
	installer, _, err = installer.fromRollback(source)
	if err != nil {
		return "", err
	}
	_, metadata, err := installer.material()
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := installer.verify(root, metadata); err == nil {
		return systemchanges.StepEffectPresent, nil
	}
	for _, name := range installer.installedFiles() {
		if _, statErr := root.Lstat(name); statErr == nil {
			return "", errors.New("partial Software Lifecycle install")
		}
	}
	return systemchanges.StepEffectAbsent, nil
}

func (installer Installer) Check(rootPath string, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	if check.Owner != systemchanges.SoftwareModule || (phase == systemchanges.PrePublication && check.Code != "SOFTWARE-LIFECYCLE-INSTALL-STAGED" || phase == systemchanges.PostPublication && check.Code != "SOFTWARE-LIFECYCLE-INSTALL-AGREEMENT") {
		return systemchanges.Unknown, errors.New("Software Lifecycle check invalid")
	}
	if phase == systemchanges.PrePublication {
		_, _, err := installer.material()
		if err != nil {
			return systemchanges.Failed, nil
		}
		return systemchanges.Healthy, nil
	}
	_, metadata, err := installer.material()
	if err != nil {
		return systemchanges.Failed, nil
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.Unknown, err
	}
	defer root.Close()
	if installer.verify(root, metadata) != nil {
		return systemchanges.Failed, nil
	}
	return systemchanges.Healthy, nil
}

func (installer Installer) material() ([]byte, softwarelifecycle.PayloadMetadata, error) {
	componentDigest := sha256.Sum256(installer.components)
	manifest, componentErr := softwarelifecycle.ValidateComponentArchive(installer.components, installer.staged.Architecture)
	if componentErr != nil || hex.EncodeToString(componentDigest[:]) != installer.staged.ComponentsSHA256 || !equalComponentManifests(manifest, installer.manifest) {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("prepared component archive refused")
	}
	executable, err := installArchiveExecutable(installer.archive)
	if err != nil {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("prepared release archive refused")
	}
	digest := sha256.Sum256(executable)
	metadata, _, metadataErr := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(executable), int64(len(executable)))
	if metadataErr != nil || hex.EncodeToString(digest[:]) != installer.staged.ExecutableSHA256 || metadata.Build != installer.staged.Build || metadata.Architecture != installer.staged.Architecture || metadata.StateSchema != installer.staged.StateSchema {
		return nil, softwarelifecycle.PayloadMetadata{}, errors.New("prepared release identity changed")
	}
	return executable, metadata, nil
}

func equalComponentManifests(left, right softwarelifecycle.ComponentManifest) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (installer Installer) verify(root *os.Root, metadata softwarelifecycle.PayloadMetadata) error {
	units, err := softwarelifecycle.RenderManagedUnits(metadata, installer.staged.Identity)
	if err != nil {
		return err
	}
	executable, err := root.ReadFile(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(executable)
	if hex.EncodeToString(digest[:]) != installer.staged.ExecutableSHA256 {
		return errors.New("installed executable digest mismatch")
	}
	target, err := root.Readlink("usr/local/bin/sbxr")
	if err != nil || target != installer.staged.InstallPath {
		return errors.New("active executable link mismatch")
	}
	for _, name := range softwarelifecycle.ManagedUnitNames() {
		body, readErr := root.ReadFile(path.Join("etc/systemd/system", name))
		if readErr != nil || !bytes.Equal(body, units[name]) {
			return errors.New("managed unit mismatch")
		}
	}
	for _, component := range installer.manifest.Files {
		name := path.Join(path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/")), component.Path)
		if component.Type == "symlink" {
			target, readErr := root.Readlink(name)
			if readErr != nil || target != component.Target {
				return errors.New("managed component link mismatch")
			}
			continue
		}
		info, statErr := root.Lstat(name)
		body, readErr := root.ReadFile(name)
		digest := sha256.Sum256(body)
		if statErr != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != fs.FileMode(component.Mode) || hex.EncodeToString(digest[:]) != component.SHA256 {
			return errors.New("managed component mismatch")
		}
	}
	return nil
}

func (installer Installer) installedFiles() []string {
	releaseDirectory := path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	names := []string{strings.TrimPrefix(installer.staged.InstallPath, "/")}
	for _, component := range installer.manifest.Files {
		names = append(names, path.Join(releaseDirectory, component.Path))
	}
	names = append(names, "usr/local/bin/sbxr")
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		names = append(names, path.Join("etc/systemd/system", unit))
	}
	return names
}

func (installer Installer) installComponents(root *os.Root) error {
	input := bytes.NewReader(installer.components)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, softwarelifecycle.MaxAssetBytes+1))
	if _, err := archive.Next(); err != nil {
		return err
	}
	releaseDirectory := path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	for _, component := range installer.manifest.Files {
		header, err := archive.Next()
		if err != nil || header.Name != component.Path {
			return errors.New("prepared component order changed")
		}
		name := path.Join(releaseDirectory, component.Path)
		if err := ensureComponentParents(root, releaseDirectory, path.Dir(name)); err != nil {
			return err
		}
		if component.Type == "symlink" {
			if err := root.Symlink(component.Target, name); err != nil {
				return err
			}
			continue
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fs.FileMode(component.Mode))
		if err != nil {
			return err
		}
		copied, copyErr := io.Copy(file, archive)
		syncErr, closeErr := file.Sync(), file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || copied != component.Size {
			return errors.New("component write failed")
		}
	}
	return compressed.Close()
}

func ensureComponentParents(root *os.Root, releaseDirectory, directory string) error {
	if directory == "." || directory == releaseDirectory {
		return nil
	}
	parent := path.Dir(directory)
	if parent != directory {
		if err := ensureComponentParents(root, releaseDirectory, parent); err != nil {
			return err
		}
	}
	return ensureInstallDirectory(root, directory, 0o755)
}

func (installer Installer) componentDirectories() []string {
	releaseDirectory := path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	seen := map[string]bool{}
	var directories []string
	for _, component := range installer.manifest.Files {
		for current := path.Dir(path.Join(releaseDirectory, component.Path)); current != releaseDirectory && current != "."; current = path.Dir(current) {
			if !seen[current] {
				seen[current] = true
				directories = append(directories, current)
			}
		}
	}
	sort.Slice(directories, func(i, j int) bool { return strings.Count(directories[i], "/") > strings.Count(directories[j], "/") })
	return directories
}

func (installer Installer) componentFile(name string) (softwarelifecycle.ComponentFile, bool) {
	releaseDirectory := path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	for _, component := range installer.manifest.Files {
		if component.Type == "regular" && name == path.Join(releaseDirectory, component.Path) {
			return component, true
		}
	}
	return softwarelifecycle.ComponentFile{}, false
}

func (installer Installer) componentSymlink(name string) bool {
	releaseDirectory := path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/"))
	for _, component := range installer.manifest.Files {
		if component.Type == "symlink" && name == path.Join(releaseDirectory, component.Path) {
			return true
		}
	}
	return false
}

func softwareStep(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.SoftwareModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && step.Rollback() == systemchanges.RestorePriorConfiguration
}

func installArchiveExecutable(body []byte) ([]byte, error) {
	input := bytes.NewReader(body)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return nil, err
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, softwarelifecycle.MaxAssetBytes+1))
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Size <= 0 || header.Size > softwarelifecycle.MaxAssetBytes || header.Mode != 0o755 || header.Uid != 0 || header.Gid != 0 {
		return nil, errors.New("unsafe archive entry")
	}
	executable, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(executable)) != header.Size {
		return nil, errors.New("truncated archive entry")
	}
	if _, err := archive.Next(); err != io.EOF {
		return nil, errors.New("extra archive entry")
	}
	remaining, err := io.Copy(io.Discard, compressed)
	if err != nil || remaining != 0 || compressed.Close() != nil || input.Len() != 0 {
		return nil, errors.New("trailing archive content")
	}
	return executable, nil
}

func ensureInstallDirectory(root *os.Root, name string, mode fs.FileMode) error {
	if err := root.Mkdir(name, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fs.ErrPermission
	}
	return nil
}

func writeInstallFile(root *os.Root, name string, body []byte, mode fs.FileMode) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func syncInstallDirectories(root *os.Root, names ...string) error {
	for _, name := range names {
		directory, err := root.Open(name)
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func reverseStrings(values []string) []string {
	result := append([]string(nil), values...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}
