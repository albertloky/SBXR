package ubuntu

import (
	"archive/tar"
	"bytes"
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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const maxUpdateSnapshot = 6 * softwarelifecycle.MaxAssetBytes

const (
	updateCandidateArchive    = "candidate/application.tar.gz"
	updateCandidateComponents = "candidate/components.tar.gz"
)

type Updater struct {
	candidate Installer
	prior     Installer
	installed softwarelifecycle.VerifiedRelease
	command   func(context.Context, string, ...string) ([]byte, error)
	expected  softwarelifecycle.ReleaseIdentity
	services  []string
}

func NewUpdater(candidate, installedCandidate softwarelifecycle.InstallCandidate) (Updater, error) {
	return newReleaseChanger(candidate, installedCandidate, false)
}

func NewStagedUpdater(candidate, installedCandidate softwarelifecycle.InstallCandidate, cloudflareProfilesSetUp bool) (Updater, error) {
	updater, err := NewUpdater(candidate, installedCandidate)
	updater.services = updateServices(cloudflareProfilesSetUp)
	return updater, err
}

func NewDowngrader(candidate, installedCandidate softwarelifecycle.InstallCandidate) (Updater, error) {
	return newReleaseChanger(candidate, installedCandidate, true)
}

func NewStagedDowngrader(candidate, installedCandidate softwarelifecycle.InstallCandidate, cloudflareProfilesSetUp bool) (Updater, error) {
	updater, err := NewDowngrader(candidate, installedCandidate)
	updater.services = updateServices(cloudflareProfilesSetUp)
	return updater, err
}

// NewRecoveryUpdater constructs the rollback-only executor for one validated
// unfinished update or downgrade transaction.
func NewRecoveryUpdater(candidate softwarelifecycle.InstallCandidate, installed softwarelifecycle.ReleaseIdentity) (Updater, error) {
	verified, staged, archive, components, valid := candidate.SoftwareLifecyclePreparedUpdate()
	if !valid || verified.Identity == installed || installed.Repository != softwarelifecycle.Repository || !validPathToken(installed.Tag, 128, false) || !validPathToken(installed.Commit, 40, true) || !validPathToken(installed.IndexSHA256, 64, true) {
		return Updater{}, errors.New("verified recovery release unavailable")
	}
	installer, err := newInstaller(staged, archive, components)
	if err != nil {
		return Updater{}, err
	}
	return newRecoveryUpdater(installer, installed)
}

// NewSnapshotRecoveryUpdater reconstructs the authenticated candidate only
// from the protected transaction snapshot supplied to Inspect or Reverse.
func NewSnapshotRecoveryUpdater(installed, candidate softwarelifecycle.ReleaseIdentity) (Updater, error) {
	if installed == candidate || installed.Repository != softwarelifecycle.Repository || candidate.Repository != softwarelifecycle.Repository || !validPathToken(installed.Tag, 128, false) || !validPathToken(installed.Commit, 40, true) || !validPathToken(installed.IndexSHA256, 64, true) || !validPathToken(candidate.Tag, 128, false) || !validPathToken(candidate.Commit, 40, true) || !validPathToken(candidate.IndexSHA256, 64, true) {
		return Updater{}, errors.New("verified recovery release unavailable")
	}
	return Updater{installed: softwarelifecycle.VerifiedRelease{Identity: installed}, expected: candidate, command: runUpdateCommand}, nil
}

func newRecoveryUpdater(candidate Installer, installed softwarelifecycle.ReleaseIdentity) (Updater, error) {
	if candidate.staged.Identity == installed || installed.Repository != softwarelifecycle.Repository || !validPathToken(installed.Tag, 128, false) || !validPathToken(installed.Commit, 40, true) || !validPathToken(installed.IndexSHA256, 64, true) {
		return Updater{}, errors.New("verified recovery release unavailable")
	}
	return Updater{candidate: candidate, installed: softwarelifecycle.VerifiedRelease{Identity: installed}, command: runUpdateCommand}, nil
}

func newReleaseChanger(candidate, installedCandidate softwarelifecycle.InstallCandidate, downgrade bool) (Updater, error) {
	verified, staged, archive, components, valid := candidate.SoftwareLifecyclePreparedUpdate()
	installed, priorStaged, priorArchive, priorComponents, installedValid := installedCandidate.SoftwareLifecyclePreparedUpdate()
	validDirection := verified.Sequence > installed.Sequence && verified.StateSchema >= installed.StateSchema
	if downgrade {
		validDirection = verified.Sequence < installed.Sequence && verified.StateSchema == installed.StateSchema
	}
	if !valid || !installedValid || verified.Identity == installed.Identity || !validDirection || verified.MinimumUpdaterSchema > 1 {
		return Updater{}, errors.New("verified update candidate unavailable")
	}
	installer, err := newInstaller(staged, archive, components)
	if err != nil {
		return Updater{}, err
	}
	prior, err := newInstaller(priorStaged, priorArchive, priorComponents)
	if err != nil {
		return Updater{}, err
	}
	var updater Updater
	if downgrade {
		updater, err = newDowngrader(installer, prior, installed, verified.Sequence)
	} else {
		updater, err = newUpdater(installer, prior, installed)
	}
	updater.command = runUpdateCommand
	return updater, err
}

func newDowngrader(candidate, prior Installer, installed softwarelifecycle.VerifiedRelease, candidateSequence uint64) (Updater, error) {
	if candidateSequence == 0 || candidateSequence >= installed.Sequence || candidate.staged.StateSchema != installed.StateSchema {
		return Updater{}, errors.New("verified downgrade candidate unavailable")
	}
	return newUpdater(candidate, prior, installed)
}

func newUpdater(candidate, prior Installer, installed softwarelifecycle.VerifiedRelease) (Updater, error) {
	if !validUpdaterInstalled(installed) || installed.Identity != prior.staged.Identity || installed.StateSchema != prior.staged.StateSchema || installed.Identity == candidate.staged.Identity {
		return Updater{}, errors.New("installed release unavailable")
	}
	return Updater{candidate: candidate, prior: prior, installed: installed, services: updateServices(true)}, nil
}

func updateServices(cloudflareProfilesSetUp bool) []string {
	if !cloudflareProfilesSetUp {
		return []string{"sbxr-subscription.service", "xray.service"}
	}
	return []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"}
}

func validUpdateServices(services []string) bool {
	return slices.Equal(services, updateServices(false)) || slices.Equal(services, updateServices(true))
}

func validUpdaterInstalled(installed softwarelifecycle.VerifiedRelease) bool {
	identity := installed.Identity
	return identity.Repository == softwarelifecycle.Repository && validPathToken(identity.Tag, 128, false) && validPathToken(identity.Commit, 40, true) && validPathToken(identity.IndexSHA256, 64, true) && installed.Sequence > 0 && installed.StateSchema > 0 && installed.StateSchema <= 2 && installed.MinimumUpdaterSchema <= 1
}

func validPathToken(value string, size int, hexOnly bool) bool {
	if len(value) == 0 || len(value) > size || hexOnly && len(value) != size {
		return false
	}
	for index, character := range value {
		if hexOnly && (character < '0' || character > '9') && (character < 'a' || character > 'f') || !hexOnly && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._+-", character)) {
			return false
		}
	}
	return true
}

type updateSnapshotHeader struct {
	Schema    int                               `json:"schema"`
	Release   softwarelifecycle.ReleaseIdentity `json:"release"`
	Candidate softwarelifecycle.StagedRelease   `json:"candidate"`
	Services  []string                          `json:"services"`
}

type updateSnapshotEntry struct {
	name, link string
	mode       fs.FileMode
	typeflag   byte
	body       []byte
}

func (updater Updater) CaptureRollback(rootPath string, step systemchanges.Step, write func(io.Reader) error) error {
	if !softwareStep(step) || write == nil {
		return errors.New("Software Lifecycle update rollback capture unavailable")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := updater.verifyPrior(root); err != nil {
		return err
	}
	var snapshot bytes.Buffer
	archive := tar.NewWriter(&snapshot)
	header, _ := json.Marshal(updateSnapshotHeader{Schema: 3, Release: updater.installed.Identity, Candidate: updater.candidate.staged, Services: updater.services})
	if err := writeUpdateSnapshotEntry(archive, updateSnapshotEntry{name: "snapshot.json", mode: 0o600, typeflag: tar.TypeReg, body: header}); err != nil {
		return err
	}
	if err := writeUpdateSnapshotEntry(archive, updateSnapshotEntry{name: updateCandidateArchive, mode: 0o600, typeflag: tar.TypeReg, body: updater.candidate.archive}); err != nil {
		return err
	}
	if err := writeUpdateSnapshotEntry(archive, updateSnapshotEntry{name: updateCandidateComponents, mode: 0o600, typeflag: tar.TypeReg, body: updater.candidate.components}); err != nil {
		return err
	}
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	err = fs.WalkDir(root.FS(), priorDirectory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || (info.Mode()&os.ModeSymlink == 0 && info.Mode()&0o022 != 0) || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return fs.ErrPermission
		}
		value := updateSnapshotEntry{name: name, mode: info.Mode().Perm()}
		switch {
		case info.IsDir():
			value.typeflag = tar.TypeDir
		case info.Mode().IsRegular():
			value.typeflag = tar.TypeReg
			value.body, err = root.ReadFile(name)
		case info.Mode()&os.ModeSymlink != 0:
			value.typeflag = tar.TypeSymlink
			value.link, err = root.Readlink(name)
		default:
			return errors.New("unsupported prior release entry")
		}
		if err != nil || snapshot.Len()+len(value.body) > maxUpdateSnapshot {
			return errors.New("prior release snapshot refused")
		}
		return writeUpdateSnapshotEntry(archive, value)
	})
	if err != nil {
		return err
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		name := path.Join("etc/systemd/system", unit)
		info, statErr := root.Lstat(name)
		body, readErr := root.ReadFile(name)
		if statErr != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			return errors.New("prior managed unit unavailable")
		}
		if err := writeUpdateSnapshotEntry(archive, updateSnapshotEntry{name: name, mode: 0o644, typeflag: tar.TypeReg, body: body}); err != nil {
			return err
		}
	}
	if err := writeUpdateSnapshotEntry(archive, updateSnapshotEntry{name: "usr/local/bin/sbxr", mode: 0o777, typeflag: tar.TypeSymlink, link: softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)}); err != nil || archive.Close() != nil || snapshot.Len() > maxUpdateSnapshot {
		return errors.New("prior release snapshot refused")
	}
	return write(bytes.NewReader(snapshot.Bytes()))
}

func writeUpdateSnapshotEntry(archive *tar.Writer, entry updateSnapshotEntry) error {
	header := &tar.Header{Name: entry.name, Mode: int64(entry.mode.Perm()), Size: int64(len(entry.body)), Typeflag: entry.typeflag, Linkname: entry.link, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0), AccessTime: time.Unix(0, 0), ChangeTime: time.Unix(0, 0), Format: tar.FormatPAX}
	if err := archive.WriteHeader(header); err != nil {
		return err
	}
	_, err := archive.Write(entry.body)
	return err
}

func (updater Updater) Activate(rootPath string, step systemchanges.Step, _ time.Duration) (systemchanges.StepEvidence, error) {
	if !softwareStep(step) {
		return systemchanges.StepEvidence{}, errors.New("Software Lifecycle update step invalid")
	}
	executable, metadata, err := updater.candidate.material()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	units, err := softwarelifecycle.RenderManagedUnits(metadata, updater.candidate.staged.Identity)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	if err := updater.verifyPrior(root); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	releaseDirectory := path.Dir(strings.TrimPrefix(updater.candidate.staged.InstallPath, "/"))
	if err := ensureInstallDirectory(root, releaseDirectory, 0o755); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := writeInstallFile(root, strings.TrimPrefix(updater.candidate.staged.InstallPath, "/"), executable, 0o755); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := updater.candidate.installComponents(root); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		if err := replaceInstallFile(root, path.Join("etc/systemd/system", unit), units[unit], 0o644); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := replaceInstallSymlink(root, "usr/local/bin/sbxr", updater.candidate.staged.InstallPath); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := updater.candidate.verify(root, metadata); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	if err := root.RemoveAll(priorDirectory); err != nil || syncInstallDirectories(root, "opt/sbxr/releases", "etc/systemd/system", "usr/local/bin") != nil {
		return systemchanges.StepEvidence{}, errors.New("prior release removal failed")
	}
	digest := sha256.Sum256(executable)
	return systemchanges.StepEvidence{Code: "software-release-updated", SHA256: hex.EncodeToString(digest[:])}, nil
}

func replaceInstallFile(root *os.Root, name string, body []byte, mode fs.FileMode) error {
	temporary := name + ".sbxr-update"
	if err := writeInstallFile(root, temporary, body, mode); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return nil
}

func replaceInstallSymlink(root *os.Root, name, target string) error {
	temporary := name + ".sbxr-update"
	if err := root.Symlink(target, temporary); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return nil
}

func (updater Updater) Reverse(rootPath string, step systemchanges.Step, source io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if !softwareStep(step) || source == nil {
		return systemchanges.StepEvidence{}, errors.New("Software Lifecycle update rollback unavailable")
	}
	entries, candidate, err := updater.readSnapshot(source)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	updater.candidate = candidate
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	candidateDirectory := strings.TrimPrefix(path.Dir(updater.candidate.staged.InstallPath), "/")
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	if err := updater.verifyRollbackSurface(root, entries, candidateDirectory, priorDirectory); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := root.RemoveAll(candidateDirectory); err != nil || root.RemoveAll(priorDirectory) != nil {
		return systemchanges.StepEvidence{}, errors.New("release rollback cleanup failed")
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		_ = root.Remove(path.Join("etc/systemd/system", unit))
		_ = root.Remove(path.Join("etc/systemd/system", unit) + ".sbxr-update")
	}
	_ = root.Remove("usr/local/bin/sbxr")
	_ = root.Remove("usr/local/bin/sbxr.sbxr-update")
	for _, entry := range entries {
		switch entry.typeflag {
		case tar.TypeDir:
			if err := ensureInstallDirectory(root, entry.name, entry.mode); err != nil {
				return systemchanges.StepEvidence{}, err
			}
		case tar.TypeReg:
			if err := writeInstallFile(root, entry.name, entry.body, entry.mode); err != nil {
				return systemchanges.StepEvidence{}, err
			}
		case tar.TypeSymlink:
			if err := root.Symlink(entry.link, entry.name); err != nil {
				return systemchanges.StepEvidence{}, err
			}
		}
	}
	if err := updater.verifySnapshot(root, entries); err != nil || syncInstallDirectories(root, "opt/sbxr/releases", "etc/systemd/system", "usr/local/bin") != nil {
		return systemchanges.StepEvidence{}, errors.New("prior release restoration failed")
	}
	if updater.command != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if _, err := updater.command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior service reload failed")
		}
		if _, err := updater.command(ctx, "/usr/bin/systemctl", append([]string{"restart"}, updater.services...)...); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior service restart failed")
		}
	}
	digest := sha256.Sum256([]byte(updater.installed.Identity.IndexSHA256))
	return systemchanges.StepEvidence{Code: "software-release-restored", SHA256: hex.EncodeToString(digest[:])}, nil
}

func runUpdateCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arguments...).CombinedOutput()
}

func (updater Updater) CleanupComplete(rootPath string) error {
	identity := updater.candidate.staged.Identity
	if identity == (softwarelifecycle.ReleaseIdentity{}) {
		identity = updater.expected
	}
	if identity.Repository != softwarelifecycle.Repository || !validPathToken(identity.Tag, 128, false) || !validPathToken(identity.Commit, 40, true) || !validPathToken(identity.IndexSHA256, 64, true) {
		return errors.New("completed update candidate unavailable")
	}
	directory := filepath.Join(rootPath, "var/lib/sbxr/software-lifecycle")
	if _, err := os.Lstat(directory); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	store := NewCandidateStoreAt(directory)
	record, err := store.Load()
	if errors.Is(err, softwarelifecycle.ErrCandidateNotFound) {
		return nil
	}
	digest := sha256.Sum256(record.Evidence.Index)
	if err != nil || record.Evidence.Repository != identity.Repository || record.Evidence.Tag != identity.Tag || record.Evidence.Commit != identity.Commit || hex.EncodeToString(digest[:]) != identity.IndexSHA256 {
		return err
	}
	return store.RemoveVerified(identity)
}

func (updater Updater) verifyRollbackSurface(root *os.Root, entries []updateSnapshotEntry, candidateDirectory, priorDirectory string) error {
	snapshot := make(map[string]updateSnapshotEntry, len(entries))
	for _, entry := range entries {
		snapshot[entry.name] = entry
	}
	if err := verifySnapshotTree(root, priorDirectory, snapshot); err != nil {
		return errors.New("prior release changed before rollback")
	}
	executable, metadata, err := updater.candidate.material()
	if err != nil || verifyCandidateTree(root, updater.candidate, candidateDirectory, executable) != nil {
		return errors.New("candidate release changed before rollback")
	}
	units, err := softwarelifecycle.RenderManagedUnits(metadata, updater.candidate.staged.Identity)
	if err != nil {
		return err
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		name := path.Join("etc/systemd/system", unit)
		info, statErr := root.Lstat(name)
		if errors.Is(statErr, fs.ErrNotExist) {
			continue
		}
		body, readErr := root.ReadFile(name)
		prior := snapshot[name]
		if statErr != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || !bytes.Equal(body, units[unit]) && !bytes.Equal(body, prior.body) {
			return errors.New("managed unit changed before rollback")
		}
		temporary := name + ".sbxr-update"
		if tempInfo, tempErr := root.Lstat(temporary); tempErr == nil {
			tempBody, readErr := root.ReadFile(temporary)
			if readErr != nil || !tempInfo.Mode().IsRegular() || tempInfo.Mode().Perm() != 0o644 || !bytes.Equal(tempBody, units[unit]) {
				return errors.New("managed unit temporary changed before rollback")
			}
		} else if !errors.Is(tempErr, fs.ErrNotExist) {
			return tempErr
		}
	}
	active, activeErr := root.Readlink("usr/local/bin/sbxr")
	priorTarget := softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) || activeErr == nil && active != priorTarget && active != updater.candidate.staged.InstallPath {
		return errors.New("active executable changed before rollback")
	}
	if temporary, tempErr := root.Readlink("usr/local/bin/sbxr.sbxr-update"); tempErr == nil && temporary != updater.candidate.staged.InstallPath || tempErr != nil && !errors.Is(tempErr, fs.ErrNotExist) {
		return errors.New("active executable temporary changed before rollback")
	}
	return nil
}

func verifySnapshotTree(root *os.Root, directory string, snapshot map[string]updateSnapshotEntry) error {
	if _, err := root.Lstat(directory); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return fs.WalkDir(root.FS(), directory, func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entry, ok := snapshot[name]
		if !ok {
			return errors.New("unexpected prior release entry")
		}
		return verifySnapshotEntry(root, entry)
	})
}

func verifySnapshotEntry(root *os.Root, entry updateSnapshotEntry) error {
	info, err := root.Lstat(entry.name)
	if err != nil {
		return err
	}
	switch entry.typeflag {
	case tar.TypeDir:
		if !info.IsDir() || info.Mode().Perm() != entry.mode {
			return errors.New("snapshot directory mismatch")
		}
	case tar.TypeReg:
		body, readErr := root.ReadFile(entry.name)
		if readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != entry.mode || !bytes.Equal(body, entry.body) {
			return errors.New("snapshot file mismatch")
		}
	case tar.TypeSymlink:
		target, readErr := root.Readlink(entry.name)
		if readErr != nil || target != entry.link {
			return errors.New("snapshot link mismatch")
		}
	}
	return nil
}

func verifyCandidateTree(root *os.Root, candidate Installer, directory string, executable []byte) error {
	if _, err := root.Lstat(directory); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	executableName := strings.TrimPrefix(candidate.staged.InstallPath, "/")
	return fs.WalkDir(root.FS(), directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if name == directory {
			if !info.IsDir() || info.Mode().Perm() != 0o755 {
				return errors.New("candidate directory mismatch")
			}
			return nil
		}
		if name == executableName {
			body, readErr := root.ReadFile(name)
			if readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || !bytes.Equal(body, executable) {
				return errors.New("candidate executable mismatch")
			}
			return nil
		}
		component, ok := candidateComponent(candidate, name)
		if !ok {
			for _, expected := range candidate.componentDirectories() {
				if name == expected && info.IsDir() {
					return nil
				}
			}
			return errors.New("unexpected candidate release entry")
		}
		if component.Type == "symlink" {
			target, readErr := root.Readlink(name)
			if readErr != nil || target != component.Target {
				return errors.New("candidate component link mismatch")
			}
			return nil
		}
		body, readErr := root.ReadFile(name)
		digest := sha256.Sum256(body)
		if readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != fs.FileMode(component.Mode) || hex.EncodeToString(digest[:]) != component.SHA256 {
			return errors.New("candidate component mismatch")
		}
		return nil
	})
}

func candidateComponent(candidate Installer, name string) (softwarelifecycle.ComponentFile, bool) {
	releaseDirectory := path.Dir(strings.TrimPrefix(candidate.staged.InstallPath, "/"))
	for _, component := range candidate.manifest.Files {
		if name == path.Join(releaseDirectory, component.Path) {
			return component, true
		}
	}
	return softwarelifecycle.ComponentFile{}, false
}

func (updater Updater) Inspect(rootPath string, step systemchanges.Step, source io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	if !softwareStep(step) || source == nil {
		return "", errors.New("Software Lifecycle update inspection unavailable")
	}
	entries, candidate, err := updater.readSnapshot(source)
	if err != nil {
		return "", err
	}
	updater.candidate = candidate
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	_, metadata, materialErr := updater.candidate.material()
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	if materialErr == nil && updater.candidate.verify(root, metadata) == nil {
		if _, statErr := root.Lstat(priorDirectory); errors.Is(statErr, fs.ErrNotExist) {
			return systemchanges.StepEffectPresent, nil
		}
	}
	candidateDirectory := strings.TrimPrefix(path.Dir(updater.candidate.staged.InstallPath), "/")
	if updater.verifySnapshot(root, entries) == nil {
		if _, statErr := root.Lstat(candidateDirectory); errors.Is(statErr, fs.ErrNotExist) {
			return systemchanges.StepEffectAbsent, nil
		}
	}
	return "", errors.New("partial Software Lifecycle update")
}

func (updater Updater) Check(rootPath string, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	if check.Owner != systemchanges.SoftwareModule || phase == systemchanges.PrePublication && check.Code != "SOFTWARE-LIFECYCLE-UPDATE-STAGED" || phase == systemchanges.PostPublication && check.Code != "SOFTWARE-LIFECYCLE-UPDATE-AGREEMENT" {
		return systemchanges.Unknown, errors.New("Software Lifecycle update check invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.Unknown, err
	}
	defer root.Close()
	if phase == systemchanges.PrePublication {
		_, metadata, err := updater.candidate.material()
		if err != nil || updater.candidate.verify(root, metadata) != nil {
			return systemchanges.Failed, nil
		}
		priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
		if _, err := root.Lstat(priorDirectory); !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.Failed, nil
		}
		return systemchanges.Healthy, nil
	}
	_, metadata, err := updater.candidate.material()
	if err != nil || updater.candidate.verify(root, metadata) != nil {
		return systemchanges.Failed, nil
	}
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	if _, err := root.Lstat(priorDirectory); !errors.Is(err, fs.ErrNotExist) {
		return systemchanges.Failed, nil
	}
	return systemchanges.Healthy, nil
}

func (updater Updater) verifyPrior(root *os.Root) error {
	target, err := root.Readlink("usr/local/bin/sbxr")
	if err != nil || target != softwarelifecycle.ReleaseInstallPath(updater.installed.Identity) {
		return errors.New("installed release changed")
	}
	_, metadata, err := updater.prior.material()
	if err != nil || updater.prior.verify(root, metadata) != nil {
		return errors.New("installed release content changed")
	}
	for _, name := range append([]string{strings.TrimPrefix(target, "/")}, updater.prior.installedFiles()...) {
		info, statErr := root.Lstat(name)
		if statErr != nil || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Mode().IsRegular() && info.Mode()&0o022 != 0 {
			return errors.New("installed release ownership changed")
		}
	}
	candidateDirectory := strings.TrimPrefix(path.Dir(updater.candidate.staged.InstallPath), "/")
	if _, err := root.Lstat(candidateDirectory); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("candidate release target occupied")
	}
	return nil
}

func (updater *Updater) readSnapshot(source io.Reader) ([]updateSnapshotEntry, Installer, error) {
	raw, err := io.ReadAll(io.LimitReader(source, maxUpdateSnapshot+1))
	if err != nil || len(raw) > maxUpdateSnapshot || !exactTarBoundary(raw) {
		return nil, Installer{}, errors.New("update snapshot boundary invalid")
	}
	archive := tar.NewReader(bytes.NewReader(raw))
	header, err := archive.Next()
	if err != nil || header.Name != "snapshot.json" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 1<<20 {
		return nil, Installer{}, errors.New("update snapshot header invalid")
	}
	body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	var metadata updateSnapshotHeader
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || int64(len(body)) != header.Size || decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF || metadata.Release != updater.installed.Identity || metadata.Schema != 2 && metadata.Schema != 3 || metadata.Schema == 2 && len(metadata.Services) != 0 || metadata.Schema == 3 && !validUpdateServices(metadata.Services) {
		return nil, Installer{}, errors.New("update snapshot identity invalid")
	}
	if metadata.Schema == 2 {
		metadata.Services = updateServices(true)
	}
	updater.services = append([]string(nil), metadata.Services...)
	candidateMaterial := make(map[string][]byte, 2)
	for _, name := range []string{updateCandidateArchive, updateCandidateComponents} {
		header, err = archive.Next()
		if err != nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Mode != 0o600 || header.Size <= 0 || header.Size > softwarelifecycle.MaxAssetBytes {
			return nil, Installer{}, errors.New("update snapshot candidate invalid")
		}
		candidateMaterial[name], err = io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(candidateMaterial[name])) != header.Size {
			return nil, Installer{}, errors.New("update snapshot candidate truncated")
		}
	}
	candidate, err := newInstaller(metadata.Candidate, candidateMaterial[updateCandidateArchive], candidateMaterial[updateCandidateComponents])
	if err != nil || updater.expected != (softwarelifecycle.ReleaseIdentity{}) && metadata.Candidate.Identity != updater.expected || updater.candidate.staged.Identity != (softwarelifecycle.ReleaseIdentity{}) && (metadata.Candidate != updater.candidate.staged || !bytes.Equal(candidate.archive, updater.candidate.archive) || !bytes.Equal(candidate.components, updater.candidate.components)) {
		return nil, Installer{}, errors.New("update snapshot candidate identity invalid")
	}
	priorDirectory := strings.TrimPrefix(path.Dir(softwarelifecycle.ReleaseInstallPath(updater.installed.Identity)), "/")
	allowedUnits := map[string]bool{}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		allowedUnits[path.Join("etc/systemd/system", unit)] = true
	}
	seen := map[string]bool{}
	var entries []updateSnapshotEntry
	for {
		header, err = archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header.Name == "" || seen[header.Name] || header.Name != priorDirectory && !strings.HasPrefix(header.Name, priorDirectory+"/") && !allowedUnits[header.Name] && header.Name != "usr/local/bin/sbxr" || header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeSymlink || header.Size < 0 || header.Size > maxUpdateSnapshot {
			return nil, Installer{}, errors.New("update snapshot entry invalid")
		}
		seen[header.Name] = true
		entry := updateSnapshotEntry{name: header.Name, link: header.Linkname, mode: fs.FileMode(header.Mode), typeflag: header.Typeflag}
		if header.Typeflag == tar.TypeReg {
			entry.body, err = io.ReadAll(io.LimitReader(archive, header.Size+1))
			if err != nil || int64(len(entry.body)) != header.Size {
				return nil, Installer{}, errors.New("update snapshot entry truncated")
			}
		}
		entries = append(entries, entry)
	}
	if !seen[priorDirectory] || !seen["usr/local/bin/sbxr"] || len(seen) < len(allowedUnits)+2 {
		return nil, Installer{}, errors.New("update snapshot incomplete")
	}
	for name := range allowedUnits {
		if !seen[name] {
			return nil, Installer{}, errors.New("update snapshot unit missing")
		}
	}
	return entries, candidate, nil
}

func exactTarBoundary(raw []byte) bool {
	zeroBlock := make([]byte, 512)
	for offset := 0; offset+512 <= len(raw); {
		block := raw[offset : offset+512]
		if bytes.Equal(block, zeroBlock) {
			return offset+1024 == len(raw) && bytes.Equal(raw[offset+512:], zeroBlock)
		}
		sizeText := strings.Trim(string(block[124:136]), " \x00")
		size := int64(0)
		var err error
		if sizeText != "" {
			size, err = strconv.ParseInt(sizeText, 8, 64)
		}
		if err != nil || size < 0 {
			return false
		}
		blocks := (size + 511) / 512
		next := int64(offset+512) + blocks*512
		if next > int64(len(raw)) {
			return false
		}
		offset = int(next)
	}
	return false
}

func (updater Updater) verifySnapshot(root *os.Root, entries []updateSnapshotEntry) error {
	for _, entry := range entries {
		if err := verifySnapshotEntry(root, entry); err != nil {
			return err
		}
	}
	return nil
}
