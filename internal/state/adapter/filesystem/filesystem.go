// Package filesystem provides the one production Desired State storage Adapter.
package filesystem

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/albertloky/SBXR/internal/state"
)

const (
	StateDirectory = "/var/lib/sbxr/state"
	StatePath      = StateDirectory + "/state.json"
)

type adapter struct {
	root           string
	uid            int
	beforeFileOpen func()
	interrupt      func(string) error
}

// New wires State to the root-owned production Adapter at the fixed State path.
// The Adapter itself is not exposed, so production callers cannot read around
// the State Interface.
func New() state.Interface { return state.New(newAt(filepath.Dir(StateDirectory), 0)) }

// NewAt wires State to the production filesystem semantics under a controlled root.
func NewAt(root string) state.Interface { return state.New(newAt(root, os.Geteuid())) }

func newAt(root string, uid int) state.Storage { return adapter{root: root, uid: uid} }

func (a adapter) Read() ([]byte, error) {
	root, err := openDirectory(a.root, 0o700, a.uid)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	stateDirectory, err := openRootDirectory(root, "state", 0o700, a.uid)
	if err != nil {
		return nil, err
	}
	defer stateDirectory.Close()

	return readVerifiedFile(stateDirectory, "state.json", a.uid, a.beforeFileOpen)
}

func (a adapter) Publish(expectedPrior, candidate []byte, candidateSHA256 string) ([]byte, error) {
	digest := sha256.Sum256(candidate)
	if hex.EncodeToString(digest[:]) != candidateSHA256 {
		return nil, storageFinding("STATE-PUBLICATION-CHECKSUM", "prepared Desired State", "the prepared document checksum disagrees", "the exact checksum bound during preparation", "changed candidate bytes cannot be published", "resolve the active Change Set through System Changes")
	}
	root, err := openDirectory(a.root, 0o700, a.uid)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	stateDirectory, err := a.openStateDirectoryForPublish(root, expectedPrior)
	if err != nil {
		return nil, err
	}
	defer stateDirectory.Close()
	if err := verifyExpectedPrior(stateDirectory, expectedPrior, a.uid); err != nil {
		return nil, err
	}

	const next = "state.json.next"
	if err := a.removeStaleCandidate(stateDirectory, next); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-candidate-write"); err != nil {
		return nil, err
	}
	file, err := stateDirectory.OpenFile(next, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	removeNext := true
	defer func() {
		file.Close()
		if removeNext {
			if stateDirectory.Remove(next) == nil {
				_ = syncRoot(stateDirectory)
			}
		}
	}()
	if written, writeErr := file.Write(candidate); writeErr != nil || written != len(candidate) {
		if writeErr != nil {
			return nil, writeErr
		}
		return nil, io.ErrShortWrite
	}
	if err := a.checkpoint("after-candidate-write"); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-candidate-flush"); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := a.checkpoint("after-candidate-flush"); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-candidate-verify"); err != nil {
		return nil, err
	}
	prepared, err := readVerifiedFile(stateDirectory, next, a.uid, nil)
	if err != nil {
		return nil, err
	}
	preparedDigest := sha256.Sum256(prepared)
	if !bytes.Equal(prepared, candidate) || hex.EncodeToString(preparedDigest[:]) != candidateSHA256 {
		return nil, storageFinding("STATE-PUBLICATION-CHECKSUM", "prepared Desired State", "the flushed candidate bytes disagree", "the exact checksum bound during preparation", "changed candidate bytes cannot be published", "resolve the active Change Set through System Changes")
	}
	if err := a.checkpoint("after-candidate-verify"); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-replace"); err != nil {
		return nil, err
	}
	if err := verifyExpectedPrior(stateDirectory, expectedPrior, a.uid); err != nil {
		return nil, err
	}
	if err := stateDirectory.Rename(next, "state.json"); err != nil {
		return nil, err
	}
	removeNext = false
	if err := a.checkpoint("after-replace"); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-directory-flush"); err != nil {
		return nil, err
	}
	if err := syncRoot(stateDirectory); err != nil {
		return nil, err
	}
	if err := a.checkpoint("after-directory-flush"); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-readback"); err != nil {
		return nil, err
	}
	readback, err := readVerifiedFile(stateDirectory, "state.json", a.uid, nil)
	if err != nil {
		return nil, err
	}
	if err := a.checkpoint("after-readback"); err != nil {
		return nil, err
	}
	return readback, nil
}

func (a adapter) Restore(expectedCurrent, prior []byte) ([]byte, error) {
	if len(prior) > 0 {
		digest := sha256.Sum256(prior)
		return a.Publish(expectedCurrent, prior, hex.EncodeToString(digest[:]))
	}
	root, err := openDirectory(a.root, 0o700, a.uid)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	stateDirectory, err := openRootDirectory(root, "state", 0o700, a.uid)
	if err != nil {
		return nil, err
	}
	defer stateDirectory.Close()
	if err := verifyExpectedPrior(stateDirectory, expectedCurrent, a.uid); err != nil {
		return nil, err
	}
	if err := a.removeStaleCandidate(stateDirectory, "state.json.next"); err != nil {
		return nil, err
	}
	if err := stateDirectory.Remove("state.json"); err != nil {
		return nil, err
	}
	if err := syncRoot(stateDirectory); err != nil {
		return nil, err
	}
	if _, err := a.Read(); !errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("removed Desired State remained readable")
	}
	return nil, nil
}

func (a adapter) removeStaleCandidate(stateDirectory *os.Root, name string) error {
	info, err := stateDirectory.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if finding := verifyFile(info, a.uid); finding != nil {
		return finding
	}
	if err := a.checkpoint("before-stale-candidate-remove"); err != nil {
		return err
	}
	if err := stateDirectory.Remove(name); err != nil {
		return err
	}
	if err := a.checkpoint("after-stale-candidate-remove"); err != nil {
		return err
	}
	if err := a.checkpoint("before-stale-candidate-directory-flush"); err != nil {
		return err
	}
	if err := syncRoot(stateDirectory); err != nil {
		return err
	}
	return a.checkpoint("after-stale-candidate-directory-flush")
}

func (a adapter) openStateDirectoryForPublish(root *os.Root, expectedPrior []byte) (*os.Root, error) {
	stateDirectory, err := openRootDirectory(root, "state", 0o700, a.uid)
	if err == nil {
		return stateDirectory, nil
	}
	if !errors.Is(err, fs.ErrNotExist) || len(expectedPrior) != 0 {
		return nil, err
	}
	if err := a.checkpoint("before-state-directory-create"); err != nil {
		return nil, err
	}
	if err := root.Mkdir("state", 0o700); err != nil {
		return nil, err
	}
	if err := a.checkpoint("after-state-directory-create"); err != nil {
		return nil, err
	}
	if err := a.checkpoint("before-parent-directory-flush"); err != nil {
		return nil, err
	}
	if err := syncRoot(root); err != nil {
		return nil, err
	}
	if err := a.checkpoint("after-parent-directory-flush"); err != nil {
		return nil, err
	}
	return openRootDirectory(root, "state", 0o700, a.uid)
}

func (a adapter) checkpoint(point string) error {
	if a.interrupt == nil {
		return nil
	}
	return a.interrupt(point)
}

func verifyExpectedPrior(stateDirectory *os.Root, expected []byte, uid int) error {
	current, err := readVerifiedFile(stateDirectory, "state.json", uid, nil)
	if len(expected) == 0 && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil && bytes.Equal(current, expected) {
		return nil
	}
	return storageFinding("STATE-PUBLICATION-STALE", "prior Desired State", "current bytes differ from the prepared baseline", "the exact prior State bound to the Change Set", "publication cannot replace a different lineage", "resolve the active Change Set through System Changes")
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readVerifiedFile(stateDirectory *os.Root, name string, uid int, beforeOpen func()) ([]byte, error) {
	before, err := stateDirectory.Lstat(name)
	if err != nil {
		return nil, err
	}
	if finding := verifyFile(before, uid); finding != nil {
		return nil, finding
	}
	if beforeOpen != nil {
		beforeOpen()
	}
	file, err := stateDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := stateDirectory.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) {
		return nil, storageFinding("STATE-STORAGE-PATH", "Desired State path", "the file changed during protected open", "one stable state.json path", "path substitution can bypass the protected boundary", "restore the protected path and check again")
	}
	if finding := verifyFile(after, uid); finding != nil {
		return nil, finding
	}
	return io.ReadAll(file)
}

func openDirectory(path string, mode os.FileMode, uid int) (*os.Root, error) {
	return openVerifiedDirectory(func() (os.FileInfo, error) { return os.Lstat(path) }, func() (*os.Root, error) { return os.OpenRoot(path) }, mode, uid)
}

func openRootDirectory(parent *os.Root, name string, mode os.FileMode, uid int) (*os.Root, error) {
	return openVerifiedDirectory(func() (os.FileInfo, error) { return parent.Lstat(name) }, func() (*os.Root, error) { return parent.OpenRoot(name) }, mode, uid)
}

func openVerifiedDirectory(lstat func() (os.FileInfo, error), open func() (*os.Root, error), mode os.FileMode, uid int) (*os.Root, error) {
	before, err := lstat()
	if err != nil {
		return nil, err
	}
	if finding := verifyDirectory(before, mode, uid); finding != nil {
		return nil, finding
	}
	root, err := open()
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	current, err := lstat()
	if err != nil {
		root.Close()
		return nil, err
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) {
		root.Close()
		return nil, storageFinding("STATE-STORAGE-PATH", "Desired State directory", "the directory changed during protected open", "one stable root-owned directory", "path substitution can bypass the protected boundary", "restore the protected path and check again")
	}
	if finding := verifyDirectory(current, mode, uid); finding != nil {
		root.Close()
		return nil, finding
	}
	return root, nil
}

func verifyDirectory(info os.FileInfo, mode os.FileMode, uid int) *state.Finding {
	if info.Mode()&os.ModeSymlink != 0 {
		return storageFinding("STATE-STORAGE-SYMLINK", "Desired State directory", "a symbolic link", "a real protected directory", "symbolic links can substitute another path", "restore the protected directory and check again")
	}
	if !info.IsDir() {
		return storageFinding("STATE-STORAGE-TYPE", "Desired State directory", "an unexpected file type", "a directory", "the protected boundary is not the expected type", "restore the protected directory and check again")
	}
	if owner(info) != uid {
		return storageFinding("STATE-STORAGE-OWNER", "Desired State directory", "the wrong owner", "root ownership", "another identity can control the protected boundary", "correct ownership and check again")
	}
	if !exactMode(info.Mode(), mode) {
		return storageFinding("STATE-STORAGE-MODE", "Desired State directory", "permissions other than 0700", "exact mode 0700", "broader permissions can expose protected State", "correct permissions and check again")
	}
	return nil
}

func verifyFile(info os.FileInfo, uid int) *state.Finding {
	if info.Mode()&os.ModeSymlink != 0 {
		return storageFinding("STATE-STORAGE-SYMLINK", "Desired State file", "a symbolic link", "one regular protected file", "symbolic links can substitute another path", "restore state.json and check again")
	}
	if !info.Mode().IsRegular() {
		return storageFinding("STATE-STORAGE-TYPE", "Desired State file", "an unexpected file type", "one regular file", "the protected boundary is not the expected type", "restore state.json and check again")
	}
	if owner(info) != uid {
		return storageFinding("STATE-STORAGE-OWNER", "Desired State file", "the wrong owner", "root ownership", "another identity can control protected State", "correct ownership and check again")
	}
	if !exactMode(info.Mode(), 0o600) {
		return storageFinding("STATE-STORAGE-MODE", "Desired State file", "permissions other than 0600", "exact mode 0600", "broader permissions can expose protected State", "correct permissions and check again")
	}
	if links(info) != 1 {
		return storageFinding("STATE-STORAGE-HARDLINK", "Desired State file", "more than one hard link", "one exclusively named state.json", "another path can alter the same protected bytes", "remove the unsafe link and check again")
	}
	return nil
}

func exactMode(actual, wanted os.FileMode) bool {
	const special = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return actual.Perm() == wanted && actual&special == 0
}

func owner(info os.FileInfo) int { return int(info.Sys().(*syscall.Stat_t).Uid) }

func links(info os.FileInfo) uint64 { return uint64(info.Sys().(*syscall.Stat_t).Nlink) }

func storageFinding(code, concept, found, required, why, next string) *state.Finding {
	return &state.Finding{Code: code, Concept: concept, Found: found, Required: required, Why: why, NextAction: next}
}
