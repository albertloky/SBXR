// Package filesystem provides the one production Desired State storage Adapter.
package filesystem

import (
	"io"
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
}

// New wires Load to the root-owned production Adapter at the fixed State path.
// The Adapter itself is not exposed, so production callers cannot read around
// the State Interface.
func New() state.Interface { return state.New(newAt(filepath.Dir(StateDirectory), 0)) }

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

	before, err := stateDirectory.Lstat("state.json")
	if err != nil {
		return nil, err
	}
	if finding := verifyFile(before, a.uid); finding != nil {
		return nil, finding
	}
	if a.beforeFileOpen != nil {
		a.beforeFileOpen()
	}
	file, err := stateDirectory.Open("state.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := stateDirectory.Lstat("state.json")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) {
		return nil, storageFinding("STATE-STORAGE-PATH", "Desired State path", "the file changed during protected open", "one stable state.json path", "path substitution can bypass the protected boundary", "restore the protected path and check again")
	}
	if finding := verifyFile(after, a.uid); finding != nil {
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
