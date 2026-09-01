package softwarelifecycle

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	executablePath      = "/usr/local/bin/sbxr"
	installedRecordPath = "/var/lib/sbxr/installed.json"
	mutationLockPath    = "/run/lock/sbxr.lock"
)

var transactionPaths = []string{
	"/usr/local/bin/.sbxr-update-prior",
	"/usr/local/bin/.sbxr-update-candidate",
	"/var/lib/sbxr/.installed.json.prior",
	"/var/lib/sbxr/.installed.json.candidate",
	"/var/lib/sbxr/update.json",
	"/var/lib/sbxr/.update.json.next",
}

type filesystemInspector struct {
	updateRuntime          *UpdateRuntime
	requireSupport         bool
	root                   string
	uid                    uint32
	beforeRecoveryMutation func()
	updateAdmission        UpdateAdmission
}

func newLocalInspector(root string, uid uint32) localInspector {
	return filesystemInspector{root: root, uid: uid}
}

func (inspector filesystemInspector) inspect(ctx context.Context) localInspection {
	if ctx.Err() != nil {
		return localInspection{}
	}
	held, inspectionValid := inspector.inspectLock()
	if held || !inspectionValid {
		return localInspection{inspectionValid: inspectionValid, lockHeld: held}
	}
	transaction, inspectionValid := inspector.hasTransactionEvidence()
	if !inspectionValid || transaction {
		return localInspection{inspectionValid: inspectionValid, transactionEvidence: transaction}
	}
	if !inspector.safeDirectory("/var/lib/sbxr", 0o700) {
		return localInspection{}
	}
	executable, ok := inspector.readSafeFile(executablePath, 0o755, 1, maxInstalledBinary)
	if !ok {
		return localInspection{}
	}
	record, ok := inspector.readSafeFile(installedRecordPath, 0o600, 1, maxInstalledRecord)
	if !ok {
		return localInspection{}
	}
	transaction, inspectionValid = inspector.hasTransactionEvidence()
	if !inspectionValid || transaction {
		return localInspection{inspectionValid: inspectionValid, transactionEvidence: transaction}
	}
	held, inspectionValid = inspector.inspectLock()
	return localInspection{inspectionValid: inspectionValid, lockHeld: held, installedRecord: record, executable: executable}
}

func (inspector filesystemInspector) inspectLock() (bool, bool) {
	path := inspector.path(mutationLockPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, true
	}
	if err != nil || !safeLockInfo(info, inspector.uid) {
		return false, false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, false
	}
	defer file.Close()
	if !sameFile(info, file) {
		return false, false
	}
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		return true, true
	}
	if err != nil {
		return false, false
	}
	return false, syscall.Flock(int(file.Fd()), syscall.LOCK_UN) == nil
}

func (inspector filesystemInspector) hasTransactionEvidence() (bool, bool) {
	for _, name := range transactionPaths {
		_, err := os.Lstat(inspector.path(name))
		if err == nil {
			return true, true
		}
		if !os.IsNotExist(err) {
			return false, false
		}
	}
	return false, true
}

func (inspector filesystemInspector) safeDirectory(name string, mode os.FileMode) bool {
	info, err := os.Lstat(inspector.path(name))
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == inspector.uid
}

func (inspector filesystemInspector) readSafeFile(name string, mode os.FileMode, links uint64, limit int64) ([]byte, bool) {
	path := inspector.path(name)
	info, err := os.Lstat(path)
	if err != nil || !safeFileInfo(info, inspector.uid, mode, links, limit) {
		return nil, false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	if !sameFile(info, file) {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	return body, err == nil && int64(len(body)) <= limit
}

func safeFileInfo(info os.FileInfo, uid uint32, mode os.FileMode, links uint64, limit int64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == mode && stat.Uid == uid && uint64(stat.Nlink) == links && info.Size() > 0 && info.Size() <= limit
}

func safeLockInfo(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && stat.Uid == uid && uint64(stat.Nlink) == 1 && info.Size() <= maxInstalledRecord
}

func sameFile(before os.FileInfo, file *os.File) bool {
	after, err := file.Stat()
	if err != nil {
		return false
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	return aok && bok && a.Dev == b.Dev && a.Ino == b.Ino
}

func (inspector filesystemInspector) path(name string) string {
	if inspector.root == "/" {
		return name
	}
	return filepath.Join(inspector.root, strings.TrimPrefix(name, "/"))
}

func (inspector filesystemInspector) safeRemovalParents(name string) bool {
	for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(inspector.path(parent))
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != inspector.uid {
			return false
		}
		if parent == "/" {
			return true
		}
	}
}

func (inspector filesystemInspector) inspectCompleteRemoval(ctx context.Context, expected ReleaseIdentity) CompleteRemovalInspection {
	if ctx.Err() != nil || !inspector.safeRemovalParents(executablePath) || !inspector.safeRemovalParents(installedRecordPath) || !inspector.safeDirectory("/var/lib/sbxr", 0o700) {
		return CompleteRemovalInspection{}
	}
	record, recordOK := inspector.readSafeFile(installedRecordPath, 0o600, 1, maxInstalledRecord)
	if !recordOK {
		if _, err := os.Lstat(inspector.path(installedRecordPath)); !os.IsNotExist(err) {
			return CompleteRemovalInspection{}
		}
	}
	executable, executableOK := inspector.readSafeFile(executablePath, 0o755, 1, maxInstalledBinary)
	if !executableOK {
		if _, err := os.Lstat(inspector.path(executablePath)); !os.IsNotExist(err) {
			return CompleteRemovalInspection{}
		}
	}
	if recordOK && executableOK {
		identity, ok := verifyInstalledPair(record, executable)
		if !ok || identity != expected {
			return CompleteRemovalInspection{}
		}
	} else if recordOK {
		var decoded installedRecord
		if !decodeExactObject(record, &decoded) || !validInstalledRecord(decoded) || releaseIdentity(decoded) != expected {
			return CompleteRemovalInspection{}
		}
	} else if executableOK {
		return CompleteRemovalInspection{}
	}
	entries, err := os.ReadDir(inspector.path("/var/lib/sbxr"))
	if err != nil {
		return CompleteRemovalInspection{}
	}
	empty := true
	for _, entry := range entries {
		if entry.Name() != "installed.json" && entry.Name() != "proxy-ownership.json" {
			empty = false
		}
	}
	return CompleteRemovalInspection{Valid: recordOK || !executableOK, ExecutablePresent: executableOK, InstalledRecordPresent: recordOK, StateDirectoryEmpty: empty}
}

func (inspector filesystemInspector) removeCompleteRemovalExecutable(ctx context.Context, expected ReleaseIdentity) bool {
	facts := inspector.inspectCompleteRemoval(ctx, expected)
	if !facts.Valid || !facts.StateDirectoryEmpty {
		return false
	}
	if !facts.ExecutablePresent {
		return syncRemovalDirectory(inspector.path("/usr/local/bin")) == nil
	}
	return os.Remove(inspector.path(executablePath)) == nil && syncRemovalDirectory(inspector.path("/usr/local/bin")) == nil
}

func (inspector filesystemInspector) removeCompleteRemovalInstalledRecord(ctx context.Context, expected ReleaseIdentity) bool {
	facts := inspector.inspectCompleteRemoval(ctx, expected)
	if !facts.Valid || !facts.StateDirectoryEmpty || facts.ExecutablePresent {
		return false
	}
	if !facts.InstalledRecordPresent {
		return syncRemovalDirectory(inspector.path("/var/lib/sbxr")) == nil
	}
	return os.Remove(inspector.path(installedRecordPath)) == nil && syncRemovalDirectory(inspector.path("/var/lib/sbxr")) == nil
}

func syncRemovalDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func releaseIdentity(record installedRecord) ReleaseIdentity {
	return ReleaseIdentity{Repository: record.Repository, Tag: record.Tag, Commit: record.Commit, IndexSHA256: record.ReleaseIndexSHA256}
}
