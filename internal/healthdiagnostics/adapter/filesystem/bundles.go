package filesystem

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

type BundleStorage struct {
	root                   string
	uid                    int
	read                   func(*os.Root, string) ([]byte, error)
	afterRead              func(string)
	crashAt                string
	failFinalSync          bool
	failTransactionRemove  bool
	failRollbackAfterPhase bool
	failRollbackStage      bool
	failRollbackWrite      bool
	failRollbackSync       bool
	failCommitPhase        bool
}

type bundleTransaction struct {
	Schema      string `json:"schema"`
	Phase       string `json:"phase"`
	Name        string `json:"name"`
	Replacement string `json:"replacement,omitempty"`
	Stage       string `json:"stage"`
	Tombstone   string `json:"tombstone,omitempty"`
}

func NewBundleStorage() BundleStorage { return BundleStorage{root: "/", uid: 0} }

func newBundleStorage(root string, uid int) BundleStorage { return BundleStorage{root: root, uid: uid} }

func (storage BundleStorage) Existing() ([]string, error) {
	return storage.existing(true)
}

func (storage BundleStorage) existing(takeLock bool) ([]string, error) {
	diagnostics, err := (EventStorage{root: storage.root, uid: storage.uid}).open(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("support bundle storage is unsafe")
	}
	defer diagnostics.Close()
	if takeLock {
		lock, err := lockBundleStorage(diagnostics, storage.uid)
		if err != nil {
			return nil, err
		}
		defer unlockBundleStorage(lock)
	}
	bundlesInfo, bundlesErr := diagnostics.Lstat("bundles")
	stagingInfo, stagingErr := diagnostics.Lstat("staging")
	if errors.Is(bundlesErr, os.ErrNotExist) && errors.Is(stagingErr, os.ErrNotExist) {
		return nil, nil
	}
	if bundlesErr != nil || stagingErr != nil || !safeDirectory(bundlesInfo, storage.uid) || !safeDirectory(stagingInfo, storage.uid) {
		return nil, errors.New("support bundle storage is unsafe")
	}
	staging, err := diagnostics.OpenRoot("staging")
	if err != nil {
		return nil, errors.New("support bundle staging is unavailable")
	}
	stagingEntries, stagingErr := fs.ReadDir(staging.FS(), ".")
	if stagingErr == nil && len(stagingEntries) != 0 {
		stagingErr = recoverBundleTransaction(diagnostics, staging, storage.uid)
		if stagingErr == nil {
			stagingEntries, stagingErr = fs.ReadDir(staging.FS(), ".")
		}
	}
	staging.Close()
	if stagingErr != nil || len(stagingEntries) != 0 {
		return nil, errors.New("support bundle staging is not empty")
	}
	bundles, err := diagnostics.OpenRoot("bundles")
	if err != nil {
		return nil, errors.New("support bundle storage is unavailable")
	}
	defer bundles.Close()
	entries, err := fs.ReadDir(bundles.FS(), ".")
	if err != nil || len(entries) > 3 {
		return nil, errors.New("support bundle storage is invalid")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		before, err := bundles.Lstat(name)
		if err != nil || !bundleName(name) || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() <= 0 || before.Size() > healthdiagnostics.BundleArchiveBytes || owner(before) != storage.uid || links(before) != 1 {
			return nil, errors.New("support bundle archive is unsafe")
		}
		data, err := bundles.ReadFile(name)
		if storage.read != nil {
			data, err = storage.read(bundles, name)
		}
		if storage.afterRead != nil {
			storage.afterRead(name)
		}
		after, afterErr := bundles.Lstat(name)
		if err != nil || afterErr != nil || int64(len(data)) != before.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !healthdiagnostics.ValidCompletedBundle(data) {
			return nil, errors.New("support bundle archive changed or is invalid")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (storage BundleStorage) Publish(candidate healthdiagnostics.BundleCandidate) error {
	name, archive, replacement := candidate.Name(), candidate.Archive(), candidate.Replacement()
	if !candidate.Verified() || !bundleName(name) || len(archive) == 0 || len(archive) > healthdiagnostics.BundleArchiveBytes || replacement != "" && !bundleName(replacement) || !healthdiagnostics.ValidCompletedBundle(archive) {
		return errors.New("support bundle candidate is invalid")
	}
	diagnostics, err := (EventStorage{root: storage.root, uid: storage.uid}).open(true)
	if err != nil {
		return errors.New("support bundle storage is unsafe")
	}
	defer diagnostics.Close()
	lock, err := lockBundleStorage(diagnostics, storage.uid)
	if err != nil {
		return errors.New("support bundle storage lock failed")
	}
	defer unlockBundleStorage(lock)
	for _, directory := range []string{"bundles", "staging"} {
		if err := ensureBundleDirectory(diagnostics, directory, storage.uid); err != nil {
			return err
		}
	}
	existing, err := storage.existing(false)
	if err != nil || containsName(existing, name) || len(existing) == 3 && !containsName(existing, replacement) || len(existing) < 3 && replacement != "" {
		return errors.New("support bundle replacement is invalid")
	}

	stageName := "." + strings.TrimSuffix(name, ".tar.gz") + ".stage"
	tombstone := "." + strings.TrimSuffix(replacement, ".tar.gz") + ".reviewed-delete"
	staging, err := diagnostics.OpenRoot("staging")
	if err != nil {
		return errors.New("support bundle staging is unavailable")
	}
	defer staging.Close()
	transaction := bundleTransaction{Schema: "sbxr-support-bundle-transaction-v1", Phase: "prepared", Name: name, Replacement: replacement, Stage: stageName, Tombstone: tombstone}
	if writeBundleTransaction(staging, transaction, storage.uid) != nil {
		return errors.New("support bundle transaction creation failed")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = recoverBundleTransaction(diagnostics, staging, storage.uid)
		}
	}()
	if staging.Mkdir(stageName, 0o700) != nil || staging.Lchown(stageName, storage.uid, -1) != nil {
		return errors.New("support bundle staging creation failed")
	}
	stage, err := staging.OpenRoot(stageName)
	if err != nil {
		return errors.New("support bundle staging is unavailable")
	}
	file, err := stage.OpenFile("bundle.tar.gz", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		stage.Close()
		return errors.New("support bundle staging write failed")
	}
	if file.Chown(storage.uid, -1) != nil || file.Chmod(0o600) != nil {
		file.Close()
		stage.Close()
		return errors.New("support bundle staging ownership failed")
	}
	if written, writeErr := file.Write(archive); writeErr != nil || written != len(archive) || file.Sync() != nil || file.Close() != nil {
		stage.Close()
		return errors.New("support bundle staging write failed")
	}
	info, statErr := stage.Lstat("bundle.tar.gz")
	readback, readErr := stage.ReadFile("bundle.tar.gz")
	stage.Close()
	if statErr != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || owner(info) != storage.uid || links(info) != 1 || !bytes.Equal(readback, archive) {
		return errors.New("support bundle staging verification failed")
	}
	if storage.crashAt == "prepared" {
		cleanup = false
		return errors.New("simulated support bundle crash")
	}
	if replacement != "" {
		if err := diagnostics.Rename("bundles/"+replacement, "staging/"+stageName+"/reviewed.tar.gz"); err != nil {
			return errors.New("support bundle reviewed replacement failed")
		}
	}
	if storage.crashAt == "reviewed" {
		cleanup = false
		return errors.New("simulated support bundle crash")
	}
	if diagnostics.Rename("staging/"+stageName+"/bundle.tar.gz", "bundles/"+name) != nil {
		return errors.New("support bundle publication failed")
	}
	if storage.crashAt == "published" {
		cleanup = false
		return errors.New("simulated support bundle crash")
	}
	bundles, bundlesErr := diagnostics.OpenRoot("bundles")
	stagingRoot, stagingErr := diagnostics.OpenRoot("staging")
	if bundlesErr != nil || stagingErr != nil || syncDirectory(bundles) != nil || syncDirectory(stagingRoot) != nil || syncDirectory(diagnostics) != nil {
		if bundles != nil {
			bundles.Close()
		}
		if stagingRoot != nil {
			stagingRoot.Close()
		}
		_ = diagnostics.Remove("bundles/" + name)
		return errors.New("support bundle publication sync failed")
	}
	bundles.Close()
	stagingRoot.Close()
	var reviewedArchive []byte
	if replacement != "" {
		reviewedArchive, err = staging.ReadFile(stageName + "/reviewed.tar.gz")
		if err != nil || !healthdiagnostics.ValidCompletedBundle(reviewedArchive) {
			return errors.New("support bundle reviewed archive is unreadable")
		}
	}
	if replacement != "" && diagnostics.Rename("staging/"+stageName+"/reviewed.tar.gz", "bundles/"+tombstone) != nil {
		return errors.New("support bundle reviewed replacement cleanup failed")
	}
	if staging.Remove(stageName) != nil {
		return errors.New("support bundle staging cleanup failed")
	}
	if storage.crashAt == "cleanup" {
		cleanup = false
		return errors.New("simulated support bundle crash")
	}
	bundles, bundlesErr = diagnostics.OpenRoot("bundles")
	stagingRoot, stagingErr = diagnostics.OpenRoot("staging")
	if bundlesErr != nil || stagingErr != nil || syncDirectory(bundles) != nil || syncDirectory(stagingRoot) != nil || syncDirectory(diagnostics) != nil {
		if bundles != nil {
			bundles.Close()
		}
		if stagingRoot != nil {
			stagingRoot.Close()
		}
		return errors.New("support bundle cleanup sync failed")
	}
	bundles.Close()
	stagingRoot.Close()
	if replacement != "" && storage.persistRollbackMaterial(staging, transaction, reviewedArchive) != nil {
		return errors.New("support bundle rollback material failed")
	}
	transaction.Phase = "committing"
	if storage.failCommitPhase {
		return errors.New("controlled support bundle commit phase failure")
	}
	if writeBundleTransaction(staging, transaction, storage.uid) != nil {
		return errors.New("support bundle commit phase failed")
	}
	if storage.crashAt == "committing" {
		cleanup = false
		return errors.New("simulated support bundle crash")
	}
	if replacement != "" && diagnostics.Remove("bundles/"+tombstone) != nil {
		return errors.New("support bundle reviewed deletion failed")
	}
	bundles, bundlesErr = diagnostics.OpenRoot("bundles")
	finalSyncErr := errors.New("support bundle final deletion sync failed")
	if bundlesErr == nil && !storage.failFinalSync {
		finalSyncErr = errors.Join(syncDirectory(bundles), syncDirectory(diagnostics))
	}
	if finalSyncErr != nil {
		if bundles != nil {
			bundles.Close()
		}
		if storage.rollbackCommittedBundle(diagnostics, staging, transaction, reviewedArchive) != nil {
			_ = recoverBundleTransaction(diagnostics, staging, storage.uid)
			cleanup = false
			return errors.New("support bundle durable rollback failed")
		}
		cleanup = false
		return errors.New("support bundle final deletion sync failed")
	}
	bundles.Close()
	if replacement != "" {
		if staging.Remove(stageName+"/reviewed.tar.gz") != nil || staging.Remove(stageName) != nil || syncDirectory(staging) != nil {
			if storage.rollbackCommittedBundle(diagnostics, staging, transaction, reviewedArchive) != nil {
				_ = recoverBundleTransaction(diagnostics, staging, storage.uid)
				cleanup = false
				return errors.New("support bundle durable rollback failed")
			}
			cleanup = false
			return errors.New("support bundle rollback material cleanup failed")
		}
	}
	transactionErr := error(nil)
	if storage.failTransactionRemove {
		transactionErr = errors.New("controlled transaction removal failure")
	} else {
		transactionErr = staging.Remove("transaction.json")
	}
	if transactionErr != nil || syncDirectory(staging) != nil || syncDirectory(diagnostics) != nil {
		if storage.rollbackCommittedBundle(diagnostics, staging, transaction, reviewedArchive) != nil {
			_ = recoverBundleTransaction(diagnostics, staging, storage.uid)
			cleanup = false
			return errors.New("support bundle durable rollback failed")
		}
		cleanup = false
		return errors.New("support bundle transaction cleanup failed")
	}
	cleanup = false
	return nil
}

func (storage BundleStorage) rollbackCommittedBundle(diagnostics, staging *os.Root, transaction bundleTransaction, reviewed []byte) error {
	if transaction.Replacement != "" {
		if !validStagedReviewed(staging, transaction.Stage, storage.uid) && storage.persistRollbackMaterial(staging, transaction, reviewed) != nil {
			return errors.New("support bundle rollback material is unavailable")
		}
	}
	transaction.Phase = "rolling-back"
	_ = writeBundleTransaction(staging, transaction, storage.uid)
	if storage.failRollbackAfterPhase {
		return errors.New("controlled support bundle rollback failure")
	}
	if storage.crashAt == "rolling-back" {
		return nil
	}
	bundles, err := diagnostics.OpenRoot("bundles")
	if err != nil {
		return err
	}
	defer bundles.Close()
	if err := bundles.Remove(transaction.Name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if transaction.Replacement != "" {
		if diagnostics.Rename("staging/"+transaction.Stage+"/reviewed.tar.gz", "bundles/"+transaction.Replacement) != nil {
			return errors.New("support bundle reviewed archive restore failed")
		}
	}
	_ = bundles.Remove(transaction.Tombstone)
	_ = staging.Remove(transaction.Stage + "/bundle.tar.gz")
	_ = staging.Remove(transaction.Stage + "/reviewed.tar.gz")
	_ = staging.Remove(transaction.Stage)
	_ = staging.Remove(".transaction.next")
	_ = staging.Remove("transaction.json")
	return errors.Join(syncDirectory(bundles), syncDirectory(staging), syncDirectory(diagnostics))
}

func (storage BundleStorage) persistRollbackMaterial(staging *os.Root, transaction bundleTransaction, reviewed []byte) error {
	if len(reviewed) == 0 || storage.failRollbackStage {
		return errors.New("support bundle rollback staging failed")
	}
	info, err := staging.Lstat(transaction.Stage)
	if errors.Is(err, os.ErrNotExist) {
		if staging.Mkdir(transaction.Stage, 0o700) != nil || staging.Lchown(transaction.Stage, storage.uid, -1) != nil {
			return errors.New("support bundle rollback staging failed")
		}
	} else if err != nil || !safeDirectory(info, storage.uid) {
		return errors.New("support bundle rollback staging is unsafe")
	}
	stage, err := staging.OpenRoot(transaction.Stage)
	if err != nil {
		return err
	}
	writeErr := error(nil)
	if storage.failRollbackWrite {
		writeErr = errors.New("controlled support bundle rollback write failure")
	} else {
		_ = stage.Remove("reviewed.tar.gz")
		writeErr = writeBundleFile(stage, "reviewed.tar.gz", reviewed, storage.uid)
	}
	stageSyncErr := error(nil)
	if storage.failRollbackSync {
		stageSyncErr = errors.New("controlled support bundle rollback sync failure")
	} else {
		stageSyncErr = syncDirectory(stage)
	}
	stage.Close()
	if writeErr != nil || stageSyncErr != nil || syncDirectory(staging) != nil {
		return errors.New("support bundle rollback material failed")
	}
	return nil
}

func validStagedReviewed(staging *os.Root, stageName string, uid int) bool {
	stage, err := staging.OpenRoot(stageName)
	if err != nil {
		return false
	}
	defer stage.Close()
	info, err := stage.Lstat("reviewed.tar.gz")
	if err != nil || !safeBundleFile(info, uid, healthdiagnostics.BundleArchiveBytes) {
		return false
	}
	body, err := stage.ReadFile("reviewed.tar.gz")
	return err == nil && int64(len(body)) == info.Size() && healthdiagnostics.ValidCompletedBundle(body)
}

func writeBundleFile(root *os.Root, name string, body []byte, uid int) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if file.Chown(uid, -1) != nil || file.Chmod(0o600) != nil {
		file.Close()
		return errors.New("support bundle restore ownership failed")
	}
	if written, writeErr := file.Write(body); writeErr != nil || written != len(body) || file.Sync() != nil || file.Close() != nil {
		return errors.New("support bundle restore write failed")
	}
	return nil
}

func writeBundleTransaction(staging *os.Root, transaction bundleTransaction, uid int) error {
	body, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	const temporary = ".transaction.next"
	_ = staging.Remove(temporary)
	file, err := staging.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if file.Chown(uid, -1) != nil || file.Chmod(0o600) != nil {
		file.Close()
		return errors.New("support bundle transaction ownership failed")
	}
	if written, writeErr := file.Write(body); writeErr != nil || written != len(body) || file.Sync() != nil || file.Close() != nil || staging.Rename(temporary, "transaction.json") != nil {
		return errors.New("support bundle transaction write failed")
	}
	return syncDirectory(staging)
}

func recoverBundleTransaction(diagnostics, staging *os.Root, uid int) error {
	entries, err := fs.ReadDir(staging.FS(), ".")
	if err != nil {
		return err
	}
	if len(entries) == 1 && entries[0].Name() == ".transaction.next" {
		if info, statErr := staging.Lstat(".transaction.next"); statErr != nil || !safeBundleFile(info, uid, healthdiagnostics.BundleItemBytes) || staging.Remove(".transaction.next") != nil {
			return errors.New("support bundle transaction is unsafe")
		}
		return syncDirectory(staging)
	}
	info, err := staging.Lstat("transaction.json")
	if err != nil || !safeBundleFile(info, uid, healthdiagnostics.BundleItemBytes) {
		return errors.New("support bundle transaction is unsafe")
	}
	body, err := staging.ReadFile("transaction.json")
	if err != nil || int64(len(body)) != info.Size() {
		return errors.New("support bundle transaction is unreadable")
	}
	var transaction bundleTransaction
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&transaction) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validBundleTransaction(transaction) {
		return errors.New("support bundle transaction is invalid")
	}
	bundles, err := diagnostics.OpenRoot("bundles")
	if err != nil {
		return errors.New("support bundle storage is unavailable")
	}
	defer bundles.Close()
	if transaction.Phase == "committing" && validStoredBundle(bundles, transaction.Name, uid) {
		if transaction.Tombstone != "" {
			if err := bundles.Remove(transaction.Tombstone); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("support bundle reviewed deletion recovery failed")
			}
		}
	} else {
		if err := bundles.Remove(transaction.Name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("support bundle publication rollback failed")
		}
		if transaction.Replacement != "" {
			if _, err := bundles.Lstat(transaction.Replacement); errors.Is(err, os.ErrNotExist) {
				staged := validStagedReviewed(staging, transaction.Stage, uid) && diagnostics.Rename("staging/"+transaction.Stage+"/reviewed.tar.gz", "bundles/"+transaction.Replacement) == nil
				if !staged && bundles.Rename(transaction.Tombstone, transaction.Replacement) != nil {
					return errors.New("support bundle reviewed archive recovery failed")
				}
			} else if err != nil {
				return errors.New("support bundle reviewed archive is unavailable")
			}
			_ = bundles.Remove(transaction.Tombstone)
		}
	}
	_ = staging.Remove(transaction.Stage + "/bundle.tar.gz")
	_ = staging.Remove(transaction.Stage + "/reviewed.tar.gz")
	if err := staging.Remove(transaction.Stage); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("support bundle staging recovery failed")
	}
	_ = staging.Remove(".transaction.next")
	if staging.Remove("transaction.json") != nil || syncDirectory(bundles) != nil || syncDirectory(staging) != nil || syncDirectory(diagnostics) != nil {
		return errors.New("support bundle recovery sync failed")
	}
	return nil
}

func validBundleTransaction(transaction bundleTransaction) bool {
	if transaction.Schema != "sbxr-support-bundle-transaction-v1" || transaction.Phase != "prepared" && transaction.Phase != "committing" && transaction.Phase != "rolling-back" || !bundleName(transaction.Name) || transaction.Stage != "."+strings.TrimSuffix(transaction.Name, ".tar.gz")+".stage" {
		return false
	}
	if transaction.Replacement == "" {
		return transaction.Tombstone == ".reviewed-delete"
	}
	return bundleName(transaction.Replacement) && transaction.Tombstone == "."+strings.TrimSuffix(transaction.Replacement, ".tar.gz")+".reviewed-delete" && transaction.Replacement != transaction.Name
}

func safeBundleFile(info os.FileInfo, uid int, maximum int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Size() > 0 && info.Size() <= int64(maximum) && owner(info) == uid && links(info) == 1
}

func validStoredBundle(root *os.Root, name string, uid int) bool {
	info, err := root.Lstat(name)
	if err != nil || !safeBundleFile(info, uid, healthdiagnostics.BundleArchiveBytes) {
		return false
	}
	body, err := root.ReadFile(name)
	return err == nil && int64(len(body)) == info.Size() && healthdiagnostics.ValidCompletedBundle(body)
}

func lockBundleStorage(root *os.Root, uid int) (*os.File, error) {
	before, beforeErr := root.Lstat(".bundle.lock")
	missing := errors.Is(beforeErr, os.ErrNotExist)
	if beforeErr != nil && !missing || beforeErr == nil && (before == nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() != 0 || owner(before) != uid || links(before) != 1) {
		return nil, errors.New("support bundle lock is unsafe")
	}
	file, err := root.OpenFile(".bundle.lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if missing && (file.Chown(uid, -1) != nil || file.Chmod(0o600) != nil) {
		file.Close()
		return nil, errors.New("support bundle lock ownership failed")
	}
	info, err := file.Stat()
	pathInfo, pathErr := root.Lstat(".bundle.lock")
	if err != nil || pathErr != nil || info == nil || pathInfo == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 || owner(info) != uid || links(info) != 1 || !os.SameFile(info, pathInfo) || syscall.Flock(int(file.Fd()), syscall.LOCK_EX) != nil {
		file.Close()
		return nil, errors.New("support bundle lock is unsafe")
	}
	return file, nil
}

func unlockBundleStorage(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func ensureBundleDirectory(root *os.Root, name string, uid int) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if root.Mkdir(name, 0o700) != nil || root.Lchown(name, uid, -1) != nil {
			return errors.New("support bundle directory creation failed")
		}
		info, err = root.Lstat(name)
	}
	if err != nil || !safeDirectory(info, uid) {
		return errors.New("support bundle directory is unsafe")
	}
	return nil
}

func safeDirectory(info os.FileInfo, uid int) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0o700 && owner(info) == uid
}

func bundleName(name string) bool {
	if len(name) != len("sbxr-support-20060102T150405Z.tar.gz") || !strings.HasPrefix(name, "sbxr-support-") || !strings.HasSuffix(name, ".tar.gz") {
		return false
	}
	_, err := time.Parse("20060102T150405Z", strings.TrimSuffix(strings.TrimPrefix(name, "sbxr-support-"), ".tar.gz"))
	return err == nil
}

func containsName(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
