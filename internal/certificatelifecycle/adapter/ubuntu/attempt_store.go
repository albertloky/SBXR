package ubuntu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

type RenewalAttemptStore struct {
	root string
	uid  int
}

func NewRenewalAttemptStore() RenewalAttemptStore {
	return RenewalAttemptStore{root: "/", uid: 0}
}

func newRenewalAttemptStore(root string, uid int) RenewalAttemptStore {
	return RenewalAttemptStore{root: root, uid: uid}
}

type persistedAttempt struct {
	SchemaVersion int                                 `json:"schema_version"`
	Time          time.Time                           `json:"time"`
	Outcome       certificatelifecycle.RenewalAttempt `json:"outcome"`
}

func (store RenewalAttemptStore) LoadAttempt(lineage certificatelifecycle.Lineage) (time.Time, certificatelifecycle.RenewalAttempt, bool, error) {
	attemptFile, err := attemptFile(lineage)
	if err != nil {
		return time.Time{}, "", false, err
	}
	directory, err := store.openAttemptRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, "", false, nil
		}
		return time.Time{}, "", false, err
	}
	defer directory.Close()
	info, err := directory.Lstat(attemptFile)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, "", false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 4096 || fileUID(info) != store.uid {
		return time.Time{}, "", false, errors.New("renewal attempt history is unsafe")
	}
	data, err := directory.ReadFile(attemptFile)
	if err != nil {
		return time.Time{}, "", false, errors.New("renewal attempt history is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record persistedAttempt
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || record.SchemaVersion != 1 || record.Time.IsZero() || record.Time.Location() != time.UTC || record.Outcome != certificatelifecycle.RenewalFailed && record.Outcome != certificatelifecycle.RenewalBusy {
		return time.Time{}, "", false, errors.New("renewal attempt history is invalid")
	}
	return record.Time, record.Outcome, true, nil
}

func (store RenewalAttemptStore) StoreAttempt(lineage certificatelifecycle.Lineage, at time.Time, outcome certificatelifecycle.RenewalAttempt) error {
	if at.IsZero() || outcome != certificatelifecycle.RenewalFailed && outcome != certificatelifecycle.RenewalBusy {
		return errors.New("renewal attempt is invalid")
	}
	attemptFile, err := attemptFile(lineage)
	if err != nil {
		return err
	}
	directory, err := store.openAttemptRoot(true)
	if err != nil {
		return errors.New("renewal attempt directory is unsafe")
	}
	defer directory.Close()
	data, err := json.Marshal(persistedAttempt{SchemaVersion: 1, Time: at.UTC(), Outcome: outcome})
	if err != nil {
		return errors.New("renewal attempt serialization failed")
	}
	temporary := "." + attemptFile + ".next"
	_ = directory.Remove(temporary)
	file, err := directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("renewal attempt write failed")
	}
	remove := true
	defer func() {
		file.Close()
		if remove {
			_ = directory.Remove(temporary)
		}
	}()
	if file.Chown(store.uid, -1) != nil || file.Chmod(0o600) != nil {
		return errors.New("renewal attempt ownership failed")
	}
	if written, writeErr := file.Write(data); writeErr != nil || written != len(data) || file.Sync() != nil || file.Close() != nil {
		return errors.New("renewal attempt write failed")
	}
	if err := directory.Rename(temporary, attemptFile); err != nil {
		return errors.New("renewal attempt replacement failed")
	}
	remove = false
	return syncRoot(directory)
}

func (store RenewalAttemptStore) ClearAttempt(lineage certificatelifecycle.Lineage) error {
	attemptFile, err := attemptFile(lineage)
	if err != nil {
		return err
	}
	directory, err := store.openAttemptRoot(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer directory.Close()
	err = directory.Remove(attemptFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("renewal attempt cleanup failed")
	}
	return syncRoot(directory)
}

func attemptFile(lineage certificatelifecycle.Lineage) (string, error) {
	switch lineage {
	case certificatelifecycle.IPLineage:
		return "ip-attempt.json", nil
	case certificatelifecycle.DomainLineage:
		return "domain-attempt.json", nil
	default:
		return "", errors.New("certificate renewal lineage is invalid")
	}
}

func (store RenewalAttemptStore) openAttemptRoot(create bool) (*os.Root, error) {
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return nil, errors.New("renewal attempt root is unavailable")
	}
	defer root.Close()
	baseInfo, err := root.Lstat("var/lib/sbxr")
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode().Perm() != 0o700 || baseInfo.Mode()&os.ModeSymlink != 0 || fileUID(baseInfo) != store.uid {
		return nil, errOrUnsafe(err)
	}
	base, err := root.OpenRoot("var/lib/sbxr")
	if err != nil {
		return nil, errors.New("renewal attempt base is unavailable")
	}
	defer base.Close()
	info, err := base.Lstat("certificate-renewal")
	if errors.Is(err, os.ErrNotExist) && create {
		if err := base.Mkdir("certificate-renewal", 0o700); err != nil {
			return nil, errors.New("renewal attempt directory creation failed")
		}
		if err := base.Lchown("certificate-renewal", store.uid, -1); err != nil {
			return nil, errors.New("renewal attempt directory ownership failed")
		}
		info, err = base.Lstat("certificate-renewal")
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != store.uid {
		return nil, errOrUnsafe(err)
	}
	directory, err := base.OpenRoot("certificate-renewal")
	if err != nil {
		return nil, errors.New("renewal attempt directory is unavailable")
	}
	return directory, nil
}

func errOrUnsafe(err error) error {
	if err != nil {
		return err
	}
	return errors.New("renewal attempt directory is unsafe")
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("renewal attempt directory sync failed")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("renewal attempt directory sync failed")
	}
	return nil
}
