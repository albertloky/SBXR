package ubuntu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type DraftStore struct{ home string }

func NewDraftStore() (DraftStore, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return DraftStore{}, errors.New("Owner home unavailable")
	}
	return DraftStore{home: home}, nil
}

func NewDraftStoreAt(home string) DraftStore { return DraftStore{home: home} }

func (store DraftStore) Save(draft softwarelifecycle.InstallationDraft) error {
	if !draft.Valid() {
		return errors.New("installation draft refused")
	}
	directory := store.directory()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := verifyDraftDirectory(directory); err != nil {
		return err
	}
	if err := verifyDraftFile(store.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	body, err := json.Marshal(draft)
	if err != nil {
		return err
	}
	temporary := store.path() + ".next"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return errors.New("installation draft write failed")
	}
	if err := os.Rename(temporary, store.path()); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncPath(directory)
}

func (store DraftStore) Load() (softwarelifecycle.InstallationDraft, error) {
	if err := verifyDraftDirectory(store.directory()); err != nil {
		return softwarelifecycle.InstallationDraft{}, err
	}
	if err := verifyDraftFile(store.path()); err != nil {
		return softwarelifecycle.InstallationDraft{}, err
	}
	body, err := os.ReadFile(store.path())
	if err != nil || len(body) == 0 || len(body) > 16<<10 {
		return softwarelifecycle.InstallationDraft{}, errors.New("installation draft read failed")
	}
	var draft softwarelifecycle.InstallationDraft
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&draft) != nil || !draft.Valid() {
		return softwarelifecycle.InstallationDraft{}, errors.New("installation draft refused")
	}
	canonical, _ := json.Marshal(draft)
	if !bytes.Equal(body, canonical) {
		return softwarelifecycle.InstallationDraft{}, errors.New("installation draft is ambiguous")
	}
	return draft, nil
}

func (store DraftStore) Discard() error {
	if err := verifyDraftFile(store.path()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(store.path()); err != nil {
		return err
	}
	return syncPath(store.directory())
}

func (store DraftStore) directory() string {
	return filepath.Join(store.home, ".local", "state", "sbxr")
}
func (store DraftStore) path() string { return filepath.Join(store.directory(), "install-draft.json") }

func verifyDraftDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fs.ErrPermission
	}
	return nil
}

func verifyDraftFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fs.ErrPermission
	}
	return nil
}

func syncPath(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}
