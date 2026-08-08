// Package filesystem persists the one root-only Health and Diagnostics event history.
package filesystem

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

const eventFile = "events.json"

type EventStorage struct {
	root string
	uid  int
}

func NewEventStorage() EventStorage { return EventStorage{root: "/", uid: 0} }

func newEventStorage(root string, uid int) EventStorage { return EventStorage{root: root, uid: uid} }

func (storage EventStorage) Load() ([]healthdiagnostics.DiagnosticEvent, error) {
	directory, err := storage.open(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer directory.Close()
	info, err := directory.Lstat(eventFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 2 || info.Size() > healthdiagnostics.EventRetentionBytes || owner(info) != storage.uid || links(info) != 1 {
		return nil, errors.New("diagnostic event history is unsafe")
	}
	data, err := directory.ReadFile(eventFile)
	if err != nil {
		return nil, errors.New("diagnostic event history is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var records []healthdiagnostics.EventRecord
	if decoder.Decode(&records) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("diagnostic event history is invalid")
	}
	events := make([]healthdiagnostics.DiagnosticEvent, 0, len(records))
	for _, record := range records {
		event, err := healthdiagnostics.RestoreDiagnosticEvent(record)
		if err != nil {
			return nil, errors.New("diagnostic event history is invalid")
		}
		events = append(events, event)
	}
	return events, nil
}

func (storage EventStorage) EncodedSize(events []healthdiagnostics.DiagnosticEvent) (int64, error) {
	data, err := encode(events)
	return int64(len(data)), err
}

func (storage EventStorage) Replace(events []healthdiagnostics.DiagnosticEvent) error {
	data, err := encode(events)
	if err != nil || len(data) > healthdiagnostics.EventRetentionBytes {
		return errors.New("diagnostic event history is too large")
	}
	directory, err := storage.open(true)
	if err != nil {
		return errors.New("diagnostic event directory is unsafe")
	}
	defer directory.Close()
	temporary := ".events.next"
	_ = directory.Remove(temporary)
	file, err := directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("diagnostic event write failed")
	}
	remove := true
	defer func() {
		file.Close()
		if remove {
			_ = directory.Remove(temporary)
		}
	}()
	if file.Chown(storage.uid, -1) != nil || file.Chmod(0o600) != nil {
		return errors.New("diagnostic event ownership failed")
	}
	if written, writeErr := file.Write(data); writeErr != nil || written != len(data) || file.Sync() != nil || file.Close() != nil {
		return errors.New("diagnostic event write failed")
	}
	if directory.Rename(temporary, eventFile) != nil {
		return errors.New("diagnostic event replacement failed")
	}
	remove = false
	return syncDirectory(directory)
}

func encode(events []healthdiagnostics.DiagnosticEvent) ([]byte, error) {
	records := make([]healthdiagnostics.EventRecord, len(events))
	for index, event := range events {
		record := event.Record()
		if _, err := healthdiagnostics.RestoreDiagnosticEvent(record); err != nil {
			return nil, err
		}
		records[index] = record
	}
	return json.Marshal(records)
}

func (storage EventStorage) open(create bool) (*os.Root, error) {
	root, err := os.OpenRoot(storage.root)
	if err != nil {
		return nil, errors.New("diagnostic event root is unavailable")
	}
	defer root.Close()
	baseInfo, err := root.Lstat("var/lib/sbxr")
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode().Perm() != 0o700 || owner(baseInfo) != storage.uid {
		return nil, unsafe(err)
	}
	base, err := root.OpenRoot("var/lib/sbxr")
	if err != nil {
		return nil, errors.New("diagnostic event base is unavailable")
	}
	defer base.Close()
	info, err := base.Lstat("diagnostics")
	if errors.Is(err, os.ErrNotExist) && create {
		if base.Mkdir("diagnostics", 0o700) != nil || base.Lchown("diagnostics", storage.uid, -1) != nil {
			return nil, errors.New("diagnostic event directory creation failed")
		}
		info, err = base.Lstat("diagnostics")
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || owner(info) != storage.uid {
		return nil, unsafe(err)
	}
	directory, err := base.OpenRoot("diagnostics")
	if err != nil {
		return nil, errors.New("diagnostic event directory is unavailable")
	}
	return directory, nil
}

func owner(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}

func links(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}

func unsafe(err error) error {
	if err != nil {
		return err
	}
	return errors.New("diagnostic event directory is unsafe")
}

func syncDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("diagnostic event directory sync failed")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("diagnostic event directory sync failed")
	}
	return nil
}
