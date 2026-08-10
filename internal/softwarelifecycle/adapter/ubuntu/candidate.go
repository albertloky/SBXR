package ubuntu

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const candidateManifestName = "candidate.json"

const maxCandidateFileBytes = 4*softwarelifecycle.MaxAssetBytes + 2*softwarelifecycle.MaxIndexBytes + 8<<10

type CandidateStore struct{ directory string }

func NewCandidateStore() CandidateStore {
	return NewCandidateStoreAt("/var/lib/sbxr/software-lifecycle")
}

func NewCandidateStoreAt(directory string) CandidateStore {
	return CandidateStore{directory: directory}
}

type candidateManifest struct {
	Schema         int                                `json:"schema"`
	Sequence       uint64                             `json:"sequence"`
	Repository     string                             `json:"repository"`
	Tag            string                             `json:"tag"`
	Commit         string                             `json:"commit"`
	AttestedAssets []softwarelifecycle.AttestedAsset  `json:"attested_assets"`
	Verifier       softwarelifecycle.VerifierEvidence `json:"verifier"`
	VerifiedAt     string                             `json:"verified_at"`
}

func (store CandidateStore) RetainNewest(record softwarelifecycle.CandidateRecord) error {
	if record.Sequence == 0 || record.VerifiedAt.IsZero() || record.VerifiedAt.Location() != time.UTC || len(record.Evidence.Index) == 0 || len(record.Evidence.Index) > softwarelifecycle.MaxIndexBytes {
		return errors.New("update candidate refused")
	}
	if err := prepareCandidateDirectory(store.directory); err != nil {
		return err
	}
	return store.withLock(func() error {
		current, err := store.loadUnlocked()
		if err == nil && current.Sequence >= record.Sequence {
			return nil
		}
		if err != nil && !errors.Is(err, softwarelifecycle.ErrCandidateNotFound) {
			return err
		}
		return store.replaceUnlocked(record)
	})
}

func (store CandidateStore) Load() (softwarelifecycle.CandidateRecord, error) {
	if err := verifyCandidateDirectory(store.directory); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return softwarelifecycle.CandidateRecord{}, softwarelifecycle.ErrCandidateNotFound
		}
		return softwarelifecycle.CandidateRecord{}, err
	}
	var record softwarelifecycle.CandidateRecord
	err := store.withLock(func() error {
		var err error
		record, err = store.loadUnlocked()
		return err
	})
	return record, err
}

func (store CandidateStore) RemoveVerified(release softwarelifecycle.ReleaseIdentity) error {
	if err := verifyCandidateDirectory(store.directory); err != nil {
		return err
	}
	return store.withLock(func() error {
		record, err := store.loadUnlocked()
		if errors.Is(err, softwarelifecycle.ErrCandidateNotFound) {
			return nil
		}
		digest := sha256.Sum256(record.Evidence.Index)
		if err != nil || record.Evidence.Repository != release.Repository || record.Evidence.Tag != release.Tag || record.Evidence.Commit != release.Commit || hex.EncodeToString(digest[:]) != release.IndexSHA256 {
			return errors.New("completed update candidate identity changed")
		}
		if err := os.Remove(store.path()); err != nil {
			return err
		}
		return syncPath(store.directory)
	})
}

func (store CandidateStore) loadUnlocked() (softwarelifecycle.CandidateRecord, error) {
	if err := store.removeTemporary(); err != nil {
		return softwarelifecycle.CandidateRecord{}, err
	}
	if err := verifyCandidateFile(store.path()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return softwarelifecycle.CandidateRecord{}, softwarelifecycle.ErrCandidateNotFound
		}
		return softwarelifecycle.CandidateRecord{}, err
	}
	file, err := os.Open(store.path())
	if err != nil {
		return softwarelifecycle.CandidateRecord{}, err
	}
	info, statErr := file.Stat()
	if statErr != nil || info.Size() <= 0 || info.Size() > maxCandidateFileBytes {
		_ = file.Close()
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate size refused")
	}
	record, readErr := readCandidate(file, info.Size())
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate read failed")
	}
	return record, nil
}

func (store CandidateStore) replaceUnlocked(record softwarelifecycle.CandidateRecord) error {
	if err := verifyCandidateFile(store.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(store.temporaryPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeCandidate(file, record)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(store.temporaryPath())
		return errors.New("update candidate write failed")
	}
	if err := os.Rename(store.temporaryPath(), store.path()); err != nil {
		_ = os.Remove(store.temporaryPath())
		return err
	}
	return syncPath(store.directory)
}

func (store CandidateStore) withLock(action func() error) error {
	directory, err := os.Open(store.directory)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX); err != nil {
		_ = directory.Close()
		return err
	}
	actionErr := action()
	unlockErr := syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	closeErr := directory.Close()
	if actionErr != nil {
		return actionErr
	}
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func (store CandidateStore) path() string {
	return filepath.Join(store.directory, "update-candidate.tar")
}
func (store CandidateStore) temporaryPath() string { return store.path() + ".next" }

func (store CandidateStore) removeTemporary() error {
	info, err := os.Lstat(store.temporaryPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fs.ErrPermission
	}
	if err := os.Remove(store.temporaryPath()); err != nil {
		return err
	}
	return syncPath(store.directory)
}

func writeCandidate(output io.Writer, record softwarelifecycle.CandidateRecord) error {
	manifest, err := json.Marshal(candidateManifest{Schema: 1, Sequence: record.Sequence, Repository: record.Evidence.Repository, Tag: record.Evidence.Tag, Commit: record.Evidence.Commit, AttestedAssets: record.Evidence.AttestedAssets, Verifier: record.Evidence.Verifier, VerifiedAt: record.VerifiedAt.Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	written := map[string]bool{}
	archive := tar.NewWriter(output)
	for _, item := range append([]softwarelifecycle.DownloadedAsset{{Name: candidateManifestName, Bytes: manifest}, {Name: "release-index.json", Bytes: record.Evidence.Index}}, record.Evidence.Assets...) {
		if !safeCandidateName(item.Name) || written[item.Name] || len(item.Bytes) == 0 || int64(len(item.Bytes)) > candidateLimit(item.Name) {
			return errors.New("update candidate item refused")
		}
		written[item.Name] = true
		if err := archive.WriteHeader(&tar.Header{Name: item.Name, Mode: 0o600, Size: int64(len(item.Bytes)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := archive.Write(item.Bytes); err != nil {
			return err
		}
	}
	return archive.Close()
}

func readCandidate(input io.Reader, fileSize int64) (softwarelifecycle.CandidateRecord, error) {
	archive := tar.NewReader(input)
	items := map[string][]byte{}
	expectedSize := int64(1024)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(items) >= 6 || header.Typeflag != tar.TypeReg || header.Mode != 0o600 || !safeCandidateName(header.Name) || items[header.Name] != nil || header.Size <= 0 || header.Size > candidateLimit(header.Name) {
			return softwarelifecycle.CandidateRecord{}, errors.New("update candidate archive refused")
		}
		body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(body)) != header.Size {
			return softwarelifecycle.CandidateRecord{}, errors.New("update candidate archive refused")
		}
		items[header.Name] = body
		expectedSize += 512 + (header.Size+511)/512*512
	}
	if expectedSize != fileSize {
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate trailing content refused")
	}
	manifestBody, index := items[candidateManifestName], items["release-index.json"]
	delete(items, candidateManifestName)
	delete(items, "release-index.json")
	if len(manifestBody) == 0 || len(index) == 0 || len(items) != 4 || softwarelifecycle.ValidateUniqueJSON(manifestBody) != nil {
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate manifest refused")
	}
	var manifest candidateManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBody))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.Schema != 1 || manifest.Sequence == 0 {
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate manifest refused")
	}
	canonical, _ := json.Marshal(manifest)
	verifiedAt, err := time.Parse(time.RFC3339Nano, manifest.VerifiedAt)
	if err != nil || !bytes.Equal(canonical, manifestBody) || verifiedAt.Location() != time.UTC {
		return softwarelifecycle.CandidateRecord{}, errors.New("update candidate manifest refused")
	}
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	assets := make([]softwarelifecycle.DownloadedAsset, 0, len(names))
	for _, name := range names {
		assets = append(assets, softwarelifecycle.DownloadedAsset{Name: name, Bytes: items[name]})
	}
	return softwarelifecycle.CandidateRecord{Sequence: manifest.Sequence, Evidence: softwarelifecycle.ReleaseEvidence{Repository: manifest.Repository, Tag: manifest.Tag, Commit: manifest.Commit, Index: index, Assets: assets, AttestedAssets: manifest.AttestedAssets, Verifier: manifest.Verifier}, VerifiedAt: verifiedAt}, nil
}

func candidateLimit(name string) int64 {
	if name == candidateManifestName || name == "release-index.json" {
		return softwarelifecycle.MaxIndexBytes
	}
	return softwarelifecycle.MaxAssetBytes
}

func safeCandidateName(name string) bool {
	return name != "" && len(name) <= 128 && filepath.Base(name) == name && name != "." && name != ".."
}

func verifyCandidateDirectory(name string) error {
	return walkCandidateParents(name, false)
}

func prepareCandidateDirectory(name string) error {
	return walkCandidateParents(name, true)
}

func walkCandidateParents(name string, create bool) error {
	clean := filepath.Clean(name)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return fs.ErrPermission
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fs.ErrPermission
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) && create {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || index == len(parts)-1 && info.Mode().Perm() != 0o700 {
			return fs.ErrPermission
		}
	}
	return nil
}

func verifyCandidateFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxCandidateFileBytes || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fs.ErrPermission
	}
	return nil
}
