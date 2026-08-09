package ubuntu

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestCandidateStoreAtomicallyRetainsOnlyTheNewestVerifiedEvidence(t *testing.T) {
	directory := filepath.Join(candidateTestRoot(t), "candidates")
	store := NewCandidateStoreAt(directory)
	first := candidateRecord("v1.1.0")
	second := candidateRecord("v1.2.0")
	second.Sequence = 3
	if err := store.RetainNewest(first); err != nil {
		t.Fatal(err)
	}
	if err := store.RetainNewest(second); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || !reflect.DeepEqual(got, second) {
		t.Fatalf("Load() = (%#v, %v)", got, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "update-candidate.tar" {
		t.Fatalf("retained files = %v, %v", entries, err)
	}
	info, err := os.Lstat(filepath.Join(directory, "update-candidate.tar"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("candidate mode = %+v, %v", info, err)
	}
}

func TestCandidateStoreRestartKeepsCurrentAndRemovesInterruptedReplacement(t *testing.T) {
	directory := filepath.Join(candidateTestRoot(t), "candidates")
	store := NewCandidateStoreAt(directory)
	want := candidateRecord("v1.1.0")
	if err := store.RetainNewest(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "update-candidate.tar.next"), []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewCandidateStoreAt(directory).Load()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("restart Load() = (%#v, %v)", got, err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "update-candidate.tar.next")); !os.IsNotExist(err) {
		t.Fatalf("interrupted replacement remains: %v", err)
	}
}

func TestCandidateStoreRefusesLinksAndBroadModes(t *testing.T) {
	directory := filepath.Join(candidateTestRoot(t), "candidates")
	store := NewCandidateStoreAt(directory)
	if err := store.RetainNewest(candidateRecord("v1.1.0")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "update-candidate.tar")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("broad candidate mode accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("linked candidate accepted")
	}
}

func TestCandidateStoreRefusesTrailingContentAndUnsafeParents(t *testing.T) {
	root := candidateTestRoot(t)
	directory := filepath.Join(root, "safe", "candidates")
	store := NewCandidateStoreAt(directory)
	if err := store.RetainNewest(candidateRecord("v1.1.0")); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(directory, "update-candidate.tar"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("trailing tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("trailing candidate content accepted")
	}

	linkedRoot := candidateTestRoot(t)
	if err := os.Symlink(root, filepath.Join(linkedRoot, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := NewCandidateStoreAt(filepath.Join(linkedRoot, "linked", "candidates")).RetainNewest(candidateRecord("v1.2.0")); err == nil {
		t.Fatal("linked parent accepted")
	}
	writable := filepath.Join(candidateTestRoot(t), "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := NewCandidateStoreAt(filepath.Join(writable, "candidates")).RetainNewest(candidateRecord("v1.2.0")); err == nil {
		t.Fatal("writable parent accepted")
	}
}

func TestCandidateStoreConcurrentChecksRetainTheHighestSequence(t *testing.T) {
	store := NewCandidateStoreAt(filepath.Join(candidateTestRoot(t), "candidates"))
	start := make(chan struct{})
	errors := make(chan error, 20)
	var wait sync.WaitGroup
	for sequence := uint64(2); sequence <= 21; sequence++ {
		wait.Add(1)
		go func(sequence uint64) {
			defer wait.Done()
			<-start
			record := candidateRecord("v1.1.0")
			record.Sequence = sequence
			errors <- store.RetainNewest(record)
		}(sequence)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Load()
	if err != nil || got.Sequence != 21 {
		t.Fatalf("Load() = (%#v, %v)", got, err)
	}
}

func candidateRecord(tag string) softwarelifecycle.CandidateRecord {
	return softwarelifecycle.CandidateRecord{Sequence: 2, Evidence: softwarelifecycle.ReleaseEvidence{
		Repository: softwarelifecycle.Repository,
		Tag:        tag,
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Index:      []byte(`{"schema":1}`),
		Assets: []softwarelifecycle.DownloadedAsset{
			{Name: "four.tar.gz", Bytes: []byte("four")},
			{Name: "one.tar.gz", Bytes: []byte("one")},
			{Name: "three.tar.gz", Bytes: []byte("three")},
			{Name: "two.tar.gz", Bytes: []byte("two")},
		},
		AttestedAssets: []softwarelifecycle.AttestedAsset{
			{Name: "release-index.json", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{Name: "one.tar.gz", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			{Name: "two.tar.gz", SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			{Name: "three.tar.gz", SHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			{Name: "four.tar.gz", SHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		},
		Verifier: softwarelifecycle.VerifierEvidence{Version: "2.97.0", SigningFingerprint: "7F38BBB59D064DBCB3D84D725612B36462313325", OfficialSignedDistribution: true, ReleaseVerified: true, VerifiedAssets: []string{"release-index.json", "one.tar.gz", "two.tar.gz", "three.tar.gz", "four.tar.gz"}},
	}, VerifiedAt: time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)}
}

func candidateTestRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".sbxr-candidate-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
