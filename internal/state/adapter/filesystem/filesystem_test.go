package filesystem

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
)

var release = state.ReleaseIdentity{
	Repository:         "https://github.com/albertloky/SBXR",
	Tag:                "v1.0.0",
	Commit:             "0123456789abcdef0123456789abcdef01234567",
	ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}

func TestProductionPlacement(t *testing.T) {
	if StateDirectory != "/var/lib/sbxr/state" || StatePath != "/var/lib/sbxr/state/state.json" {
		t.Fatalf("production placement = (%q, %q)", StateDirectory, StatePath)
	}
}

func TestRootOwnershipSeam(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root-run controlled Seam environment")
	}
	root := protectedBoundary(t)
	result, err := state.New(newAt(root, 0)).Load(state.LoadRequest{
		Baseline:         state.ManagedEvidence,
		SupportedRelease: release,
		Lineage:          &state.LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: release},
	})
	if err != nil || result.Status != state.Managed {
		t.Fatalf("root-owned Load() = (%+v, %v), want Managed", result, err)
	}
}

func TestFilesystemSeam(t *testing.T) {
	request := state.LoadRequest{
		Baseline:         state.ManagedEvidence,
		SupportedRelease: release,
		Lineage: &state.LineageProof{
			Revision:               7,
			LastCompletedChangeSet: "change-0007",
			ReleaseIdentity:        release,
		},
	}

	t.Run("reads the protected current document", func(t *testing.T) {
		root := protectedBoundary(t)
		loader := state.New(newAt(root, os.Geteuid()))
		for range 2 {
			result, err := loader.Load(request)
			if err != nil || result.Status != state.Managed || result.Snapshot.Revision != 7 || result.Migration == nil || result.Migration.StartingSchema != 1 || result.Migration.TargetSchema != 1 || len(result.Migration.Steps) != 0 {
				t.Fatalf("Load() = (%+v, %v), want a durable Managed read", result, err)
			}
		}
	})

	t.Run("path substitution", func(t *testing.T) {
		root := protectedBoundary(t)
		path := filepath.Join(root, "state", "state.json")
		storage := adapter{root: root, uid: os.Geteuid(), beforeFileOpen: func() {
			must(t, os.Rename(path, path+".replaced"))
			must(t, os.WriteFile(path, []byte(completeDocument(t)), 0o600))
		}}
		result, err := state.New(storage).Load(request)
		if result.Status != state.RecoveryRequired || err == nil || !strings.Contains(err.Error(), "STATE-STORAGE-PATH") {
			t.Fatalf("Load() = (%+v, %v), want STATE-STORAGE-PATH", result, err)
		}
	})

	tests := []struct {
		name string
		edit func(*testing.T, string)
		code string
	}{
		{name: "broader root-directory mode", edit: func(t *testing.T, root string) { must(t, os.Chmod(root, 0o750)) }, code: "STATE-STORAGE-MODE"},
		{name: "broader State-directory mode", edit: func(t *testing.T, root string) { must(t, os.Chmod(filepath.Join(root, "state"), 0o750)) }, code: "STATE-STORAGE-MODE"},
		{name: "broader file mode", edit: func(t *testing.T, root string) { must(t, os.Chmod(filepath.Join(root, "state", "state.json"), 0o640)) }, code: "STATE-STORAGE-MODE"},
		{name: "wrong owner", edit: func(t *testing.T, root string) {}, code: "STATE-STORAGE-OWNER"},
		{name: "symbolic-link file", edit: func(t *testing.T, root string) {
			path := filepath.Join(root, "state", "state.json")
			must(t, os.Rename(path, path+".target"))
			must(t, os.Symlink("state.json.target", path))
		}, code: "STATE-STORAGE-SYMLINK"},
		{name: "symbolic-link directory", edit: func(t *testing.T, root string) {
			must(t, os.Rename(filepath.Join(root, "state"), filepath.Join(root, "real-state")))
			must(t, os.Symlink("real-state", filepath.Join(root, "state")))
		}, code: "STATE-STORAGE-SYMLINK"},
		{name: "hard-linked file", edit: func(t *testing.T, root string) {
			must(t, os.Link(filepath.Join(root, "state", "state.json"), filepath.Join(root, "state", "second-link")))
		}, code: "STATE-STORAGE-HARDLINK"},
		{name: "unexpected file type", edit: func(t *testing.T, root string) {
			must(t, os.Remove(filepath.Join(root, "state", "state.json")))
			must(t, os.Mkdir(filepath.Join(root, "state", "state.json"), 0o600))
		}, code: "STATE-STORAGE-TYPE"},
		{name: "corrupt document", edit: func(t *testing.T, root string) {
			corrupt := corruptChecksum(t, completeDocument(t))
			must(t, os.WriteFile(filepath.Join(root, "state", "state.json"), []byte(corrupt), 0o600))
		}, code: "STATE-CHECKSUM-MISMATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := protectedBoundary(t)
			tt.edit(t, root)
			uid := os.Geteuid()
			if tt.name == "wrong owner" {
				uid++
			}
			result, err := state.New(newAt(root, uid)).Load(request)
			if result.Status != state.RecoveryRequired || err == nil || !strings.Contains(err.Error(), tt.code) {
				t.Fatalf("Load() = (%+v, %v), want %s", result, err, tt.code)
			}
			if strings.Contains(err.Error(), completeDocument(t)) {
				t.Fatal("storage finding exposed protected State")
			}
		})
	}
}

func TestAtomicPublicationSeam(t *testing.T) {
	prior := []byte(completeDocument(t))
	candidate := []byte(candidateDocument(t, 8, "change-0008"))
	digest := sha256.Sum256(candidate)

	t.Run("flushes replaces and reads back exact candidate", func(t *testing.T) {
		root := protectedBoundary(t)
		publisher := newAt(root, os.Geteuid())
		readback, err := publisher.Publish(prior, candidate, hex.EncodeToString(digest[:]))
		if err != nil || !bytes.Equal(readback, candidate) {
			t.Fatalf("Publish() = (%q, %v), want exact candidate readback", readback, err)
		}
		current, err := os.ReadFile(filepath.Join(root, "state", "state.json"))
		if err != nil || !bytes.Equal(current, candidate) {
			t.Fatal("atomic publication did not leave the exact candidate current")
		}
		if _, err := os.Lstat(filepath.Join(root, "state", "state.json.next")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("successful publication retained prepared history")
		}
	})

	t.Run("publishes fresh revision into absent State directory", func(t *testing.T) {
		root := t.TempDir()
		must(t, os.Chmod(root, 0o700))
		fresh := []byte(candidateDocument(t, 1, "change-0001"))
		freshDigest := sha256.Sum256(fresh)
		publisher := newAt(root, os.Geteuid())
		readback, err := publisher.Publish(nil, fresh, hex.EncodeToString(freshDigest[:]))
		if err != nil || !bytes.Equal(readback, fresh) {
			t.Fatalf("fresh Publish() = (%q, %v), want exact revision 1", readback, err)
		}
	})

	t.Run("refuses a changed baseline or candidate checksum", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			expected []byte
			checksum string
		}{
			{name: "changed baseline", expected: append([]byte("\n"), prior...), checksum: hex.EncodeToString(digest[:])},
			{name: "wrong candidate checksum", expected: prior, checksum: strings.Repeat("0", 64)},
		} {
			t.Run(test.name, func(t *testing.T) {
				root := protectedBoundary(t)
				publisher := newAt(root, os.Geteuid())
				if _, err := publisher.Publish(test.expected, candidate, test.checksum); err == nil {
					t.Fatal("unsafe publication succeeded")
				}
				current, err := os.ReadFile(filepath.Join(root, "state", "state.json"))
				if err != nil || !bytes.Equal(current, prior) {
					t.Fatal("refused publication changed current State")
				}
			})
		}
	})

	t.Run("detects candidate corruption after flush", func(t *testing.T) {
		root := protectedBoundary(t)
		storage := adapter{root: root, uid: os.Geteuid(), interrupt: func(point string) error {
			if point == "before-candidate-verify" {
				return os.WriteFile(filepath.Join(root, "state", "state.json.next"), []byte(`{"corrupt":true}`), 0o600)
			}
			return nil
		}}
		if _, err := storage.Publish(prior, candidate, hex.EncodeToString(digest[:])); err == nil || !strings.Contains(err.Error(), "STATE-PUBLICATION-CHECKSUM") {
			t.Fatalf("Publish() error = %v, want STATE-PUBLICATION-CHECKSUM", err)
		}
		current, err := os.ReadFile(filepath.Join(root, "state", "state.json"))
		if err != nil || !bytes.Equal(current, prior) {
			t.Fatal("candidate corruption changed current State")
		}
	})

	t.Run("refuses current path substitution before replacement", func(t *testing.T) {
		root := protectedBoundary(t)
		path := filepath.Join(root, "state", "state.json")
		storage := adapter{root: root, uid: os.Geteuid(), interrupt: func(point string) error {
			if point == "before-replace" {
				if err := os.Rename(path, path+".substituted"); err != nil {
					return err
				}
				return os.WriteFile(path, append([]byte("\n"), prior...), 0o600)
			}
			return nil
		}}
		if _, err := storage.Publish(prior, candidate, hex.EncodeToString(digest[:])); err == nil || !strings.Contains(err.Error(), "STATE-PUBLICATION-STALE") {
			t.Fatalf("Publish() error = %v, want STATE-PUBLICATION-STALE", err)
		}
		current, err := os.ReadFile(path)
		if err != nil || bytes.Equal(current, candidate) {
			t.Fatal("publication replaced a substituted current path")
		}
	})

	t.Run("recovers stale candidate files left by restart", func(t *testing.T) {
		for _, stale := range [][]byte{[]byte(`{"partial":`), candidate} {
			root := protectedBoundary(t)
			must(t, os.WriteFile(filepath.Join(root, "state", "state.json.next"), stale, 0o600))
			publisher := newAt(root, os.Geteuid())
			readback, err := publisher.Publish(prior, candidate, hex.EncodeToString(digest[:]))
			if err != nil || !bytes.Equal(readback, candidate) {
				t.Fatalf("restart Publish() = (%q, %v), want exact candidate", readback, err)
			}
			if _, err := os.Lstat(filepath.Join(root, "state", "state.json.next")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("restart recovery retained stale candidate history")
			}
		}
	})

	t.Run("refuses an unsafe stale candidate", func(t *testing.T) {
		root := protectedBoundary(t)
		must(t, os.Symlink("state.json", filepath.Join(root, "state", "state.json.next")))
		publisher := newAt(root, os.Geteuid())
		if _, err := publisher.Publish(prior, candidate, hex.EncodeToString(digest[:])); err == nil || !strings.Contains(err.Error(), "STATE-STORAGE-SYMLINK") {
			t.Fatalf("Publish() error = %v, want STATE-STORAGE-SYMLINK", err)
		}
		current, err := os.ReadFile(filepath.Join(root, "state", "state.json"))
		if err != nil || !bytes.Equal(current, prior) {
			t.Fatal("unsafe stale candidate changed current State")
		}
	})
}

func TestAtomicRollbackRestoresManagedOrNotInstalledBaseline(t *testing.T) {
	prior := []byte(completeDocument(t))
	candidate := []byte(candidateDocument(t, 8, "change-0008"))

	t.Run("Managed", func(t *testing.T) {
		root := protectedBoundary(t)
		storage := adapter{root: root, uid: os.Geteuid()}
		candidateDigest := sha256.Sum256(candidate)
		if _, err := storage.Publish(prior, candidate, hex.EncodeToString(candidateDigest[:])); err != nil {
			t.Fatal(err)
		}
		readback, err := storage.Restore(candidate, prior)
		if err != nil || !bytes.Equal(readback, prior) {
			t.Fatalf("Restore() = (%q, %v), want exact Managed baseline", readback, err)
		}
	})

	t.Run("Not installed", func(t *testing.T) {
		root := t.TempDir()
		must(t, os.Chmod(root, 0o700))
		storage := adapter{root: root, uid: os.Geteuid()}
		candidateDigest := sha256.Sum256(candidate)
		if _, err := storage.Publish(nil, candidate, hex.EncodeToString(candidateDigest[:])); err != nil {
			t.Fatal(err)
		}
		readback, err := storage.Restore(candidate, nil)
		if err != nil || readback != nil {
			t.Fatalf("Restore() = (%q, %v), want proven Not installed", readback, err)
		}
		if _, err := storage.Read(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed State remained readable: %v", err)
		}
	})

	t.Run("changed current State", func(t *testing.T) {
		root := protectedBoundary(t)
		storage := adapter{root: root, uid: os.Geteuid()}
		candidateDigest := sha256.Sum256(candidate)
		if _, err := storage.Publish(prior, candidate, hex.EncodeToString(candidateDigest[:])); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Restore(append([]byte("changed"), candidate...), prior); err == nil {
			t.Fatal("Restore accepted an unproven current State")
		}
		current, err := storage.Read()
		if err != nil || !bytes.Equal(current, candidate) {
			t.Fatal("refused rollback changed current State")
		}
	})
}

func TestStaleCandidateCleanupInterruptionPoints(t *testing.T) {
	prior := []byte(completeDocument(t))
	candidate := []byte(candidateDocument(t, 8, "change-0008"))
	digest := sha256.Sum256(candidate)
	points := []string{
		"before-stale-candidate-remove", "after-stale-candidate-remove",
		"before-stale-candidate-directory-flush", "after-stale-candidate-directory-flush",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			root := protectedBoundary(t)
			must(t, os.WriteFile(filepath.Join(root, "state", "state.json.next"), []byte(`{"partial":`), 0o600))
			interrupted := adapter{root: root, uid: os.Geteuid(), interrupt: func(current string) error {
				if current == point {
					return errors.New("simulated interruption")
				}
				return nil
			}}
			if _, err := interrupted.Publish(prior, candidate, hex.EncodeToString(digest[:])); err == nil {
				t.Fatal("simulated stale cleanup interruption did not stop publication")
			}
			readback, err := newAt(root, os.Geteuid()).Publish(prior, candidate, hex.EncodeToString(digest[:]))
			if err != nil || !bytes.Equal(readback, candidate) {
				t.Fatalf("retry Publish() = (%q, %v), want exact candidate", readback, err)
			}
		})
	}
}

func TestAtomicPublicationInterruptionPoints(t *testing.T) {
	prior := []byte(completeDocument(t))
	candidate := []byte(candidateDocument(t, 8, "change-0008"))
	digest := sha256.Sum256(candidate)
	points := []string{
		"before-candidate-write", "after-candidate-write",
		"before-candidate-flush", "after-candidate-flush",
		"before-candidate-verify", "after-candidate-verify",
		"before-replace", "after-replace",
		"before-directory-flush", "after-directory-flush",
		"before-readback", "after-readback",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			root := protectedBoundary(t)
			storage := adapter{root: root, uid: os.Geteuid(), interrupt: func(current string) error {
				if current == point {
					return errors.New("simulated interruption")
				}
				return nil
			}}
			if _, err := storage.Publish(prior, candidate, hex.EncodeToString(digest[:])); err == nil {
				t.Fatal("simulated interruption did not stop publication")
			}
			current, err := os.ReadFile(filepath.Join(root, "state", "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			want := prior
			if point == "after-replace" || point == "before-directory-flush" || point == "after-directory-flush" || point == "before-readback" || point == "after-readback" {
				want = candidate
			}
			if !bytes.Equal(current, want) {
				t.Fatal("interruption left a half-written current document")
			}
		})
	}
}

func TestFreshPublicationDirectoryInterruptionPoints(t *testing.T) {
	candidate := []byte(candidateDocument(t, 1, "change-0001"))
	digest := sha256.Sum256(candidate)
	for _, point := range []string{"before-state-directory-create", "after-state-directory-create", "before-parent-directory-flush", "after-parent-directory-flush"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			must(t, os.Chmod(root, 0o700))
			storage := adapter{root: root, uid: os.Geteuid(), interrupt: func(current string) error {
				if current == point {
					return errors.New("simulated interruption")
				}
				return nil
			}}
			if _, err := storage.Publish(nil, candidate, hex.EncodeToString(digest[:])); err == nil {
				t.Fatal("simulated directory interruption did not stop publication")
			}
			if _, err := os.Lstat(filepath.Join(root, "state", "state.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fresh interruption published a partial current State")
			}
		})
	}
}

func protectedBoundary(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must(t, os.Chmod(root, 0o700))
	must(t, os.Mkdir(filepath.Join(root, "state"), 0o700))
	must(t, os.WriteFile(filepath.Join(root, "state", "state.json"), []byte(completeDocument(t)), 0o600))
	return root
}

func completeDocument(t *testing.T) string {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("..", "..", "testdata", "complete-state.json"))
	must(t, err)
	return strings.TrimSpace(string(document))
}

func candidateDocument(t *testing.T, revision uint64, changeSet string) string {
	t.Helper()
	document := completeDocument(t)
	document = strings.Replace(document, `"revision":7`, `"revision":`+fmt.Sprint(revision), 1)
	return strings.Replace(document, `"change-0007"`, `"`+changeSet+`"`, 1)
}

func corruptChecksum(t *testing.T, document string) string {
	t.Helper()
	const prefix = `"checksum":"`
	start := strings.Index(document, prefix)
	if start < 0 {
		t.Fatal("fixture has no checksum")
	}
	start += len(prefix)
	replacement := "0"
	if document[start] == '0' {
		replacement = "1"
	}
	return document[:start] + replacement + document[start+1:]
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
