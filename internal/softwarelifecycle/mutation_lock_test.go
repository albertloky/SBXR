package softwarelifecycle

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProvisionMutationLockCreatesOnceAndRetriesWithoutChangingInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxr.lock")
	lock, busy, err := ProvisionMutationLockAuthority(path, uint32(os.Getuid()))
	if err != nil || busy || lock == nil || !lock.Holds(path) {
		t.Fatalf("initial provision: lock=%v busy=%v err=%v", lock, busy, err)
	}
	before, err := os.Stat(path)
	if err != nil || before.Mode().Perm() != 0o600 || before.Size() != 0 {
		t.Fatalf("created lock = %#v, %v", before, err)
	}
	if other, busy, err := ProvisionMutationLockAuthority(path, uint32(os.Getuid())); err != nil || !busy || other != nil {
		if other != nil {
			other.Release()
		}
		t.Fatalf("contention: lock=%v busy=%v err=%v", other, busy, err)
	}
	lock.Release()

	retry, busy, err := ProvisionMutationLockAuthority(path, uint32(os.Getuid()))
	if err != nil || busy || retry == nil || !retry.Holds(path) {
		t.Fatalf("retry: lock=%v busy=%v err=%v", retry, busy, err)
	}
	retry.Release()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("retry changed inode: before=%#v after=%#v err=%v", before, after, err)
	}
}

func TestProvisionMutationLockRefusesUnsafeExistingInodesWithoutChangingThem(t *testing.T) {
	for _, kind := range []string{"mode", "hardlink", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "sbxr.lock")
			switch kind {
			case "symlink":
				target := filepath.Join(directory, "target")
				if err := os.WriteFile(target, nil, 0o600); err != nil || os.Symlink(target, path) != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				if kind == "mode" {
					if err := os.Chmod(path, 0o640); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Link(path, path+".other"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			lock, busy, err := ProvisionMutationLockAuthority(path, uint32(os.Getuid()))
			if lock != nil {
				lock.Release()
			}
			if err == nil || busy || lock != nil {
				t.Fatalf("unsafe inode accepted: lock=%v busy=%v err=%v", lock, busy, err)
			}
			after, afterErr := os.Lstat(path)
			if afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("unsafe inode changed: before=%#v after=%#v err=%v", before, after, afterErr)
			}
		})
	}
}
