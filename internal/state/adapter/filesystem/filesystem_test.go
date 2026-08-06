package filesystem

import (
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
			if err != nil || result.Status != state.Managed || result.Snapshot.Revision != 7 {
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
