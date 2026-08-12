package ubuntu

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestReclamationDigestAcceptsOnlyOneUnchangedRegularFile(t *testing.T) {
	root := t.TempDir()
	targetPath := "/opt/app/proxy"
	target := filepath.Join(root, "opt/app/proxy")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("standalone proxy")
	if err := os.WriteFile(target, content, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	want := fmt.Sprintf("%x", digest)
	contract := systemchanges.ReclamationTarget{Kind: "executable", Path: targetPath, SHA256: want, ProcessID: "4242", ReviewSHA256: want}
	adapter := NewAt(root, nil, nil)
	if got, err := adapter.reclamationDigest(contract); err != nil || got != want {
		t.Fatalf("regular target = %q, %v", got, err)
	}

	if err := os.Link(target, target+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.reclamationDigest(contract); err == nil {
		t.Fatal("shared hard link was accepted")
	}
	if err := os.Remove(target + ".hardlink"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("neighbour", target); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.reclamationDigest(contract); err == nil {
		t.Fatal("symlink was accepted")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.reclamationDigest(contract); err == nil {
		t.Fatal("directory was accepted")
	}
}

func TestReclamationDigestRefusesPathReplacementDuringProof(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "opt/app/proxy")
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("standalone proxy")
	if err := os.WriteFile(name, content, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	contract := systemchanges.ReclamationTarget{Kind: "executable", Path: "/opt/app/proxy", SHA256: fmt.Sprintf("%x", digest), ProcessID: "4242", ReviewSHA256: fmt.Sprintf("%x", digest)}
	adapter := NewAt(root, nil, nil)
	adapter.afterReclamationDigest = func(path string) {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adapter.reclamationDigest(contract); err == nil {
		t.Fatal("replacement target was accepted")
	}
	if got, err := os.ReadFile(name + ".old"); err != nil || string(got) != string(content) {
		t.Fatalf("neighbour changed: %q, %v", got, err)
	}
}
