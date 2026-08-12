package ubuntu

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestReclamationDeleteRestoresAReplacementInsteadOfDeletingIt(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "opt/app/proxy")
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, transactionDirectory, "change-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("reviewed proxy")
	replacement := []byte("unrelated replacement")
	if err := os.WriteFile(name, original, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	contract := systemchanges.ReclamationTarget{Kind: "executable", Path: "/opt/app/proxy", SHA256: fmt.Sprintf("%x", digest), ProcessID: "4242", ReviewSHA256: fmt.Sprintf("%x", digest)}
	adapter := NewAt(root, nil, nil)
	adapter.afterReclamationProof = func(path string) {
		if err := os.Rename(path, path+".reviewed"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, replacement, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adapter.deleteReclamationTarget("change-1", contract); err == nil {
		t.Fatal("replacement between proof and quarantine was deleted")
	}
	if got, err := os.ReadFile(name); err != nil || string(got) != string(replacement) {
		t.Fatalf("replacement was not restored: %q, %v", got, err)
	}
	if got, err := os.ReadFile(name + ".reviewed"); err != nil || string(got) != string(original) {
		t.Fatalf("reviewed inode changed: %q, %v", got, err)
	}
}

func TestReclamationQuarantineRestoreNeverOverwritesANewPath(t *testing.T) {
	directory := t.TempDir()
	quarantine := filepath.Join(directory, "quarantine")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(quarantine, []byte("reviewed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(quarantine, target); err == nil {
		t.Fatal("quarantine restore overwrote an unrelated path")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "unrelated" {
		t.Fatalf("unrelated target changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(quarantine); err != nil || string(got) != "reviewed" {
		t.Fatalf("quarantined target changed: %q, %v", got, err)
	}
}

func TestReclamationScriptAndProcessHandleRecheckExactProcess(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc/4242")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/python3", filepath.Join(proc, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte("/usr/bin/python3\x00/opt/app/proxy.py\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := systemchanges.ReclamationTarget{Kind: "script", Path: "/opt/app/proxy.py", Interpreter: "/usr/bin/python3", ProcessID: "4242"}
	adapter := NewAt(root, nil, nil)
	if err := adapter.verifyReclamationProcess(target); err != nil {
		t.Fatalf("exact script process = %v", err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte("/usr/bin/python3\x00/opt/app/other.py\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adapter.verifyReclamationProcess(target); err == nil {
		t.Fatal("same interpreter with another script was accepted")
	}
	adapter.stopProcess = func(_ int, _ string, _ time.Duration, verify func() error) error {
		if err := os.Remove(filepath.Join(proc, "exe")); err != nil {
			return err
		}
		if err := os.Symlink("/usr/bin/other", filepath.Join(proc, "exe")); err != nil {
			return err
		}
		return verify()
	}
	if err := adapter.stopProcess(4242, filepath.Join(proc, "status"), time.Second, func() error { return adapter.verifyReclamationProcess(target) }); err == nil {
		t.Fatal("process replacement after handle acquisition was accepted")
	}
}
