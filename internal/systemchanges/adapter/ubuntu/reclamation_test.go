package ubuntu

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestReclamationRecoveryPreservesQuarantineAndReplacement(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "opt/app/proxy")
	quarantine := filepath.Join(root, transactionDirectory, "change-1", "reclamation-target")
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(quarantine), 0o700); err != nil {
		t.Fatal(err)
	}
	reviewed := []byte("reviewed")
	replacement := []byte("unrelated")
	if err := os.WriteFile(quarantine, reviewed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(reviewed)
	target := systemchanges.ReclamationTarget{Kind: "executable", Path: "/opt/app/proxy", SHA256: fmt.Sprintf("%x", digest), ProcessID: "4242", ReviewSHA256: fmt.Sprintf("%x", digest)}
	adapter := NewAt(root, nil, nil)
	if _, err := adapter.deleteReclamationTarget("change-1", target); err == nil {
		t.Fatal("recovery deleted quarantine while original pathname was occupied")
	}
	if got, err := os.ReadFile(name); err != nil || string(got) != string(replacement) {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(quarantine); err != nil || string(got) != string(reviewed) {
		t.Fatalf("quarantine changed: %q, %v", got, err)
	}
}

func TestReclamationReadinessRefusesCrossDeviceQuarantine(t *testing.T) {
	first := fakeFileInfo{stat: &syscall.Stat_t{Dev: 11}}
	second := fakeFileInfo{stat: &syscall.Stat_t{Dev: 22}}
	if sameFilesystem(first, second) || !sameFilesystem(first, fakeFileInfo{stat: &syscall.Stat_t{Dev: 11}}) {
		t.Fatal("cross-device quarantine was accepted")
	}
}

type fakeFileInfo struct{ stat *syscall.Stat_t }

func (fakeFileInfo) Name() string       { return "fixture" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0o755 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (info fakeFileInfo) Sys() any      { return info.stat }

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

func TestPackageReclamationUsesOnlyExactNativePurgeAndHoldCommands(t *testing.T) {
	t.Run("allowlisted purge", func(t *testing.T) {
		installed := true
		var commands []string
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/xray.list"), []byte("/opt/xray\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		adapter := NewAt(root, nil, nil)
		adapter.packageCommand = func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(arguments, " "))
			switch {
			case name == "/usr/bin/dpkg-query" && len(arguments) == 3 && installed:
				return []byte("install ok installed\t1.2.3\n"), nil
			case name == "/usr/bin/dpkg-query" && len(arguments) == 3:
				return nil, os.ErrNotExist
			case name == "/usr/bin/dpkg-query" && installed:
				return []byte("xray\t1.2.3\tamd64\tinstall ok installed\t\t\nunrelated\t9.9\tamd64\tinstall ok installed\t\t\n"), nil
			case name == "/usr/bin/dpkg-query":
				return []byte("unrelated\t9.9\tamd64\tinstall ok installed\t\t\n"), nil
			case name == "/usr/bin/dpkg":
				installed = false
				return nil, nil
			default:
				return nil, fmt.Errorf("unexpected command")
			}
		}
		target := systemchanges.ReclamationTarget{Kind: "package-purge", Package: "xray", PackageVersion: "1.2.3", OwnedPaths: []string{"/opt/xray"}}
		if _, err := adapter.purgeReclamationPackage(target, time.Second); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(commands, "\n")
		if !strings.Contains(joined, "/usr/bin/dpkg --purge --no-triggers -- xray") || strings.Contains(joined, "apt-get") || strings.Contains(joined, "autoremove") || strings.Contains(joined, "upgrade") {
			t.Fatalf("package purge commands = %s", joined)
		}
	})

	t.Run("unsupported package hold", func(t *testing.T) {
		held := false
		adapter := NewAt(t.TempDir(), nil, nil)
		adapter.packageCommand = func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
			switch {
			case name == "/usr/bin/dpkg-query":
				return []byte("install ok installed\t4.5.6\n"), nil
			case name == "/usr/bin/apt-mark" && len(arguments) == 2 && arguments[0] == "hold" && arguments[1] == "vendor-proxy":
				held = true
				return []byte("vendor-proxy set on hold.\n"), nil
			case name == "/usr/bin/apt-mark" && len(arguments) == 1 && arguments[0] == "showhold":
				if held {
					return []byte("vendor-proxy\n"), nil
				}
				return nil, nil
			default:
				return nil, fmt.Errorf("unexpected command")
			}
		}
		target := systemchanges.ReclamationTarget{Kind: "package-hold", Package: "vendor-proxy", PackageVersion: "4.5.6"}
		if err := adapter.holdReclamationPackage(target, time.Second); err != nil || !held {
			t.Fatalf("package hold = %v, held=%t", err, held)
		}
	})
}

func TestPackagePurgeRefusesUnrelatedDependencyMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/xray:amd64.postrm"), []byte("#!/bin/sh\nrm -rf /srv/site\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	adapter := NewAt(root, nil, nil)
	adapter.packageCommand = func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
		if name == "/usr/bin/dpkg-query" && len(arguments) == 3 {
			return []byte("install ok installed\t1.2.3\n"), nil
		}
		if name == "/usr/bin/dpkg-query" {
			return []byte("xray\t1.2.3\tamd64\tinstall ok installed\t\t\nunrelated\t9.9\tamd64\tinstall ok installed\t\t\n"), nil
		}
		return nil, fmt.Errorf("unexpected mutation command")
	}
	target := systemchanges.ReclamationTarget{Kind: "package-purge", Package: "xray", PackageVersion: "1.2.3", OwnedPaths: []string{"/opt/xray"}}
	if _, err := adapter.purgeReclamationPackage(target, time.Second); err == nil {
		t.Fatal("package with hostile maintainer script was accepted")
	}
}

func TestPackagePurgeRefusesChangedOwnedPaths(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "xray.list"), []byte("/opt/xray\n/var/www/site\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := NewAt(root, nil, nil)
	adapter.packageCommand = func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
		if name == "/usr/bin/dpkg-query" && len(arguments) == 3 {
			return []byte("install ok installed\t1.2.3\n"), nil
		}
		return nil, fmt.Errorf("unexpected mutation command")
	}
	target := systemchanges.ReclamationTarget{Kind: "package-purge", Package: "xray", PackageVersion: "1.2.3", OwnedPaths: []string{"/opt/xray"}}
	if _, err := adapter.purgeReclamationPackage(target, time.Second); err == nil {
		t.Fatal("changed package-owned paths were accepted")
	}
}

func TestPackagePurgeRefusesConffilesSymlinksAndLateReplacement(t *testing.T) {
	for _, test := range []struct {
		name       string
		setup      func(string) error
		hook       func(string)
		wrongOwner bool
	}{
		{name: "conffiles", setup: func(info string) error {
			return os.WriteFile(filepath.Join(info, "xray.conffiles"), []byte("/var/www/site\n"), 0o600)
		}},
		{name: "symlink list", setup: func(info string) error {
			if err := os.WriteFile(filepath.Join(info, "owned"), []byte("/opt/xray\n"), 0o600); err != nil {
				return err
			}
			return os.Symlink("owned", filepath.Join(info, "xray.list"))
		}},
		{name: "wrong owner directory", wrongOwner: true, setup: func(info string) error {
			return os.WriteFile(filepath.Join(info, "xray.list"), []byte("/opt/xray\n"), 0o600)
		}},
		{name: "replacement after proof", setup: func(info string) error {
			return os.WriteFile(filepath.Join(info, "xray.list"), []byte("/opt/xray\n"), 0o600)
		}, hook: func(info string) {
			if err := os.WriteFile(filepath.Join(info, "replacement"), []byte("/opt/xray\n/var/www/site\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(info, "replacement"), filepath.Join(info, "xray.list")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			info := filepath.Join(root, "var/lib/dpkg/info")
			if err := os.MkdirAll(info, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := test.setup(info); err != nil {
				t.Fatal(err)
			}
			adapter := NewAt(root, nil, nil)
			if test.wrongOwner {
				adapter.uid++
			}
			adapter.packageCommand = func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
				if name == "/usr/bin/dpkg-query" && len(arguments) == 3 {
					return []byte("install ok installed\t1.2.3\n"), nil
				}
				return nil, fmt.Errorf("unexpected mutation command")
			}
			if test.hook != nil {
				adapter.afterPackageControlProof = func(string) { test.hook(info) }
			}
			target := systemchanges.ReclamationTarget{Kind: "package-purge", Package: "xray", PackageVersion: "1.2.3", OwnedPaths: []string{"/opt/xray"}}
			if _, err := adapter.purgeReclamationPackage(target, time.Second); err == nil {
				t.Fatal("unsafe package control material was accepted")
			}
		})
	}
}

func TestPackagePurgeRefusesLateUnrelatedPackageChange(t *testing.T) {
	installed := true
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, transactionDirectory, "change-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/xray.list"), []byte("/opt/xray\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := func(_ time.Duration, name string, arguments ...string) ([]byte, error) {
		switch {
		case name == "/usr/bin/dpkg-query" && len(arguments) == 3 && installed:
			return []byte("install ok installed\t1.2.3\n"), nil
		case name == "/usr/bin/dpkg-query" && len(arguments) == 3:
			return nil, os.ErrNotExist
		case name == "/usr/bin/dpkg-query" && installed:
			return []byte("xray\t1.2.3\tamd64\tinstall ok installed\t\t\nunrelated\t9.9\tamd64\tinstall ok installed\t\t\n"), nil
		case name == "/usr/bin/dpkg-query":
			return []byte("unrelated\t9.9\tamd64\tdeinstall ok config-files\tforeign-trigger\t\n"), nil
		case name == "/usr/bin/dpkg":
			installed = false
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected command")
	}
	target := systemchanges.ReclamationTarget{Kind: "package-purge", Package: "xray", PackageVersion: "1.2.3", ReviewSHA256: strings.Repeat("a", 64), OwnedPaths: []string{"/opt/xray"}}
	adapter := NewAt(root, nil, nil)
	adapter.packageCommand = command
	if err := adapter.writeReclamationPackageInventory("change-1", target, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.purgeReclamationPackage(target, time.Second); err != nil {
		t.Fatal(err)
	}

	recovered := NewAt(root, nil, nil)
	recovered.packageCommand = command
	if err := recovered.verifyReclamationPackageInventory("change-1", []systemchanges.ReclamationTarget{target}, time.Second); err == nil {
		t.Fatal("late unrelated package change was accepted")
	}
}
