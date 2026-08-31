//go:build linux

package host

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// This subprocess checks real mount/credential isolation, not public trust or
// a packaged VPS. Its synthetic cgroup membership is explicitly test evidence.
func TestServingSandboxChild(t *testing.T) {
	root := os.Getenv("SBXR_TEST_SERVING_ROOT")
	if root == "" {
		return
	}
	runtime.LockOSThread()
	if os.Geteuid() != 0 {
		os.Exit(77)
	}
	if syscall.Unshare(syscall.CLONE_NEWNS) != nil {
		os.Exit(77)
	}
	if syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "") != nil {
		os.Exit(77)
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, 0, 0)
	}); err != nil {
		t.Fatal("fixture ownership failed")
	}
	if syscall.Chroot(root) != nil || os.Chdir("/") != nil {
		t.Fatal("fixture root failed")
	}
	var authority ServingAuthority
	body, err := os.ReadFile("/authority.json")
	if err != nil || json.Unmarshal(body, &authority) != nil {
		t.Fatal("test authority failed")
	}
	for _, path := range []string{ServingStagingPath, "/proc", "/run/systemd", "/run/dbus"} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal("mount target failed")
		}
		if syscall.Mount("none", path, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=000") != nil {
			t.Fatal("inaccessible mount failed")
		}
	}
	if os.WriteFile("/inaccessible", []byte(""), 0000) != nil || syscall.Mount("/inaccessible", ServingTokenPath, "", syscall.MS_BIND, "") != nil {
		t.Fatal("credential mount failed")
	}
	if os.MkdirAll(servingCgroup, 0755) != nil || os.WriteFile(servingCgroup+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())+"\n"), 0644) != nil {
		t.Fatal("test cgroup failed")
	}
	header := struct {
		Version uint32
		PID     int32
	}{Version: 0x20080522}
	data := [2]struct{ Effective, Permitted, Inheritable uint32 }{}
	// All operations stay on one kernel thread, including the actual guard.
	// Go subprocess main can otherwise migrate between threads with old caps.
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatal("no-new-privileges failed")
	}
	_, _, errno = syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)), 0)
	if errno != 0 {
		t.Fatal("capability drop failed")
	}
	if !(Adapter{root: "/"}).ValidateServingDispatch(authority) {
		t.Fatal("protected dispatch refused")
	}
	for _, path := range []string{ServingTokenPath, ServingStagingPath} {
		if f, err := os.Open(path); err == nil {
			f.Close()
			t.Fatal("sandbox credential access permitted")
		}
	}
}

func TestServingSandboxUsesRealInaccessibleMounts(t *testing.T) {
	a, authority := servingFiles(t)
	body, _ := json.Marshal(authority)
	if err := os.WriteFile(filepath.Join(a.root, "authority.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{os.Args[0], "-test.run=^TestServingSandboxChild$"}
	program := args[0]
	args = args[1:]
	if os.Geteuid() != 0 {
		if exec.Command("sudo", "-n", "true").Run() != nil {
			if os.Getenv("GITHUB_ACTIONS") == "true" {
				t.Fatal("CI requires root mount capability")
			}
			t.Skip("root mount capability unavailable")
		}
		// The child changes only this fixture's ownership. Restore it before
		// t.TempDir cleanup in the unprivileged parent, including on failures.
		t.Cleanup(func() {
			owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
			if exec.Command("sudo", "-n", "chown", "-R", owner, a.root).Run() != nil {
				t.Error("sandbox fixture ownership cleanup failed")
			}
		})
		program = "sudo"
		args = []string{"-n", "--preserve-env=SBXR_TEST_SERVING_ROOT", os.Args[0], "-test.run=^TestServingSandboxChild$"}
	}
	cmd := exec.Command(program, args...)
	cmd.Env = append(os.Environ(), "SBXR_TEST_SERVING_ROOT="+a.root)
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 77 {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("CI requires mount namespace capability")
		}
		t.Skip("mount namespace capability unavailable")
	}
	if err != nil {
		t.Fatalf("sandbox mechanics failed: %v %s", err, output)
	}
}
