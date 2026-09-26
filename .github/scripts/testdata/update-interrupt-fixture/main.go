// This is a syscall/menu fixture, NOT SBXR, an updater, or release evidence.
// It supplies real Go threads, files, fsync, flock and child processes to the
// isolated controller rehearsal. No public network or CA operation occurs.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const state = "/var/lib/sbxr/"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path string, body []byte, mode os.FileMode) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	must(err)
	_, err = f.Write(body)
	must(err)
	must(f.Sync())
	must(f.Close())
}

func syncDir(path string) {
	f, err := os.Open(path)
	must(err)
	must(f.Sync())
	must(f.Close())
}

func main() {
	run := os.Getenv("SBXR_INTERRUPT_FIXTURE")
	if run == "" {
		panic("fixture run directory required")
	}
	if len(os.Args) > 1 {
		write(filepath.Join(run, fmt.Sprint(os.Getpid())+".child"), []byte("child\n"), 0600)
		for {
			time.Sleep(time.Second)
		}
	}
	write(filepath.Join(run, "product.pid"), []byte(fmt.Sprint(os.Getpid())), 0600)
	scan := bufio.NewScanner(os.Stdin)
	menu := "SBXR V3\n1. Update\n0. Exit"
	mode := os.Getenv("SBXR_INTERRUPT_MODE")
	fmt.Println(menu)
	scan.Scan()
	// Match the real terminal's review-before-confirmation order.
	fmt.Println("Code: SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE")
	if mode == "wrong-prompt" {
		fmt.Println("Start proxy setup? [y/N]")
	} else {
		fmt.Println("Update SBXR? [y/N]")
	}
	scan.Scan()
	if scan.Text() != "y" {
		return
	}
	if mode == "refusal" {
		fmt.Println("Code: SOFTWARE-LIFECYCLE-UPDATE-RELEASE-REFUSED")
		return
	}
	if mode == "slow" {
		for {
			time.Sleep(time.Second)
		}
	}
	// Force additional OS threads and a fork/exec before the durable boundary.
	ready := make(chan bool)
	for i := 0; i < 3; i++ {
		go func() { runtime.LockOSThread(); ready <- true; select {} }()
		<-ready
	}
	child := exec.Command("/usr/local/bin/sbxr", "child")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	must(child.Start())
	for {
		matches, err := filepath.Glob(filepath.Join(run, "*.child"))
		must(err)
		if len(matches) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	lock, err := os.OpenFile("/run/lock/sbxr.lock", os.O_CREATE|os.O_RDWR, 0600)
	must(err)
	if mode != "unlocked" {
		must(syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	}
	defer lock.Close()
	body, err := os.ReadFile(filepath.Join(run, "expected.json"))
	must(err)
	var record map[string]any
	must(json.Unmarshal(body, &record))
	record["schema"] = 2
	record["checkpoint"] = "Prepared"
	copyFile := func(from, to string, mode os.FileMode) {
		body, err := os.ReadFile(from)
		must(err)
		write(to, body, mode)
	}
	copyFile(filepath.Join(run, "candidate"), "/usr/local/bin/.sbxr-update-candidate", 0755)
	copyFile(filepath.Join(run, "candidate.json"), state+".installed.json.candidate", 0600)
	copyFile(state+"installed.json", state+".installed.json.prior", 0600)
	must(os.Link("/usr/local/bin/sbxr", "/usr/local/bin/.sbxr-update-prior"))
	syncDir(state)
	syncDir("/usr/local/bin")
	if mode == "wrong-record" {
		record["candidate_executable_sha256"] = strings.Repeat("0", 64)
	}
	publish := func() {
		body, err := json.Marshal(record)
		must(err)
		write(state+".update.json.next", body, 0600)
		must(os.Rename(state+".update.json.next", state+"update.json"))
		wanted := "Prepared"
		if os.Getenv("SBXR_INTERRUPT_BOUNDARY") == "postcommit" {
			wanted = "Committed"
		}
		if mode == "no-directory-sync" && record["checkpoint"] == wanted {
			// Visibility alone must never count as the durable boundary.
			marker := filepath.Join(run, "visible-unsynced")
			must(os.WriteFile(marker+".pending", []byte(wanted), 0600))
			must(os.Rename(marker+".pending", marker))
			for {
				time.Sleep(time.Second)
			}
		}
		syncDir(state)
	}
	publish()
	write(filepath.Join(run, "after-prepared"), []byte("continued\n"), 0600)
	must(os.Rename(state+".installed.json.candidate", state+"installed.json"))
	syncDir(state)
	must(os.Rename("/usr/local/bin/.sbxr-update-candidate", "/usr/local/bin/sbxr"))
	syncDir("/usr/local/bin")
	record["checkpoint"] = "Committed"
	publish()
	write(filepath.Join(run, "runtime-completed"), []byte("continued\n"), 0600)
	fmt.Println("Code: SOFTWARE-LIFECYCLE-UPDATE-INSTALLED")
}
