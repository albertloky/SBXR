package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// Sequence descendants exercise ignored syscalls without touching product state.
func sequenceFile(name, value string) {
	if err := os.WriteFile(name, []byte(value), 0600); err != nil {
		panic(err)
	}
}
func sequenceWait(name, value string) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		body, _ := os.ReadFile(name)
		if string(body) == value {
			return
		}
		time.Sleep(time.Millisecond)
	}
	panic("sequence descendant deadline: " + name)
}
func sequencePID(directory string) {
	file, err := os.OpenFile(filepath.Join(directory, "pids"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err = fmt.Fprintln(file, os.Getpid()); err != nil {
		panic(err)
	}
}
func sequenceSignal() {
	received := make(chan os.Signal, 1)
	signal.Notify(received, syscall.SIGUSR1)
	defer signal.Stop(received)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		panic(err)
	}
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		panic("SIGUSR1 was not delivered")
	}
}
func sequenceDescendant() bool {
	if len(os.Args) != 7 {
		return false
	}
	mode := os.Args[1]
	if mode != "sequence-work" && mode != "sequence-grandchild" && mode != "sequence-live" {
		return false
	}
	directory := filepath.Dir(os.Args[2])
	sequencePID(directory)
	sequenceSignal()
	if mode == "sequence-grandchild" {
		return true
	}
	if mode == "sequence-work" {
		args := append([]string(nil), os.Args[1:]...)
		args[0] = "sequence-grandchild"
		if err := exec.Command(os.Args[0], args...).Run(); err != nil {
			panic(err)
		}
		for i := 0; i < 15000; i++ {
			syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
		}
		target := os.Getenv("SBXR_SEQUENCE_TARGET")
		sequenceFile(target, "descendant")
		if err := os.Remove(target); err != nil {
			panic(err)
		}
		sequenceFile(filepath.Join(directory, "work-done"), target)
		return true
	}
	sequenceFile(filepath.Join(directory, "live-ready"), "ready")
	sequenceWait(os.Args[6], "1")
	sequenceFile(os.Args[4], "live descendant")
	if err := os.Remove(os.Args[4]); err != nil {
		panic(err)
	}
	sequenceFile(filepath.Join(directory, "live-progress"), "continued")
	sequenceWait(os.Args[6], "3")
	sequenceFile(filepath.Join(directory, "live-done"), "released")
	return true
}

func main() {
	if sequenceDescendant() {
		return
	}
	if len(os.Args) != 5 && !(len(os.Args) == 7 && os.Args[1] == "sequence") {
		panic("fixture arguments")
	}
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
			}
		}()
	}
	if os.Args[1] == "sequence" {
		directory := filepath.Dir(os.Args[2])
		sequencePID(directory)
		var live *exec.Cmd
		marker := os.Args[4]
		if len(os.Args) == 7 {
			marker = os.Args[6]
		}
		for index, phase := range []string{"first", "second", "third"} {
			record, _ := json.Marshal(map[string]string{"phase": phase})
			if err := os.WriteFile(os.Args[2], record, 0600); err != nil {
				panic(err)
			}
			target := os.Args[3]
			if len(os.Args) == 7 {
				target = os.Args[3+index]
			}
			if len(os.Args) == 7 {
				if index == 1 {
					sequenceWait(filepath.Join(directory, "live-progress"), "continued")
				}
				args := append([]string(nil), os.Args[1:]...)
				args[0] = "sequence-work"
				work := exec.Command(os.Args[0], args...)
				work.Env = append(os.Environ(), "SBXR_SEQUENCE_TARGET="+target)
				if err := work.Run(); err != nil {
					panic(err)
				}
				if index == 0 {
					args[0] = "sequence-live"
					live = exec.Command(os.Args[0], args...)
					if err := live.Start(); err != nil {
						panic(err)
					}
					sequenceWait(filepath.Join(directory, "live-ready"), "ready")
				}
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				panic(err)
			}
			if err = file.Close(); err != nil {
				panic(err)
			}
			if err = os.WriteFile(marker, []byte{byte('1' + index)}, 0600); err != nil {
				panic(err)
			}
		}
		if live != nil {
			if err := live.Wait(); err != nil {
				panic(err)
			}
		}
		close(done)
		return
	}
	if child := os.Getenv("SBXR_FIXTURE_CHILD"); child != "" {
		if err := exec.Command(child).Run(); err != nil {
			panic(err)
		}
		receipt, err := json.Marshal(map[string]any{"attempts": []any{map[string]any{"recorder_pid": os.Getpid()}}})
		if err != nil {
			panic(err)
		}
		if err = os.WriteFile(os.Args[2], receipt, 0600); err != nil {
			panic(err)
		}
	}
	f, e := os.OpenFile(os.Args[3], os.O_WRONLY|os.O_CREATE, 0600)
	if e != nil {
		panic(e)
	}
	if os.Args[1] == "after-close" {
		if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
			panic(e)
		}
		if e = f.Close(); e != nil {
			panic(e)
		}
	}
	if e = os.WriteFile(os.Args[4], []byte("ran"), 0600); e != nil {
		panic(e)
	}
	close(done)
}
