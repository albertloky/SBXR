package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 5 {
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
		for index, phase := range []string{"first", "second", "third"} {
			record, _ := json.Marshal(map[string]string{"phase": phase})
			if err := os.WriteFile(os.Args[2], record, 0600); err != nil {
				panic(err)
			}
			file, err := os.OpenFile(os.Args[3], os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				panic(err)
			}
			if err = file.Close(); err != nil {
				panic(err)
			}
			if err = os.WriteFile(os.Args[4], []byte{byte('1' + index)}, 0600); err != nil {
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
