//go:build linux

package terminal

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type lifecycleStub struct{ status softwarelifecycle.Result }

func (stub lifecycleStub) Status(context.Context) softwarelifecycle.Result { return stub.status }
func (lifecycleStub) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	panic("Check must not run before the operation Adapter is connected")
}
func (lifecycleStub) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	panic("Update must not run before the operation Adapter is connected")
}
func (lifecycleStub) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	panic("Recover must not run before the operation Adapter is connected")
}

func TestRunFramesAndSelectsOnlyFreshLegalActions(t *testing.T) {
	identity := softwarelifecycle.ReleaseIdentity{Tag: "v2.0.0"}
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	original, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan runResult, 1)
	go func() {
		action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm-256color", "LANG=C.UTF-8"}, lifecycleStub{status: softwarelifecycle.Result{
			State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready.",
		}})
		done <- runResult{action: action, status: status}
	}()

	waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
	writePTY(t, master, "\x1b[B")                                              // Update.
	writePTY(t, master, "\x1b[200~"+strings.Repeat("2\r", 32<<10)+"\x1b[201~") // Pasted authorization is streamed and discarded.
	writePTY(t, master, "\x1b[<0;10;10M")                                      // Mouse input is invalid.
	writePTY(t, master, "\x1b[1;2A")                                           // Modified arrow is invalid.
	writePTY(t, master, "\x1b")                                                // Incomplete escape times out.
	time.Sleep(120 * time.Millisecond)
	writePTY(t, master, "1") // Direct selection does not execute.
	select {
	case result := <-done:
		t.Fatalf("digit executed %v before Enter", result.action)
	case <-time.After(20 * time.Millisecond):
	}
	writePTY(t, master, "\r")

	result := <-done
	if result.action != CheckAction || result.status != 0 {
		t.Fatalf("Run() = (%v, %d), want (%v, 0)", result.action, result.status, CheckAction)
	}
	restored, err := getTermios(slave.Fd())
	if err != nil || !reflect.DeepEqual(restored, original) {
		t.Fatalf("termios was not restored exactly: error=%v\nbefore=%+v\nafter=%+v", err, original, restored)
	}
	transcript := readPTY(master)
	for _, want := range []string{
		"\x1b[H\x1b[2J", "Current SBXR version: v2.0.0", "Latest stable version: Not checked", "Status: Ready",
		"Result: SBXR is ready.", "Code: SOFTWARE-LIFECYCLE-STATUS-READY", "\x1b[38;2;41;71;102m1. Check for updates\x1b[0m",
		"\x1b[38;2;41;71;102m2. Update SBXR\x1b[0m", "Use ↑/↓ or a displayed number, then Enter.", "Use ↑/↓ or a number, then Enter: 1",
	} {
		if !strings.Contains(transcript, want) {
			t.Fatalf("terminal transcript missing %q\n%s", want, transcript)
		}
	}
	for _, forbidden := range []string{"\x1b[?1049", "\x1b[3J", "\x1b[?25l"} {
		if strings.Contains(transcript, forbidden) {
			t.Fatalf("terminal transcript contains forbidden sequence %q", forbidden)
		}
	}
}

func TestRunShowsOnlyActionsLegalForFreshStatus(t *testing.T) {
	tests := []struct {
		name   string
		result softwarelifecycle.Result
		input  string
		action Action
		want   []string
		absent []string
	}{
		{name: "ready wraps CSI up", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1b[A\r", action: ExitAction, want: []string{"1. Check for updates", "2. Update SBXR", "0. Exit", "Enter: 0"}},
		{name: "ready wraps SS3 up", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1bOA\r", action: ExitAction, want: []string{"Enter: 0"}},
		{name: "ready accepts SS3 down", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1bOB\r", action: UpdateAction, want: []string{"Enter: 2"}},
		{name: "update in progress", result: softwarelifecycle.Result{State: softwarelifecycle.UpdateInProgress, Code: softwarelifecycle.StatusUpdateInProgress, Message: "Another Software Lifecycle change is in progress."}, input: "\r", action: ExitAction, want: []string{"Status: Update in progress", "0. Exit", "Enter: 0"}, absent: []string{"Check for updates", "Update SBXR", "Start recovery"}},
		{name: "recovery rejects unavailable digit", result: softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState, Code: softwarelifecycle.StatusRecoveryRequired, Message: "SBXR needs recovery before normal operations can continue."}, input: "2\r", action: RecoverAction, want: []string{"Status: Recovery required", "1. Start recovery", "0. Exit", "Enter: 1", "Use ↑/↓ or a displayed number, then Enter."}, absent: []string{"Check for updates", "Update SBXR"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			done := make(chan runResult, 1)
			go func() {
				action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LC_ALL=C.UTF-8"}, lifecycleStub{status: test.result})
				done <- runResult{action: action, status: status}
			}()
			waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
			writePTY(t, master, test.input)
			got := <-done
			if got.action != test.action || got.status != 0 {
				t.Fatalf("Run() = (%v, %d), want (%v, 0)", got.action, got.status, test.action)
			}
			transcript := readPTY(master)
			for _, want := range test.want {
				if !strings.Contains(transcript, want) {
					t.Fatalf("terminal transcript missing %q\n%s", want, transcript)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(transcript, absent) {
					t.Fatalf("terminal transcript unexpectedly contains %q\n%s", absent, transcript)
				}
			}
		})
	}
}

func TestRunRefusesArgumentsAndUnsafeLaunchesBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  []string
	}{
		{name: "argument", args: []string{"version"}, env: []string{"TERM=xterm", "LANG=C.UTF-8"}},
		{name: "redirected", env: []string{"TERM=xterm", "LANG=C.UTF-8"}},
		{name: "non UTF-8", env: []string{"TERM=xterm", "LANG=C"}},
		{name: "UTF-8 substring", env: []string{"TERM=xterm", "LANG=XUTF-8EVIL"}},
		{name: "dumb terminal", env: []string{"TERM=dumb", "LANG=C.UTF-8"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			action, status := Run(t.Context(), test.args, input, output, output, test.env, lifecycleStub{})
			body, _ := os.ReadFile(output.Name())
			if action != NoAction || status != 1 || string(body) != terminalRequired {
				t.Fatalf("Run() = (%v, %d), output %q", action, status, body)
			}
			if strings.Contains(string(body), "\x1b[") {
				t.Fatal("unsafe launch mutated the terminal")
			}
		})
	}
	t.Run("different terminals", func(t *testing.T) {
		inputMaster, input := openPTY(t)
		defer inputMaster.Close()
		defer input.Close()
		outputMaster, output := openPTY(t)
		defer outputMaster.Close()
		defer output.Close()
		action, status := Run(t.Context(), nil, input, output, output, []string{"TERM=xterm", "LANG=C.UTF-8"}, lifecycleStub{})
		if action != NoAction || status != 1 {
			t.Fatalf("Run() = (%v, %d), want refusal", action, status)
		}
		if got := strings.ReplaceAll(readPTY(outputMaster), "\r", ""); got != terminalRequired {
			t.Fatalf("refusal = %q, want %q", got, terminalRequired)
		}
	})
}

type runResult struct {
	action Action
	status int
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	masterFD, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unlock := int32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(masterFD), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		syscall.Close(masterFD)
		t.Fatal(errno)
	}
	var number uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(masterFD), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		syscall.Close(masterFD)
		t.Fatal(errno)
	}
	slaveFD, err := syscall.Open(fmt.Sprintf("/dev/pts/%d", number), syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		syscall.Close(masterFD)
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(masterFD, true); err != nil {
		syscall.Close(masterFD)
		syscall.Close(slaveFD)
		t.Fatal(err)
	}
	return os.NewFile(uintptr(masterFD), "ptmx"), os.NewFile(uintptr(slaveFD), "pts")
}

func waitForPTY(t *testing.T, master *os.File, want string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var transcript strings.Builder
	buffer := make([]byte, 4096)
	for time.Now().Before(deadline) {
		count, err := master.Read(buffer)
		if count > 0 {
			transcript.Write(buffer[:count])
			if strings.Contains(transcript.String(), want) {
				return transcript.String()
			}
		}
		if err != nil && err != syscall.EAGAIN {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("terminal transcript missing %q\n%s", want, transcript.String())
	return ""
}

func writePTY(t *testing.T, master *os.File, value string) {
	t.Helper()
	remaining := []byte(value)
	for len(remaining) > 0 {
		count, err := master.Write(remaining)
		remaining = remaining[count:]
		if err == syscall.EAGAIN {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func readPTY(master *os.File) string {
	var transcript strings.Builder
	buffer := make([]byte, 4096)
	for {
		count, err := master.Read(buffer)
		if count > 0 {
			transcript.Write(buffer[:count])
		}
		if err == syscall.EAGAIN || count == 0 {
			return transcript.String()
		}
	}
}
