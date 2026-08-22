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

type lifecycleStub struct {
	status  softwarelifecycle.Result
	check   func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result
	update  func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result
	recover func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result
}

func (stub lifecycleStub) Status(context.Context) softwarelifecycle.Result { return stub.status }
func (stub lifecycleStub) Check(ctx context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	if stub.check != nil {
		return stub.check(ctx, progress)
	}
	return stub.status
}
func (stub lifecycleStub) Update(ctx context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	if stub.update != nil {
		return stub.update(ctx, progress)
	}
	return stub.status
}
func (stub lifecycleStub) Recover(ctx context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	if stub.recover != nil {
		return stub.recover(ctx, progress)
	}
	return stub.status
}

func TestRunExecutesCheckAndPresentsItsTypedResult(t *testing.T) {
	called := make(chan struct{})
	module := lifecycleStub{
		status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."},
		check: func(_ context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
			close(called)
			progress(softwarelifecycle.Progress{Operation: softwarelifecycle.CheckOperation, Status: "Checking the qualified latest release", Mode: softwarelifecycle.Spinner})
			return softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.CheckAlreadyCurrent, Message: "SBXR is already current."}
		},
	}
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	done := make(chan runResult, 1)
	go func() {
		action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, module)
		done <- runResult{action: action, status: status}
	}()
	waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
	writePTY(t, master, "\r")
	<-called
	waitForPTY(t, master, "Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT")
	writePTY(t, master, "0\r")
	if got := <-done; got.action != ExitAction || got.status != 0 {
		t.Fatalf("Run() = (%v, %d), want (%v, 0)", got.action, got.status, ExitAction)
	}
}

func TestRunCoalescesProgressAndDiscardsQueuedAuthority(t *testing.T) {
	release := make(chan struct{})
	recovered := make(chan struct{}, 1)
	module := lifecycleStub{
		status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."},
		update: func(_ context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
			progress(softwarelifecycle.Progress{Operation: softwarelifecycle.UpdateOperation, Status: "Checking the qualified latest release", Mode: softwarelifecycle.Spinner})
			progress(softwarelifecycle.Progress{Operation: softwarelifecycle.UpdateOperation, Status: "Installing verified work", Mode: softwarelifecycle.ProgressBar, Completed: 4, Total: 10})
			<-release
			return softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState, Code: softwarelifecycle.UpdateRecoveryRequired, Message: "The update needs recovery before normal operations can continue."}
		},
		recover: func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
			recovered <- struct{}{}
			return softwarelifecycle.Result{}
		},
	}
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	done := make(chan runResult, 1)
	go func() {
		action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, module)
		done <- runResult{action: action, status: status}
	}()
	waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
	writePTY(t, master, "2\r")
	waitForPTY(t, master, "[####------] 40% Installing verified work")
	writePTY(t, master, "1\r")
	close(release)
	waitForPTY(t, master, "Code: SOFTWARE-LIFECYCLE-UPDATE-RECOVERY-REQUIRED")
	writePTY(t, master, "0\r")
	if got := <-done; got.action != ExitAction || got.status != 0 {
		t.Fatalf("Run() = (%v, %d), want (%v, 0)", got.action, got.status, ExitAction)
	}
	select {
	case <-recovered:
		t.Fatal("queued input authorized recovery after the update result")
	default:
	}
}

func TestRunDefersManagedSignalsUntilTheTypedResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		signal syscall.Signal
		status int
		notice string
	}{
		{"SIGINT", syscall.SIGINT, 130, "Ctrl+C received."},
		{"SIGTERM", syscall.SIGTERM, 143, "Termination requested."},
		{"SIGHUP", syscall.SIGHUP, 129, "Terminal hangup received."},
	} {
		t.Run(test.name, func(t *testing.T) {
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			original, err := getTermios(slave.Fd())
			if err != nil {
				t.Fatal(err)
			}
			module := lifecycleStub{
				status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."},
				check: func(ctx context.Context, progress softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
					progress(softwarelifecycle.Progress{Operation: softwarelifecycle.CheckOperation, Status: "Checking the qualified latest release", Mode: softwarelifecycle.Spinner})
					<-ctx.Done()
					return softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.CheckReleaseUnavailable, Message: "The latest SBXR release is unavailable. Check again later."}
				},
			}
			done := make(chan runResult, 1)
			go func() {
				action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, module)
				done <- runResult{action: action, status: status}
			}()
			waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
			writePTY(t, master, "\r")
			waitForPTY(t, master, "Latest stable version: | Checking the qualified latest release")
			if err := syscall.Kill(os.Getpid(), test.signal); err != nil {
				t.Fatal(err)
			}
			transcript := waitForPTY(t, master, "Code: SOFTWARE-LIFECYCLE-CHECK-RELEASE-UNAVAILABLE")
			if !strings.Contains(transcript, test.notice) {
				t.Fatalf("terminal transcript missing %q\n%s", test.notice, transcript)
			}
			if got := <-done; got.action != NoAction || got.status != test.status {
				t.Fatalf("Run() = (%v, %d), want (%v, %d)", got.action, got.status, NoAction, test.status)
			}
			restored, err := getTermios(slave.Fd())
			if err != nil || !reflect.DeepEqual(restored, original) {
				t.Fatalf("termios was not restored exactly: error=%v", err)
			}
		})
	}
}

func TestRunRestoresTerminalBeforePropagatingPanics(t *testing.T) {
	for _, test := range []struct {
		name   string
		module lifecycleStub
		start  bool
	}{
		{"main stack", lifecycleStub{}, false},
		{"operation worker", lifecycleStub{status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady}, check: func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
			panic("worker panic")
		}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			original, err := getTermios(slave.Fd())
			if err != nil {
				t.Fatal(err)
			}
			module := test.module
			if !test.start {
				module = lifecycleStub{check: func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
					return softwarelifecycle.Result{}
				}}
			}
			panicked := make(chan any, 1)
			go func() {
				defer func() { panicked <- recover() }()
				if !test.start {
					Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, panicStatusLifecycle{})
					return
				}
				Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, module)
			}()
			if test.start {
				waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
				writePTY(t, master, "\r")
			}
			if recovered := <-panicked; recovered == nil {
				t.Fatal("panic was swallowed")
			}
			restored, err := getTermios(slave.Fd())
			if err != nil || !reflect.DeepEqual(restored, original) {
				t.Fatalf("termios was not restored exactly: error=%v", err)
			}
		})
	}
}

func TestRunRestoresTerminalBeforePropagatingReaderPanic(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	highFD, _, errno := syscall.Syscall(syscall.SYS_FCNTL, slave.Fd(), syscall.F_DUPFD_CLOEXEC, 1024)
	if errno != 0 {
		t.Fatal(errno)
	}
	input := os.NewFile(highFD, "high-pts")
	defer input.Close()
	original, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		Run(t.Context(), nil, input, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, lifecycleStub{status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady}})
	}()
	waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
	writePTY(t, master, "\x1b")
	if recovered := <-panicked; recovered == nil {
		t.Fatal("reader panic was swallowed")
	}
	restored, err := getTermios(slave.Fd())
	if err != nil || !reflect.DeepEqual(restored, original) {
		t.Fatalf("termios was not restored exactly: error=%v", err)
	}
}

func TestRunHandlesWaitingAndActiveOperationEOF(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "waiting"
		if active {
			name = "active operation"
		}
		t.Run(name, func(t *testing.T) {
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			original, err := getTermios(slave.Fd())
			if err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			module := lifecycleStub{
				status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."},
				check: func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
					<-release
					return softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.CheckAlreadyCurrent, Message: "SBXR is already current."}
				},
			}
			done := make(chan runResult, 1)
			go func() {
				action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LANG=C.UTF-8"}, module)
				done <- runResult{action: action, status: status}
			}()
			waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
			if active {
				writePTY(t, master, "\r")
				waitForPTY(t, master, "Latest stable version: | Checking the qualified latest release")
			}
			writePTY(t, master, "\x04")
			if active {
				waitForPTY(t, master, "End of input received. SBXR will exit after a safe terminal result.")
				close(release)
				waitForPTY(t, master, "Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT")
			} else {
				close(release)
			}
			if got := <-done; got.status != 0 || active && got.action != NoAction || !active && got.action != ExitAction {
				t.Fatalf("Run() = (%v, %d), active=%t", got.action, got.status, active)
			}
			restored, err := getTermios(slave.Fd())
			if err != nil || !reflect.DeepEqual(restored, original) {
				t.Fatalf("termios was not restored exactly: error=%v", err)
			}
		})
	}
}

func TestRunAttemptsEveryCleanupAfterAWriteFailure(t *testing.T) {
	master, input := openPTY(t)
	defer master.Close()
	defer input.Close()
	outputFD, err := syscall.Dup(int(input.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	output := os.NewFile(uintptr(outputFD), "output-pts")
	original, err := getTermios(input.Fd())
	if err != nil {
		t.Fatal(err)
	}
	errorOutput, err := os.CreateTemp(t.TempDir(), "terminal-error")
	if err != nil {
		t.Fatal(err)
	}
	defer errorOutput.Close()
	done := make(chan runResult, 1)
	go func() {
		action, status := Run(t.Context(), nil, input, output, errorOutput, []string{"TERM=xterm", "LANG=C.UTF-8"}, lifecycleStub{status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady}})
		done <- runResult{action: action, status: status}
	}()
	waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	writePTY(t, master, "x")
	if got := <-done; got.action != NoAction || got.status != 1 {
		t.Fatalf("Run() = (%v, %d), want (%v, 1)", got.action, got.status, NoAction)
	}
	restored, err := getTermios(input.Fd())
	if err != nil || !reflect.DeepEqual(restored, original) {
		t.Fatalf("termios was not restored exactly: error=%v", err)
	}
	body, err := os.ReadFile(errorOutput.Name())
	if err != nil || string(body) != terminalFailed {
		t.Fatalf("terminal correction = %q, error=%v", body, err)
	}
}

func TestRunRestoresTerminalAfterStartupAndReadFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		open func(string) (*os.File, error)
	}{
		{"startup output failure after snapshot", os.Open},
		{"input read failure", func(name string) (*os.File, error) {
			fd, err := syscall.Open(name, syscall.O_WRONLY|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
			if err != nil {
				return nil, err
			}
			return os.NewFile(uintptr(fd), "write-only-pts"), nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			failureFile, err := test.open(slave.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer failureFile.Close()
			original, err := getTermios(slave.Fd())
			if err != nil {
				t.Fatal(err)
			}
			errorOutput, err := os.CreateTemp(t.TempDir(), "terminal-error")
			if err != nil {
				t.Fatal(err)
			}
			defer errorOutput.Close()
			input, output := slave, failureFile
			if test.name == "input read failure" {
				input, output = failureFile, slave
			}
			action, status := Run(t.Context(), nil, input, output, errorOutput, []string{"TERM=xterm", "LANG=C.UTF-8"}, lifecycleStub{status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady}})
			if action != NoAction || status != 1 {
				t.Fatalf("Run() = (%v, %d), want (%v, 1)", action, status, NoAction)
			}
			restored, err := getTermios(slave.Fd())
			if err != nil || !reflect.DeepEqual(restored, original) {
				t.Fatalf("termios was not restored exactly: error=%v", err)
			}
			body, err := os.ReadFile(errorOutput.Name())
			if err != nil || string(body) != terminalFailed {
				t.Fatalf("terminal correction = %q, error=%v", body, err)
			}
		})
	}
}

type panicStatusLifecycle struct{}

func (panicStatusLifecycle) Status(context.Context) softwarelifecycle.Result { panic("main panic") }
func (panicStatusLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (panicStatusLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (panicStatusLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func TestRunFramesAndSelectsOnlyFreshLegalActions(t *testing.T) {
	identity := softwarelifecycle.ReleaseIdentity{Tag: "v2.0.0"}
	checked := make(chan struct{})
	module := lifecycleStub{
		status: softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."},
		check: func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
			close(checked)
			return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.CheckAlreadyCurrent, Message: "SBXR is already current."}
		},
	}
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	original, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan runResult, 1)
	go func() {
		action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm-256color", "LANG=C.UTF-8"}, module)
		done <- runResult{action: action, status: status}
	}()

	transcript := waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
	writePTY(t, master, "\x1b[B") // Update.
	transcript += waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 2")
	writePTY(t, master, "\x1b[200~"+strings.Repeat("2\r", 32<<10)+"\x1b[201~") // Pasted authorization is streamed and discarded.
	writePTY(t, master, "\x1b[<0;10;10M")                                      // Mouse input is invalid.
	transcript += waitForPTY(t, master, "Use ↑/↓ or a displayed number, then Enter.")
	writePTY(t, master, "\x1b[1;2A") // Modified arrow is invalid.
	transcript += waitForPTY(t, master, "Use ↑/↓ or a displayed number, then Enter.")
	writePTY(t, master, "\x1b") // Incomplete escape times out.
	transcript += waitForPTY(t, master, "Use ↑/↓ or a displayed number, then Enter.")
	writePTY(t, master, "1") // Direct selection does not execute.
	transcript += waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 1")
	select {
	case result := <-done:
		t.Fatalf("digit executed %v before Enter", result.action)
	case <-time.After(20 * time.Millisecond):
	}
	writePTY(t, master, "\r")
	<-checked
	transcript += waitForPTY(t, master, "Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT")
	writePTY(t, master, "0")
	transcript += waitForPTY(t, master, "Use ↑/↓ or a number, then Enter: 0")
	writePTY(t, master, "\r")

	result := <-done
	if result.action != ExitAction || result.status != 0 {
		t.Fatalf("Run() = (%v, %d), want (%v, 0)", result.action, result.status, ExitAction)
	}
	restored, err := getTermios(slave.Fd())
	if err != nil || !reflect.DeepEqual(restored, original) {
		t.Fatalf("termios was not restored exactly: error=%v\nbefore=%+v\nafter=%+v", err, original, restored)
	}
	transcript += readPTY(master)
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
		ready  string
		action Action
		want   []string
		absent []string
	}{
		{name: "ready wraps CSI up", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1b[A", ready: "Enter: 0", action: ExitAction, want: []string{"1. Check for updates", "2. Update SBXR", "0. Exit", "Enter: 0"}},
		{name: "ready wraps SS3 up", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1bOA", ready: "Enter: 0", action: ExitAction, want: []string{"Enter: 0"}},
		{name: "ready accepts SS3 down", result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Code: softwarelifecycle.StatusReady, Message: "SBXR is ready."}, input: "\x1bOB", ready: "Enter: 2", action: UpdateAction, want: []string{"Enter: 2"}},
		{name: "update in progress", result: softwarelifecycle.Result{State: softwarelifecycle.UpdateInProgress, Code: softwarelifecycle.StatusUpdateInProgress, Message: "Another Software Lifecycle change is in progress."}, action: ExitAction, want: []string{"Status: Update in progress", "0. Exit", "Enter: 0"}, absent: []string{"Check for updates", "Update SBXR", "Start recovery"}},
		{name: "recovery rejects unavailable digit", result: softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState, Code: softwarelifecycle.StatusRecoveryRequired, Message: "SBXR needs recovery before normal operations can continue."}, input: "2", ready: "Use ↑/↓ or a displayed number, then Enter.", action: RecoverAction, want: []string{"Status: Recovery required", "1. Start recovery", "0. Exit", "Enter: 1", "Use ↑/↓ or a displayed number, then Enter."}, absent: []string{"Check for updates", "Update SBXR"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invoked := make(chan struct{}, 1)
			operation := func(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
				invoked <- struct{}{}
				return test.result
			}
			module := lifecycleStub{status: test.result, check: operation, update: operation, recover: operation}
			master, slave := openPTY(t)
			defer master.Close()
			defer slave.Close()
			done := make(chan runResult, 1)
			go func() {
				action, status := Run(t.Context(), nil, slave, slave, slave, []string{"TERM=xterm", "LC_ALL=C.UTF-8"}, module)
				done <- runResult{action: action, status: status}
			}()
			transcript := waitForPTY(t, master, "Use ↑/↓ or a number, then Enter:")
			if test.input != "" {
				writePTY(t, master, test.input)
				transcript += waitForPTY(t, master, test.ready)
			}
			writePTY(t, master, "\r")
			if test.action != ExitAction {
				<-invoked
				transcript += waitForPTY(t, master, "Code: "+string(test.result.Code))
				writePTY(t, master, "0")
				transcript += waitForPTY(t, master, "Enter: 0")
				writePTY(t, master, "\r")
			}
			got := <-done
			if got.action != ExitAction || got.status != 0 {
				t.Fatalf("Run() = (%v, %d), want (%v, 0)", got.action, got.status, ExitAction)
			}
			transcript += readPTY(master)
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
	return os.NewFile(uintptr(masterFD), "ptmx"), os.NewFile(uintptr(slaveFD), fmt.Sprintf("/dev/pts/%d", number))
}

func waitForPTY(t *testing.T, master *os.File, want string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var transcript strings.Builder
	buffer := make([]byte, 4096)
	for time.Now().Before(deadline) {
		count, err := syscall.Read(int(master.Fd()), buffer)
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
		count, err := syscall.Read(int(master.Fd()), buffer)
		if count > 0 {
			transcript.Write(buffer[:count])
		}
		if err == syscall.EAGAIN || count == 0 {
			return transcript.String()
		}
	}
}
