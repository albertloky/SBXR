//go:build linux

// Package terminal presents Software Lifecycle through the supported numbered line menu.
package terminal

import (
	"context"
	"fmt"
	"math/bits"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	terminalRequired  = "SBXR requires an interactive UTF-8 ANSI terminal on standard input and standard output.\nRun: sudo sbxr\n"
	terminalFailed    = "SBXR could not use the terminal safely.\nRun: reset\nThen run: sudo sbxr\n"
	selected          = "\x1b[38;2;41;71;102m"
	reset             = "\x1b[0m"
	bracketedPasteOn  = "\x1b[?2004h"
	bracketedPasteOff = "\x1b[?2004l"
	redraw            = "\x1b[H\x1b[2J"
	tcflush           = 0x540b
	tciflush          = 0
)

type Action uint8

const (
	NoAction Action = iota
	CheckAction
	UpdateAction
	RecoverAction
	ExitAction
)

type menuAction struct {
	number byte
	label  string
	action Action
}

// Run owns one admitted terminal session, including every lifecycle operation and redraw.
func Run(ctx context.Context, arguments []string, input, output, errorOutput *os.File, environment []string, lifecycle softwarelifecycle.Interface) (action Action, status int) {
	if errorOutput == nil {
		return NoAction, 1
	}
	if len(arguments) != 0 || input == nil || output == nil || lifecycle == nil || !supportedEnvironment(environment) {
		_, _ = errorOutput.WriteString(terminalRequired)
		return NoAction, 1
	}
	original, ok := admittedTerminal(input, output)
	if !ok {
		_, _ = errorOutput.WriteString(terminalRequired)
		return NoAction, 1
	}
	configured := *original
	configured.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ECHONL | syscall.IEXTEN
	configured.Iflag &^= syscall.IXON
	configured.Cc[syscall.VINTR] = 0x03
	configured.Cc[syscall.VQUIT] = 0
	configured.Cc[syscall.VSUSP] = 0
	configured.Cc[syscall.VMIN] = 1
	configured.Cc[syscall.VTIME] = 0

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	terminalOK := true
	defer func() {
		for _, cleanup := range []func() error{
			func() error { _, err := output.WriteString(reset); return err },
			func() error { _, err := output.WriteString(bracketedPasteOff); return err },
			func() error { return setTermios(input.Fd(), original) },
			func() error { _, err := output.WriteString("\n"); return err },
		} {
			if cleanup() != nil {
				terminalOK = false
			}
		}
		if !terminalOK {
			_, _ = errorOutput.WriteString(terminalFailed)
			action, status = NoAction, 1
		}
	}()
	terminalOK = setTermios(input.Fd(), &configured) == nil
	if terminalOK {
		_, err := output.WriteString(bracketedPasteOn)
		terminalOK = err == nil
	}
	if !terminalOK {
		return NoAction, 1
	}

	var generation atomic.Uint64
	events := make(chan readerEvent, 1)
	stopReader := make(chan struct{})
	defer close(stopReader)
	go readInput(inputReader{fd: int(input.Fd())}, &generation, events, stopReader)

	result := lifecycle.Status(ctx)
	actions := legalActions(result.State)
	selection := 0
	invalid := false
	if writeFrame(output, result, actions, selection, invalid) != nil {
		terminalOK = false
		return NoAction, 1
	}
	progresses := make(chan softwarelifecycle.Progress, 1)
	results := make(chan operationResult, 1)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var active bool
	var operation softwarelifecycle.Operation
	var progress softwarelifecycle.Progress
	var operationCancel context.CancelFunc
	var exit *exitRequest
	spinner := 0
	lastDraw := time.Time{}
	pendingProgress := false
	drawOperation := func() {
		if writeOperationFrame(output, result, progress, spinner, exitNotice(exit)) != nil {
			terminalOK = false
			if exit == nil {
				exit = &exitRequest{status: 1}
				operationCancel()
			} else {
				exit.status = 1
			}
		}
		lastDraw, pendingProgress = time.Now(), false
	}
	for {
		if !active {
			select {
			case received := <-signals:
				return NoAction, managedSignal(received).status
			case received := <-events:
				if received.panic != nil {
					panic(received.panic)
				}
				if received.generation != generation.Load() {
					continue
				}
				event := received.event
				invalid = false
				switch event.kind {
				case eventEOF:
					return ExitAction, 0
				case eventReadFailure:
					terminalOK = false
					return NoAction, 1
				case eventPaste:
					continue
				case eventUp:
					selection = (selection + len(actions) - 1) % len(actions)
				case eventDown:
					selection = (selection + 1) % len(actions)
				case eventDigit:
					found := false
					for index := range actions {
						if actions[index].number == event.value {
							selection, found = index, true
							break
						}
					}
					invalid = !found
				case eventEnter:
					selectedAction := actions[selection].action
					if selectedAction == ExitAction {
						return ExitAction, 0
					}
					operation = actionOperation(selectedAction)
					progress = initialProgress(operation)
					active, spinner, pendingProgress = true, 0, false
					lastDraw = time.Now()
					operationCtx, cancel := context.WithCancel(ctx)
					operationCancel = cancel
					go runOperation(operationCtx, lifecycle, operation, progresses, results)
					drawOperation()
					continue
				default:
					invalid = true
				}
				if writeFrame(output, result, actions, selection, invalid) != nil {
					terminalOK = false
					return NoAction, 1
				}
			}
			continue
		}

		select {
		case received := <-signals:
			if exit == nil {
				request := managedSignal(received)
				exit = &request
				operationCancel()
				if terminalOK {
					drawOperation()
				}
			}
		case received := <-events:
			if received.panic != nil {
				operationCancel()
				panic(received.panic)
			}
			if received.event.kind == eventReadFailure {
				terminalOK = false
				if exit == nil {
					exit = &exitRequest{status: 1}
					operationCancel()
				}
			} else if received.event.kind == eventEOF && exit == nil {
				exit = &exitRequest{status: 0, notice: "End of input received. SBXR will exit after a safe terminal result."}
				if terminalOK {
					drawOperation()
				}
			}
		case next := <-progresses:
			progress, pendingProgress = next, true
			if terminalOK && time.Since(lastDraw) >= 100*time.Millisecond {
				drawOperation()
			}
		case <-ticker.C:
			if terminalOK && (progress.Mode != softwarelifecycle.ProgressBar || progress.Total == 0 || pendingProgress) {
				drawOperation()
				spinner = (spinner + 1) % 4
			}
		case completed := <-results:
			operationCancel()
			if completed.panic != nil {
				panic(completed.panic)
			}
			result = completed.result
			if !terminalOK {
				return NoAction, 1
			}
			if exit != nil {
				if writeResultFrame(output, result) != nil {
					terminalOK = false
					return NoAction, 1
				}
				return NoAction, exit.status
			}
			if flushInput(input) != nil {
				terminalOK = false
				return NoAction, 1
			}
			generation.Add(1)
			drainEvents(events)
			actions, selection, invalid = legalActions(result.State), 0, false
			active = false
			if writeFrame(output, result, actions, selection, invalid) != nil {
				terminalOK = false
				return NoAction, 1
			}
		}
	}
}

type readerEvent struct {
	event      inputEvent
	generation uint64
	panic      any
}

func readInput(reader inputReader, generation *atomic.Uint64, events chan<- readerEvent, stop <-chan struct{}) {
	defer func() {
		if recovered := recover(); recovered != nil {
			select {
			case events <- readerEvent{panic: recovered}:
			case <-stop:
			}
		}
	}()
	for {
		received := readerEvent{generation: generation.Load(), event: reader.next()}
		select {
		case events <- received:
		case <-stop:
			return
		}
		if received.event.kind == eventEOF || received.event.kind == eventReadFailure {
			return
		}
	}
}

type operationResult struct {
	result softwarelifecycle.Result
	panic  any
}

func runOperation(ctx context.Context, lifecycle softwarelifecycle.Interface, operation softwarelifecycle.Operation, progresses chan softwarelifecycle.Progress, results chan<- operationResult) {
	completed := operationResult{}
	defer func() {
		completed.panic = recover()
		results <- completed
	}()
	report := func(progress softwarelifecycle.Progress) {
		select {
		case progresses <- progress:
		default:
			select {
			case <-progresses:
			default:
			}
			select {
			case progresses <- progress:
			default:
			}
		}
	}
	switch operation {
	case softwarelifecycle.CheckOperation:
		completed.result = lifecycle.Check(ctx, report)
	case softwarelifecycle.UpdateOperation:
		completed.result = lifecycle.Update(ctx, report)
	case softwarelifecycle.RecoverOperation:
		completed.result = lifecycle.Recover(ctx, report)
	}
}

type exitRequest struct {
	status int
	notice string
}

func actionOperation(action Action) softwarelifecycle.Operation {
	switch action {
	case CheckAction:
		return softwarelifecycle.CheckOperation
	case UpdateAction:
		return softwarelifecycle.UpdateOperation
	default:
		return softwarelifecycle.RecoverOperation
	}
}

func initialProgress(operation softwarelifecycle.Operation) softwarelifecycle.Progress {
	status := softwarelifecycle.InspectingRecoveryEvidence
	if operation != softwarelifecycle.RecoverOperation {
		status = softwarelifecycle.CheckingQualifiedLatest
	}
	return softwarelifecycle.Progress{Operation: operation, Status: status, Mode: softwarelifecycle.Spinner}
}

func managedSignal(value os.Signal) exitRequest {
	switch value {
	case syscall.SIGINT:
		return exitRequest{status: 130, notice: "Ctrl+C received. SBXR will exit after a safe terminal result."}
	case syscall.SIGTERM:
		return exitRequest{status: 143, notice: "Termination requested. SBXR will exit after a safe terminal result."}
	default:
		return exitRequest{status: 129, notice: "Terminal hangup received. SBXR will exit after a safe terminal result."}
	}
}

func exitNotice(request *exitRequest) string {
	if request == nil {
		return ""
	}
	return request.notice
}

func flushInput(input *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, input.Fd(), tcflush, tciflush)
	if errno != 0 {
		return errno
	}
	return nil
}

func drainEvents(events <-chan readerEvent) {
	for {
		select {
		case <-events:
		default:
			return
		}
	}
}

func admittedTerminal(input, output *os.File) (*syscall.Termios, bool) {
	in, err := getTermios(input.Fd())
	if err != nil {
		return nil, false
	}
	if _, err := getTermios(output.Fd()); err != nil {
		return nil, false
	}
	var inputStat, outputStat syscall.Stat_t
	if syscall.Fstat(int(input.Fd()), &inputStat) != nil || syscall.Fstat(int(output.Fd()), &outputStat) != nil || inputStat.Rdev != outputStat.Rdev {
		return nil, false
	}
	return in, true
}

func getTermios(fd uintptr) (*syscall.Termios, error) {
	value := new(syscall.Termios)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(value)))
	if errno != 0 {
		return nil, errno
	}
	return value, nil
}

func setTermios(fd uintptr, value *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(value)))
	if errno != 0 {
		return errno
	}
	return nil
}

func supportedEnvironment(environment []string) bool {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		if name, value, ok := strings.Cut(entry, "="); ok {
			values[name] = value
		}
	}
	term := values["TERM"]
	locale := values["LANG"]
	if values["LC_CTYPE"] != "" {
		locale = values["LC_CTYPE"]
	}
	if values["LC_ALL"] != "" {
		locale = values["LC_ALL"]
	}
	if modifier := strings.IndexByte(locale, '@'); modifier >= 0 {
		locale = locale[:modifier]
	}
	encoding := locale
	if separator := strings.LastIndexByte(locale, '.'); separator >= 0 {
		encoding = locale[separator+1:]
	}
	return term != "" && term != "dumb" && (strings.EqualFold(encoding, "utf-8") || strings.EqualFold(encoding, "utf8"))
}

func legalActions(state softwarelifecycle.LifecycleState) []menuAction {
	switch state {
	case softwarelifecycle.Ready:
		return []menuAction{{'1', "Check for updates", CheckAction}, {'2', "Update SBXR", UpdateAction}, {'0', "Exit", ExitAction}}
	case softwarelifecycle.RecoveryRequiredState:
		return []menuAction{{'1', "Start recovery", RecoverAction}, {'0', "Exit", ExitAction}}
	default:
		return []menuAction{{'0', "Exit", ExitAction}}
	}
}

func writeFrame(output *os.File, result softwarelifecycle.Result, actions []menuAction, selection int, invalid bool) error {
	var frame strings.Builder
	writeResult(&frame, result)
	for index, item := range actions {
		line := fmt.Sprintf("%c. %s", item.number, item.label)
		if index == selection {
			frame.WriteString(selected)
			frame.WriteString(line)
			frame.WriteString(reset)
		} else {
			frame.WriteString(line)
		}
		frame.WriteByte('\n')
	}
	frame.WriteByte('\n')
	if invalid {
		frame.WriteString("Use ↑/↓ or a displayed number, then Enter.\n")
	}
	fmt.Fprintf(&frame, "Use ↑/↓ or a number, then Enter: %c\n", actions[selection].number)
	_, err := output.WriteString(frame.String())
	return err
}

func writeResultFrame(output *os.File, result softwarelifecycle.Result) error {
	var frame strings.Builder
	writeResult(&frame, result)
	_, err := output.WriteString(frame.String())
	return err
}

func writeResult(frame *strings.Builder, result softwarelifecycle.Result) {
	writeHeader(frame, result, "")
	fmt.Fprintf(frame, "\nResult: %s\nCode: %s\n\n", result.Message, result.Code)
}

func writeHeader(frame *strings.Builder, result softwarelifecycle.Result, latestDisplay string) {
	frame.WriteString(redraw)
	frame.WriteString("SBXR\n\n")
	if result.Installed != nil {
		fmt.Fprintf(frame, "Current SBXR version: %s\n", result.Installed.Tag)
	}
	if latestDisplay == "" {
		latestDisplay = "Not checked"
		if result.Latest != nil {
			latestDisplay = result.Latest.Tag
		}
	}
	fmt.Fprintf(frame, "Latest stable version: %s\nStatus: %s\n", latestDisplay, result.State)
}

func writeOperationFrame(output *os.File, result softwarelifecycle.Result, progress softwarelifecycle.Progress, spinner int, notice string) error {
	var frame strings.Builder
	latest := ""
	if progress.Operation == softwarelifecycle.CheckOperation && progress.Status != "" {
		latest = progressIndicator(progress, spinner) + " " + progress.Status
	}
	writeHeader(&frame, result, latest)
	frame.WriteByte('\n')
	if progress.Status == "" {
		fmt.Fprintf(&frame, "%s in progress.\n", progress.Operation)
	} else if progress.Operation != softwarelifecycle.CheckOperation {
		fmt.Fprintf(&frame, "%s: %s %s\n", progress.Operation, progressIndicator(progress, spinner), progress.Status)
	}
	if notice != "" {
		fmt.Fprintf(&frame, "\n%s\n", notice)
	}
	_, err := output.WriteString(frame.String())
	return err
}

func progressIndicator(progress softwarelifecycle.Progress, spinner int) string {
	if progress.Mode != softwarelifecycle.ProgressBar || progress.Total == 0 {
		return string("|/-\\"[spinner%4])
	}
	completed := min(progress.Completed, progress.Total)
	filled := scaled(completed, progress.Total, 10)
	percent := scaled(completed, progress.Total, 100)
	return fmt.Sprintf("[%s%s] %d%%", strings.Repeat("#", int(filled)), strings.Repeat("-", 10-int(filled)), percent)
}

func scaled(value, total, scale uint64) uint64 {
	high, low := bits.Mul64(value, scale)
	quotient, _ := bits.Div64(high, low, total)
	return quotient
}

type eventKind uint8

const (
	eventInvalid eventKind = iota
	eventEOF
	eventUp
	eventDown
	eventDigit
	eventEnter
	eventPaste
	eventReadFailure
)

type inputEvent struct {
	kind  eventKind
	value byte
}

type inputReader struct{ fd int }

func (reader inputReader) next() inputEvent {
	value, outcome := reader.read(false)
	if outcome == readEOF {
		return inputEvent{kind: eventEOF}
	}
	if outcome == readFailure {
		return inputEvent{kind: eventReadFailure}
	}
	switch value {
	case '\r', '\n':
		return inputEvent{kind: eventEnter}
	case 0x1b:
		return reader.escape()
	default:
		if value >= '0' && value <= '9' {
			return inputEvent{kind: eventDigit, value: value}
		}
		return inputEvent{kind: eventInvalid}
	}
}

func (reader inputReader) escape() inputEvent {
	second, outcome := reader.read(true)
	if outcome == readFailure {
		return inputEvent{kind: eventReadFailure}
	}
	if outcome != readByte {
		return inputEvent{kind: eventInvalid}
	}
	if second == 'O' {
		third, outcome := reader.read(true)
		if outcome == readFailure {
			return inputEvent{kind: eventReadFailure}
		}
		if outcome != readByte {
			return inputEvent{kind: eventInvalid}
		}
		if third == 'A' {
			return inputEvent{kind: eventUp}
		}
		if third == 'B' {
			return inputEvent{kind: eventDown}
		}
		return inputEvent{kind: eventInvalid}
	}
	if second != '[' {
		return inputEvent{kind: eventInvalid}
	}
	sequence := make([]byte, 0, 8)
	for len(sequence) < 32 {
		value, outcome := reader.read(true)
		if outcome == readFailure {
			return inputEvent{kind: eventReadFailure}
		}
		if outcome != readByte {
			return inputEvent{kind: eventInvalid}
		}
		sequence = append(sequence, value)
		if value < 0x40 || value > 0x7e {
			continue
		}
		switch string(sequence) {
		case "A":
			return inputEvent{kind: eventUp}
		case "B":
			return inputEvent{kind: eventDown}
		case "200~":
			if reader.discardPaste() == readFailure {
				return inputEvent{kind: eventReadFailure}
			}
			return inputEvent{kind: eventPaste}
		default:
			return inputEvent{kind: eventInvalid}
		}
	}
	return inputEvent{kind: eventInvalid}
}

func (reader inputReader) discardPaste() readOutcome {
	marker := []byte("\x1b[201~")
	matched := 0
	for {
		value, outcome := reader.read(false)
		if outcome != readByte {
			return outcome
		}
		if value == marker[matched] {
			matched++
			if matched == len(marker) {
				return readByte
			}
		} else if value == marker[0] {
			matched = 1
		} else {
			matched = 0
		}
	}
}

type readOutcome uint8

const (
	readByte readOutcome = iota
	readTimeout
	readEOF
	readFailure
)

func (reader inputReader) read(deadline bool) (byte, readOutcome) {
	if deadline {
		set := syscall.FdSet{}
		set.Bits[reader.fd/64] |= 1 << (uint(reader.fd) % 64)
		timeout := syscall.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
		ready, err := syscall.Select(reader.fd+1, &set, nil, nil, &timeout)
		if err != nil {
			return 0, readFailure
		}
		if ready != 1 {
			return 0, readTimeout
		}
	}
	buffer := []byte{0}
	count, err := syscall.Read(reader.fd, buffer)
	if err != nil {
		return 0, readFailure
	}
	if count == 0 {
		return 0, readEOF
	}
	return buffer[0], readByte
}
