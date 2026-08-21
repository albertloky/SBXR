//go:build linux

// Package terminal presents Software Lifecycle through the supported numbered line menu.
package terminal

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// Run owns one admitted terminal session and returns the freshly selected action.
// Operation execution is connected by the operation Adapter, not by this selection seam.
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

	result := lifecycle.Status(ctx)
	actions := legalActions(result.State)
	selection := 0
	invalid := false
	if writeFrame(output, result, actions, selection, invalid) != nil {
		terminalOK = false
		return NoAction, 1
	}
	reader := inputReader{fd: int(input.Fd())}
	for {
		event := reader.next()
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
			return actions[selection].action, 0
		default:
			invalid = true
		}
		if writeFrame(output, result, actions, selection, invalid) != nil {
			terminalOK = false
			return NoAction, 1
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
	frame.WriteString(redraw)
	frame.WriteString("SBXR\n\n")
	if result.Installed != nil {
		fmt.Fprintf(&frame, "Current SBXR version: %s\n", result.Installed.Tag)
	}
	latest := "Not checked"
	if result.Latest != nil {
		latest = result.Latest.Tag
	}
	fmt.Fprintf(&frame, "Latest stable version: %s\nStatus: %s\n\nResult: %s\nCode: %s\n\n", latest, result.State, result.Message, result.Code)
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
