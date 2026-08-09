package ownerconsole

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// DetectTerminal reports capabilities, not terminal product names.
func DetectTerminal(input, output *os.File, environment []string) Capabilities {
	capabilities := Capabilities{}
	if input == nil || output == nil {
		return capabilities
	}
	capabilities.InteractiveInput = characterDevice(input)
	capabilities.InteractiveOutput = characterDevice(output)
	if capabilities.InteractiveOutput {
		capabilities.Width, capabilities.Height = terminalSize(output)
	}
	values := environmentValues(environment)
	encoding := values["LC_ALL"]
	if encoding == "" {
		encoding = values["LC_CTYPE"]
	}
	if encoding == "" {
		encoding = values["LANG"]
	}
	normalizedEncoding := strings.ToLower(strings.ReplaceAll(encoding, "-", ""))
	capabilities.Unicode = strings.Contains(normalizedEncoding, "utf8")
	capabilities.ReadableEncoding = capabilities.Unicode || normalizedEncoding == "c" || normalizedEncoding == "posix" || strings.Contains(normalizedEncoding, "ascii")
	capabilities.KeyboardInput = capabilities.InteractiveInput
	capabilities.DrawingModeProbeRequired = capabilities.InteractiveInput && capabilities.InteractiveOutput && values["TERM"] != "" && values["TERM"] != "dumb"
	return capabilities
}

func characterDevice(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func terminalSize(file *os.File) (int, int) {
	size := struct{ rows, columns, x, y uint16 }{}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, 0
	}
	return int(size.columns), int(size.rows)
}

func environmentValues(environment []string) map[string]string {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	return values
}
