//go:build linux && arm64

package filesystem

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func exchangeDirectories(root *os.Root, first, second string) error {
	const (
		renameat2Trap  = 276
		atFDCWD        = ^uintptr(99)
		renameExchange = 2
	)
	oldPath, err := syscall.BytePtrFromString(filepath.Join(root.Name(), first))
	if err != nil {
		return err
	}
	newPath, err := syscall.BytePtrFromString(filepath.Join(root.Name(), second))
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(renameat2Trap, atFDCWD, uintptr(unsafe.Pointer(oldPath)), atFDCWD, uintptr(unsafe.Pointer(newPath)), renameExchange, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
