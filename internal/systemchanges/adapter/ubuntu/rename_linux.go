//go:build linux

package ubuntu

import (
	"syscall"
	"unsafe"
)

func renameNoReplace(oldPath, newPath string) error {
	oldPointer, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(sysRenameat2, ^uintptr(99), uintptr(unsafe.Pointer(oldPointer)), ^uintptr(99), uintptr(unsafe.Pointer(newPointer)), 1, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
