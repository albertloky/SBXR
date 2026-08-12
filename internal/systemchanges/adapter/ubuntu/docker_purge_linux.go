//go:build linux

package ubuntu

import (
	"errors"
	"path/filepath"
	"syscall"
)

func enterDockerPurgeNamespace(packageName string, preserved []string) error {
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil || syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "") != nil {
		return errors.New("Docker preservation namespace unavailable")
	}
	for _, path := range preserved {
		if !filepath.IsAbs(path) || syscall.Mount(path, path, "", syscall.MS_BIND, "") != nil || syscall.Mount("", path, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "") != nil {
			return errors.New("Docker preserved path unavailable")
		}
	}
	return syscall.Exec("/usr/bin/dpkg", []string{"dpkg", "--purge", "--no-triggers", "--", packageName}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"})
}
