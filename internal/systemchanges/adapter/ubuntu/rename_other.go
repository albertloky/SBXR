//go:build !linux

package ubuntu

import "os"

func renameNoReplace(oldPath, newPath string) error {
	if _, err := os.Lstat(newPath); err == nil {
		return os.ErrExist
	}
	return os.Rename(oldPath, newPath)
}
