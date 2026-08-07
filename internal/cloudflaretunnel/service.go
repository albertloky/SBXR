package cloudflaretunnel

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ValidateServiceMaterial is the final read-only guard used by the System
// Changes Adapter before activating prepared cloudflared material.
func ValidateServiceMaterial(root string, rootUID, rootGID, cloudflaredGID int) error {
	checks := []struct {
		name      string
		mode      fs.FileMode
		directory bool
		gid       int
	}{
		{"etc/sbxr", 0o700, true, rootGID},
		{"etc/sbxr/cloudflared", 0o750, true, cloudflaredGID},
		{"etc/sbxr/cloudflared/token", 0o640, false, cloudflaredGID},
	}
	for _, check := range checks {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(check.name)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != check.directory || info.Mode().Perm() != check.mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fs.ErrPermission
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != rootUID || int(owner.Gid) != check.gid || !check.directory && owner.Nlink != 1 {
			return fs.ErrPermission
		}
	}
	return nil
}
