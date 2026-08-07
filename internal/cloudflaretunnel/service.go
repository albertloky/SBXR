package cloudflaretunnel

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const cloudflaredServiceUnit = `[Unit]
Description=SBXR Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
User=cloudflared
Group=cloudflared
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run --token-file /etc/sbxr/cloudflared/token
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

func CloudflaredServiceUnit() string { return cloudflaredServiceUnit }

func ValidateCloudflaredServiceUnit(unit string) bool {
	return unit == cloudflaredServiceUnit && strings.Contains(unit, "User=cloudflared\nGroup=cloudflared") && strings.Contains(unit, "--token-file "+cloudflaredTokenPath) && !strings.Contains(unit, "Environment=")
}

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
		{"etc/sbxr/cloudflared/config.yml", 0o640, false, cloudflaredGID},
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

func ValidateInstalledService(root string, rootUID, rootGID, cloudflaredGID int) error {
	if err := ValidateServiceMaterial(root, rootUID, rootGID, cloudflaredGID); err != nil {
		return err
	}
	name := filepath.Join(root, "etc/systemd/system/cloudflared.service")
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Mode()&os.ModeSymlink != 0 {
		return fs.ErrPermission
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	content, readErr := os.ReadFile(name)
	if !ok || int(owner.Uid) != rootUID || int(owner.Gid) != rootGID || owner.Nlink != 1 || readErr != nil || !bytes.Equal(content, []byte(cloudflaredServiceUnit)) {
		return fs.ErrPermission
	}
	return nil
}
