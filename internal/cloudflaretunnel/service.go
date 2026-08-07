package cloudflaretunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
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
		{"etc", 0o755, true, rootGID},
		{"etc/sbxr", 0o755, true, rootGID},
		{"etc/sbxr/cloudflared", 0o750, true, cloudflaredGID},
		{"etc/sbxr/cloudflared/token", 0o640, false, cloudflaredGID},
		{"etc/sbxr/cloudflared/config.yml", 0o640, false, cloudflaredGID},
		{"etc/systemd", 0o755, true, rootGID},
		{"etc/systemd/system", 0o755, true, rootGID},
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

type serviceMaterial struct {
	TunnelID       string `json:"tunnel_id"`
	TunnelRunToken string `json:"tunnel_run_token"`
	Routes         []struct {
		Hostname string `json:"hostname"`
		Origin   string `json:"origin"`
	} `json:"routes"`
}

var serviceArtifacts = []string{
	"etc/sbxr/cloudflared/token",
	"etc/sbxr/cloudflared/config.yml",
	"etc/systemd/system/cloudflared.service",
	"etc/sbxr/cloudflared/token.preparing",
	"etc/sbxr/cloudflared/config.yml.preparing",
	"etc/systemd/system/cloudflared.service.preparing",
}

type serviceRollback struct {
	Absent              bool `json:"absent"`
	SBXRDirectoryAbsent bool `json:"sbxr_directory_absent"`
}

func (executor Executor) CaptureServiceRollback(rootPath string, write func(io.Reader) error) error {
	if rootPath == "" || write == nil {
		return errors.New("cloudflared rollback capture unavailable")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	identity := executor.serviceIdentity
	if identity == nil {
		identity = cloudflaredIdentity
	}
	rootUID, rootGID, _, err := identity()
	if err != nil {
		return err
	}
	for _, directory := range []string{"etc", "etc/systemd", "etc/systemd/system"} {
		if err := validateServiceDirectory(root, directory, 0o755, rootUID, rootGID); err != nil {
			return err
		}
	}
	sbxrAbsent := false
	if _, err := root.Lstat("etc/sbxr"); errors.Is(err, fs.ErrNotExist) {
		sbxrAbsent = true
	} else if err != nil || validateServiceDirectory(root, "etc/sbxr", 0o755, rootUID, rootGID) != nil {
		return fs.ErrPermission
	}
	if _, err := root.Lstat("etc/sbxr/cloudflared"); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return errors.New("existing cloudflared service cannot be adopted")
	}
	for _, name := range serviceArtifacts {
		if _, err := root.Lstat(name); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return errors.New("existing cloudflared service cannot be adopted")
		}
	}
	snapshot, _ := json.Marshal(serviceRollback{Absent: true, SBXRDirectoryAbsent: sbxrAbsent})
	return write(bytes.NewReader(snapshot))
}

func (executor Executor) ActivateService(rootPath string, source io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	material, err := readServiceMaterial(source)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	identity := executor.serviceIdentity
	if identity == nil {
		identity = cloudflaredIdentity
	}
	rootUID, rootGID, cloudflaredGID, err := identity()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	command := executor.command
	if command == nil {
		command = runCommand
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	version, err := command(ctx, "/usr/bin/cloudflared", "--version")
	if err != nil || !qualifiedCloudflared(version) {
		return systemchanges.StepEvidence{}, errors.New("qualified cloudflared version unavailable")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	if err := ensureServiceDirectory(root, "etc", 0o755, rootUID, rootGID); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := ensureServiceDirectory(root, "etc/sbxr", 0o755, rootUID, rootGID); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := ensureServiceDirectory(root, "etc/sbxr/cloudflared", 0o750, rootUID, cloudflaredGID); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := ensureServiceDirectory(root, "etc/systemd", 0o755, rootUID, rootGID); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := ensureServiceDirectory(root, "etc/systemd/system", 0o755, rootUID, rootGID); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	routes := make([]Route, 0, len(material.Routes)+1)
	for _, route := range material.Routes {
		routes = append(routes, Route{Hostname: route.Hostname, Service: route.Origin})
	}
	routes = append(routes, Route{Service: "http_status:404"})
	config, _ := json.Marshal(struct {
		Ingress []Route `json:"ingress"`
	}{Ingress: routes})
	config = append(config, '\n')
	for _, file := range []struct {
		name    string
		content []byte
		mode    fs.FileMode
		gid     int
	}{
		{"etc/sbxr/cloudflared/token", []byte(material.TunnelRunToken + "\n"), 0o640, cloudflaredGID},
		{"etc/sbxr/cloudflared/config.yml", config, 0o640, cloudflaredGID},
		{"etc/systemd/system/cloudflared.service", []byte(cloudflaredServiceUnit), 0o644, rootGID},
	} {
		if err := writeServiceFile(root, file.name, file.content, file.mode, rootUID, file.gid); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := syncServiceNamespace(root, "etc/sbxr/cloudflared", "etc/sbxr", "etc", "etc/systemd/system", "etc/systemd"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service activation failed")
	}
	if executor.validateInstalledService(rootPath) != nil || executor.ValidateNativeConfiguration(rootPath, timeout) != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service activation failed")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service activation failed")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", "--now", "cloudflared.service"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service activation failed")
	}
	return providerEvidence("cloudflared-service-activated", "", ""), nil
}

func (executor Executor) ReverseService(rootPath string, source io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	snapshot, ok := readServiceSnapshot(source)
	if !ok {
		return systemchanges.StepEvidence{}, errors.New("cloudflared rollback snapshot is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	for _, directory := range []string{"etc", "etc/systemd", "etc/systemd/system"} {
		if err := requireSafeRollbackParent(root, directory); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	for _, directory := range []string{"etc/sbxr", "etc/sbxr/cloudflared"} {
		if _, err := root.Lstat(directory); err == nil {
			if err := requireSafeRollbackParent(root, directory); err != nil {
				return systemchanges.StepEvidence{}, err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := executor.command
	if command == nil {
		command = runCommand
	}
	if _, err := root.Lstat("etc/systemd/system/cloudflared.service"); err == nil {
		if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", "cloudflared.service"); err != nil {
			return systemchanges.StepEvidence{}, errors.New("cloudflared service stop failed")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return systemchanges.StepEvidence{}, err
	}
	for _, name := range serviceArtifacts {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := root.Remove("etc/sbxr/cloudflared"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return systemchanges.StepEvidence{}, err
	}
	if snapshot.SBXRDirectoryAbsent {
		if err := root.Remove("etc/sbxr"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	}
	if err := syncServiceNamespace(root, "etc/sbxr", "etc", "etc/systemd/system", "etc/systemd"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service rollback sync failed")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("cloudflared service reload failed")
	}
	return providerEvidence("cloudflared-service-removed", "", ""), nil
}

func (executor Executor) InspectService(rootPath string, source io.Reader) (systemchanges.StepEffect, error) {
	snapshot, ok := readServiceSnapshot(source)
	if !ok {
		return "", errors.New("cloudflared rollback snapshot is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for _, name := range serviceArtifacts {
		if _, err := root.Lstat(name); err == nil {
			return systemchanges.StepEffectPresent, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	if _, err := root.Lstat("etc/sbxr/cloudflared"); err == nil {
		return systemchanges.StepEffectPresent, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if snapshot.SBXRDirectoryAbsent {
		if _, err := root.Lstat("etc/sbxr"); err == nil {
			return systemchanges.StepEffectPresent, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return systemchanges.StepEffectAbsent, nil
}

func readServiceMaterial(source io.Reader) (serviceMaterial, error) {
	var material serviceMaterial
	if source == nil {
		return material, errors.New("prepared cloudflared service material unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(source, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&material) != nil || decoder.Decode(&struct{}{}) != io.EOF || !tunnelUUID.MatchString(material.TunnelID) || material.TunnelRunToken == "" || len(material.TunnelRunToken) > 16<<10 || strings.ContainsAny(material.TunnelRunToken, "\r\n\x00") || len(material.Routes) < 1 || len(material.Routes) > 2 {
		return serviceMaterial{}, errors.New("prepared cloudflared service material is invalid")
	}
	xhttp, websocket := false, false
	for _, route := range material.Routes {
		if !validZoneName(route.Hostname) {
			return serviceMaterial{}, errors.New("prepared cloudflared route is invalid")
		}
		switch route.Origin {
		case xhttpOrigin:
			xhttp = !xhttp
		case webSocketOrigin:
			websocket = !websocket
		default:
			return serviceMaterial{}, errors.New("prepared cloudflared route is invalid")
		}
	}
	if !xhttp || len(material.Routes) == 2 && (!websocket || material.Routes[0].Hostname == material.Routes[1].Hostname) {
		return serviceMaterial{}, errors.New("prepared cloudflared routes are incomplete")
	}
	return material, nil
}

func ensureServiceDirectory(root *os.Root, name string, mode fs.FileMode, uid, gid int) error {
	if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		if err := root.Mkdir(name, mode); err != nil || root.Chown(name, uid, gid) != nil {
			return fs.ErrPermission
		}
	} else if err != nil {
		return err
	}
	return validateServiceDirectory(root, name, mode, uid, gid)
}

func validateServiceDirectory(root *os.Root, name string, mode fs.FileMode, uid, gid int) error {
	info, err := root.Lstat(name)
	owner, ok := fileOwner(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || int(owner.Uid) != uid || int(owner.Gid) != gid {
		return fs.ErrPermission
	}
	return nil
}

func requireSafeRollbackParent(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fs.ErrPermission
	}
	return nil
}

func writeServiceFile(root *os.Root, name string, content []byte, mode fs.FileMode, uid, gid int) error {
	temporary := name + ".preparing"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = root.Remove(temporary)
		}
	}()
	if file.Chown(uid, gid) != nil {
		return fs.ErrPermission
	}
	if _, err := file.Write(content); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("protected cloudflared service write failed")
	}
	if err := root.Link(temporary, name); err != nil {
		return errors.New("cloudflared service target changed after review")
	}
	if err := root.Remove(temporary); err != nil {
		return err
	}
	failed = false
	return nil
}

func qualifiedCloudflared(output []byte) bool {
	fields := strings.Fields(string(output))
	return len(fields) >= 3 && fields[0] == "cloudflared" && fields[1] == "version" && fields[2] == qualifiedCloudflaredVersion
}

func syncServiceNamespace(root *os.Root, names ...string) error {
	for _, name := range names {
		directory, err := root.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func readServiceSnapshot(source io.Reader) (serviceRollback, bool) {
	var snapshot serviceRollback
	decoder := json.NewDecoder(io.LimitReader(source, 1024))
	decoder.DisallowUnknownFields()
	ok := decoder.Decode(&snapshot) == nil && snapshot.Absent && decoder.Decode(&struct{}{}) == io.EOF
	return snapshot, ok
}

func fileOwner(info fs.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return owner, ok
}
