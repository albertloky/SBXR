package ubuntu

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

// InspectRelease proves the fixed active executable and its release-bound managed units.
func InspectRelease(rootPath string, identity softwarelifecycle.ReleaseIdentity) systemchanges.HealthStatus {
	return inspectRelease(rootPath, identity, 0)
}

func inspectRelease(rootPath string, identity softwarelifecycle.ReleaseIdentity, uid uint32) systemchanges.HealthStatus {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.Unknown
	}
	defer root.Close()
	expected := softwarelifecycle.ReleaseInstallPath(identity)
	target, err := root.Readlink("usr/local/bin/sbxr")
	if err != nil || target != expected {
		return systemchanges.Failed
	}
	name := strings.TrimPrefix(expected, "/")
	info, err := root.Lstat(name)
	if err != nil {
		return systemchanges.Failed
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || info.Size() <= 0 || info.Size() > softwarelifecycle.MaxAssetBytes || stat.Uid != uid || stat.Nlink != 1 {
		return systemchanges.Failed
	}
	file, err := root.Open(name)
	if err != nil {
		return systemchanges.Unknown
	}
	metadata, _, metadataErr := softwarelifecycle.ReadPayloadMetadata(file, info.Size())
	file.Close()
	if metadataErr != nil || metadata.Build.Repository != identity.Repository || metadata.Build.Tag != identity.Tag || metadata.Build.Commit != identity.Commit {
		return systemchanges.Failed
	}
	units, err := softwarelifecycle.RenderManagedUnits(metadata, identity)
	if err != nil {
		return systemchanges.Failed
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		unitInfo, statErr := root.Lstat(path.Join("etc/systemd/system", unit))
		body, readErr := root.ReadFile(path.Join("etc/systemd/system", unit))
		if statErr != nil || readErr != nil {
			return systemchanges.Failed
		}
		unitStat, statOK := unitInfo.Sys().(*syscall.Stat_t)
		if !statOK || !unitInfo.Mode().IsRegular() || unitInfo.Mode().Perm() != fs.FileMode(0o644) || unitStat.Uid != uid || !bytes.Equal(body, units[unit]) {
			return systemchanges.Failed
		}
	}
	return systemchanges.Healthy
}
