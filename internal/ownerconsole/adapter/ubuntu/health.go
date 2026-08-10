package ubuntu

import (
	"os"
	"syscall"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

// Inspect proves that this Owner Console is the fixed root-owned installed executable.
func Inspect() ownerconsole.ModuleHealth {
	return inspect("/usr/local/bin/sbxr", "/proc/self/exe", 0)
}

func inspect(installedPath, runningPath string, uid uint32) ownerconsole.ModuleHealth {
	installed, installedErr := os.Stat(installedPath)
	running, runningErr := os.Stat(runningPath)
	if installedErr != nil || runningErr != nil {
		return ownerconsole.HealthUnknown
	}
	stat, ok := installed.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerconsole.HealthUnknown
	}
	if !installed.Mode().IsRegular() || installed.Mode().Perm() != 0o755 || stat.Uid != uid || stat.Nlink != 1 || !os.SameFile(installed, running) {
		return ownerconsole.HealthFailed
	}
	return ownerconsole.HealthHealthy
}
