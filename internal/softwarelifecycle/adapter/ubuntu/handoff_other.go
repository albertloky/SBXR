//go:build !linux

package ubuntu

import (
	"errors"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func openVerifiedInstallExecutable(softwarelifecycle.StagedRelease) (*os.File, error) {
	return nil, errors.New("privileged install is supported only on Linux")
}

func verifyInstallApplyProcess(*os.File, *os.File) error {
	return errors.New("privileged install is supported only on Linux")
}
