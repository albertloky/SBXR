package ubuntu

import (
	"context"
	"errors"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type Approval struct {
	recheck func(context.Context) (softwarelifecycle.InstallRecheck, error)
	uid     int
}

func NewApproval(recheck func(context.Context) (softwarelifecycle.InstallRecheck, error)) Approval {
	return Approval{recheck: recheck, uid: os.Geteuid()}
}

func (approval Approval) AuthorizeAndRecheck(ctx context.Context) (softwarelifecycle.InstallRecheck, error) {
	if ctx == nil || approval.uid != 0 || approval.recheck == nil {
		return softwarelifecycle.InstallRecheck{}, errors.New("privileged install recheck unavailable")
	}
	return approval.recheck(ctx)
}
