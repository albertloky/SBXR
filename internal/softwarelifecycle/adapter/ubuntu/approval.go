package ubuntu

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type Approval struct {
	recheck   func(context.Context) (softwarelifecycle.InstallRecheck, error)
	authorize func(context.Context, string, ...string) error
	uid       int
}

func NewApproval(recheck func(context.Context) (softwarelifecycle.InstallRecheck, error)) Approval {
	return Approval{recheck: recheck, authorize: ordinarySudo, uid: os.Geteuid()}
}

func (approval Approval) AuthorizeAndRecheck(ctx context.Context) (softwarelifecycle.InstallRecheck, error) {
	if ctx == nil || approval.uid == 0 || approval.authorize == nil || approval.recheck == nil {
		return softwarelifecycle.InstallRecheck{}, errors.New("unprivileged install approval unavailable")
	}
	if err := approval.authorize(ctx, "/usr/bin/sudo", "-v"); err != nil {
		return softwarelifecycle.InstallRecheck{}, errors.New("ordinary system sudo approval failed")
	}
	return approval.recheck(ctx)
}

func ordinarySudo(ctx context.Context, name string, arguments ...string) error {
	if name != "/usr/bin/sudo" || len(arguments) != 1 || arguments[0] != "-v" {
		return errors.New("unsupported privilege request")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
