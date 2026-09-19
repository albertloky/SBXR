package proxyinstallation

import (
	"context"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type lockProvisioningHost interface {
	ProvisionMutationLock(string) (*hostadapter.MutationLock, bool, error)
}

// ProvisionMutationLock is the fixed early-boot role. It may create only the
// canonical volatile coordination inode and grants no product operation.
func ProvisionMutationLock(ctx context.Context, lifecycle softwarelifecycle.Interface) bool {
	return provisionMutationLock(ctx, lifecycle, hostadapter.New())
}

func provisionMutationLock(ctx context.Context, lifecycle softwarelifecycle.Interface, host lockProvisioningHost) bool {
	before := lifecycle.Status(ctx)
	if ctx.Err() != nil || before.State != softwarelifecycle.Ready || before.Installed == nil {
		return false
	}
	lock, busy, err := host.ProvisionMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy || lock == nil {
		return false
	}
	defer lock.Release()
	mutation, ok := lifecycle.(mutationLifecycle)
	if !ok {
		return false
	}
	after := mutation.StatusUnderMutationLock(ctx, lock)
	return ctx.Err() == nil && after.State == softwarelifecycle.Ready && after.Installed != nil && *after.Installed == *before.Installed
}
