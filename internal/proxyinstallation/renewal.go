package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"os"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type renewalHost interface {
	InspectRenewal(hostadapter.RenewalAuthority) hostadapter.RenewalInspection
	PrepareRenewalRecorder(hostadapter.RenewalAuthority) (hostadapter.RenewalAttemptRunner, bool)
	RecordRenewalHook(hostadapter.RenewalAuthority, string, map[string]string) bool
	AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool)
	RemoveRenewalIntegration(context.Context, hostadapter.RenewalAuthority, *hostadapter.RenewalExclusion) bool
	RenewalIntegrationAbsent(hostadapter.RenewalAuthority) bool
}

// RecordRenewal is a fixed private systemd role. Its argument selects no
// authority; the installed pair and complete Ownership Record do.
func RecordRenewal(ctx context.Context, lifecycle softwarelifecycle.Interface) int {
	return recordRenewal(ctx, lifecycle, hostadapter.New())
}

type renewalDispatchHost interface {
	AcquireSubscriptionReviewLock(string) (*hostadapter.MutationLock, bool, error)
	ReadOwnership(string) ([]byte, error)
	PrepareRenewalRecorder(hostadapter.RenewalAuthority) (hostadapter.RenewalAttemptRunner, bool)
	RecordRenewalHook(hostadapter.RenewalAuthority, string, map[string]string) bool
}

func recordRenewal(ctx context.Context, lifecycle softwarelifecycle.Interface, host renewalDispatchHost) int {
	lock, busy, err := host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return hostadapter.RenewalRecorderRefused
	}
	lc, ok := lifecycle.(mutationLifecycle)
	if !ok {
		lock.Release()
		return hostadapter.RenewalRecorderRefused
	}
	installed := lc.StatusUnderMutationLock(ctx, lock)
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	record, valid := decodeOwnership(body)
	if err != nil || !valid || installed.State != softwarelifecycle.Ready || installed.Installed == nil || record.Renewal == nil || record.Serving == nil || record.ClientRotation != nil || record.Direction != noDirection || record.Phase != runningPhase || !compatibleOwnership(record, *installed.Installed) {
		lock.Release()
		return hostadapter.RenewalRecorderRefused
	}
	for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath} {
		if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
			lock.Release()
			return hostadapter.RenewalRecorderRefused
		}
	}
	runner, prepared := host.PrepareRenewalRecorder(*record.Renewal)
	current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if !prepared || err != nil || !bytes.Equal(body, current) {
		if prepared {
			runner.Abort()
		}
		lock.Release()
		return hostadapter.RenewalRecorderRefused
	}
	lock.Release()
	return runner.Run(ctx)
}

func RecordRenewalHook(ctx context.Context, lifecycle softwarelifecycle.Interface, role string, environment map[string]string) bool {
	return recordRenewalHook(ctx, lifecycle, hostadapter.New(), role, environment)
}

func recordRenewalHook(ctx context.Context, lifecycle softwarelifecycle.Interface, host renewalDispatchHost, role string, environment map[string]string) bool {
	status := lifecycle.Status(ctx)
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	record, valid := decodeOwnership(body)
	if err != nil || !valid || status.State != softwarelifecycle.Ready || status.Installed == nil || record.Renewal == nil || record.Serving == nil || record.ClientRotation != nil || record.Direction != noDirection || record.Phase != runningPhase || !compatibleOwnership(record, *status.Installed) {
		return false
	}
	for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath} {
		if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	if !host.RecordRenewalHook(*record.Renewal, role, environment) {
		return false
	}
	current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if err != nil || !bytes.Equal(body, current) {
		return false
	}
	if role != hostadapter.RenewalDeployRole {
		return true
	}
	fullHost, ok := host.(interface {
		hostInterface
		certificateActivationHost
		renewalHost
	})
	if !ok {
		return false
	}
	module := newInstalledInterface(lifecycle, fullHost, singboxadapter.New()).(*installedInterface)
	review := module.reviewPublishedCertificateActivation(ctx)
	if review.Prepared == nil {
		return review.SubscriptionStatus == SubscriptionAvailable
	}
	return module.Execute(ctx, *review.Prepared, Approved, nil).Code == SubscriptionChangeFinished
}
