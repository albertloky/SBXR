package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"os"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// SoftwareUpdateRuntime supplies private collaboration to the existing
// Software Lifecycle transaction; it creates no Proxy Installation Action.
func SoftwareUpdateRuntime() softwarelifecycle.UpdateRuntime {
	host := hostadapter.New()
	return softwareUpdateRuntime(host)
}

type softwareUpdateHost interface {
	hostInterface
	AcquireServingExclusion() (*hostadapter.ServingExclusion, bool)
	AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool)
	SoftwareUpdateContracts(context.Context, *hostadapter.ServingAuthority, *hostadapter.RenewalAuthority, *hostadapter.SubscriptionResourceAuthority, *hostadapter.ProxyStartupAuthority) bool
	InspectPreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) hostadapter.Observation
	CompleteSoftwareUpdateServing(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) bool
}

func softwareUpdateRuntime(host softwareUpdateHost) softwarelifecycle.UpdateRuntime {
	return softwarelifecycle.UpdateRuntime{
		Acquire: func(ctx context.Context, body []byte, source softwarelifecycle.ReleaseIdentity, target *softwarelifecycle.UpdateTarget, lock *softwarelifecycle.MutationLockAuthority) (func(), bool) {
			if lock == nil {
				return nil, false
			}
			for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath} {
				if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
					return nil, false
				}
			}
			packageLocks, busy, err := host.AcquirePackageLocks()
			if err != nil || busy || packageLocks == nil {
				return nil, false
			}
			release := func() { packageLocks.Release() }
			if len(body) == 0 {
				facts := host.Inspect(ctx, footprint)
				if !facts.Complete || !resourcesObserved(facts.Resources) || resourcesPresent(facts.Resources) || !host.InspectSubscriptionAbsence(ctx).Accepted {
					release()
					return nil, false
				}
				return release, true
			}
			record, ok := decodeOwnership(body)
			if !ok {
				release()
				return nil, false
			}
			if target == nil {
				source = record.Release
			}
			if !AdmitSoftwareUpdate(body, source, target) {
				release()
				return nil, false
			}
			if record.Renewal != nil {
				exclusion, ok := host.AcquireRenewalExclusion(*record.Renewal)
				if !ok {
					release()
					return nil, false
				}
				release = func() { exclusion.Release(); packageLocks.Release() }
			}
			if record.Serving != nil {
				exclusion, ok := host.AcquireServingExclusion()
				if !ok {
					release()
					return nil, false
				}
				priorRelease := release
				release = func() { exclusion.Release(); priorRelease() }
			}
			facts := host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
			// Recover must work after reboot, when the pending transaction has
			// correctly prevented ordinary proxy startup. It never starts it.
			compatible := ownedFactsAccepted(facts) && all(facts.Host, facts.PublicIPv4Matches).Accepted
			if target != nil {
				compatible = runningAccepted(facts)
			}
			if !host.SoftwareUpdateContracts(ctx, record.Serving, record.Renewal, record.SubscriptionResources, record.Startup) || !compatible {
				release()
				return nil, false
			}
			if target != nil && record.Serving != nil && !host.InspectPreparedSubscription(ctx, *record.Serving, *record.Renewal).Accepted {
				release()
				return nil, false
			}
			current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
			if err != nil || !bytes.Equal(current, body) {
				release()
				return nil, false
			}
			return release, true
		},
		Complete: func(ctx context.Context, body []byte, _ softwarelifecycle.ReleaseIdentity, lock *softwarelifecycle.MutationLockAuthority) bool {
			if len(body) == 0 {
				return true
			}
			record, ok := decodeOwnership(body)
			if !ok {
				return false
			}
			if record.Serving != nil && !host.CompleteSoftwareUpdateServing(hostadapter.RuntimeStartContext(ctx, lock), *record.Serving, *record.Renewal) {
				return false
			}
			current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
			return err == nil && bytes.Equal(current, body) && host.SoftwareUpdateContracts(ctx, record.Serving, record.Renewal, record.SubscriptionResources, record.Startup) && ownedFactsAccepted(host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4))
		},
	}
}
