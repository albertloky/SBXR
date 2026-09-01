package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type servingRemovalHost interface {
	InspectServingFiles(hostadapter.ServingAuthority, bool) hostadapter.Observation
	AcquireServingExclusion() (*hostadapter.ServingExclusion, bool)
	RemoveServingRuntime(context.Context, hostadapter.ServingAuthority, *hostadapter.ServingExclusion) bool
	ServingRuntimeAbsent(hostadapter.ServingAuthority) bool
}

type subscriptionResourceRemovalHost interface {
	RemoveSubscriptionResources(context.Context, hostadapter.SubscriptionResourceAuthority, *hostadapter.ServingAuthority) bool
}

type subscriptionRepairRemovalHost interface {
	RemoveSubscriptionRepair(context.Context, hostadapter.ServingAuthority, hostadapter.ServingAuthority, *hostadapter.ServingExclusion) bool
}

type subscriptionExclusion struct {
	serving *hostadapter.ServingExclusion
	renewal *hostadapter.RenewalExclusion
}

func (e *subscriptionExclusion) Release() {
	if e == nil {
		return
	}
	if e.serving != nil {
		e.serving.Release()
	}
	if e.renewal != nil {
		e.renewal.Release()
	}
}

func (m *installedInterface) acquireSubscriptionExclusion(record ownershipRecord) (*subscriptionExclusion, bool) {
	exclusion := &subscriptionExclusion{}
	if record.Renewal != nil {
		host, ok := m.host.(renewalHost)
		if !ok {
			return nil, false
		}
		exclusion.renewal, ok = host.AcquireRenewalExclusion(*record.Renewal)
		if !ok {
			return nil, false
		}
	}
	if record.Serving != nil {
		host, ok := m.host.(servingRemovalHost)
		if !ok {
			exclusion.Release()
			return nil, false
		}
		exclusion.serving, ok = host.AcquireServingExclusion()
		if !ok {
			exclusion.Release()
			return nil, false
		}
	}
	return exclusion, true
}

type servingDispatchHost interface {
	AcquireSubscriptionReviewLock(string) (*hostadapter.MutationLock, bool, error)
	ReadOwnership(string) ([]byte, error)
	ValidateServingDispatch(hostadapter.ServingAuthority, *hostadapter.RenewalAuthority) bool
	ServingPublicIPv4(context.Context, string) bool
	WatchServingPublicIPv4(context.Context, string) <-chan bool
	ReadServingConfiguration(hostadapter.SetupSpec, string) ([]byte, error)
	LoadServingCertificate(hostadapter.ServingAuthority) (subscriptionserving.Certificate, bool)
	ServingGeneration(hostadapter.ServingAuthority) subscriptionserving.Generation
	BindServingListener(string) (net.Listener, error)
}

func (m *installedInterface) servingSurfaceSafe() bool {
	if m.host == nil {
		return false
	}
	body, err := m.readOwnership()
	record, ok := decodeOwnership(body)
	if err != nil || !ok || record.Serving == nil {
		return false
	}
	staged, err := m.host.ReadOwnership(hostSetupSpec.OwnershipNextPath)
	if err == nil {
		next, valid := decodeOwnership(staged)
		if !valid {
			return false
		}
		if record.Direction == removalRequired && next.RemovalCheckpoint == record.RemovalCheckpoint+1 {
			next.RemovalCheckpoint = record.RemovalCheckpoint
		}
		if !bytes.Equal(ownershipBytes(next), ownershipBytes(record)) {
			return false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	host, ok := m.host.(servingRemovalHost)
	if !ok || !host.InspectServingFiles(*record.Serving, true).Accepted {
		return false
	}
	if record.Renewal != nil {
		renewal, ok := m.host.(renewalHost)
		return ok && renewal.InspectRenewal(*record.Renewal).Observed
	}
	return true
}

func (m *installedInterface) subscriptionRemovalSurfaceSafe() bool {
	if m.servingSurfaceSafe() {
		return true
	}
	body, err := m.readOwnership()
	record, ok := decodeOwnership(body)
	if err == nil && ok && record.ClientRotation != nil && record.ClientRotation.Subscription != nil {
		_, stagedErr := m.host.ReadOwnership(hostSetupSpec.OwnershipNextPath)
		return errors.Is(stagedErr, os.ErrNotExist) && m.inspectClientIdentitySubscription(record)
	}
	if err != nil || !ok || record.Enablement == nil || record.Enablement.Resources == nil || !record.Enablement.Resources.Valid() {
		return false
	}
	_, stagedErr := m.host.ReadOwnership(hostSetupSpec.OwnershipNextPath)
	return errors.Is(stagedErr, os.ErrNotExist)
}

// ServeSubscription is the private same-executable systemd role, not an Owner
// operation. The concrete private Module receives only validated in-memory
// state and an already bound listener. This path never publishes authority.
func ServeSubscription(ctx context.Context, lifecycle softwarelifecycle.Interface) subscriptionserving.Code {
	return serveSubscription(ctx, lifecycle, hostadapter.New(), subscriptionserving.New(nil, nil))
}

func serveSubscription(ctx context.Context, lifecycle softwarelifecycle.Interface, host servingDispatchHost, m *subscriptionserving.Module) subscriptionserving.Code {
	lock, busy, err := host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	borrowed := false
	if err == nil && busy {
		if starter, ok := host.(interface {
			BorrowRuntimeStartLock(string) (*hostadapter.MutationLock, error)
		}); ok {
			lock, err = starter.BorrowRuntimeStartLock(hostadapter.ServingRole)
			busy = err != nil
			borrowed = err == nil
		}
	}
	if err != nil || busy || lock == nil {
		return subscriptionserving.Refused
	}
	defer lock.Release()
	lc, ok := lifecycle.(mutationLifecycle)
	if !ok {
		return subscriptionserving.Refused
	}
	installed := lc.StatusUnderMutationLock(ctx, lock)
	if installed.State != softwarelifecycle.Ready || installed.Installed == nil {
		return subscriptionserving.Refused
	}
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	record, ok := decodeOwnership(body)
	if err != nil || !ok || record.Direction != noDirection || record.Phase != runningPhase || !compatibleOwnership(record, *installed.Installed) {
		return subscriptionserving.Refused
	}
	if record.Rotation != nil && !borrowed {
		return subscriptionserving.Refused
	}
	if record.ClientRotation != nil {
		policy, _, known := clientIdentityPolicy(record.ClientRotation.Checkpoint)
		selected := record.ClientRotation.Source
		if policy.forward {
			selected = record.ClientRotation.Target
		}
		if !known || !policy.ordinaryStart && !borrowed || record.ClientRotation.Subscription == nil || record.ConfigurationSHA256 != selected {
			return subscriptionserving.Refused
		}
	}
	if record.Repair != nil && record.Repair.Checkpoint != repairPrepared && record.Repair.Target == nil {
		return subscriptionserving.Refused
	}
	var selected hostadapter.ServingAuthority
	var renewal *hostadapter.RenewalAuthority
	if record.Serving != nil {
		selected, renewal = *record.Serving, record.Renewal
	} else if record.Enablement != nil && record.Enablement.Serving != nil && record.Enablement.Renewal != nil {
		selected, renewal = *record.Enablement.Serving, record.Enablement.Renewal
	} else {
		return subscriptionserving.Refused
	}
	if record.Activation != nil {
		selected = record.Activation.Target
	}
	if record.Repair != nil && record.Repair.Target != nil {
		selected = *record.Repair.Target
	}
	for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath} {
		if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
			return subscriptionserving.Refused
		}
	}
	if !host.ValidateServingDispatch(selected, renewal) || !host.ServingPublicIPv4(ctx, record.PublicIPv4) {
		return subscriptionserving.Refused
	}
	configuration, err := host.ReadServingConfiguration(hostSetupSpec, record.ConfigurationSHA256)
	if err != nil {
		return subscriptionserving.Refused
	}
	facts, err := singboxadapter.New().CurrentConnectionFacts(configuration, record.PublicIPv4)
	if err != nil || facts.ServerName != record.DestinationName {
		return subscriptionserving.Refused
	}
	certificate, ok := host.LoadServingCertificate(selected)
	if !ok {
		return subscriptionserving.Refused
	}
	state, code := m.Prepare(facts, host.ServingGeneration(selected), certificate)
	if code != subscriptionserving.Ready {
		return code
	}
	current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if err != nil || !bytes.Equal(body, current) {
		return subscriptionserving.Refused
	}
	listener, err := host.BindServingListener(record.PublicIPv4)
	if err != nil {
		return subscriptionserving.Refused
	}
	lock.Release()
	servingContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case accepted, ok := <-host.WatchServingPublicIPv4(servingContext, record.PublicIPv4):
			if ok && !accepted {
				cancel()
			}
		case <-servingContext.Done():
		}
	}()
	return m.Serve(servingContext, state, listener)
}
