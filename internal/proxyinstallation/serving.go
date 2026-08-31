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
	RemoveServingRuntime(context.Context, hostadapter.ServingAuthority) bool
	ServingRuntimeAbsent(hostadapter.ServingAuthority) bool
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
	return ok && host.InspectServingFiles(*record.Serving, record.Direction == removalRequired).Accepted
}

// ServeSubscription is the private same-executable systemd role, not an Owner
// operation. The concrete private Module receives only validated in-memory
// state and an already bound listener. This path never publishes authority.
func ServeSubscription(ctx context.Context, lifecycle softwarelifecycle.Interface) subscriptionserving.Code {
	host := hostadapter.New()
	lock, busy, err := host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	if err != nil || busy {
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
	if err != nil || !ok || record.Serving == nil || record.Direction != noDirection || record.Phase != runningPhase || !compatibleOwnership(record, *installed.Installed) {
		return subscriptionserving.Refused
	}
	for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath} {
		if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
			return subscriptionserving.Refused
		}
	}
	if !host.ValidateServingDispatch(*record.Serving) || !host.ServingPublicIPv4(ctx, record.PublicIPv4) {
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
	certificate, ok := host.LoadServingCertificate(*record.Serving)
	if !ok {
		return subscriptionserving.Refused
	}
	m := subscriptionserving.New(nil, nil)
	state, code := m.Prepare(facts, host.ServingGeneration(*record.Serving), certificate)
	if code != subscriptionserving.Ready {
		return code
	}
	current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if err != nil || !bytes.Equal(body, current) {
		return subscriptionserving.Refused
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(record.PublicIPv4, "8443"))
	if err != nil {
		return subscriptionserving.Refused
	}
	lock.Release()
	return m.Serve(ctx, state, listener)
}
