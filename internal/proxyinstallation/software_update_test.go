package proxyinstallation

import (
	"bytes"
	"context"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type updateTestHost struct{ *controlledHost }

func (h *updateTestHost) SoftwareUpdateContracts(context.Context, *hostadapter.ServingAuthority, *hostadapter.RenewalAuthority, *hostadapter.SubscriptionResourceAuthority, *hostadapter.ProxyStartupAuthority) bool {
	return true
}
func (h *updateTestHost) CompleteSoftwareUpdateServing(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) bool {
	return true
}

func TestSoftwareRecoveryAdmitsStoppedProxyWithoutRestartingIt(t *testing.T) {
	host := &updateTestHost{acceptedHost()}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup=%+v", result)
	}
	before := bytes.Clone(host.ownership)
	operations := len(host.operations)
	host.active, host.listener = false, false
	collaboration := softwareUpdateRuntime(host)
	lock := &softwarelifecycle.MutationLockAuthority{}
	release, ok := collaboration.Acquire(t.Context(), host.ownership, softwarelifecycle.ReleaseIdentity{}, nil, lock)
	if !ok {
		t.Fatal("Recover refused intact stopped proxy")
	}
	defer release()
	if !collaboration.Complete(t.Context(), host.ownership, testInstalledIdentity(), lock) {
		t.Fatal("forward completion requires running proxy")
	}
	if host.active || host.listener || len(host.operations) != operations || !bytes.Equal(before, host.ownership) {
		t.Fatal("recovery changed proxy or authority")
	}
	target := &softwarelifecycle.UpdateTarget{Identity: testInstalledIdentity(), Executable: []byte(expandedProxyAuthorityCapability), Support: &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []softwarelifecycle.ReleaseIdentity{testInstalledIdentity()}}}
	if release, ok := collaboration.Acquire(t.Context(), host.ownership, testInstalledIdentity(), target, lock); ok {
		release()
		t.Fatal("ordinary update admitted stopped proxy")
	}
	host.configUnknown = true
	if release, ok := collaboration.Acquire(t.Context(), host.ownership, softwarelifecycle.ReleaseIdentity{}, nil, lock); ok {
		release()
		t.Fatal("recovery admitted unknown configuration")
	}
}
