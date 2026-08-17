// Package cloudflareprofilesetup owns the atomic Managed-to-Managed setup of
// the five Cloudflare-dependent Connection Profiles.
package cloudflareprofilesetup

import (
	"context"
	"errors"
	"fmt"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type StateDependency struct {
	Load    func(state.LoadRequest) (state.Result, error)
	Prepare func(state.PrepareRequest, state.DeferredCloudflareAuthority) (*state.PreparedCommit, error)
}

type SystemChangesDependency struct {
	Inspect func() systemchanges.Inspection
	Apply   func(*systemchanges.ChangeSet) systemchanges.ApplyResult
}

// Dependencies is the one permitted dependency set. Each field is one owning
// Module; Installation is deliberately absent.
type Dependencies struct {
	NetworkPolicy           func(networkpolicy.Request) networkpolicy.Result
	CloudflareTunnel        func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult
	CertificateLifecycle    func(context.Context, certificatelifecycle.PlanRequest) certificatelifecycle.PlanResult
	ConnectionProfiles      func(context.Context, connectionprofiles.RegistryPlanRequest) connectionprofiles.PlanResult
	SubscriptionPublication func(context.Context, subscriptionpublication.PlanRequest) subscriptionpublication.PlanResult
	State                   StateDependency
	SystemChanges           SystemChangesDependency
}

func (dependencies Dependencies) validate() error {
	if dependencies.NetworkPolicy == nil || dependencies.CloudflareTunnel == nil || dependencies.CertificateLifecycle == nil || dependencies.ConnectionProfiles == nil || dependencies.SubscriptionPublication == nil || dependencies.State.Load == nil || dependencies.State.Prepare == nil || dependencies.SystemChanges.Inspect == nil || dependencies.SystemChanges.Apply == nil {
		return errors.New("Cloudflare Profile Setup dependencies unavailable")
	}
	return nil
}

type testPorts struct {
	loadState            func(state.LoadRequest) (state.Result, error)
	inspectSystemChanges func() systemchanges.Inspection
}

type Interface struct {
	dependencies Dependencies
	ports        testPorts
}

func New(dependencies Dependencies) (*Interface, error) {
	if err := dependencies.validate(); err != nil {
		return nil, err
	}
	return &Interface{dependencies: dependencies, ports: testPorts{loadState: dependencies.State.Load, inspectSystemChanges: dependencies.SystemChanges.Inspect}}, nil
}

func newWithPorts(ports testPorts) *Interface { return &Interface{ports: ports} }

func (*Interface) String() string   { return "Cloudflare Profile Setup Module: protected" }
func (*Interface) GoString() string { return "Cloudflare Profile Setup Module: protected" }

type ViewRequest struct{ State state.LoadRequest }

type ViewKind string

const (
	SetupAvailable ViewKind = "Available"
	SetupComplete  ViewKind = "Complete"
	SetupBlocked   ViewKind = "Blocked"
)

type Correction struct {
	Code, Problem, Found, Required, WhyStopped, NextAction string
}

type ViewResult struct {
	Kind       ViewKind
	Revision   uint64
	ChangeSet  string
	Correction *Correction
}

func (result ViewResult) String() string {
	code := ""
	if result.Correction != nil {
		code = result.Correction.Code
	}
	return fmt.Sprintf("Cloudflare Profile Setup View: kind=%s revision=%d change_set=%s correction=%s", result.Kind, result.Revision, result.ChangeSet, code)
}

func (result ViewResult) GoString() string { return result.String() }

func (module *Interface) View(request ViewRequest) ViewResult {
	if module == nil || module.ports.loadState == nil || module.ports.inspectSystemChanges == nil {
		return blocked("CLOUDFLARE-SETUP-DEPENDENCIES", "Cloudflare Profile Setup is unavailable", "a required Module is unavailable", "all seven owning Modules", "setup cannot establish complete authority", "Restore the required Module, then check again.")
	}
	inspection := module.ports.inspectSystemChanges()
	if inspection.Status == systemchanges.ChangeInProgress || inspection.Status == systemchanges.RecoveryRequired || inspection.Lock != systemchanges.LockReleased {
		result := blocked("CLOUDFLARE-SETUP-TRANSACTION", "Another transaction controls setup", string(inspection.Status), "a released System Changes lock and no unfinished Change Set", "Cloudflare Profile Setup never creates a second transaction path", "Resolve the current Change Set, then check again.")
		result.ChangeSet = inspection.CurrentChangeSet
		return result
	}
	loaded, err := module.ports.loadState(request.State)
	if err != nil || loaded.Status != state.Managed || loaded.Snapshot == nil {
		return blocked("CLOUDFLARE-SETUP-STATE", "Managed State is unavailable", "current State is not a proven Managed revision", "one exact Managed revision", "setup cannot start from unproved lineage", "Load current Managed State, then check again.")
	}
	profiles := loaded.Snapshot.DesiredState.ConnectionProfiles
	result := ViewResult{Revision: loaded.Snapshot.Revision}
	if allDeferred(profiles) {
		result.Kind = SetupAvailable
		return result
	}
	if allSetUp(profiles) {
		result.Kind = SetupComplete
		return result
	}
	result = blocked("CLOUDFLARE-SETUP-PARTIAL", "Connection Profile setup state is inconsistent", "some but not all deferred profiles are set up", "all five deferred profiles Not set up or all five set up", "partial Cloudflare Profile Setup is unsupported", "Inspect the current transaction and State evidence.")
	result.Revision = loaded.Snapshot.Revision
	return result
}

func allDeferred(profiles state.ConnectionProfiles) bool {
	return profiles.VLESSRealityVision.Lifecycle == state.ProfileEnabled && profiles.VLESSXHTTP.Lifecycle == state.ProfileNotSetUp && profiles.VLESSWebSocket.Lifecycle == state.ProfileNotSetUp && profiles.Hysteria2.Lifecycle == state.ProfileNotSetUp && profiles.TUIC.Lifecycle == state.ProfileNotSetUp && profiles.AnyTLS.Lifecycle == state.ProfileNotSetUp
}

func allSetUp(profiles state.ConnectionProfiles) bool {
	return profiles.VLESSRealityVision.Lifecycle != state.ProfileNotSetUp && profiles.VLESSXHTTP.Lifecycle != state.ProfileNotSetUp && profiles.VLESSWebSocket.Lifecycle != state.ProfileNotSetUp && profiles.Hysteria2.Lifecycle != state.ProfileNotSetUp && profiles.TUIC.Lifecycle != state.ProfileNotSetUp && profiles.AnyTLS.Lifecycle != state.ProfileNotSetUp
}

func blocked(code, problem, found, required, why, next string) ViewResult {
	return ViewResult{Kind: SetupBlocked, Correction: &Correction{Code: code, Problem: problem, Found: found, Required: required, WhyStopped: why, NextAction: next}}
}
