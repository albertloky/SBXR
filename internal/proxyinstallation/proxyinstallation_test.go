package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type controlledHost struct {
	inspection         hostadapter.Inspection
	preflight          hostadapter.Preflight
	ownership          []byte
	checkpoints        [][]byte
	operations         []hostadapter.Operation
	configuration      []byte
	configurationReads int
	enabled            bool
	active             bool
	listener           bool
	busy               bool
	lockHeld           bool
	lockChangesFacts   bool
	statusBusy         bool
	activeUnknown      bool
	hostUnknown        bool
	configUnknown      bool
	fails              map[hostadapter.Operation]bool
	failPublish        setupPhase
	latePublish        bool
	publishFailed      bool
	cancelOn           hostadapter.Operation
	cancel             context.CancelFunc
	removal            *hostadapter.RemovalInspection
	failRemovalPublish map[int]bool
	lateRemovalPublish map[int]bool
	finalizing         bool
	finalRemovalFails  int
}

type controlledHostFacts struct {
	inspection                                  hostadapter.Inspection
	preflight                                   hostadapter.Preflight
	ownership, configuration                    []byte
	operations                                  []hostadapter.Operation
	enabled, active, listener, busy, statusBusy bool
}

func (host *controlledHost) facts() controlledHostFacts {
	return controlledHostFacts{
		inspection: host.inspection, preflight: host.preflight,
		ownership: bytes.Clone(host.ownership), configuration: bytes.Clone(host.configuration), operations: slices.Clone(host.operations),
		enabled: host.enabled, active: host.active, listener: host.listener, busy: host.busy, statusBusy: host.statusBusy,
	}
}

func acceptedHost() *controlledHost { return &controlledHost{preflight: acceptedPreflightFacts()} }

func (host *controlledHost) Inspect(_ context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	if host.inspection.Resources == nil {
		resources := observedAbsent(requested)
		for index := range resources {
			switch resources[index].Name {
			case hostSetupSpec.OwnershipPath:
				resources[index].Present = len(host.ownership) > 0 && !host.finalizing
			case finalOwnershipPath:
				resources[index].Present = len(host.ownership) > 0 && host.finalizing
			}
		}
		return hostadapter.Inspection{Resources: resources, Complete: true}
	}
	return host.inspection
}

func (host *controlledHost) Preflight(_ context.Context, requested []hostadapter.Resource, _ []hostadapter.Destination) hostadapter.Preflight {
	if host.preflight.Resources == nil {
		host.preflight.Resources = observedAbsent(requested)
	}
	return host.preflight
}

func (host *controlledHost) ReadOwnership(name string) ([]byte, error) {
	if len(host.ownership) == 0 {
		return nil, os.ErrNotExist
	}
	if host.finalizing != (name == finalOwnershipPath) {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(host.ownership), nil
}

func (host *controlledHost) ReadConfiguration(_ context.Context, _ hostadapter.SetupSpec, expectedDigest string) ([]byte, error) {
	host.configurationReads++
	sum := sha256.Sum256(host.configuration)
	if hex.EncodeToString(sum[:]) != expectedDigest {
		return nil, errors.New("configuration mismatch")
	}
	return bytes.Clone(host.configuration), nil
}

func (host *controlledHost) MutationInProgress(string) (bool, bool) { return host.statusBusy, true }

func (host *controlledHost) PublishOwnership(_, _ string, expected, next []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	record, _ := decodeOwnership(next)
	if record.Direction == removalRequired && host.failRemovalPublish[record.RemovalCheckpoint] {
		delete(host.failRemovalPublish, record.RemovalCheckpoint)
		return errors.New("removal checkpoint failed")
	}
	if record.Phase == host.failPublish && !host.publishFailed && !host.latePublish {
		host.publishFailed = true
		return errors.New("checkpoint failed")
	}
	host.ownership = bytes.Clone(next)
	host.checkpoints = append(host.checkpoints, bytes.Clone(next))
	if record.Direction == removalRequired && host.lateRemovalPublish[record.RemovalCheckpoint] {
		delete(host.lateRemovalPublish, record.RemovalCheckpoint)
		return errors.New("late removal checkpoint failure")
	}
	if record.Phase == host.failPublish && !host.publishFailed && host.latePublish {
		host.publishFailed = true
		return errors.New("late checkpoint failure")
	}
	return nil
}

func (host *controlledHost) RemoveOwnership(_, _ string, expected []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	host.ownership = nil
	return nil
}

func (host *controlledHost) RemoveFinalOwnership(_, _, _ string, expected []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	if host.finalRemovalFails > 0 {
		host.finalRemovalFails--
		host.finalizing = true
		return errors.New("simulated process death")
	}
	host.finalizing = false
	return host.RemoveOwnership("", "", expected)
}

func (host *controlledHost) AcquireMutationLock(string) (*hostadapter.MutationLock, bool, error) {
	host.lockHeld = true
	if host.lockChangesFacts {
		host.preflight.MutationLockAvailable = false
	}
	return &hostadapter.MutationLock{}, host.busy, nil
}

func (host *controlledHost) AcquirePackageLocks() (*hostadapter.PackageLocks, bool, error) {
	return &hostadapter.PackageLocks{}, host.busy, nil
}

func (host *controlledHost) Apply(_ context.Context, input hostadapter.OperationInput) hostadapter.OperationResult {
	host.operations = append(host.operations, input.Operation)
	if host.fails[input.Operation] {
		return hostadapter.OperationResult{}
	}
	switch input.Operation {
	case hostadapter.InstallConfiguration:
		host.configuration = bytes.Clone(input.Body)
	case hostadapter.EnableService:
		host.enabled = true
	case hostadapter.StartService:
		host.active, host.listener = true, true
	case hostadapter.StopDisableService:
		host.enabled, host.active, host.listener = false, false, false
	}
	if input.Operation == host.cancelOn && host.cancel != nil {
		host.cancel()
	}
	return hostadapter.OperationResult{OK: true, Fact: "accepted"}
}

func (host *controlledHost) InspectRunning(_ context.Context, _ hostadapter.SetupSpec, _, ownership []byte, _, _ string) hostadapter.RunningInspection {
	if host.removal != nil {
		return host.removal.RunningInspection
	}
	prepared := false
	for _, operation := range host.operations {
		if operation == hostadapter.ValidateConfiguration {
			prepared = true
		}
	}
	fact := func(accepted bool) hostadapter.Observation {
		return hostadapter.Observation{Observed: true, Accepted: accepted}
	}
	active := fact(host.active)
	if host.activeUnknown {
		active = hostadapter.Observation{}
	}
	hostFact, configuration := fact(true), fact(prepared)
	if host.hostUnknown {
		hostFact = hostadapter.Observation{}
	}
	if host.configUnknown {
		configuration = hostadapter.Observation{}
	}
	return hostadapter.RunningInspection{
		OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", PublicIPv4: "8.8.8.8", Host: hostFact, PublicIPv4Matches: fact(true),
		Ownership: fact(bytes.Equal(ownership, host.ownership)), TransactionFilesAbsent: fact(true), APTKey: fact(prepared), APTSource: fact(prepared), Package: fact(prepared), Hold: fact(prepared),
		PackageIdentity: fact(prepared), Configuration: configuration, State: fact(prepared), Validation: fact(prepared), ServiceProvenance: fact(prepared),
		ServiceEnabled: fact(host.enabled), ServiceActive: active, Listener: fact(host.listener),
	}
}

func (host *controlledHost) InspectActivation(ctx context.Context, spec hostadapter.SetupSpec, source, ownership []byte, digest, publicIPv4 string, _ hostadapter.Destination) hostadapter.ActivationInspection {
	return hostadapter.ActivationInspection{RunningInspection: host.InspectRunning(ctx, spec, source, ownership, digest, publicIPv4), DestinationCompatible: true, ListenerAvailable: !host.listener}
}

func (host *controlledHost) InspectRemoval(ctx context.Context, spec hostadapter.SetupSpec, source, ownership []byte, digest, publicIPv4 string) hostadapter.RemovalInspection {
	if host.removal != nil {
		return *host.removal
	}
	accepted := hostadapter.Observation{Observed: true, Accepted: true}
	return hostadapter.RemovalInspection{
		RunningInspection: host.InspectRunning(ctx, spec, source, ownership, digest, publicIPv4),
		PackageLocks:      accepted, ConfigurationEntries: accepted, StateEntries: accepted,
		IdentityExclusive: accepted, ProcessExclusive: accepted, ServiceSafe: accepted,
	}
}

func observedAbsent(requested []hostadapter.Resource) []hostadapter.Resource {
	resources := make([]hostadapter.Resource, len(requested))
	copy(resources, requested)
	for index := range resources {
		resources[index].Observed = true
	}
	return resources
}

func acceptedPreflightFacts() hostadapter.Preflight {
	return hostadapter.Preflight{
		Resources: observedAbsent(footprint),
		OSID:      "ubuntu", OSVersion: "24.04", Architecture: "amd64", PublicIPv4: "8.8.8.8",
		ClockSynchronized: true, TCP443Available: true, MutationLockAvailable: true, PackageLocksAvailable: true,
		Destinations: []hostadapter.DestinationObservation{{Destination: hostadapter.Destination{Address: "microsoft.com:443", ServerName: "microsoft.com"}, DNS: true, TCP: true, TLS13: true, HTTP2: true, CertificateName: true}},
	}
}

type acceptedSingBox struct{}

func (acceptedSingBox) PrepareIdentity() (singboxadapter.Identity, error) {
	return singboxadapter.Identity{UUID: "11111111-2222-4333-8444-555555555555", PrivateKey: "private", PublicKey: "public", ShortID: "01020304"}, nil
}

func (acceptedSingBox) ValidIdentity(identity singboxadapter.Identity) bool {
	return identity.UUID == "11111111-2222-4333-8444-555555555555" && identity.PrivateKey == "private" && identity.PublicKey == "public" && identity.ShortID == "01020304"
}

func (adapter acceptedSingBox) EncodeServerConfiguration(identity singboxadapter.Identity, _, _ string) ([]byte, error) {
	if !adapter.ValidIdentity(identity) {
		return nil, errors.New("invalid identity")
	}
	return []byte(`{"inbound":"secret-safe-test-fixture"}` + "\n"), nil
}

func (adapter acceptedSingBox) EncodeClientConfiguration(_ []byte, publicIPv4 string) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"server":%q,"uuid":"11111111-2222-4333-8444-555555555555","public_key":"public","short_id":"01020304"}`+"\n", publicIPv4)), nil
}

type readyLifecycle struct{}

func (readyLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := testInstalledIdentity()
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

func (lifecycle readyLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.Status(ctx)
}

func testInstalledIdentity() softwarelifecycle.ReleaseIdentity {
	return softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
}

func (readyLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

type mismatchedLifecycle struct{ readyLifecycle }

func (mismatchedLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

type lockSensitiveLifecycle struct {
	readyLifecycle
	host *controlledHost
}

func (lifecycle *lockSensitiveLifecycle) Status(ctx context.Context) softwarelifecycle.Result {
	if lifecycle.host.lockHeld {
		return softwarelifecycle.Result{State: softwarelifecycle.UpdateInProgress, Code: softwarelifecycle.StatusUpdateInProgress}
	}
	return lifecycle.readyLifecycle.Status(ctx)
}

func (lifecycle *lockSensitiveLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.readyLifecycle.Status(ctx)
}

func TestOwnerCanReviewAndDeclineCleanSetup(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	review := installation.Review(t.Context(), StartSetupAction)

	wantActions := []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}
	if review.Version != "v3.0.0" || review.Status != NotSetUp || review.Result.Code != StatusNotSetUp || !reflect.DeepEqual(review.LegalActions, wantActions) || review.Prepared == nil {
		t.Fatalf("Review() = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, required := range []string{"Ubuntu 24.04 amd64", "8.8.8.8:443", "microsoft.com:443", "sing-box 1.13.19 amd64", "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", "24597120 bytes", "one generated Client Identity", "/var/lib/sbxr/proxy-ownership.json", "Infrastructure Secret", "will not change SSH, firewall, routing, or provider settings"} {
		if !strings.Contains(plan, required) {
			t.Errorf("plan missing %q:\n%s", required, plan)
		}
	}

	result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
	if result.Status != NotSetUp || result.Message != "No changes were made." || result.Code != ActionCancelled {
		t.Fatalf("Execute() = %#v", result)
	}
}

func TestSetupRevalidationAcceptsItsAcquiredMutationLock(t *testing.T) {
	host := acceptedHost()
	host.lockChangesFacts = true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var phases []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		phases = append(phases, progress.Phase)
	})

	if result.Status != Running || result.Code != SetupComplete || !slices.Contains(phases, string(hostadapter.ValidateConfiguration)) {
		t.Fatalf("Execute() = %#v, phases = %v", result, phases)
	}
}

func TestSetupRevalidatesInstalledReleaseWhileItOwnsTheSharedLock(t *testing.T) {
	host := acceptedHost()
	lifecycle := &lockSensitiveLifecycle{host: host}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var phases []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		phases = append(phases, progress.Phase)
	})

	if result.Status != Running || result.Code != SetupComplete || !slices.Contains(phases, string(hostadapter.ValidateConfiguration)) {
		t.Fatalf("Execute() = %#v, phases = %v", result, phases)
	}
}

func TestUnfinishedActionsRevalidateInstalledReleaseUnderTheirOwnedSharedLock(t *testing.T) {
	for _, test := range []struct {
		name     string
		finish   Action
		failures map[hostadapter.Operation]bool
		want     ResultCode
	}{
		{name: "cleanup", finish: FinishCleanupAction, failures: map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}, want: SetupCleanedUp},
		{name: "setup", finish: FinishSetupAction, failures: map[hostadapter.Operation]bool{hostadapter.StartService: true}, want: SetupComplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			host.fails = test.failures
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			start := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *start.Prepared, Approved, nil)
			host.fails = nil
			host.lockHeld = false
			restarted := newInstalledInterface(&lockSensitiveLifecycle{host: host}, host, acceptedSingBox{})
			finish := restarted.Review(t.Context(), test.finish)

			result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

			if result.Code != test.want {
				t.Fatalf("Execute() = %#v", result)
			}
		})
	}
}

func TestOwnerCanReviewAndDeclineCompleteRemovalWithoutMutation(t *testing.T) {
	for _, status := range []Status{NotSetUp, Running} {
		t.Run(string(status), func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			if status == Running {
				setup := installation.Review(t.Context(), StartSetupAction)
				if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
					t.Fatalf("setup = %#v", result)
				}
			}
			before := host.facts()

			review := installation.Review(t.Context(), CompleteRemovalAction)

			if review.Prepared == nil || review.Status != status {
				t.Fatalf("Review() = %#v", review)
			}
			plan := strings.Join(review.Plan, "\n")
			for _, required := range []string{
				"Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
				"Outside copies of the Client Configuration cannot be deleted by SBXR.",
				"SBXR preserves SSH, firewall, routing, forwarding, provider settings, shared package-manager state, and every unrelated resource.",
				"Exact confirmation required: REMOVE SBXR",
			} {
				if !strings.Contains(plan, required) {
					t.Errorf("plan missing %q:\n%s", required, plan)
				}
			}
			result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
			if result.Status != status || result.Message != "No changes were made." || result.Code != ActionCancelled || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("Execute() = %#v ownership=%q operations=%v", result, host.ownership, host.operations)
			}
			if reused := installation.Execute(t.Context(), *review.Prepared, Approved, nil); reused.Code != ActionRefused || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("reused Execute() = %#v ownership=%q operations=%v", reused, host.ownership, host.operations)
			}
			for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private", "secret-safe-test-fixture"} {
				if strings.Contains(plan, secret) {
					t.Errorf("plan disclosed %q", secret)
				}
			}
		})
	}
}

func TestCompleteRemovalReviewRefusesEveryUnsafeOwnedFact(t *testing.T) {
	tests := []struct {
		name   string
		change func(*hostadapter.RemovalInspection)
	}{
		{"changed bytes metadata links types or ownership", func(facts *hostadapter.RemovalInspection) { facts.Configuration.Accepted = false }},
		{"package identity or hold", func(facts *hostadapter.RemovalInspection) { facts.Package.Accepted = false }},
		{"package hold", func(facts *hostadapter.RemovalInspection) { facts.Hold.Accepted = false }},
		{"service identity", func(facts *hostadapter.RemovalInspection) { facts.ServiceProvenance.Accepted = false }},
		{"system identity", func(facts *hostadapter.RemovalInspection) { facts.Host.Accepted = false }},
		{"unknown directory entries", func(facts *hostadapter.RemovalInspection) { facts.ConfigurationEntries.Accepted = false }},
		{"unexpected state membership", func(facts *hostadapter.RemovalInspection) { facts.StateEntries.Accepted = false }},
		{"reused package identities", func(facts *hostadapter.RemovalInspection) { facts.IdentityExclusive.Accepted = false }},
		{"outside process use", func(facts *hostadapter.RemovalInspection) { facts.ProcessExclusive.Accepted = false }},
		{"outside listener use", func(facts *hostadapter.RemovalInspection) { facts.ServiceSafe.Accepted = false }},
		{"package lock conflict", func(facts *hostadapter.RemovalInspection) { facts.PackageLocks.Accepted = false }},
		{"unknown fact", func(facts *hostadapter.RemovalInspection) {
			facts.StateEntries.Observed = false
			facts.StateEntries.Accepted = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
				t.Fatalf("setup = %#v", result)
			}
			facts := host.InspectRemoval(t.Context(), hostSetupSpec, aptSourceBody, host.ownership, strings.Repeat("0", 64), "8.8.8.8")
			test.change(&facts)
			host.removal = &facts
			before := host.facts()

			review := installation.Review(t.Context(), CompleteRemovalAction)
			details := installation.Review(t.Context(), ViewDetailsAction)

			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck != "Complete removal preflight" || !strings.Contains(strings.Join(review.Details, "\n"), "Safe correction:") || !strings.Contains(strings.Join(details.Details, "\n"), "Safe correction:") || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("Review() = %#v ownership=%q operations=%v", review, host.ownership, host.operations)
			}
		})
	}
}

func TestCompleteRemovalAllowsStoppedOrDisabledServiceReduction(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.enabled, host.active, host.listener = false, false, false

	review := installation.Review(t.Context(), CompleteRemovalAction)

	if review.Prepared == nil {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestCompleteRemovalTreatsOnlyContractPermittedAbsenceAsAlreadyRemoved(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	accepted := installation.Review(t.Context(), CompleteRemovalAction)
	record, _ := decodeOwnership(host.ownership)
	facts := host.InspectRemoval(t.Context(), hostSetupSpec, aptSourceBody, host.ownership, record.ConfigurationSHA256, record.PublicIPv4)
	if accepted.Prepared == nil || !facts.TransactionFilesAbsent.Accepted {
		t.Fatalf("contract-permitted absent transaction resources = %#v", accepted)
	}
	host.removal = &hostadapter.RemovalInspection{}
	missingRequired := installation.Review(t.Context(), CompleteRemovalAction)
	if missingRequired.Prepared != nil || missingRequired.Result.Code != ActionRefused {
		t.Fatalf("unproved missing required resource = %#v", missingRequired)
	}
}

func TestApprovedCompleteRemovalRevalidatesBeforeTheExpectedCommitmentRefusal(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), CompleteRemovalAction)
	before := slices.Clone(host.operations)
	host.active = false
	changed := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if changed.Code != ActionRefused || changed.FailedCheck != "Prepared Action facts" || !reflect.DeepEqual(host.operations, before) {
		t.Fatalf("changed Execute() = %#v operations=%v", changed, host.operations)
	}

	host.active = true
	review = installation.Review(t.Context(), CompleteRemovalAction)
	unchanged := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if unchanged.Code != ActionRefused || unchanged.FailedCheck != "Complete removal commitment" || !reflect.DeepEqual(host.operations, before) {
		t.Fatalf("unchanged Execute() = %#v operations=%v", unchanged, host.operations)
	}
}

func TestApprovedCompleteRemovalCommitsThenFinishesForwardToNotInstalled(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	setupCheckpoints := len(host.checkpoints)

	review := installation.Review(t.Context(), CompleteRemovalAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Status != "" || result.Message != "SBXR is not installed." || result.Code != CompleteRemovalCompleted {
		t.Fatalf("Execute() = %#v", result)
	}
	if lifecycle.executable || lifecycle.installedRecord || len(host.ownership) != 0 {
		t.Fatalf("remaining lifecycle=%#v ownership=%q", lifecycle, host.ownership)
	}
	if len(host.checkpoints) == setupCheckpoints {
		t.Fatal("no durable removal checkpoint")
	}
	committed, ok := decodeOwnership(host.checkpoints[setupCheckpoints])
	if !ok || committed.Phase != removalCommitted || committed.Direction != removalRequired {
		t.Fatalf("first checkpoint = %#v ok=%v", committed, ok)
	}
}

func TestCompleteRemovalRestartsFromEveryDurableDeletionCheckpoint(t *testing.T) {
	for checkpoint := 0; checkpoint <= 11; checkpoint++ {
		t.Run(fmt.Sprintf("checkpoint-%d", checkpoint), func(t *testing.T) {
			host := acceptedHost()
			host.failRemovalPublish = map[int]bool{checkpoint: true}
			lifecycle := &controlledRemovalLifecycle{ready: true}
			installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
				t.Fatalf("setup = %#v", result)
			}

			removal := installation.Review(t.Context(), CompleteRemovalAction)
			interrupted := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
			if checkpoint == 0 {
				if interrupted.Status != Running || interrupted.Code != ActionRefused {
					t.Fatalf("pre-commit failure = %#v", interrupted)
				}
				removal = installation.Review(t.Context(), CompleteRemovalAction)
			} else {
				if interrupted.Status != RemovalIncomplete || interrupted.Code != RemovalNeedsCompletion {
					t.Fatalf("interrupted = %#v", interrupted)
				}
				restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
				status := restarted.Review(t.Context(), StatusAction)
				if status.Status != RemovalIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishRemovalAction, ViewDetailsAction}) {
					t.Fatalf("restart status = %#v", status)
				}
				removal = restarted.Review(t.Context(), FinishRemovalAction)
				installation = restarted
			}
			finished := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
			if finished.Code != CompleteRemovalCompleted || len(host.ownership) != 0 {
				t.Fatalf("finished = %#v ownership=%q", finished, host.ownership)
			}
		})
	}
}

func TestCompleteRemovalRestartsAfterProcessDeathDuringFinalOwnershipRemoval(t *testing.T) {
	host := acceptedHost()
	host.finalRemovalFails = 1
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	removal := installation.Review(t.Context(), CompleteRemovalAction)
	interrupted := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
	if interrupted.Status != RemovalIncomplete || !host.finalizing {
		t.Fatalf("interrupted = %#v finalizing=%t", interrupted, host.finalizing)
	}

	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if status.Status != RemovalIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishRemovalAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishRemovalAction)
	if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || len(host.ownership) != 0 {
		t.Fatalf("finish = %#v ownership=%q", result, host.ownership)
	}
}

func TestCompleteRemovalRecoversLateCheckpointIOAndManagedTermination(t *testing.T) {
	t.Run("late checkpoint I/O", func(t *testing.T) {
		host := acceptedHost()
		host.lateRemovalPublish = map[int]bool{4: true}
		lifecycle := &controlledRemovalLifecycle{ready: true}
		installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		setup := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
		removal := installation.Review(t.Context(), CompleteRemovalAction)
		if result := installation.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
			t.Fatalf("Execute() = %#v", result)
		}
	})

	t.Run("managed termination", func(t *testing.T) {
		host := acceptedHost()
		lifecycle := &controlledRemovalLifecycle{ready: true}
		installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		setup := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
		ctx, cancel := context.WithCancel(t.Context())
		host.cancelOn, host.cancel = hostadapter.RemovePackageHold, cancel
		removal := installation.Review(ctx, CompleteRemovalAction)
		interrupted := installation.Execute(ctx, *removal.Prepared, Approved, nil)
		if interrupted.Status != RemovalIncomplete || interrupted.FailedCheck != "Managed termination" {
			t.Fatalf("interrupted = %#v", interrupted)
		}
		restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishRemovalAction)
		if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
			t.Fatalf("finish = %#v", result)
		}
	})
}

type controlledRemovalLifecycle struct {
	ready, executable, installedRecord  bool
	failExecutable, failInstalledRecord bool
}

func (lifecycle *controlledRemovalLifecycle) Status(context.Context) softwarelifecycle.Result {
	if lifecycle.ready {
		identity := testInstalledIdentity()
		lifecycle.executable, lifecycle.installedRecord = true, true
		return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity}
	}
	return softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState}
}
func (lifecycle *controlledRemovalLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.Status(ctx)
}
func (*controlledRemovalLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (*controlledRemovalLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (*controlledRemovalLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (lifecycle *controlledRemovalLifecycle) InspectCompleteRemoval(context.Context, softwarelifecycle.ReleaseIdentity) softwarelifecycle.CompleteRemovalInspection {
	return softwarelifecycle.CompleteRemovalInspection{Valid: true, ExecutablePresent: lifecycle.executable, InstalledRecordPresent: lifecycle.installedRecord, StateDirectoryEmpty: true}
}
func (lifecycle *controlledRemovalLifecycle) RemoveCompleteRemovalExecutable(context.Context, softwarelifecycle.ReleaseIdentity) bool {
	if lifecycle.failExecutable {
		lifecycle.failExecutable = false
		return false
	}
	lifecycle.executable = false
	lifecycle.ready = false
	return true
}
func (lifecycle *controlledRemovalLifecycle) RemoveCompleteRemovalInstalledRecord(context.Context, softwarelifecycle.ReleaseIdentity) bool {
	if lifecycle.failInstalledRecord {
		lifecycle.failInstalledRecord = false
		return false
	}
	lifecycle.installedRecord = false
	return true
}

func TestApprovedSetupReachesLocallyVerifiedRunning(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var progress []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(event Progress) { progress = append(progress, event.Phase) })

	if string(result.Status) != "Running" || result.Message != "Proxy setup is complete and locally verified." || string(result.Code) != "PROXY-INSTALLATION-SETUP-COMPLETE" {
		t.Fatalf("Execute() = %#v", result)
	}
	wantPhases := []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase}
	if len(host.checkpoints) != len(wantPhases) {
		t.Fatalf("checkpoints=%d, want %d", len(host.checkpoints), len(wantPhases))
	}
	for index, body := range host.checkpoints {
		record, ok := decodeOwnership(body)
		if !ok || record.Phase != wantPhases[index] {
			t.Fatalf("checkpoint %d = %q, valid=%t", index, record.Phase, ok)
		}
	}
	if len(progress) != len(wantPhases) {
		t.Fatalf("progress = %v", progress)
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private"} {
		if bytes.Contains(host.ownership, []byte(secret)) {
			t.Fatalf("Ownership Record disclosed %q", secret)
		}
	}
}

func TestOwnerCanReviewDeclineAndDiscloseOneRunningClientConfiguration(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), ShowClientConfigurationAction)
	if review.Prepared == nil || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction, ShowClientConfigurationAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	warnings := strings.Join(review.Plan, "\n")
	for _, required := range []string{"contains a credential", "anyone with a copy can use the proxy", "terminal history or recording", "no client file", "outside copies survive Complete removal"} {
		if !strings.Contains(strings.ToLower(warnings), strings.ToLower(required)) {
			t.Errorf("warning missing %q:\n%s", required, warnings)
		}
	}
	if result := installation.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled {
		t.Fatalf("declined Execute() = %#v", result)
	}

	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	var configurations [][]byte
	reporter := func(progress Progress) {
		if len(progress.ClientConfiguration) > 0 {
			configurations = append(configurations, bytes.Clone(progress.ClientConfiguration))
		}
	}
	result := installation.Execute(t.Context(), *review.Prepared, Approved, reporter)
	if result.Status != Running || result.Code != ClientConfigurationDisclosed || len(configurations) != 1 || !json.Valid(configurations[0]) {
		t.Fatalf("approved Execute() = %#v", result)
	}
	configuration := string(configurations[0])
	for _, required := range []string{"8.8.8.8", "11111111-2222-4333-8444-555555555555", "public", "01020304"} {
		if !strings.Contains(configuration, required) {
			t.Errorf("configuration missing %q: %s", required, configuration)
		}
	}
	if strings.Contains(configuration, "private") || len(host.operations) != 11 {
		t.Fatalf("disclosure leaked private key or mutated host: configuration=%s operations=%v", configuration, host.operations)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "private") {
		t.Fatalf("disclosure result leaked the private key: %#v", result)
	}
	if reused := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); reused.Code != ActionRefused || len(configurations) != 1 {
		t.Fatalf("reused Execute() = %#v", reused)
	}
	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	if repeated := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); repeated.Code != ClientConfigurationDisclosed || len(configurations) != 2 {
		t.Fatalf("repeated Execute() = %#v configurations=%d", repeated, len(configurations))
	}
	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	if missingBoundary := installation.Execute(t.Context(), *review.Prepared, Approved, nil); missingBoundary.Code != ActionRefused || missingBoundary.FailedCheck != "Presentation boundary" || host.configurationReads != 2 {
		t.Fatalf("missing-boundary Execute() = %#v reads=%d", missingBoundary, host.configurationReads)
	}

	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	host.active = false
	if changed := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); changed.Code != ActionRefused || len(configurations) != 2 || host.configurationReads != 2 {
		t.Fatalf("changed-fact Execute() = %#v reads=%d", changed, host.configurationReads)
	}
}

func TestEveryPreCommitFailureCleansUpToNotSetUp(t *testing.T) {
	for _, operation := range []hostadapter.Operation{hostadapter.InstallAPTKey, hostadapter.InstallAPTSource, hostadapter.MaskService, hostadapter.InstallPackage, hostadapter.HoldPackage, hostadapter.CreateStateDirectory, hostadapter.InstallConfiguration, hostadapter.ValidateConfiguration} {
		t.Run(string(operation), func(t *testing.T) {
			host := acceptedHost()
			host.fails = map[hostadapter.Operation]bool{operation: true}
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			review := installation.Review(t.Context(), StartSetupAction)

			result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

			if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
				t.Fatalf("Execute() = %#v ownership=%q operations=%v", result, host.ownership, host.operations)
			}
		})
	}
}

func TestInterruptedCleanupExposesOnlyFinishCleanupAndResumes(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Status != SetupIncomplete || result.Code != SetupNeedsCleanup || len(host.ownership) == 0 {
		t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
	}

	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if !reflect.DeepEqual(status.LegalActions, []Action{FinishCleanupAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishCleanupAction)
	host.fails = nil
	result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
		t.Fatalf("Finish cleanup = %#v ownership=%q", result, host.ownership)
	}
}

func TestCommittedSetupNeverRollsBackAndFinishSetupResumes(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Status != SetupIncomplete || result.Code != SetupNeedsCompletion {
		t.Fatalf("Execute() = %#v", result)
	}
	for _, operation := range host.operations {
		if operation == hostadapter.RemovePackage || operation == hostadapter.RemoveAPTSource || operation == hostadapter.RemoveAPTKey {
			t.Fatalf("committed setup rolled back through %q", operation)
		}
	}
	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if !reflect.DeepEqual(status.LegalActions, []Action{FinishSetupAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishSetupAction)
	host.fails = nil
	result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Status != Running || result.Code != SetupComplete {
		t.Fatalf("Finish setup = %#v", result)
	}
}

func TestLateActivationCheckpointFailureContinuesForward(t *testing.T) {
	host := acceptedHost()
	host.failPublish, host.latePublish = activationCommitted, true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)

	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Status != Running || result.Code != SetupComplete {
		t.Fatalf("Execute() = %#v", result)
	}
	for _, operation := range host.operations {
		if operation == hostadapter.RemovePackage {
			t.Fatal("late committed write triggered rollback")
		}
	}
}

func TestEveryCheckpointIOFailureKeepsTheLegalRecoveryDirection(t *testing.T) {
	for _, phase := range []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s late=%t", phase, late), func(t *testing.T) {
				host := acceptedHost()
				host.failPublish, host.latePublish = phase, late
				installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
				review := installation.Review(t.Context(), StartSetupAction)
				result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

				switch {
				case phase == ownershipRecorded && !late:
					if result.Code != ActionRefused || len(host.ownership) != 0 {
						t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
					}
				case phaseAtOrAfter(phase, serviceEnabled) && !late:
					if result.Status != SetupIncomplete || result.Code != SetupNeedsCompletion {
						t.Fatalf("Execute() = %#v", result)
					}
					host.failPublish = ""
					restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
					finish := restarted.Review(t.Context(), FinishSetupAction)
					if finish.Prepared == nil {
						t.Fatalf("Finish setup Review() = %#v", finish)
					}
					if result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SetupComplete {
						t.Fatalf("Finish setup Execute() = %#v", result)
					}
				case phaseAtOrAfter(phase, activationCommitted) && late:
					if result.Status != Running || result.Code != SetupComplete {
						t.Fatalf("Execute() = %#v", result)
					}
				default:
					if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
						t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
					}
				}
			})
		}
	}
}

func TestRestartDerivesStatusAndOnlyLegalFinishingActionFromEveryCheckpoint(t *testing.T) {
	source := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, source, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *review.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("fixture setup = %#v", result)
	}
	for _, body := range source.checkpoints {
		record, ok := decodeOwnership(body)
		if !ok {
			t.Fatalf("invalid fixture checkpoint: %q", body)
		}
		host := acceptedHost()
		host.ownership = bytes.Clone(body)
		if record.Phase == runningPhase {
			host.operations = []hostadapter.Operation{hostadapter.ValidateConfiguration}
			host.enabled, host.active, host.listener = true, true, true
		}
		status := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), StatusAction)
		switch {
		case record.Phase == runningPhase:
			if status.Status != Running || status.Result.Code != SetupComplete {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		case phaseAtOrAfter(record.Phase, activationCommitted):
			if status.Status != SetupIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishSetupAction, ViewDetailsAction}) {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		default:
			if status.Status != SetupIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishCleanupAction, ViewDetailsAction}) {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		}
	}
}

func TestStatusDerivesChangeInProgressFromTheMutationLock(t *testing.T) {
	host := acceptedHost()
	host.statusBusy = true
	status := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), StatusAction)
	if status.Status != ChangeInProgress || status.Result.Code != StatusChangeInProgress || !reflect.DeepEqual(status.LegalActions, []Action{ViewDetailsAction}) {
		t.Fatalf("Review() = %#v", status)
	}
}

func TestManagedTerminationStopsAfterTheCurrentDurableCheckpoint(t *testing.T) {
	tests := []struct {
		name     string
		cancelOn hostadapter.Operation
		fail     hostadapter.Operation
		code     ResultCode
	}{
		{"pre-commit setup", hostadapter.InstallPackage, "", SetupNeedsCleanup},
		{"committed setup", hostadapter.EnableService, "", SetupNeedsCompletion},
		{"cleanup", hostadapter.RemovePackageArtifact, hostadapter.HoldPackage, SetupNeedsCleanup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			host := acceptedHost()
			host.cancelOn, host.cancel = test.cancelOn, cancel
			if test.fail != "" {
				host.fails = map[hostadapter.Operation]bool{test.fail: true}
			}
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			review := installation.Review(ctx, StartSetupAction)
			result := installation.Execute(ctx, *review.Prepared, Approved, nil)
			if result.Status != SetupIncomplete || result.Code != test.code || result.FailedCheck != "Managed termination" {
				t.Fatalf("Execute() = %#v operations=%v", result, host.operations)
			}
		})
	}
}

func TestFinishingActionsRevalidateAuthorityAndActivationFactsBeforeMutation(t *testing.T) {
	t.Run("changed cleanup authority", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishCleanupAction)
		record, _ := decodeOwnership(host.ownership)
		record.CleanupCheckpoint++
		host.ownership = ownershipBytes(record)
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})

	t.Run("changed cleanup host facts", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishCleanupAction)
		host.inspection = hostadapter.Inspection{Resources: observedAbsent(footprint), Complete: true}
		host.inspection.Resources[2].Present = true
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})

	t.Run("changed activation facts", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishSetupAction)
		host.fails = nil
		host.listener = true
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})
}

func TestExecuteRefusesLockConflictBeforeMutation(t *testing.T) {
	host := acceptedHost()
	host.busy = true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)

	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Code != ActionRefused || result.FailedCheck != "SBXR mutation lock" || len(host.operations) != 0 || len(host.ownership) != 0 {
		t.Fatalf("Execute() = %#v operations=%v ownership=%q", result, host.operations, host.ownership)
	}
}

func TestFreshInspectionReportsConflictingFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	resources[3].Present = true
	host := &controlledHost{inspection: hostadapter.Inspection{Resources: resources, Complete: true}, preflight: acceptedPreflightFacts()}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || review.Result.Message != "A proxy problem was detected. View details before continuing." || !reflect.DeepEqual(review.LegalActions, []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestFreshInspectionReportsUnknownFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	for index := range resources {
		if resources[index].Name == "/etc/sing-box" {
			resources[index].Observed = false
		}
	}
	installation := newInstalledInterface(readyLifecycle{}, &controlledHost{inspection: hostadapter.Inspection{Resources: resources}}, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || !strings.Contains(strings.Join(review.Details, "\n"), "/etc/sing-box could not be inspected") {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestExecuteRefusesUntrustedPreparedAuthority(t *testing.T) {
	newInstallation := func(host *controlledHost) Interface {
		return newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	}
	assertRefused := func(t *testing.T, result Result, failedCheck string) {
		t.Helper()
		if result.Code != ActionRefused || result.FailedCheck != failedCheck {
			t.Fatalf("Execute() = %#v", result)
		}
	}

	t.Run("invalid", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		assertRefused(t, newInstallation(host).Execute(t.Context(), PreparedAction{}, Approved, nil), "Prepared Action")
	})

	t.Run("mismatched module", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		first, second := newInstallation(host), newInstallation(host)
		prepared := first.Review(t.Context(), StartSetupAction).Prepared
		assertRefused(t, second.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("stale after a later review", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Review(t.Context(), StatusAction)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("reused", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Execute(t.Context(), *prepared, Declined, nil)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("changed facts", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		host.preflight.PublicIPv4 = "1.1.1.1"
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action facts")
	})
}

func TestReviewRefusesEveryFailedSetupPreflight(t *testing.T) {
	tests := []struct {
		name   string
		failed string
		change func(*hostadapter.Preflight)
	}{
		{"changed footprint", "Clean proxy footprint", func(facts *hostadapter.Preflight) {
			facts.Resources[3].Present = true
		}},
		{"unsupported Ubuntu", "Ubuntu version", func(facts *hostadapter.Preflight) { facts.OSVersion = "22.04" }},
		{"unsupported architecture", "Architecture", func(facts *hostadapter.Preflight) { facts.Architecture = "arm64" }},
		{"reserved IPv4", "Public IPv4", func(facts *hostadapter.Preflight) { facts.PublicIPv4 = "203.0.113.7" }},
		{"unsynchronized clock", "Synchronized clock", func(facts *hostadapter.Preflight) { facts.ClockSynchronized = false }},
		{"occupied port", "Public TCP port 443", func(facts *hostadapter.Preflight) { facts.TCP443Available = false }},
		{"busy mutation lock", "SBXR mutation lock", func(facts *hostadapter.Preflight) { facts.MutationLockAvailable = false }},
		{"busy package locks", "Ubuntu package locks", func(facts *hostadapter.Preflight) { facts.PackageLocksAvailable = false }},
		{"no compatible destination", "REALITY destination", func(facts *hostadapter.Preflight) { facts.Destinations[0].HTTP2 = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := acceptedPreflightFacts()
			test.change(&facts)
			installation := newInstalledInterface(readyLifecycle{}, &controlledHost{preflight: facts}, acceptedSingBox{})

			review := installation.Review(t.Context(), StartSetupAction)

			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck != test.failed || review.Result.Correction == "" {
				t.Fatalf("Review() = %#v", review)
			}
		})
	}
}

func TestReviewReturnsSecretSafeNotSetUpDetails(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0 " + strings.Repeat("a", 40) + " " + strings.Repeat("b", 64),
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Not set up",
		"Required unfinished direction: none",
		"Mutation lock: Available",
		"Ownership Record: Absent",
		"Proxy Package Identity: https://deb.sagernet.org/; signing-key bytes SHA-256 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1; sing-box 1.13.19 amd64; DEB 24597120 bytes; DEB SHA-256 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf; Absent",
		"Package hold: Absent",
		"Protected configuration identity: Absent",
		"Packaged validation result: Not applicable",
		"systemd unit provenance: Absent",
		"Service enabled: No",
		"Service active: No",
		"Expected public listener ownership: Absent",
		"Client Identity: Absent",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private"} {
		if strings.Contains(details, secret) {
			t.Errorf("details disclose %q", secret)
		}
	}
}

func TestViewDetailsReportsFreshActiveMutationCheckpoint(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.statusBusy = true

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	if review.Status != ChangeInProgress || review.Result.Code != StatusChangeInProgress || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	for _, required := range []string{
		"Proxy Installation Status: Change in progress",
		"Mutation lock: In use",
		"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
		"Required unfinished direction: none",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestViewDetailsExplainsTheRequiredUnfinishedDirection(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != SetupIncomplete {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Proxy Installation Status: Setup incomplete",
		"Required unfinished direction: setup required",
		"Ownership Record: Valid; phase Service enabled; cleanup checkpoint 0",
		"Public endpoint: 8.8.8.8:443",
		"Client Identity: Present",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestViewDetailsExplainsCleanupRequired(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != SetupIncomplete {
		t.Fatalf("setup = %#v", result)
	}

	details := strings.Join(installation.Review(t.Context(), ViewDetailsAction).Details, "\n")
	for _, required := range []string{"Proxy Installation Status: Setup incomplete", "Required unfinished direction: cleanup required", "Ownership Record: Valid; phase Service masked"} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestReviewReturnsCompleteSecretSafeRunningDetails(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	record, _ := decodeOwnership(host.ownership)
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0 " + strings.Repeat("a", 40) + " " + strings.Repeat("b", 64),
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Running",
		"Required unfinished direction: none",
		"Mutation lock: Available",
		"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
		"Proxy Package Identity: https://deb.sagernet.org/; signing-key bytes SHA-256 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1; sing-box 1.13.19 amd64; DEB 24597120 bytes; DEB SHA-256 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"Package hold: Present",
		"Protected configuration identity: /etc/sing-box/config.json SHA-256 " + record.ConfigurationSHA256 + "; Matches",
		"Packaged validation result: Accepted",
		"systemd unit provenance: /lib/systemd/system/sing-box.service from sing-box; Matches",
		"Service enabled: Yes",
		"Service active: Yes",
		"Expected public listener ownership: sing-box on TCP 8.8.8.8:443; Matches",
		"Public endpoint: 8.8.8.8:443",
		"Selected destination: microsoft.com:443",
		"Server name: microsoft.com",
		"Client Identity: Present",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private", "secret-safe-test-fixture"} {
		if strings.Contains(details, secret) {
			t.Errorf("details disclose %q", secret)
		}
	}
}

func TestReviewReportsRunningDriftWithExactSafeCorrection(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.active = false

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	for _, required := range []string{
		"Detected mismatch: sing-box.service is not active",
		"Safe correction: Start sing-box.service from the exact installed package, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, forbidden := range []string{"generic repair", "adopt", "force", "override"} {
		if strings.Contains(strings.ToLower(details), forbidden) {
			t.Errorf("details contain forbidden generic action %q:\n%s", forbidden, details)
		}
	}
}

func TestReviewDistinguishesUnavailableObservationFromConfirmedDrift(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.active = false
	host.activeUnknown = true
	host.hostUnknown = true
	host.configUnknown = true

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Ubuntu: Unavailable",
		"Service active: Unavailable",
		"Client Identity: Absent",
		"Detected mismatch: service active state could not be inspected",
		"Safe correction: Restore working systemctl active-state inspection for sing-box.service, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	if strings.Contains(details, "sing-box.service is not active") || strings.Contains(details, "Start sing-box.service") {
		t.Fatalf("unavailable observation reported as confirmed drift:\n%s", details)
	}
	if strings.Contains(details, "Client Identity: Unavailable") {
		t.Fatalf("Client Identity escaped its binary vocabulary:\n%s", details)
	}
}

func TestValidOwnershipIdentityMismatchKeepsKnownDetails(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	for _, test := range []struct {
		name       string
		busy       bool
		status     Status
		lock       string
		correction string
	}{
		{"idle", false, ProblemDetected, "Available", "Restore the exact installed SBXR Release Identity"},
		{"active mutation", true, ChangeInProgress, "In use", "Wait for the active atomic mutation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host.statusBusy = test.busy
			review := newInstalledInterface(mismatchedLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), ViewDetailsAction)
			details := strings.Join(review.Details, "\n")
			if review.Status != test.status {
				t.Fatalf("status = %s, want %s", review.Status, test.status)
			}
			for _, required := range []string{
				"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
				"Mutation lock: " + test.lock,
				"Public endpoint: 8.8.8.8:443",
				"Selected destination: microsoft.com:443",
				"Server name: microsoft.com",
				test.correction,
			} {
				if !strings.Contains(details, required) {
					t.Errorf("details missing %q:\n%s", required, details)
				}
			}
			if strings.Contains(details, "Invalid or unsafe") {
				t.Fatalf("valid Ownership Record was reported invalid:\n%s", details)
			}
		})
	}
}

func TestViewDetailsKeepsOwnershipProblemsCompleteAndSecretSafe(t *testing.T) {
	host := acceptedHost()
	host.ownership = []byte(`{"client_uuid":"11111111-2222-4333-8444-555555555555"}`)
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0",
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Problem detected",
		"Mutation lock: Available",
		"Ownership Record: Invalid or unsafe; checkpoint unavailable",
		"Proxy Package Identity:",
		"Public endpoint: Unavailable",
		"Selected destination: Unavailable",
		"Server name: Unavailable",
		"Client Identity: Absent",
		"Safe correction: Restore the exact root-owned schema-1 Ownership Record from the active Release Identity, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	if strings.Contains(details, "11111111-2222-4333-8444-555555555555") {
		t.Fatalf("details disclosed invalid record bytes:\n%s", details)
	}
}

func TestActiveMutationDetailsStayCompleteWhenOwnershipIsInvalid(t *testing.T) {
	host := acceptedHost()
	host.statusBusy = true
	host.ownership = []byte(`not-json`)
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Change in progress",
		"Mutation lock: In use",
		"Ownership Record: Invalid or unsafe; checkpoint unavailable",
		"Proxy Package Identity:",
		"Public endpoint: Unavailable",
		"Safe correction: Wait for the active atomic mutation and checkpoint to finish, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestReviewRefusesIllegalActionsWithoutAuthority(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	illegal := installation.Review(t.Context(), FinishSetupAction)
	if illegal.Result.Code != ActionRefused || illegal.Result.FailedCheck != "Legal action" || illegal.Prepared != nil {
		t.Fatalf("Finish setup Review() = %#v", illegal)
	}
}
