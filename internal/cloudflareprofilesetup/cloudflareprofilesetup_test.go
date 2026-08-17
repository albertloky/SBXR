package cloudflareprofilesetup

import (
	"errors"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestViewReportsAvailableCompleteAndBlockedWithoutAcceptingSecrets(t *testing.T) {
	module := newWithPorts(testPorts{
		loadState: func(state.LoadRequest) (state.Result, error) {
			return state.Result{Status: state.Managed, Snapshot: &state.Snapshot{Revision: 7, DesiredState: revisionOneProfiles()}}, nil
		},
		inspectSystemChanges: func() systemchanges.Inspection {
			return systemchanges.Inspection{Status: systemchanges.Managed, Lock: systemchanges.LockReleased}
		},
	})

	available := module.View(ViewRequest{})
	if available.Kind != SetupAvailable || available.Revision != 7 || available.Correction != nil {
		t.Fatalf("available View = %+v", available)
	}
	if strings.Contains(available.String(), "token") {
		t.Fatalf("View rendered Infrastructure Secret vocabulary: %s", available)
	}

	module.ports.loadState = func(state.LoadRequest) (state.Result, error) {
		desired := revisionOneProfiles()
		desired.ConnectionProfiles.VLESSXHTTP.Lifecycle = state.ProfileEnabled
		desired.ConnectionProfiles.VLESSWebSocket.Lifecycle = state.ProfileEnabled
		desired.ConnectionProfiles.Hysteria2.Lifecycle = state.ProfileEnabled
		desired.ConnectionProfiles.TUIC.Lifecycle = state.ProfileEnabled
		desired.ConnectionProfiles.AnyTLS.Lifecycle = state.ProfileEnabled
		return state.Result{Status: state.Managed, Snapshot: &state.Snapshot{Revision: 8, DesiredState: desired}}, nil
	}
	complete := module.View(ViewRequest{})
	if complete.Kind != SetupComplete || complete.Revision != 8 {
		t.Fatalf("complete View = %+v", complete)
	}

	module.ports.inspectSystemChanges = func() systemchanges.Inspection {
		return systemchanges.Inspection{Status: systemchanges.ChangeInProgress, CurrentChangeSet: "change-0009", Checkpoint: systemchanges.PreparedCheckpoint, Lock: systemchanges.LockHeld}
	}
	blocked := module.View(ViewRequest{})
	if blocked.Kind != SetupBlocked || blocked.ChangeSet != "change-0009" || blocked.Correction == nil {
		t.Fatalf("blocked View = %+v", blocked)
	}

	module.ports.loadState = func(state.LoadRequest) (state.Result, error) { return state.Result{}, errors.New("marker-secret") }
	failed := module.View(ViewRequest{})
	if failed.Correction == nil || strings.Contains(failed.String(), "marker-secret") {
		t.Fatalf("failed View leaked raw State error: %+v", failed)
	}
}

func TestApplyCallsSystemChangesExactlyOnceAndConsumesApproval(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedSetup{changeSet: "setup-0008", revision: 8, starting: strings.Repeat("a", 64), candidate: strings.Repeat("b", 64), identity: "cloudflare-setup-0123456789abcdef01234567", sha256: strings.Repeat("c", 64)}
	for _, test := range []struct {
		outcome systemchanges.ApplyOutcome
		want    ApplyKind
	}{{systemchanges.Completed, ApplyComplete}, {systemchanges.RollbackSucceeded, ApplyRolledBack}, {systemchanges.RecoveryRequiredOutcome, ApplyRecoveryRequired}} {
		calls := 0
		module := &Interface{dependencies: Dependencies{SystemChanges: SystemChangesDependency{Apply: func(change *systemchanges.ChangeSet) systemchanges.ApplyResult {
			calls++
			if change == nil || change.Identity() != prepared.changeSet {
				t.Fatalf("Change Set = %+v", change)
			}
			return systemchanges.ApplyResult{Outcome: test.outcome}
		}}}}
		plan := &Plan{
			identity: prepared.identity, sha256: prepared.sha256, volatileSHA256: strings.Repeat("d", 64), changeSet: prepared.changeSet,
			starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: prepared.starting}, prepared: prepared,
			steps: []systemchanges.Step{step}, checks: []systemchanges.Check{
				{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SETUP-PRE"},
				{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SETUP-POST"},
			},
			disk:         systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
			confirmation: func(systemchanges.CloudflareSetupConfirmationRequest) bool { return true },
		}
		approval := Approval{cell: &approvalCell{plan: plan}}
		if result := module.Apply(approval); result.Kind != test.want || result.Operation != prepared.changeSet || calls != 1 {
			t.Fatalf("Apply = %+v calls=%d", result, calls)
		}
		if reused := module.Apply(approval); reused.Kind != ApplyRefused || calls != 1 {
			t.Fatalf("reused Apply = %+v calls=%d", reused, calls)
		}
	}
}

type preparedSetup struct {
	changeSet, starting, candidate, identity, sha256 string
	revision                                         uint64
}

func (preparedSetup) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }
func (p preparedSetup) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return p.changeSet, p.revision, p.starting, p.candidate, p.identity, p.sha256, true
}

func revisionOneProfiles() state.DesiredState {
	return state.DesiredState{ConnectionProfiles: state.ConnectionProfiles{
		VLESSRealityVision: state.VLESSRealityVision{Lifecycle: state.ProfileEnabled},
		VLESSXHTTP:         state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp},
		VLESSWebSocket:     state.VLESSWebSocket{Lifecycle: state.ProfileNotSetUp},
		Hysteria2:          state.Hysteria2{Lifecycle: state.ProfileNotSetUp},
		TUIC:               state.TUIC{Lifecycle: state.ProfileNotSetUp},
		AnyTLS:             state.AnyTLS{Lifecycle: state.ProfileNotSetUp},
	}}
}
