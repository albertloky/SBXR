package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type nativeSingBoxQualification struct{ binary string }

func (validator nativeSingBoxQualification) ValidateSingBox(ctx context.Context, document io.Reader) error {
	command := exec.CommandContext(ctx, validator.binary, "check", "-c", "/dev/stdin")
	command.Stdin = document
	return command.Run()
}

var controlledRevisionOneOnce sync.Once
var controlledRevisionOneRoot string
var controlledRevisionOneLoad state.LoadRequest
var controlledRevisionOneErr error

func controlledRevisionOneCopy(t *testing.T) (string, state.LoadRequest) {
	t.Helper()
	controlledRevisionOneOnce.Do(func() {
		controlledRevisionOneRoot, controlledRevisionOneErr = os.MkdirTemp("", "sbxr-controlled-revision-one-")
		if controlledRevisionOneErr == nil {
			controlledRevisionOneErr = os.Chmod(controlledRevisionOneRoot, 0o700)
		}
		if controlledRevisionOneErr == nil {
			controlledRevisionOneLoad, controlledRevisionOneErr = installation.RunControlledInstallationAt(t.Context(), controlledRevisionOneRoot)
		}
	})
	if controlledRevisionOneErr != nil {
		t.Fatal(controlledRevisionOneErr)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(controlledRevisionOneRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == controlledRevisionOneRoot {
			return err
		}
		target, relativeErr := filepath.Rel(controlledRevisionOneRoot, path)
		if relativeErr != nil {
			return relativeErr
		}
		target = filepath.Join(root, target)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(target, body, info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
	return root, controlledRevisionOneLoad
}

func TestControlledStagedOnboardingChainsRevisionOneToTwo(t *testing.T) {
	root, load := controlledRevisionOneCopy(t)
	if err := runControlledCloudflareProfileSetup(t.Context(), root, load); err != nil {
		t.Fatal(err)
	}
}

func TestControlledStagedOnboardingSecretScanKeepsMarkersOnlyInOwningArtifacts(t *testing.T) {
	markers := softwarelifecycle.ControlledStagedOnboardingSecretMarkers()
	markerText := make([]string, len(markers))
	for index, marker := range markers {
		markerText[index] = string(marker.Value)
	}
	if err := ownerconsole.QualifyControlledStagedOnboardingTerminalSecretSafe(t.Context(), markerText); err != nil {
		t.Fatal(err)
	}
	root, load := controlledRevisionOneCopy(t)
	surfaces := map[string][]byte{}
	options := controlledSetupOptions{confirm: true, scanSurface: func(name string, body []byte) error {
		surfaces[name] = append(surfaces[name], body...)
		return nil
	}}
	if err := runControlledCloudflareProfileSetupWithOptions(t.Context(), root, load, options); err != nil {
		t.Fatal(err)
	}
	failureRoot, failureLoad := controlledRevisionOneCopy(t)
	options.failAction = systemchanges.CloudflareDNSCreate
	if err := runControlledCloudflareProfileSetupWithOptions(t.Context(), failureRoot, failureLoad, options); err == nil {
		t.Fatal("controlled post-checkpoint marker scan did not reach failure")
	}
	journalRoot := filepath.Join(failureRoot, "var/lib/sbxr/transactions/cloudflare-profile-setup-0002")
	if err := filepath.Walk(journalRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		body, err := os.ReadFile(path)
		if err == nil {
			surfaces["journal"] = append(surfaces["journal"], body...)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stateModule := statefilesystem.NewAt(failureRoot)
	loaded, err := stateModule.Load(failureLoad)
	if err != nil || loaded.Snapshot == nil {
		t.Fatal("controlled recovery State unavailable")
	}
	_, stateSHA, _, _, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid {
		t.Fatal("controlled recovery lineage unavailable")
	}
	base := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 1, StateSHA256: stateSHA, LastChangeSet: string(loaded.Snapshot.LastCompletedChangeSet), Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	observed, err := systemubuntu.RecoveryHealthObservation(failureRoot, func() (systemchanges.Observation, error) { return base, nil })
	if err != nil {
		t.Fatal(err)
	}
	recoveryAdapter, err := systemubuntu.NewControlledManagedProviderAdapter(failureRoot, observed, stateModule, func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error) {
		return systemchanges.StepEvidence{}, errors.New("controlled recovery provider refusal")
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.New(recoveryAdapter)
	surfaces["inspect"] = []byte(fmt.Sprintf("%+v", recovery.Inspect()))
	surfaces["recovery"] = []byte(fmt.Sprintf("%+v", recovery.Recover()))
	ownerChecks := []struct {
		path    string
		pattern string
	}{
		{path: "./internal/installation", pattern: "^(TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan|TestInstallationInterfaceOwnsRootRuntimeTransactionOutcomes)$"},
		{path: "./internal/cloudflaretunnel", pattern: "^(TestHTTPAPIParsesOfficialShapesWithScopedAuthenticationAndPagination|TestHTTPAPIRefusesMalformedAmbiguousAndUnsafeResponses|TestHTTPMutationAPIRetrievesTheCurrentTunnelTokenOnlyThroughTheDocumentedEndpoint|TestViewFailsClosedWithoutLeakingAuthority)$"},
		{path: "./internal/cloudflareprofilesetup", pattern: "^TestPlanComposesSevenFreshOwningModuleResults$"},
		{path: "./internal/state", pattern: "^TestPrepareCommitValidatesCandidateAndSerializesLeastPrivilegeMaterial$"},
		{path: "./internal/subscriptionserving", pattern: "^TestServeNeverExposesSecretOrOperationalMarkers$"},
	}
	for _, check := range ownerChecks {
		command := exec.CommandContext(t.Context(), "go", "test", check.path, "-run", check.pattern, "-count=1", "-v")
		command.Dir = filepath.Clean(filepath.Join("..", ".."))
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatal("controlled owning-Module marker check unavailable")
		}
		surfaces["test"] = append(surfaces["test"], output...)
	}
	for _, marker := range markers {
		if bytes.Count(surfaces["test"], []byte(marker.Proof)) == 0 {
			t.Fatal("controlled owning-Module marker class is unproved")
		}
	}
	required := []string{"transaction", "diagnostic", "http", "apply", "typed-error", "journal", "inspect", "recovery", "test"}
	for _, name := range required {
		for _, marker := range markers {
			if bytes.Contains(surfaces[name], marker.Value) {
				t.Fatalf("controlled %s surface exposed %s", name, marker.Class)
			}
		}
	}
	if err := softwarelifecycle.QualifyControlledStagedOnboardingSurfaces(surfaces, required); err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		for _, surface := range required {
			leaked := make(map[string][]byte, len(surfaces))
			for name, body := range surfaces {
				leaked[name] = append([]byte(nil), body...)
			}
			leaked[surface] = append(leaked[surface], marker.Value...)
			if err := softwarelifecycle.QualifyControlledStagedOnboardingSurfaces(leaked, required); err == nil {
				t.Fatalf("%s marker was accepted on %s", marker.Class, surface)
			}
		}
	}
}

func TestControlledStagedOnboardingPassesPinnedNativeSingBox(t *testing.T) {
	binary, version := os.Getenv("SBXR_SING_BOX_BIN"), os.Getenv("SBXR_SING_BOX_VERSION")
	if binary == "" || version == "" {
		t.Skip("set SBXR_SING_BOX_BIN and SBXR_SING_BOX_VERSION to the pinned sing-box validator")
	}
	output, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "sing-box version "+version) {
		t.Fatalf("pinned sing-box version %q is unavailable", version)
	}
	root, load := controlledRevisionOneCopy(t)
	if err := runControlledCloudflareProfileSetupWithOptions(t.Context(), root, load, controlledSetupOptions{confirm: true, singBoxValidator: nativeSingBoxQualification{binary: binary}}); err != nil {
		t.Fatal(err)
	}
}

func TestControlledCloudflareProfileSetupFailureBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		options controlledSetupOptions
		journal bool
	}{
		{name: "pre-checkpoint rollback", options: controlledSetupOptions{confirm: false}},
		{name: "post-checkpoint recovery required", options: controlledSetupOptions{confirm: true, failAction: systemchanges.CloudflareDNSCreate}, journal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, load := controlledRevisionOneCopy(t)
			setupErr := runControlledCloudflareProfileSetupWithOptions(t.Context(), root, load, test.options)
			if setupErr == nil {
				t.Fatal("controlled setup failure was not reported")
			}
			if test.journal {
				var applyErr *controlledSetupApplyError
				if !errors.As(setupErr, &applyErr) || applyErr.transaction.Outcome != systemchanges.RecoveryRequiredOutcome {
					t.Fatalf("post-checkpoint outcome = %v", setupErr)
				}
			}
			loaded, err := statefilesystem.NewAt(root).Load(load)
			if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 {
				t.Fatalf("revision 1 rollback = (%+v, %v)", loaded, err)
			}
			_, journalErr := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/cloudflare-profile-setup-0002/journal.jsonl"))
			if test.journal == errors.Is(journalErr, os.ErrNotExist) {
				t.Fatalf("durable recovery journal error = %v", journalErr)
			}
		})
	}
}

func TestControlledFirstInstallationSurvivesFreshProcessLoad(t *testing.T) {
	root, load := controlledRevisionOneCopy(t)
	loaded, err := statefilesystem.NewAt(root).Load(state.LoadRequest{Baseline: load.Baseline, SupportedRelease: load.SupportedRelease, Lineage: load.Lineage})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 {
		t.Fatalf("fresh-process revision 1 = (%+v, %v)", loaded, err)
	}
}

func TestControlledCloudflareProfileSetupDeathRestartsForward(t *testing.T) {
	root, load := controlledRevisionOneCopy(t)
	func() {
		defer func() { _ = recover() }()
		_ = runControlledCloudflareProfileSetupWithOptions(t.Context(), root, load, controlledSetupOptions{confirm: true, crashAt: systemchanges.StatePublished, crashAfter: true})
	}()
	stateModule := statefilesystem.NewAt(root)
	finalLoad := state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: load.SupportedRelease, Lineage: &state.LineageProof{Revision: 2, LastCompletedChangeSet: "cloudflare-profile-setup-0002", ReleaseIdentity: load.SupportedRelease}}
	loaded, err := stateModule.Load(finalLoad)
	if err != nil || loaded.Snapshot == nil {
		t.Fatalf("published revision 2 = (%+v, %v)", loaded, err)
	}
	_, finalSHA, _, _, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid {
		t.Fatal("published revision 2 lineage unavailable")
	}
	observation := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 2, StateSHA256: finalSHA, LastChangeSet: "cloudflare-profile-setup-0002", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter, err := systemubuntu.NewControlledManagedProviderAdapter(root, observation, stateModule, func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error) {
		return systemchanges.StepEvidence{}, errors.New("provider effect must not repeat after restart")
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := systemchanges.New(adapter).Recover(); result.Outcome != systemchanges.Completed {
		t.Fatalf("fresh-process setup recovery = %+v", result)
	}
}
