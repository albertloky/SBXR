package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/installation"
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
	markers := controlledStagedOnboardingSecretMarkers()
	protected := make(map[string][]byte, len(markers))
	for _, marker := range markers {
		protected[marker.owner] = append(protected[marker.owner], marker.value...)
	}
	public := map[string][]byte{}
	for _, surface := range controlledStagedOnboardingPublicSurfaces() {
		public[surface] = []byte("fixed secret-safe qualification output")
	}
	if err := qualifyControlledStagedOnboardingSecretScan(public, protected); err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		for _, surface := range controlledStagedOnboardingPublicSurfaces() {
			leaked := make(map[string][]byte, len(public))
			for name, body := range public {
				leaked[name] = append([]byte(nil), body...)
			}
			leaked[surface] = append(leaked[surface], marker.value...)
			if err := qualifyControlledStagedOnboardingSecretScan(leaked, protected); err == nil {
				t.Fatalf("%s marker was accepted on %s", marker.class, surface)
			}
		}
	}
	wrongOwner := make(map[string][]byte, len(protected))
	for owner, body := range protected {
		wrongOwner[owner] = append([]byte(nil), body...)
	}
	wrongOwner[markers[1].owner] = append(wrongOwner[markers[1].owner], markers[0].value...)
	if err := qualifyControlledStagedOnboardingSecretScan(public, wrongOwner); err == nil {
		t.Fatal("marker was accepted outside its protected owning artifact")
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
