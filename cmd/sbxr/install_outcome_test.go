package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
	"github.com/creack/pty"
)

func TestInstallationOutcomeDoesNotPresentArbitraryErrors(t *testing.T) {
	const marker = "SECRET-CREDENTIAL-PROVIDER-RESPONSE"
	review := (&installOutcome{construction: errors.New(marker)}).Review(t.Context())
	if review.Correction == nil || review.Correction.Evidence != "INSTALL-PLAN-REFUSED" || strings.Contains(fmt.Sprint(review), marker) {
		t.Fatalf("Installation Correction exposed an arbitrary error: %+v", review)
	}
}

func TestInstallationSSHFailureCauseSelectsOnlyLegalCorrectionActions(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHLaunchIdentityInvalid, hide: true},
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		presented := ownerCorrection(&installation.Correction{Problem: "SSH proof failed", Found: "redacted cause", Required: "fresh proof", WhyStopped: "Installation stopped", OwnerSteps: []string{"Follow the exact safe guidance."}, Evidence: "NETWORK-INSTALLATION-SSH-UNPROVED", SSHFailureCause: test.cause})
		if presented.Correction == nil || presented.Correction.HideCheckAgain != test.hide {
			t.Fatalf("SSH Correction action mapping for %q was wrong", test.cause)
		}
	}
}

func newTestInstallOutcome(t *testing.T) *installOutcome {
	t.Helper()
	module, err := newInstallationModuleWith(
		func() (versionReport, error) {
			return versionReport{Build: softwarelifecycle.EmbeddedBuildIdentity{Tag: "v1.0.7"}, Architecture: softwarelifecycle.AMD64}, nil
		},
		func() networkpolicy.InstallationPreflightResult {
			return networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &installOutcome{module: module}
}

func TestInstallationBackDiscardsUnfinishedInput(t *testing.T) {
	var outcome ownerconsole.OutcomeModule = newTestInstallOutcome(t)
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Help.Purpose == "" || review.Editing.Help.URL != "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options" {
		t.Fatalf("Owner email Help did not cross the Installation presentation boundary: %+v", review)
	}
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" || review.Editing.Help.Recovery == "" {
		t.Fatalf("edited Installation input = %+v", review)
	}
	if review := outcome.Back(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("Back retained unfinished Installation input: %+v", review)
	}
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("Installation Review restored unfinished input: %+v", review)
	}
}

func TestProductionInstallationRunAdvancesOwnerEmailToAgreementAtExactSizes(t *testing.T) {
	for _, size := range []struct{ width, height uint16 }{{80, 24}, {120, 36}} {
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		if err := pty.Setsize(slave, &pty.Winsize{Cols: size.width, Rows: size.height}); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(&output, master); close(copied) }()
		capabilities := ownerconsole.Capabilities{InteractiveInput: true, InteractiveOutput: true, AlternateScreen: true, CursorAddressing: true, ReadableEncoding: true, KeyboardInput: true, Width: int(size.width), Height: int(size.height)}
		outcome := newTestInstallOutcome(t)
		done := make(chan error, 1)
		go func() {
			done <- ownerconsole.Run(t.Context(), ownerconsole.Session{Input: slave, Output: slave, Environment: []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"}, Capabilities: &capabilities, Scenario: ownerconsole.InstallationReview, Outcome: outcome})
		}()
		time.Sleep(500 * time.Millisecond)
		for _, input := range []string{"owner@example.net", "\r", "", "\t", "\x1b[B", "\r", "", "\x03\r"} {
			time.Sleep(80 * time.Millisecond)
			_, _ = master.Write([]byte(input))
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Owner Console Run did not exit")
		}
		_ = slave.Close()
		_ = master.Close()
		select {
		case <-copied:
		case <-time.After(time.Second):
			t.Fatal("Owner Console transcript did not close")
		}
		got := output.String()
		for _, want := range []string{"ACME subscriber agreement", "No Plan, Change Set, rollback material, or sudo"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d Owner email transition omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		helpStart := strings.LastIndex(got, "ACME SUBSCRIBER AGREEMENT HELP")
		if helpStart < 0 {
			t.Fatalf("%dx%d ACME agreement Help was unavailable\n%s", size.width, size.height, got)
		}
		help := got[helpStart:]
		for _, want := range []string{"Purpose: Record acceptance", "Instructions: Enter accepted", "format: accepted", "Common mistakes: Do not continue before review.", "Recovery: Review the agreement", "https://letsencrypt.org/repository/"} {
			if !strings.Contains(help, want) {
				t.Fatalf("%dx%d ACME agreement Help omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if strings.Contains(got, "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED") || strings.Contains(help, "EXAMPLE ONLY") {
			t.Fatalf("%dx%d Owner email did not advance to the ACME agreement\n%s", size.width, size.height, got)
		}
	}
}

type protectedInstallFixture struct{ observations, launches int }

func (fixture *protectedInstallFixture) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	fixture.observations++
	observed, err := networkpolicy.ControlledInstallationAdapter().Observe(request)
	if request.Scope == networkpolicy.LocalObservations {
		observed.Reclamation.Packages = []networkpolicy.PackageConflict{{Name: "xray", Version: "1.2.3", Owns: "/usr/local/bin/xray", OwnedPaths: []string{"/usr/local/bin/xray", "/usr/lib/libshared.so"}}}
	}
	return observed, err
}

type installPendingStub struct{}

func (installPendingStub) PendingChangeSet() (systemchanges.PendingChangeSet, bool, error) {
	return systemchanges.PendingChangeSet{}, false, nil
}

func controlledCommandInstallRequest() (softwareubuntu.InstallHandoffRequest, error) {
	application := []byte("authenticated application archive")
	componentFiles := map[string][]byte{
		"xray": []byte("#!/bin/sh\nexit 0\n"), "sing-box": []byte("#!/bin/sh\nexit 0\n"), "cloudflared": []byte("#!/bin/sh\nexit 0\n"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	if err != nil {
		return softwareubuntu.InstallHandoffRequest{}, err
	}
	components, err := softwarelifecycle.BuildComponentArchive(manifest, componentFiles)
	if err != nil {
		return softwareubuntu.InstallHandoffRequest{}, err
	}
	applicationDigest, componentDigest := sha256.Sum256(application), sha256.Sum256(components)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("1", 40), IndexSHA256: strings.Repeat("2", 64)}
	applicationAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}
	componentAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}
	verified := softwarelifecycle.VerifiedRelease{Identity: identity, Version: "1.0.0", Sequence: 1, StateSchema: 2, MinimumUpdaterSchema: 1, Assets: []softwarelifecycle.AssetProof{applicationAsset, componentAsset}}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("3", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("4", 64), ComponentsSHA256: componentAsset.SHA256, InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 2}
	return softwareubuntu.InstallHandoffRequest{Schema: 1, Tag: identity.Tag, Architecture: softwarelifecycle.AMD64, Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components}}, nil
}

func newProtectedInstallOutcome(t *testing.T) (*installOutcome, *protectedInstallFixture, string) {
	t.Helper()
	request, err := controlledCommandInstallRequest()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &protectedInstallFixture{}
	module, err := installation.New(installation.Dependencies{
		Preflight: func() networkpolicy.InstallationPreflightResult {
			return networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}}
		},
		RecommendedRealityTarget: "www.microsoft.com",
		ReviewRealityTarget: func(_ context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
			return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Outcome: connectionprofiles.Healthy}}
		},
		RunningRelease: func() (installation.RunningRelease, error) {
			return installation.RunningRelease{Tag: request.Tag, Architecture: request.Architecture}, nil
		},
		ReleaseCandidate: func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error) {
			return request.Candidate, nil
		},
		Stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		Network: networkpolicy.New(fixture).Evaluate,
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)),
		Launch: func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
			fixture.launches++
			return softwareubuntu.InstallCompleted, nil
		},
		Recover: func(context.Context, systemchanges.PendingChangeSet) error { return nil }, Pending: installPendingStub{},
		WriteReceipt: func(string, softwarelifecycle.ReleaseIdentity, string) error { return nil }, RemoveReceipt: func() error { return nil },
		ObserveState: func() (systemchanges.Observation, error) {
			return systemchanges.Observation{Status: systemchanges.NotInstalled}, nil
		},
		LoadManaged: func() (systemchanges.Observation, state.ReleaseIdentity, error) {
			return systemchanges.Observation{}, state.ReleaseIdentity{}, nil
		},
		ProveSubscription: func(context.Context, string, uint16) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome := &installOutcome{module: module}
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" {
		t.Fatalf("Owner email edit = %+v", review)
	}
	review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "accepted"})
	if review.Correction == nil || !strings.Contains(review.Correction.Evidence, "NETWORK-RECLAMATION-PROTECTED") {
		t.Fatalf("controlled Installation Correction = %+v", review)
	}
	return outcome, fixture, review.Correction.Evidence
}

type installClipboard struct{ values []string }

func (clipboard *installClipboard) Copy(_ context.Context, value string) ownerconsole.CopyResult {
	clipboard.values = append(clipboard.values, value)
	return ownerconsole.CopyConfirmed
}

func runProtectedInstallCorrection(t *testing.T, width, height uint16, clipboard ownerconsole.Clipboard, inputs ...string) (string, *protectedInstallFixture, string) {
	t.Helper()
	outcome, fixture, evidence := newProtectedInstallOutcome(t)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := pty.Setsize(slave, &pty.Winsize{Cols: width, Rows: height}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copied) }()
	capabilities := ownerconsole.Capabilities{InteractiveInput: true, InteractiveOutput: true, AlternateScreen: true, CursorAddressing: true, ReadableEncoding: true, KeyboardInput: true, Width: int(width), Height: int(height)}
	done := make(chan error, 1)
	go func() {
		done <- ownerconsole.Run(t.Context(), ownerconsole.Session{Input: slave, Output: slave, Environment: []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"}, Capabilities: &capabilities, Scenario: ownerconsole.InstallationReview, Outcome: outcome, Clipboard: clipboard})
	}()
	time.Sleep(500 * time.Millisecond)
	for _, input := range inputs {
		_, _ = master.Write([]byte(input))
		time.Sleep(100 * time.Millisecond)
	}
	_, _ = master.Write([]byte("\x03\r"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console Run did not exit")
	}
	_ = slave.Close()
	_ = master.Close()
	select {
	case <-copied:
	case <-time.After(time.Second):
		t.Fatal("Owner Console transcript did not close")
	}
	return output.String(), fixture, evidence
}

func TestProductionInstallationCorrectionRunsAtExactSizes(t *testing.T) {
	for _, size := range []struct{ width, height uint16 }{{80, 24}, {120, 36}} {
		pages := 1
		inputs := make([]string, 0, pages)
		for range pages {
			inputs = append(inputs, "\r")
		}
		got, fixture, _ := runProtectedInstallCorrection(t, size.width, size.height, nil, inputs...)
		for _, want := range []string{"CORRECTION FLOW", "INSTALL-PLAN-REFUSED", "NETWORK-RECLAMATION-PROTECTED", "A package conflict owns", "Host Foundation", "Check again", "Back", "Copy redacted evidence"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d Installation Correction omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if fixture.launches != 0 || !strings.Contains(got, "\x1b[?1049h") || !strings.Contains(got, "\x1b[?1049l") {
			t.Fatalf("%dx%d Correction mutated the host or did not restore the terminal", size.width, size.height)
		}
		for _, forbidden := range []string{"Continue anyway", "Apply exact one-use Plan"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("%dx%d Installation Correction exposed %q\n%s", size.width, size.height, forbidden, got)
			}
		}
	}
}

func TestProductionInstallationCorrectionPhysicalActions(t *testing.T) {
	t.Run("Check again", func(t *testing.T) {
		_, fixture, _ := runProtectedInstallCorrection(t, 80, 24, nil, "\r", "\r")
		if fixture.observations < 6 || fixture.launches != 0 {
			t.Fatalf("Check again observations = %d, launches = %d", fixture.observations, fixture.launches)
		}
	})
	t.Run("Copy redacted evidence", func(t *testing.T) {
		clipboard := &installClipboard{}
		_, fixture, evidence := runProtectedInstallCorrection(t, 80, 24, clipboard, "\r", "\x1b[B", "\r")
		if len(clipboard.values) != 1 || clipboard.values[0] != evidence || fixture.launches != 0 {
			t.Fatalf("copied evidence = %#v, want %q; launches = %d", clipboard.values, evidence, fixture.launches)
		}
	})
	t.Run("Back", func(t *testing.T) {
		got, fixture, _ := runProtectedInstallCorrection(t, 80, 24, nil, "\r", "\x1b[B", "\x1b[B", "\r")
		if !strings.Contains(got, "Owner email") || fixture.launches != 0 {
			t.Fatalf("Back did not return without mutation; launches = %d\n%s", fixture.launches, got)
		}
	})
}

func TestProductionInstallationCorrectionResizesThroughRun(t *testing.T) {
	outcome, fixture, _ := newProtectedInstallOutcome(t)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(slave, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(copied) }()
	done := make(chan error, 1)
	capabilities := ownerconsole.Capabilities{InteractiveInput: true, InteractiveOutput: true, AlternateScreen: true, CursorAddressing: true, ReadableEncoding: true, KeyboardInput: true, Width: 80, Height: 24}
	go func() {
		done <- ownerconsole.Run(t.Context(), ownerconsole.Session{Input: slave, Output: slave, Capabilities: &capabilities, Scenario: ownerconsole.InstallationReview, Outcome: outcome})
	}()
	time.Sleep(500 * time.Millisecond)
	if err := pty.Setsize(slave, &pty.Winsize{Cols: 120, Rows: 36}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_, _ = master.Write([]byte("\x03\r"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console did not exit after resize")
	}
	_ = slave.Close()
	_ = master.Close()
	select {
	case <-copied:
	case <-time.After(time.Second):
		t.Fatal("Owner Console resize transcript did not close")
	}
	if fixture.launches != 0 || !strings.Contains(output.String(), "NETWORK-RECLAMATION-PROTECTED") {
		t.Fatalf("resized production Correction lost its typed finding or mutated the host\n%s", output.String())
	}
}

func TestLaterProcessStartsWithFreshInstallationInput(t *testing.T) {
	abandoned := newTestInstallOutcome(t)
	if review := abandoned.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" {
		t.Fatalf("abandoned process input = %+v", review)
	}

	later := newTestInstallOutcome(t)
	if review := later.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("later process restored abandoned input: %+v", review)
	}
}

func TestProductionInstallationJourneyReturnsInvalidAgreementToItsExactField(t *testing.T) {
	outcome := newTestInstallOutcome(t)
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil {
		t.Fatalf("owner-email did not continue field-local editing: %+v", review)
	}
	review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "agree"})
	if review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" || review.Editing.Field.Value != "agree" {
		t.Fatalf("invalid agreement did not return to its field: %+v", review)
	}
	review = outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "accepted"})
	if review.Editing == nil || review.Editing.Field.Identity != "reality-target" {
		t.Fatalf("accepted agreement did not advance to REALITY target: %+v", review)
	}
}

func TestProductionInstallationJourneyHasNoCloudflareInput(t *testing.T) {
	want := []string{"owner-email", "subscriber-agreement", "primary-address", "reality-port", "subscription-port", "reality-target"}
	if len(installFields) != len(want) {
		t.Fatalf("installation fields = %+v", installFields)
	}
	for index, field := range installFields {
		if field.Identity != want[index] {
			t.Fatalf("installation field %d = %q, want %q", index, field.Identity, want[index])
		}
	}
}
