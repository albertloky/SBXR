package installation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

// RunControlledInstallation runs the real Installation, State, and System
// Changes interfaces without live host or provider effects.
func RunControlledInstallation(ctx context.Context, parent string) (resultErr error) {
	root, err := os.MkdirTemp(parent, "sbxr-controlled-install-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(root)) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return runControlledInstallation(ctx, root)
}

func runControlledInstallation(ctx context.Context, root string) error {
	request, err := controlledInstallRequest()
	if err != nil {
		return err
	}
	preflight := networkpolicy.InstallationPreflightResult{ActiveSSHPort: request.Draft.SSHPort, UsablePublicIPv4: []string{request.Draft.PublicIPv4}}
	module, err := New(Dependencies{
		Preflight: func() networkpolicy.InstallationPreflightResult { return preflight },
		ReviewRealityTarget: func(_ context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
			return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Outcome: connectionprofiles.Healthy}}
		},
		RunningRelease: func() (RunningRelease, error) {
			return RunningRelease{Tag: request.Tag, Architecture: request.Architecture}, nil
		},
		ReleaseCandidate: func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error) {
			return request.Candidate, nil
		},
		Stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		Network: networkpolicy.New(networkpolicy.ControlledInstallationAdapter()).Evaluate,
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)),
		Launch: func(ctx context.Context, handoff softwareubuntu.InstallHandoffRequest, _ <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
			return applyControlledInstallation(ctx, root, handoff)
		},
		Recover:       func(context.Context, systemchanges.PendingChangeSet) error { return nil },
		Pending:       controlledPendingReader{},
		WriteReceipt:  func(string, softwarelifecycle.ReleaseIdentity, string) error { return nil },
		RemoveReceipt: func() error { return nil },
		ObserveState: func() (systemchanges.Observation, error) {
			return systemchanges.Observation{Status: systemchanges.NotInstalled}, nil
		},
		LoadManaged: func() (systemchanges.Observation, state.ReleaseIdentity, error) {
			return systemchanges.Observation{}, state.ReleaseIdentity{}, nil
		},
		ProveSubscription: func(context.Context, string, uint16) error { return nil },
	})
	if err != nil {
		return err
	}
	review := module.Review(ctx, Draft{Tag: request.Tag, Architecture: request.Architecture, Installation: request.Draft, RealityTarget: request.RealityTarget, RealityServerName: request.RealityServerName})
	if review.Plan == nil || review.Plan.DesiredStateRevision != 1 {
		return errors.New("controlled Installation review refused")
	}
	started := module.Apply(ctx, review.Approval)
	if started.Kind != ApplyStarted {
		return errors.New("controlled Installation apply refused")
	}
	for {
		operation, inspectErr := module.Inspect(ctx, started.Operation)
		if inspectErr == nil && operation.Status != OperationActive {
			if operation.Status != Completed {
				return errors.New("controlled Installation did not reach Managed")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func applyControlledInstallation(ctx context.Context, root string, request softwareubuntu.InstallHandoffRequest) (softwareubuntu.InstallApplyOutcome, error) {
	sshProof, err := networkpolicy.ControlledInstallationSSHPreservationProof()
	if err != nil {
		return 0, err
	}
	built, err := buildInstallWith(ctx, request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network:  networkpolicy.New(networkpolicy.ControlledInstallationAdapter()).Evaluate,
		random:   newInstallEntropyReader(request.Entropy),
		sshProof: sshProof,
	})
	if err != nil {
		return 0, err
	}
	stateModule := statefilesystem.NewAt(root)
	prepared, err := built.prepareState(stateModule)
	if err != nil {
		return 0, err
	}
	recheck, volatile, err := recheckInstall(ctx, request, built)
	if err != nil {
		return 0, err
	}
	adapter := systemubuntu.NewControlledInstallationAdapter(systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: volatile, FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"})
	transaction := built.plan.Apply(ctx, softwarelifecycle.InstallApplyRequest{Approval: controlledInstallApproval{recheck: recheck}, PreparedState: prepared, SystemChanges: systemchanges.New(adapter)})
	if transaction.Outcome != systemchanges.Completed {
		return 0, fmt.Errorf("System Changes outcome %s", transaction.Outcome)
	}
	identity := candidateRelease(built.candidate)
	release := state.ReleaseIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, ReleaseIndexSHA256: identity.IndexSHA256}
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 1, LastCompletedChangeSet: requestChangeSet(request), ReleaseIdentity: release}})
	if err != nil || loaded.Status != state.Managed || loaded.Snapshot == nil || !controlledRevisionOne(loaded.Snapshot.DesiredState) {
		return 0, errors.New("controlled revision 1 State is unproved")
	}
	for _, owner := range []systemchanges.Module{systemchanges.SoftwareModule, systemchanges.NetworkPolicyModule, systemchanges.ConnectionProfilesModule, systemchanges.CertificateModule, systemchanges.SubscriptionModule} {
		if !adapter.RequiredGatePassed(owner, systemchanges.PrePublication) || !adapter.RequiredGatePassed(owner, systemchanges.PostPublication) {
			return 0, fmt.Errorf("controlled Installation omitted Required %s gates", owner)
		}
	}
	return softwareubuntu.InstallCompleted, nil
}

func controlledRevisionOne(desired state.DesiredState) bool {
	profiles := desired.ConnectionProfiles
	return profiles.VLESSRealityVision.Lifecycle == state.ProfileEnabled &&
		profiles.VLESSXHTTP.Lifecycle == state.ProfileNotSetUp && profiles.VLESSWebSocket.Lifecycle == state.ProfileNotSetUp &&
		profiles.Hysteria2.Lifecycle == state.ProfileNotSetUp && profiles.TUIC.Lifecycle == state.ProfileNotSetUp && profiles.AnyTLS.Lifecycle == state.ProfileNotSetUp &&
		desired.Cloudflare == (state.CloudflareSettings{}) && desired.Certificates.IPCertificateID == "sbxr-ip" && desired.Certificates.DomainCertificateID == ""
}

type controlledPendingReader struct{}

func (controlledPendingReader) PendingChangeSet() (systemchanges.PendingChangeSet, bool, error) {
	return systemchanges.PendingChangeSet{}, false, nil
}

type controlledInstallApproval struct {
	recheck softwarelifecycle.InstallRecheck
}

func (approval controlledInstallApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.InstallRecheck, error) {
	return approval.recheck, nil
}

func controlledInstallRequest() (softwareubuntu.InstallHandoffRequest, error) {
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
	return softwareubuntu.InstallHandoffRequest{
		Schema: 1, Session: strings.Repeat("a", 64), Tag: identity.Tag, Architecture: softwarelifecycle.AMD64,
		Draft:         softwarelifecycle.InstallationDraft{OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true, PublicIPv4: "8.8.8.8", PrimaryAddress: "8.8.8.8", SSHPort: 22, RealityPort: 443, SubscriptionPort: 10443},
		RealityTarget: "www.microsoft.com:443", RealityServerName: "www.microsoft.com", Entropy: bytes.Repeat([]byte{0x42}, 32),
		Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components},
	}, nil
}
