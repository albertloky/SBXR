package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwaregithub "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
)

func managedSoftwareLifecyclePresentation(ctx context.Context, release state.ReleaseIdentity) (ownerconsole.LifecyclePresentation, softwarelifecycle.VerifiedRelease, softwarelifecycle.VerifiedRelease, error) {
	source := softwaregithub.New()
	module := softwarelifecycle.NewWithCandidateRetention(source, softwarelifecycle.VerifierQualification{Version: softwaregithub.Version, SigningFingerprint: softwaregithub.SigningFingerprint}, time.Now, softwareubuntu.NewCandidateStore(), softwareubuntu.NewStager())
	return managedSoftwareLifecyclePresentationWith(ctx, release, module, softwarelifecycle.Architecture(runtime.GOARCH))
}

func managedSoftwareLifecyclePresentationWith(ctx context.Context, release state.ReleaseIdentity, module updateViewer, architecture softwarelifecycle.Architecture) (ownerconsole.LifecyclePresentation, softwarelifecycle.VerifiedRelease, softwarelifecycle.VerifiedRelease, error) {
	installedView := module.View(ctx, softwarelifecycle.ViewRequest{Tag: release.Tag, Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
	installed := installedView.VerifiedCandidate
	if installedView.Refusal != nil || installed == nil || installed.Identity.Repository != release.Repository || installed.Identity.Tag != release.Tag || installed.Identity.Commit != release.Commit || installed.Identity.IndexSHA256 != release.ReleaseIndexSHA256 {
		return ownerconsole.LifecyclePresentation{}, softwarelifecycle.VerifiedRelease{}, softwarelifecycle.VerifiedRelease{}, errors.New("installed Release Identity could not be freshly verified")
	}
	discovery := softwarelifecycle.StableUpdateDiscovery()
	view := module.View(ctx, softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: installed, UpdateDiscovery: &discovery})
	if view.Refusal != nil {
		return ownerconsole.LifecyclePresentation{}, softwarelifecycle.VerifiedRelease{}, softwarelifecycle.VerifiedRelease{}, errors.New("stable update discovery refused")
	}
	if view.VerifiedCandidate == nil {
		return ownerconsole.LifecyclePresentation{Installed: releaseIdentityPresentation(*installed), DiscoveryCannotApply: true, DowngradeSelectionAvailable: true}, *installed, softwarelifecycle.VerifiedRelease{}, nil
	}
	return softwareLifecyclePresentation(*installed, view), *installed, *view.VerifiedCandidate, nil
}
