package main

import (
	"context"
	"errors"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwaregithub "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
)

type updateViewer interface {
	View(context.Context, softwarelifecycle.ViewRequest) softwarelifecycle.ViewResult
}

func runScheduledUpdateCheck(ctx context.Context, lifecycle updateViewer, installed softwarelifecycle.VerifiedRelease) error {
	discovery := softwarelifecycle.StableUpdateDiscovery()
	result := lifecycle.View(ctx, softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if result.Refusal != nil {
		return errors.New("scheduled update check refused")
	}
	return nil
}

func runProductionScheduledUpdateCheck(ctx context.Context) error {
	if pending, err := pendingStartupRecovery(); err != nil || pending {
		return errors.New("an unfinished Change Set must recover before update discovery")
	}
	_, release, err := managedLoadEvidence()
	if err != nil {
		return err
	}
	source := softwaregithub.New()
	module := softwarelifecycle.NewWithCandidateRetention(source, softwarelifecycle.VerifierQualification{Version: softwaregithub.Version, SigningFingerprint: softwaregithub.SigningFingerprint}, time.Now, softwareubuntu.NewCandidateStore())
	installed := module.View(ctx, softwarelifecycle.ViewRequest{Tag: release.Tag, InstallationStatus: softwarelifecycle.NotInstalled})
	if installed.Refusal != nil || installed.VerifiedCandidate == nil || installed.VerifiedCandidate.Identity.Repository != release.Repository || installed.VerifiedCandidate.Identity.Tag != release.Tag || installed.VerifiedCandidate.Identity.Commit != release.Commit || installed.VerifiedCandidate.Identity.IndexSHA256 != release.ReleaseIndexSHA256 {
		return errors.New("installed Release Identity could not be freshly verified")
	}
	return runScheduledUpdateCheck(ctx, module, *installed.VerifiedCandidate)
}
