package main

import (
	"context"
	"errors"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
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
