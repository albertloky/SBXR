package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type scheduledUpdateView struct {
	requests []softwarelifecycle.ViewRequest
	result   softwarelifecycle.ViewResult
}

func (view *scheduledUpdateView) View(_ context.Context, request softwarelifecycle.ViewRequest) softwarelifecycle.ViewResult {
	view.requests = append(view.requests, request)
	return view.result
}

func TestScheduledUpdateCheckInvokesOnlyStableSoftwareLifecycleView(t *testing.T) {
	installed := installedForUpdateCheck()
	view := &scheduledUpdateView{result: softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.Managed, UpdateEligible: true, PermittedActions: []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}}}

	if err := runScheduledUpdateCheck(t.Context(), view, installed); err != nil {
		t.Fatal(err)
	}
	if len(view.requests) != 1 {
		t.Fatalf("View calls = %d", len(view.requests))
	}
	request := view.requests[0]
	if request.InstallationStatus != softwarelifecycle.Managed || request.Installed == nil || !reflect.DeepEqual(*request.Installed, installed) || request.UpdateDiscovery == nil || request.Tag != "" || request.Architecture != "" {
		t.Fatalf("scheduled View request = %#v", request)
	}
}

func installedForUpdateCheck() softwarelifecycle.VerifiedRelease {
	return softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", IndexSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Sequence: 1, StateSchema: 1, MinimumUpdaterSchema: 1}
}
