package ubuntu

import (
	"context"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestApprovalRechecksOnlyInsideTheVerifiedRootChild(t *testing.T) {
	called := false
	approval := Approval{uid: 0, recheck: func(context.Context) (softwarelifecycle.InstallRecheck, error) {
		called = true
		return softwarelifecycle.InstallRecheck{PrivilegedNetworkHealthy: true}, nil
	}}
	result, err := approval.AuthorizeAndRecheck(t.Context())
	if err != nil || !result.PrivilegedNetworkHealthy || !called {
		t.Fatalf("AuthorizeAndRecheck() = (%+v, %v); called=%v", result, err, called)
	}
}

func TestApprovalNeverRechecksOutsideTheRootChild(t *testing.T) {
	called := false
	recheck := func(context.Context) (softwarelifecycle.InstallRecheck, error) {
		called = true
		return softwarelifecycle.InstallRecheck{}, nil
	}
	approval := Approval{uid: 501, recheck: recheck}
	if _, err := approval.AuthorizeAndRecheck(t.Context()); err == nil || called {
		t.Fatalf("unsafe approval = %+v; rechecked=%t", approval, called)
	}
}
