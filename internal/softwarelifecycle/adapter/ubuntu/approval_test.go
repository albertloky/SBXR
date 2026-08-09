package ubuntu

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestApprovalUsesOnlyOrdinarySudoBeforeFreshRecheck(t *testing.T) {
	var events []string
	approval := Approval{uid: 501, authorize: func(_ context.Context, name string, arguments ...string) error {
		events = append(events, name+" "+arguments[0])
		return nil
	}, recheck: func(context.Context) (softwarelifecycle.InstallRecheck, error) {
		events = append(events, "recheck")
		return softwarelifecycle.InstallRecheck{PrivilegedNetworkHealthy: true}, nil
	}}
	result, err := approval.AuthorizeAndRecheck(t.Context())
	if err != nil || !result.PrivilegedNetworkHealthy || !reflect.DeepEqual(events, []string{"/usr/bin/sudo -v", "recheck"}) {
		t.Fatalf("AuthorizeAndRecheck() = (%+v, %v); events=%v", result, err, events)
	}
}

func TestApprovalNeverRechecksAfterDeniedSudoOrRunsAsRoot(t *testing.T) {
	called := false
	recheck := func(context.Context) (softwarelifecycle.InstallRecheck, error) {
		called = true
		return softwarelifecycle.InstallRecheck{}, nil
	}
	for _, approval := range []Approval{{uid: 501, authorize: func(context.Context, string, ...string) error { return errors.New("denied") }, recheck: recheck}, {uid: 0, authorize: func(context.Context, string, ...string) error { return nil }, recheck: recheck}} {
		if _, err := approval.AuthorizeAndRecheck(t.Context()); err == nil || called {
			t.Fatalf("unsafe approval = %+v; rechecked=%t", approval, called)
		}
	}
}
