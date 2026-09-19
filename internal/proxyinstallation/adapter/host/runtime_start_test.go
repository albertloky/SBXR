package host

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeStartAcrossARealChildProcess(t *testing.T) {
	if root := os.Getenv("SBXR_TEST_RUNTIME_ROOT"); root != "" {
		a := Adapter{root: root}
		borrowed, err := a.BorrowRuntimeStartLock(ServingRole)
		if err != nil || !borrowed.Holds(filepath.Join(root, "run/lock/sbxr.lock")) {
			os.Exit(4)
		}
		borrowed.Release()
		os.Exit(0)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0755); err != nil {
		t.Fatal(err)
	}
	a := Adapter{root: root}
	lock, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("owner lock refused")
	}
	defer lock.Release()
	if !a.WithRuntimeStart(t.Context(), lock, ServingRole, func() bool {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeStartAcrossARealChildProcess$")
		child.Env = append(os.Environ(), "SBXR_TEST_RUNTIME_ROOT="+root)
		return child.Run() == nil
	}) {
		t.Fatal("child process handoff failed")
	}
	other, busy, err := a.AcquireSubscriptionReviewLock("/run/lock/sbxr.lock")
	if other != nil {
		other.Release()
	}
	if err != nil || !busy {
		t.Fatal("child exit released Owner lock")
	}
}

func TestOrdinaryRuntimeStartsSerializeWithRealLocks(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	first, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("fixture lock")
	}
	first.Release()
	for _, roles := range [][2]string{{ServingRole, ProxyStartRole}, {ProxyStartRole, ServingRole}} {
		owner, borrowed, err := a.AcquireRuntimeStartLock(t.Context(), roles[0])
		if err != nil || borrowed {
			t.Fatal("ordinary first start")
		}
		done := make(chan *MutationLock, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		go func() {
			lock, borrowed, err := a.AcquireRuntimeStartLock(ctx, roles[1])
			if err != nil || borrowed {
				if lock != nil {
					lock.Release()
				}
				done <- nil
				return
			}
			done <- lock
		}()
		select {
		case lock := <-done:
			if lock != nil {
				lock.Release()
			}
			owner.Release()
			cancel()
			t.Fatal("contending start did not wait for the held lock")
		case <-time.After(100 * time.Millisecond):
		}
		owner.Release()
		lock := <-done
		cancel()
		if lock == nil || !lock.Holds(a.path("/run/lock/sbxr.lock")) {
			t.Fatal("second start did not acquire actual exclusion")
		}
		lock.Release()
	}
}

func TestRuntimeStartRetriesOwnerHandoffThatAppearsAfterWaitBegins(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	owner, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("owner lock refused")
	}
	defer owner.Release()
	type outcome struct {
		lock     *MutationLock
		borrowed bool
		err      error
	}
	for _, role := range []string{ServingRole, ProxyStartRole} {
		t.Run(role, func(t *testing.T) {
			// Observe the contender's first failed handoff before the Owner
			// publishes the authenticated listener used for this start.
			decoy, err := net.ListenUnix("unix", a.runtimeStartAddress())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			done := make(chan outcome, 1)
			joined := false
			var result outcome
			go func() {
				lock, borrowed, err := a.AcquireRuntimeStartLock(ctx, role)
				done <- outcome{lock: lock, borrowed: borrowed, err: err}
			}()
			defer func() {
				cancel()
				if !joined {
					result = <-done
				}
				if result.lock != nil {
					result.lock.Release()
				}
			}()
			decoy.SetDeadline(time.Now().Add(time.Second))
			connection, err := decoy.AcceptUnix()
			if err != nil {
				decoy.Close()
				t.Fatal(err)
			}
			request := make([]byte, len(role)+1)
			if _, err := io.ReadFull(connection, request); err != nil || string(request) != role+"\n" {
				connection.Close()
				decoy.Close()
				t.Fatal("first handoff attempt was not observed")
			}
			connection.Close()
			decoy.Close()

			if !a.WithRuntimeStart(ctx, owner, role, func() bool { return true }) {
				t.Fatal("waiting start did not use the later Owner handoff")
			}
			result = <-done
			joined = true
			if result.err != nil || !result.borrowed || result.lock == nil || !result.lock.Holds(a.path("/run/lock/sbxr.lock")) {
				t.Fatalf("waiting start did not borrow Owner lock: %#v", result)
			}
			result.lock.Release()
			result.lock = nil
			if !owner.Holds(a.path("/run/lock/sbxr.lock")) {
				t.Fatal("waiting start released Owner lock")
			}
		})
	}
}

func TestRuntimeStartWaitCancelsAndDoesNotCreateOrTrustUnsafeLocks(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	owner, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("fixture lock")
	}
	defer owner.Release()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	if lock, _, err := a.AcquireRuntimeStartLock(ctx, ProxyStartRole); err == nil || lock != nil {
		t.Fatal("busy mutation admitted")
	}
	if !owner.Holds(a.path("/run/lock/sbxr.lock")) {
		t.Fatal("contender released owner exclusion")
	}
	owner.Release()
	if err := os.Chmod(a.path("/run/lock/sbxr.lock"), 0666); err != nil {
		t.Fatal(err)
	}
	if lock, _, err := a.AcquireRuntimeStartLock(t.Context(), ProxyStartRole); err == nil || lock != nil {
		t.Fatal("unsafe inode admitted")
	}
	if err := os.Remove(a.path("/run/lock/sbxr.lock")); err != nil {
		t.Fatal(err)
	}
	if lock, _, err := a.AcquireRuntimeStartLock(t.Context(), ProxyStartRole); err == nil || lock != nil {
		t.Fatal("missing lock admitted")
	}
	if _, err := os.Lstat(a.path("/run/lock/sbxr.lock")); !os.IsNotExist(err) {
		t.Fatal("ordinary start recreated lock")
	}
}

func TestRuntimeStartCancellationClosesAStalledHandoff(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	owner, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("fixture lock")
	}
	defer owner.Release()
	listener, err := net.ListenUnix("unix", a.runtimeStartAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		lock, _, err := a.AcquireRuntimeStartLock(ctx, ServingRole)
		if lock != nil {
			lock.Release()
		}
		done <- err
	}()
	listener.SetDeadline(time.Now().Add(time.Second))
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handoff admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("handoff ignored cancellation")
	}
	if !owner.Holds(a.path("/run/lock/sbxr.lock")) {
		t.Fatal("cancelled handoff released Owner lock")
	}
}

func TestRuntimeStartBorrowsRealOwnerLockWithoutUnlockingIt(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0755); err != nil {
		t.Fatal(err)
	}
	a := Adapter{root: root}
	owner, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("owner lock refused")
	}
	defer owner.Release()
	if !a.WithRuntimeStart(t.Context(), owner, ServingRole, func() bool {
		child, err := a.BorrowRuntimeStartLock(ServingRole)
		if err != nil || !child.Holds(filepath.Join(root, "run/lock/sbxr.lock")) {
			t.Error("child did not obtain the existing lock")
			return false
		}
		child.Release()
		other, busy, err := a.AcquireSubscriptionReviewLock("/run/lock/sbxr.lock")
		if other != nil {
			other.Release()
		}
		if err != nil || !busy {
			t.Error("child released the owner's lock")
		}
		if duplicate, err := a.BorrowRuntimeStartLock(ServingRole); err == nil {
			duplicate.Release()
			t.Error("runtime authority was reused")
		}
		return true
	}) {
		t.Fatal("authorized runtime start refused")
	}
	if _, err := a.BorrowRuntimeStartLock(ServingRole); err == nil {
		t.Fatal("runtime authority survived its scope")
	}
}
