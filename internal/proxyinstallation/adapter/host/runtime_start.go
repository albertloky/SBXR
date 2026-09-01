package host

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type runtimeStartLockKey struct{}

// RuntimeStartContext carries existing whole-host authority to private Host
// service effects. It grants nothing to ordinary service-manager starts.
func RuntimeStartContext(ctx context.Context, lock *MutationLock) context.Context {
	return context.WithValue(ctx, runtimeStartLockKey{}, lock)
}

func (a Adapter) runtimeStart(ctx context.Context, role string, start func() bool) bool {
	lock, ok := ctx.Value(runtimeStartLockKey{}).(*MutationLock)
	if !ok {
		return start()
	}
	return a.WithRuntimeStart(ctx, lock, role, start)
}

func (a Adapter) runtimeStartAddress() *net.UnixAddr {
	name := "sbxr-runtime-start-" + digest([]byte(a.root))[:16]
	if runtime.GOOS == "linux" {
		// Abstract sockets disappear with their last descriptor, including after
		// process death. There is no stale path to adopt or remove on recovery.
		return &net.UnixAddr{Name: "@" + name, Net: "unix"}
	}
	return &net.UnixAddr{Name: filepath.Join(os.TempDir(), name+".sock"), Net: "unix"}
}

// WithRuntimeStart lends one already-held lock to one fixed private startup
// role. It never releases the Owner lock or creates durable recovery authority.
func (a Adapter) WithRuntimeStart(ctx context.Context, lock *MutationLock, role string, start func() bool) bool {
	if role != ServingRole && role != ProxyStartRole || !lock.Holds(a.path("/run/lock/sbxr.lock")) {
		return false
	}
	descriptor, err := lock.RuntimeDescriptor()
	if err != nil {
		return false
	}
	defer descriptor.Close()
	listener, err := net.ListenUnix("unix", a.runtimeStartAddress())
	if err != nil {
		return false
	}
	defer listener.Close()
	if runtime.GOOS != "linux" && os.Chmod(a.runtimeStartAddress().Name, 0600) != nil {
		return false
	}
	deadline := time.Now().Add(15 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	listener.SetDeadline(deadline)
	done := make(chan bool, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		// Exactly one connection consumes this scoped handoff, including refusal.
		listener.Close()
		if err != nil {
			done <- false
			return
		}
		defer connection.Close()
		connection.SetDeadline(deadline)
		request := make([]byte, len(role)+1)
		uid, peerOK := runtimePeerUID(connection)
		_, err = io.ReadFull(connection, request)
		if !peerOK || uid != a.ownerUID() || err != nil || string(request) != role+"\n" {
			done <- false
			return
		}
		n, _, err := connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(descriptor.Fd())), nil)
		done <- err == nil && n == 1
	}()
	started := start()
	if !started {
		listener.Close()
	}
	return <-done && started
}

func (a Adapter) BorrowRuntimeStartLock(role string) (*MutationLock, error) {
	refused := errors.New("runtime start authority refused")
	if role != ServingRole && role != ProxyStartRole {
		return nil, refused
	}
	connection, err := net.DialUnix("unix", nil, a.runtimeStartAddress())
	if err != nil {
		return nil, refused
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(15 * time.Second))
	uid, ok := runtimePeerUID(connection)
	if !ok || uid != a.ownerUID() {
		return nil, refused
	}
	if _, err := io.WriteString(connection, role+"\n"); err != nil {
		return nil, refused
	}
	body, ancillary := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	n, control, flags, _, err := connection.ReadMsgUnix(body, ancillary)
	if err != nil || n != 1 || body[0] != 1 || flags&syscall.MSG_CTRUNC != 0 {
		return nil, refused
	}
	messages, err := syscall.ParseSocketControlMessage(ancillary[:control])
	if err != nil || len(messages) != 1 {
		return nil, refused
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, refused
	}
	syscall.CloseOnExec(fds[0])
	return softwarelifecycle.BorrowRuntimeLock(os.NewFile(uintptr(fds[0]), "runtime lock"), a.path("/run/lock/sbxr.lock"), a.ownerUID())
}
