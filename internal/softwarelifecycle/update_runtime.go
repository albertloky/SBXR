package softwarelifecycle

import (
	"context"
	"errors"
	"os"
)

// UpdateRuntime is the private collaboration with Proxy Installation. Acquire
// retains writer exclusion; Complete verifies only subscription runtime effects.
// Neither callback owns or removes the Update Record.
type UpdateRuntime struct {
	Acquire  func(context.Context, []byte, ReleaseIdentity, *UpdateTarget, *MutationLockAuthority) (func(), bool)
	Complete func(context.Context, []byte, ReleaseIdentity, *MutationLockAuthority) bool
	// AfterComplete runs under whole-host authority after update.json is gone
	// and runtime exclusions have been released. Frozen updaters lack this hook;
	// the target's first public root CLI launch supplies the same handoff.
	AfterComplete func(context.Context, ReleaseIdentity, *MutationLockAuthority) (string, bool)
}

func (inspector filesystemInspector) afterRuntime(ctx context.Context, root *os.Root, lock *MutationLockAuthority) (string, bool) {
	if inspector.updateRuntime == nil || inspector.updateRuntime.AfterComplete == nil {
		return "", true
	}
	for _, path := range []string{"var/lib/sbxr/update.json", "var/lib/sbxr/.update.json.next"} {
		if _, err := root.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return "", false
		}
	}
	identity := inspector.activeRecoveryIdentity(root)
	if identity == nil {
		return "", false
	}
	return inspector.updateRuntime.AfterComplete(ctx, *identity, lock)
}

func NewInstalledWithUpdateRuntime(latest LatestReleaseSource, admission UpdateAdmission, runtime UpdateRuntime) Interface {
	return newInstalledInterface(filesystemInspector{root: "/", uid: 0, requireSupport: true, updateAdmission: admission, updateRuntime: &runtime}, latest)
}

func updateOwnership(root *os.Root) ([]byte, error) {
	for _, name := range []string{"var/lib/.sbxr-removal.json", "var/lib/sbxr/.proxy-ownership.json.next"} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("unfinished proxy authority")
		}
	}
	name := "var/lib/sbxr/proxy-ownership.json"
	if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return readRootFile(root, name, 0600, 1, 64<<10)
}

func (inspector filesystemInspector) acquireRuntime(ctx context.Context, root *os.Root, identity ReleaseIdentity, target *UpdateTarget, lock *MutationLockAuthority) ([]byte, func(), bool) {
	body, err := updateOwnership(root)
	if err != nil || inspector.updateRuntime == nil || inspector.updateRuntime.Acquire == nil || inspector.updateRuntime.Complete == nil {
		return nil, nil, false
	}
	release, ok := inspector.updateRuntime.Acquire(ctx, body, identity, target, lock)
	if !ok || release == nil {
		if release != nil {
			release()
		}
		return nil, nil, false
	}
	current, err := updateOwnership(root)
	if err != nil || digestBytes(current) != digestBytes(body) {
		release()
		return nil, nil, false
	}
	return body, release, true
}

func (inspector filesystemInspector) completeRuntime(ctx context.Context, root *os.Root, record updateRecord, lock *MutationLockAuthority) bool {
	if record.Schema == 1 {
		return true
	}
	body, err := updateOwnership(root)
	active := inspector.activeRecoveryIdentity(root)
	return err == nil && digestBytes(body) == record.OwnershipSHA256 && active != nil && inspector.updateRuntime != nil && inspector.updateRuntime.Complete != nil && inspector.updateRuntime.Complete(ctx, body, *active, lock)
}

func (inspector filesystemInspector) activeRecoveryIdentity(root *os.Root) *ReleaseIdentity {
	body, err := readRootFile(root, "var/lib/sbxr/installed.json", 0600, 1, maxInstalledRecord)
	executable, exeErr := readRootFile(root, "usr/local/bin/sbxr", 0755, 1, maxInstalledBinary)
	identity, ok := verifyInstalledPair(body, executable)
	if err != nil || exeErr != nil || !ok {
		return nil
	}
	return &identity
}

// CommittedRuntimeStatus permits only a borrowed serving start to consume the
// exact committed pair while the transaction still excludes renewal and owners.
func (module installedInterface) CommittedRuntimeStatus(ctx context.Context, lock *MutationLockAuthority) Result {
	inspector, ok := module.local.(filesystemInspector)
	if !ok || ctx.Err() != nil || lock == nil || !lock.borrowed || !lock.Holds(inspector.path(mutationLockPath)) {
		return recoveryRequiredResult()
	}
	root, err := os.OpenRoot(inspector.root)
	if err != nil {
		return recoveryRequiredResult()
	}
	defer root.Close()
	record, err := readUpdateRecord(root)
	body, ownershipErr := updateOwnership(root)
	if err != nil || record.Schema != 2 || record.Checkpoint != committedCheckpoint || ownershipErr != nil || digestBytes(body) != record.OwnershipSHA256 || proveCommittedRecovery(root, record) != nil {
		return recoveryRequiredResult()
	}
	identity := inspector.activeRecoveryIdentity(root)
	if identity == nil {
		return recoveryRequiredResult()
	}
	return Result{State: Ready, Installed: identity, Code: StatusReady}
}
