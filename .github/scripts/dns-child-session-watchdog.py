"""Fixed immediate-child supervisor watchdog; import is inert.

Mounts are prepared by the separately approved namespace owner. This program
creates no mounts, runs no shell and never claims kernel resource cleanup.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

SUPERVISOR_HASH = 'b0b49fa2d6c8f53b71f9ee25f622192c784130e10a0596afb5a0a33a0cfe05d9'
SYMBOL = '_ZN16sbxr_dns_fixture12dns_observer23dns_child_observer_hook17h9e4679c7ef81f1e5E.llvm.11622216194542242137'


def same_image_file(directory, fd):
    def mid(n):
        return next(line.split()[1] for line in Path(f'/proc/self/fdinfo/{n}').read_text().splitlines()
                    if line.startswith('mnt_id:'))
    if not stat.S_ISREG(os.fstat(fd).st_mode) or mid(directory)!=mid(fd):
        raise ValueError('bootstrap-file-mount')


def private_mounts(host_namespace, current_namespace, mountinfo):
    if host_namespace == current_namespace:
        raise ValueError('host-mount-namespace')
    lines = mountinfo.splitlines()
    if not lines or len(lines) > 4096:
        raise ValueError('mount-inventory-bound')
    for line in lines:
        left, right = line.split(' - ', 1)
        fields = left.split()
        if len(fields) < 6 or len(right.split()) < 3:
            raise ValueError('mount-inventory-format')
        if any(x.startswith(('shared:', 'master:', 'propagate_from:')) for x in fields[6:]):
            raise ValueError('mount-propagation')


def supervise(api, argv, clock=time.monotonic, pause=time.sleep, custody=None):
    """Separate deadline, no stdout/stderr dependency; adapters mocked by tests."""
    api.runtime_setup()
    owned = api.Ownership(os.getpid())
    procs = {}
    start = clock()
    failure = None
    discovery_complete = True
    interrupted = []
    previous = {}
    child = None
    cleanup_at = None
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda s, f: interrupted.append(s) if not interrupted else None)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True, env={'PATH':'/usr/bin:/bin', 'LANG':'C',
                                                    'LC_ALL':'C', 'PYTHONDONTWRITEBYTECODE':'1'})
        procs['supervisor'] = child
        # Popen retains wait ownership even if the direct child exits immediately.
        fd = os.pidfd_open(child.pid, 0)
        try:
            parent, born = api.proc_identity(child.pid)
            if parent != os.getpid(): raise ValueError('direct-parent')
            owned.items[child.pid] = (fd, born)
        except BaseException:
            os.close(fd)
            raise
        while True:
            now = clock()
            if interrupted and failure is None: failure = 'interrupted'
            if now-start >= 105 and failure is None: failure = 'deadline'
            if failure is not None:
                if cleanup_at is None: cleanup_at = now
                sig = signal.SIGKILL if now-start >= 107 or now-cleanup_at >= 2 else signal.SIGTERM
                errors = api.cleanup_tick(owned, sig, procs)
                if errors: failure = 'cleanup-unproved'; discovery_complete = False
            else:
                try: api.discover(owned)
                except (OSError, ValueError, api.Refusal): failure = 'discovery-unproved'; discovery_complete = False
            rc = child.poll()
            residual = api.reap_adopted({child.pid})
            live = any(not select.select([fd], [], [], 0)[0]
                       for fd, _ in owned.items.values())
            if rc is not None and not residual and not live: break
            if rc is not None and failure is None: failure = 'residual-after-supervisor'
            # A delayed syscall/schedule can already exceed the wall-clock cap.
            # Attempt owned KILL once above, report lateness, never silently skip.
            if now-start >= 110: break
            if cleanup_at is not None and now-cleanup_at >= 5: break
            pause(.02)
    except (OSError, ValueError, api.Refusal):
        failure = 'watchdog-adapter-failure'
        discovery_complete = False
        limit = min(start+110, clock()+5)
        first_cleanup = True
        while procs and (first_cleanup or clock() < limit):
            first_cleanup = False
            try:
                api.cleanup_tick(owned, signal.SIGKILL, procs)
                if child.poll() is not None and not api.reap_adopted({child.pid}):
                    if all(select.select([fd], [], [], 0)[0] for fd, _ in owned.items.values()):
                        break
            except (OSError, ValueError, api.Refusal): pass
            pause(.02)
    finally:
        try:rc = child.poll() if child is not None else None
        except (OSError,ValueError):
            rc=None;failure='direct-reap-unproved'
        try:
            residual = api.reap_adopted(set(procs[p].pid for p in procs))
            live = any(not select.select([fd], [], [], 0)[0] for fd, _ in owned.items.values())
        except (OSError, ValueError, api.Refusal):
            residual, live = ['unknown'], True; discovery_complete = False
        ledger = []
        for pid,(fd,born) in owned.items.items():
            try: pending = not select.select([fd],[],[],0)[0]
            except (OSError,ValueError):
                pending=True;live=True;failure='ownership-observation-unproved';discovery_complete=False
            if pending:ledger.append({'pid':pid,'starttime':born})
        if child is not None and rc is None and child.pid not in owned.items:
            ledger.append({'pid':child.pid,'starttime':None,'ownership':'direct Popen; pidfd unavailable'})
        if custody is not None:
            # Transfer live Python objects, not reconstructed numeric PID authority.
            # main() remains inside immutable_inputs until owner_finish releases them.
            custody.update(owned=owned, procs=procs, previous_handlers=previous)
        else:
            for fd, _ in owned.items.values():
                try:os.close(fd)
                except OSError:failure='handle-close-unproved'
        if custody is None:
            for sig, handler in previous.items():
                try:signal.signal(sig, handler)
                except (OSError,ValueError):failure='handler-restore-unproved'
    return {'supervisor_returncode':rc, 'failure':failure,
            'processes_reaped':child is not None and rc is not None and not residual and not live,
            'elapsed_seconds':clock()-start, 'kernel_cleanup':'UNVERIFIED',
            'residual_ownership':ledger, 'discovery_complete':discovery_complete,
            'mount_cleanup':'namespace owner must unmount and detach recorded loops'}


def durable_record(fd, record):
    data=(json.dumps(record,sort_keys=True)+'\n').encode('ascii')
    if len(data)>32768:raise ValueError('owner-evidence-bound')
    view=memoryview(data)
    while view:
        n=os.write(fd,view)
        if n<=0:raise OSError('evidence-write')
        view=view[n:]
    os.fsync(fd)


def owner_finish(api,custody,report,evidence,clock=time.monotonic,pause=time.sleep):
    """Retain namespace, original pidfds and immutable anchors until actual reap.

    No signal/launch/mount in this function. A failed cleanup enters explicit
    quiescent custody, not an unsafe timed exit that abandons process identities.
    """
    owned,procs=custody['owned'],custody['procs']
    previous=dict(custody.get('previous_handlers',{}));start=clock();record_failed=False;held_recorded=False
    # Ordinary termination requests must not silently abandon live resources.
    # SIGKILL/host death cannot be intercepted and are outside this guarantee.
    for sig in (signal.SIGINT,signal.SIGTERM):
        old=signal.signal(sig,lambda s,f:None)
        if sig not in previous:previous[sig]=old
    def emit(value):
        nonlocal record_failed
        try:evidence(value)
        except (OSError,ValueError):record_failed=True
    emit({'state':'OWNER_CUSTODY','owner_pid':os.getpid(),'report':report})
    try:
        while True:
            uncertain=False
            try:api.discover(owned)
            except (OSError,ValueError,api.Refusal):uncertain=True
            statuses={}
            for name,p in procs.items():
                try:statuses[name]=p.poll()
                except (OSError,ValueError):statuses[name]=None;uncertain=True
            try:residual=api.reap_adopted({p.pid for p in procs.values()})
            except (OSError,ValueError,api.Refusal):residual=['unknown'];uncertain=True
            ledger=[]
            for pid,(fd,born) in owned.items.items():
                try:live=not select.select([fd],[],[],0)[0]
                except (OSError,ValueError):live=True;uncertain=True
                if live:ledger.append({'pid':pid,'starttime':born,'pidfd':fd})
            if not uncertain and not residual and not ledger and all(v is not None for v in statuses.values()):
                emit({'state':'OWNER_RELEASED','processes_reaped':True,
                      'prior_failure':report['failure'],'evidence_failed':record_failed})
                return not record_failed
            if not held_recorded:
                emit({'state':'FAILED_CLEANUP_HOLD','owner_pid':os.getpid(),
                      'residual_ownership':ledger,'direct_statuses':statuses,
                      'adopted':residual,'observation_uncertain':uncertain,
                      'actions':'no more signals or launches; no unmount/detach allowed'})
                held_recorded=True
            # 60 seconds is the bounded active verification window. After that
            # retain custody with low-frequency observation only, no new actions.
            pause(1 if clock()-start<60 else 5)
    finally:
        # This finally is reached normally only once all known and adopted
        # processes are reaped. Do not use a timeout/exception to close custody.
        for sig,handler in previous.items():signal.signal(sig,handler)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute-approved', action='store_true')
    p.add_argument('--host-mount-namespace', required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if not args.execute_approved: p.error('explicit execution approval required')
    # Namespace owner must preserve its original namespace identity independently.
    private_mounts(args.host_mount_namespace, os.readlink('/proc/self/ns/mnt'),
                   Path('/proc/self/mountinfo').read_text())
    path = Path(__file__).with_name('dns-child-fixture-supervisor.py')
    # Bootstrap before importing any sibling: immutable directory + no bytecode.
    held = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if not os.fstatvfs(held).f_flag & os.ST_RDONLY:
        os.close(held); raise ValueError('bootstrap-writable')
    info = Path(f'/proc/self/fdinfo/{held}').read_text().splitlines()
    mid = next(line.split()[1] for line in info if line.startswith('mnt_id:'))
    match = [line.split(' - ',1)[1].split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split()[0] == mid]
    if len(match)!=1 or match[0][0]!='squashfs' or 'ro' not in match[0][2].split(','):
        os.close(held); raise ValueError('bootstrap-superblock')
    path = Path(f'/proc/{os.getpid()}/fd/{held}')/path.name
    if (path.parent/'__pycache__').exists() or path.with_suffix('.pyc').exists() or path.is_symlink():
        os.close(held); raise ValueError('bootstrap-cache-or-symlink')
    import hashlib
    source_fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    same_image_file(held,source_fd)
    if hashlib.sha256(path.read_bytes()).hexdigest() != SUPERVISOR_HASH:
        raise ValueError('supervisor-hash')
    spec = importlib.util.spec_from_file_location('fixed_supervisor', path)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    try:
        api.readonly_superblock(held)
        api.reject_bytecode_cache(path)
        # The manifest must also be frozen; no hash-to-second-read mutable path.
        if args.manifest.name != 'runtime-manifest.json' or not os.path.samestat(os.stat(args.manifest.parent),os.fstat(held)):
            raise ValueError('manifest-location')
        args.manifest = path.parent/'runtime-manifest.json'
        mf = os.open(args.manifest, os.O_RDONLY | os.O_NOFOLLOW)
        try: api.readonly_superblock(mf)
        finally: os.close(mf)
        with api.immutable_inputs(args.manifest) as (_, paths, _):
            # Both directory/file anchors stay alive until all owned cleanup ends.
            argv = [paths['python'], '-I', '-S', '-B', str(path),
                    '--manifest', str(args.manifest.absolute()), '--output', str(args.output.absolute()),
                    '--case', 'immediate', '--fault', 'none', '--symbol', SYMBOL, '--execute-approved']
            custody={}
            # Open durable evidence before launching. Parent directory is the
            # fresh session output directory prepared by the approved operator.
            journal=args.output.parent/'watchdog-owner.jsonl'
            journal_fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                durable_record(journal_fd,{'state':'OWNER_ARMED','owner_pid':os.getpid(),
                                         'owner_starttime':api.proc_identity(os.getpid())[1],
                                         'namespace':os.readlink('/proc/self/ns/mnt')})
                parent_fd=os.open(args.output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent_fd)
                finally:os.close(parent_fd)
                report = supervise(api, argv, custody=custody)
                evidence_ok=owner_finish(api,custody,report,lambda value:durable_record(journal_fd,value))
                if not evidence_ok:report['failure']='durable-evidence-unproved'
                for fd,_ in custody['owned'].items.values():os.close(fd)
            finally:os.close(journal_fd)
    finally:
        os.close(source_fd)
        os.close(held)
    # One small terminal record only after cleanup; a blocked report sink cannot
    # keep the observed processes alive. No runtime-success assertion here.
    print(json.dumps(report), flush=True)
    return 0 if report['processes_reaped'] and report['failure'] is None and report['supervisor_returncode']==0 else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, ValueError): sys.exit(2)
