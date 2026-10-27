"""One-session fixture supervisor. Import/tests are inert; main requires approval.
No product support, process-name matching, process-group kills or general runner.
"""
import argparse
import ctypes
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import select
import signal
import stat
import subprocess
import sys
import time


class Refusal(Exception):
    pass


class Capture:
    def __init__(self, limit):
        self.limit, self.data, self.pending = limit, bytearray(), bytearray()

    def feed(self, chunk):
        if len(self.data) + len(chunk) > self.limit:
            raise Refusal('output-overflow')
        self.data.extend(chunk)
        self.pending.extend(chunk)
        lines = []
        while b'\n' in self.pending:
            line, _, rest = self.pending.partition(b'\n')
            self.pending[:] = rest
            if len(line) > 256:
                raise Refusal('line-overflow')
            lines.append(line.decode('ascii', errors='strict'))
        if len(self.pending) > 256:
            raise Refusal('line-overflow')
        return lines


class Gate:
    def __init__(self, pid, observed, case, fault):
        self.pid, self.observed, self.case, self.fault = pid, observed, case, fault
        self.gated = self.attached = self.sent = self.closed = self.complete = False
        self.child_at = None
        self.children = set()
        self.unrelated = None

    def line(self, source, line, now):
        if source == 'wrapper':
            if line != f'SBXR_DNS_OBSERVER_ATTACHED {self.pid}' or self.attached:
                raise Refusal('attachment-receipt')
            self.attached = True
        elif line == f'GATED {self.pid}' and not self.gated:
            self.gated = True
        elif re.fullmatch(r'(CHILD|UNRELATED) [1-9][0-9]{0,9}', line):
            kind, number = line.split(); number = int(number)
            if not self.sent or number == self.pid or number in self.children:
                raise Refusal('child-receipt')
            if kind == 'UNRELATED':
                if self.case != 'unrelated' or self.unrelated is not None or self.child_at is not None:
                    raise Refusal('unrelated-receipt')
                self.unrelated = number
            else:
                if self.child_at is not None:
                    raise Refusal('duplicate-child')
                if self.case == 'unrelated' and self.unrelated is None:
                    raise Refusal('missing-unrelated')
                self.child_at = now
            self.children.add(number)
        elif line == 'COMPLETE' and self.child_at is not None and not self.complete:
            self.complete = True
        else:
            raise Refusal('fixture-receipt')

    def input(self, now):
        if self.fault == 'withhold':
            return b''
        if self.gated and (self.attached or not self.observed) and not self.sent:
            self.sent = True
            return b'G'
        if self.case == 'pipe-wait' and self.child_at is not None and not self.closed and now-self.child_at >= .05:
            self.closed = True
            return b'C'
        return b''


def cleanup_decision(elapsed):
    return 'deadline' if elapsed >= 5 else 'KILL' if elapsed >= 2 else 'TERM'


def stat_identity(raw):
    fields = raw[raw.rfind(')')+2:].split()
    return int(fields[1]), int(fields[19])  # parent PID, starttime


class Ownership:
    """pidfd registration requires two stable ancestry/starttime observations."""
    def __init__(self, self_pid):
        self.self_pid, self.items = self_pid, {}

    def eligible(self, pid, before, after, live_parents):
        return (pid != self.self_pid and pid > 1 and before == after
                and after[0] in live_parents and pid not in self.items)

    def signal_owned(self, sender, sig):
        # Attempt every known handle even if one fails; report failure afterward.
        errors=[]
        # Only stored pidfds; never signal by numeric PID or process group.
        for pid, (fd, start) in list(self.items.items()):
            try:
                sender(fd, sig, None, 0)
            except ProcessLookupError:
                pass
            except OSError as error:
                errors.append(error)
        if errors:raise errors[0]


def proc_identity(pid):
    return stat_identity(Path(f'/proc/{pid}/stat').read_text())


def discover(owned):
    for pid,(fd,_) in list(owned.items.items()):
        if select.select([fd],[],[],0)[0]:
            os.close(fd); del owned.items[pid]
    queue = [owned.self_pid]
    parents = {owned.self_pid}
    seen = set()
    while queue:
        parent = queue.pop()
        if parent in seen:
            continue
        seen.add(parent)
        if parent != owned.self_pid:
            try:
                fd, start = owned.items[parent]
                if select.select([fd], [], [], 0)[0]: continue
                if proc_identity(parent)[1] != start: raise Refusal('parent-reuse')
            except (FileNotFoundError, ProcessLookupError): continue
        if len(seen) > 32:
            raise Refusal('process-bound')
        try:
            tasks = list(Path(f'/proc/{parent}/task').iterdir())
            overflow = len(tasks) > 128
            tasks = sorted(tasks, key=lambda x:int(x.name))[:128]
            children = set()
            for task in tasks:
                with (task/'children').open() as stream: raw = stream.read(4097)
                if len(raw) > 4096:
                    overflow = True
                    raw = raw[:4096].rsplit(' ',1)[0]
                children.update(map(int,raw.split()))
                if len(children) > 32:
                    overflow = True
                    break
        except FileNotFoundError:
            continue
        for pid in sorted(children)[:32]:
            try:
                before = proc_identity(pid)
                if pid not in owned.items:
                    if len(owned.items) >= 64: raise Refusal('owned-process-bound')
                    fd = os.pidfd_open(pid, 0)
                    try:
                        after = proc_identity(pid)
                        if parent != owned.self_pid and (select.select([owned.items[parent][0]], [], [], 0)[0] or proc_identity(parent)[1] != owned.items[parent][1]):
                            raise Refusal('parent-exited-during-discovery')
                        if not owned.eligible(pid, before, after, parents):
                            raise Refusal('ownership-race')
                        owned.items[pid] = (fd, after[1])
                    except BaseException:
                        os.close(fd)
                        raise
                elif owned.items[pid][1] != before[1]:
                    raise Refusal('pid-reuse')
                parents.add(pid)
                queue.append(pid)
            except ProcessLookupError:
                continue
            except FileNotFoundError:
                continue
        if overflow:
            raise Refusal('partial-descendant-inventory')


def pin(path, digest):
    if not re.fullmatch('[a-f0-9]{64}', digest):
        raise Refusal('digest-format')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 512*1024*1024:
            raise Refusal('file-kind-size')
        h = hashlib.sha256()
        while chunk := os.read(fd, 1024*1024):
            h.update(chunk)
        final = os.fstat(fd)
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        if h.hexdigest() != digest or any(getattr(final,k) != getattr(st,k) for k in fields):
            raise Refusal('file-identity')
        return (st.st_dev, st.st_ino)
    finally:
        os.close(fd)


def live_fixture(pid, identity):
    st = os.stat(f'/proc/{pid}/exe')
    if (st.st_dev, st.st_ino) != identity:
        raise Refusal('fixture-executable')
    for ns in ('pid', 'time'):
        a, b = Path(f'/proc/{pid}/ns/{ns}'), Path(f'/proc/self/ns/{ns}')
        if not a.exists() or not b.exists() or os.readlink(a) != os.readlink(b):
            raise Refusal('namespace-identity')
    offsets = Path(f'/proc/{pid}/timens_offsets').read_text().splitlines()
    if any(line.split()[1:] != ['0','0'] for line in offsets):
        raise Refusal('time-offset')


def reap_adopted(direct):
    # Popen owns direct child wait statuses; wait only adopted children here.
    children = Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
    remaining = []
    for raw in children:
        pid = int(raw)
        if pid in direct:
            continue
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                remaining.append(pid)
        except ChildProcessError:
            pass
    return remaining


def result(case, fault, failed, statuses, residual, elapsed):
    reaped = all(rc is not None for rc in statuses.values()) and not residual
    return {'outcome':'refused' if failed or not reaped else 'process-checks-passed',
            'failure':failed,'processes_reaped':reaped,'returncodes':statuses,
            'kernel_cleanup':'UNVERIFIED: independent before/after probe/map/perf inventory required',
            'elapsed_seconds':elapsed,'case':case,'fault':fault}


def readonly_superblock(fd):
    if not os.fstatvfs(fd).f_flag & os.ST_RDONLY:
        raise Refusal('runtime-input-mount-writable')
    info = Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines()
    mount_id = next((line.split()[1] for line in info if line.startswith('mnt_id:')),None)
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,right = line.split(' - ',1)
        if left.split()[0] == mount_id:
            # Only reviewed local filesystems; immutable underlying storage and
            # no privileged remount/raw-write actor remain platform assumptions.
            if right.split()[0] not in {'ext4','xfs','btrfs','squashfs','erofs'}:
                raise Refusal('runtime-input-filesystem-unreviewed')
            # Read-only bind views over writable superblocks are insufficient.
            if 'ro' not in right.split()[2].split(','):
                raise Refusal('runtime-input-superblock-writable')
            return
    raise Refusal('runtime-input-mount-unknown')


@contextmanager
def immutable_inputs(manifest):
    spec = json.loads(manifest.read_text())
    if set(spec) != {'fixture','wrapper','checker','template','tracer','python'}:
        raise Refusal('manifest-keys')
    held=[]; directories={}; paths={}; ids={}
    try:
        for name,item in sorted(spec.items()):
            p = Path(item['path']).absolute()
            directory = os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            held.append(directory); readonly_superblock(directory)
            st=os.fstat(directory); key=(st.st_dev,st.st_ino)
            if key in directories:
                held.pop(); os.close(directory); directory=directories[key]
            else: directories[key]=directory
            fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            held.append(fd); readonly_superblock(fd)
            # Parent-anchored path survives child close_fds=True and remains
            # valid while this supervisor retains the immutable directory.
            anchored=f'/proc/{os.getpid()}/fd/{directory}/{p.name}'
            ids[name]=pin(anchored,item['sha256']); paths[name]=anchored
            st=os.fstat(fd)
            if ids[name] != (st.st_dev,st.st_ino):raise Refusal('runtime-input-replaced')
        for name,basename in [('checker','dns-child-observer.py'),('template','dns-child-observer.bt.in')]:
            if Path(paths[name]).parent != Path(paths['wrapper']).parent or Path(paths[name]).name != basename:
                raise Refusal('wrapper-input-location')
        reject_bytecode_cache(Path(paths['checker']))
        yield spec,paths,ids
    finally:
        for fd in reversed(held):os.close(fd)


def reject_bytecode_cache(checker):
    # -B forbids cache writes, not loading existing bytecode. The directory is
    # immutable, so absence remains stable until all observer processes finish.
    for path in (checker.parent/'__pycache__',checker.with_suffix('.pyc')):
        try:path.lstat()
        except FileNotFoundError:continue
        raise Refusal('unchecked-python-bytecode')


def runtime_setup():
    if Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip():
        raise Refusal('preexisting-children')
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(36,1,0,0,0)!=0:raise Refusal('subreaper-unavailable')


def cleanup_tick(owned, sig, procs=None):
    errors=[]
    def reap():
        if procs is None:return
        for child in procs.values():
            try:child.poll()
            except OSError:errors.append('direct-reap-unproved')
        try:reap_adopted({child.pid for child in procs.values()})
        except OSError:errors.append('adopted-reap-unproved')
    # Reap independently of discovery to avoid repeatedly scanning zombie
    # prefixes when an oversized inventory is handled in bounded batches.
    reap()
    try:discover(owned)
    except (OSError,ValueError,Refusal):errors.append('discovery-unproved')
    # Discovery failure must never skip already established ownership.
    try:owned.signal_owned(signal.pidfd_send_signal,sig)
    except OSError:errors.append('cleanup-signal-denied')
    reap()
    return errors


def before_input(started):
    now=time.monotonic()
    if now-started>=105:raise Refusal('watchdog-expired')
    return now


def run(args):
    if not args.execute_approved or sys.platform!='linux':
        raise Refusal('runtime-approval-required')
    with immutable_inputs(args.manifest) as inputs:
        runtime_setup()
        return execute(args,*inputs)


def execute(args,spec,paths,ids):
    # Effectful orchestration; tests replace all OS/process adapters.
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    owned = Ownership(os.getpid()); selector = selectors.DefaultSelector()
    procs = {}; captures = {}; failed = None; cleanup_at = None
    started = time.monotonic(); injected = False; blocked_fd = None
    interrupted = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda s, f: interrupted.append(s) if not interrupted else None)
    env = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}

    def start(name, argv, stdin, stdout=subprocess.PIPE):
        p = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE,
                             env=env, close_fds=True)
        procs[name] = p
        # Popen retains direct-child wait ownership even if it exits immediately.
        fd = os.pidfd_open(p.pid,0)
        try:
            parent, born = proc_identity(p.pid)
            if parent != os.getpid(): raise Refusal('direct-child-ownership')
            owned.items[p.pid] = (fd,born)
        except BaseException:
            os.close(fd)
            raise
        for label, stream in [('out',p.stdout),('err',p.stderr)]:
            if stream is None:
                continue
            os.set_blocking(stream.fileno(), False)
            key = name+'-'+label; captures[key] = Capture(1024 if name=='fixture' else 8192)
            selector.register(stream, selectors.EVENT_READ, key)
        return p

    try:
        fixture = start('fixture',[paths['fixture'],args.case],subprocess.PIPE)
        os.set_blocking(fixture.stdin.fileno(),False)
        gate = Gate(fixture.pid,not args.baseline,args.case,args.fault)
        if not args.baseline:
            argv = [paths['python'],'-I','-S','-B',paths['wrapper'],'--bpftrace',paths['tracer'],
                    '--bpftrace-sha256',spec['tracer']['sha256'],'--executable',paths['fixture'],
                    '--symbol',args.symbol,'--pid',str(fixture.pid),'--output',str(args.output/'observer')]
            if args.fault == 'blocked-sink':
                rd,wr = os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
                blocked_fd = rd
                try:
                    while True: os.write(wr,b'X'*4096)
                except BlockingIOError: pass
                # Child gets blocking stdout; full pipe deliberately blocks receipt.
                os.set_blocking(wr,True)
                try: start('wrapper',argv,subprocess.DEVNULL,wr)
                finally: os.close(wr)
            else:
                start('wrapper',argv,subprocess.DEVNULL)
        while True:
            now = time.monotonic()
            try:
                discover(owned)
                for key, _ in selector.select(.02):
                    try: chunk = os.read(key.fd,4096)
                    except BlockingIOError: continue
                    if not chunk:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    lines = captures[key.data].feed(chunk)
                    if key.data.endswith('-err'):
                        raise Refusal('child-stderr')
                    for line in lines: gate.line(key.data.split('-')[0],line,time.monotonic())
                statuses = {name:p.poll() for name,p in procs.items()}
                adopted = reap_adopted({p.pid for p in procs.values()})
                if interrupted: raise Refusal('supervisor-interrupted')
                if any(rc not in (None,0) for rc in statuses.values()): raise Refusal('child-failed')
                if not failed:
                    now=before_input(started)
                    data = gate.input(now)
                    if data:
                        live_fixture(fixture.pid, ids['fixture'])
                        before_input(started)
                        os.write(fixture.stdin.fileno(),data)
                    if args.fault == 'observer-exit' and gate.sent and not injected:
                        # Terminate only owned wrapper; tracer is cleaned as descendant.
                        before_input(started)
                        fd = owned.items[procs['wrapper'].pid][0]
                        signal.pidfd_send_signal(fd,signal.SIGTERM,None,0); injected=True
                        raise Refusal('injected-observer-exit')
                if all(rc is not None for rc in statuses.values()) and not adopted:
                    if selector.get_map(): continue  # drain EOF before completion
                    if any(c.pending for c in captures.values()): raise Refusal('partial-output')
                    if not gate.complete and not failed: raise Refusal('incomplete-fixture')
                    break
                if now-started >= 105: raise Refusal('watchdog-expired')
            except (OSError, ValueError, Refusal, KeyError) as exc:
                if failed is None: failed = str(exc) if isinstance(exc,Refusal) else type(exc).__name__
            now=time.monotonic()
            if failed:
                if cleanup_at is None:
                    cleanup_at = now
                    if fixture.stdin and not fixture.stdin.closed: fixture.stdin.close()
                decision = cleanup_decision(now-cleanup_at)
                if decision == 'deadline': break
                errors=cleanup_tick(owned,signal.SIGTERM if decision=='TERM' else signal.SIGKILL,procs)
                if errors: failed=errors[0]
            if now-started >= 110: break
    except (OSError, ValueError, Refusal) as exc:
        failed = str(exc) if isinstance(exc,Refusal) else type(exc).__name__
        # Spawn-time failure still enters bounded owned-descendant cleanup.
        limit = min(started+110,time.monotonic()+5)
        while procs and time.monotonic()<limit:
            try:
                errors=cleanup_tick(owned,signal.SIGKILL,procs)
                if errors:failed=errors[0]
                statuses = [p.poll() for p in procs.values()]
                if all(rc is not None for rc in statuses) and not reap_adopted({p.pid for p in procs.values()}): break
            except (OSError, Refusal): failed='cleanup-unproved'
            time.sleep(.02)
    finally:
        statuses = {name:p.poll() for name,p in procs.items()}
        try: residual = reap_adopted({p.pid for p in procs.values()})
        except OSError: residual = ['unknown']
        processes_reaped = all(rc is not None for rc in statuses.values()) and not residual
        for p in procs.values():
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream is not None and not stream.closed: stream.close()
        selector.close()
        if blocked_fd is not None: os.close(blocked_fd)
        for fd,_ in owned.items.values(): os.close(fd)
    report = result(args.case,args.fault,failed,statuses,residual,time.monotonic()-started)
    # Bounded regular-file writes only after process cleanup; filesystem stalls
    # can still delay evidence publication, never confer a successful result.
    for key,cap in captures.items(): (args.output/(key+'.txt')).write_bytes(cap.data)
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['outcome']=='process-checks-passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--case',choices=['immediate','pipe-wait','unrelated'],required=True)
    p.add_argument('--symbol',required=True)
    p.add_argument('--baseline',action='store_true')
    p.add_argument('--fault',choices=['none','withhold','observer-exit','blocked-sink'],default='none')
    p.add_argument('--execute-approved',action='store_true')
    args=p.parse_args()
    if args.baseline and args.fault!='none': p.error('fault requires observer session')
    if not re.fullmatch('[A-Za-z0-9_.$]+',args.symbol): p.error('exact symbol required')
    try: return run(args)
    except (OSError,ValueError,Refusal): return 2


if __name__=='__main__': sys.exit(main())
