"""Disposable amd64/systemd VM only. Execute the real maintenance handoff.

No monkeypatching or test hooks in either executable. ptrace kills the helper
at its actual rename syscall. External ipify/snap fixtures live in the Go test.
"""
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import sys
import time

root = Path(sys.argv[1])
assert os.geteuid() == 0
assert Path('/run/sbxr-isolated-test-host').read_text() == 'disposable SBXR test VM\n'
work = Path('/root/sbxr-v3175-recovery')
work.mkdir(mode=0o700)
helper = work / 'sbxr-snapshot-recovery'
plan = work / 'vps-plan.json'
shutil.copyfile(root / 'sbxr-snapshot-recovery', helper)
shutil.copyfile(root / 'plan.json', plan)
helper.chmod(0o700)
plan.chmod(0o600)
print('helper_sha256='+hashlib.sha256(helper.read_bytes()).hexdigest(),flush=True)
print('original_executable_sha256='+hashlib.sha256(Path('/usr/local/bin/sbxr').read_bytes()).hexdigest(),flush=True)
state = Path('/var/lib/sbxr/subscription-serving.json')
staged = Path('/var/lib/sbxr/subscription-staging/serving.json')
source = (root / 'source.json').read_bytes()
target = (root / 'target.json').read_bytes()
post_reboot = json.loads(plan.read_bytes())['service_mode'] == 'post-reboot-quiescent-v1'
lock_path = Path('/run/lock/sbxr.lock')

# Exercise actual owned renewal-config removal and shared ACME preservation.
# These are local file fixtures; no Certbot invocation is possible here.
shared = {
    '/etc/letsencrypt/accounts/unrelated/fixture': b'keep shared account fixture\n',
    '/etc/letsencrypt/archive/unrelated/fixture': b'keep unrelated lineage fixture\n',
    '/etc/letsencrypt/renewal/unrelated.conf': b'archive_dir = /etc/letsencrypt/archive/unrelated\n',
}
for name, body in shared.items():
    p = Path(name)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    assert not p.exists()
    p.write_bytes(body)
    p.chmod(0o600)
owned_conf = Path('/etc/letsencrypt/renewal/sbxr-subscription.conf')
owned_conf.write_text('archive_dir = /etc/letsencrypt/archive/sbxr-subscription\n'
                      'cert = /etc/letsencrypt/live/sbxr-subscription/cert.pem\n')
owned_conf.chmod(0o600)


def run(args, **kwargs):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=120, **kwargs)


def command(args):
    result = run(args)
    assert result.returncode == 0, result.stdout.decode()


def inventory(include_snapshot=True):
    paths = [Path('/usr/local/bin/sbxr'), Path('/etc/sing-box/config.json')]
    for directory in ['/var/lib/sbxr', '/etc/letsencrypt', '/var/lib/letsencrypt',
                      '/var/log/letsencrypt', '/etc/systemd/system']:
        paths += [p for p in Path(directory).rglob('*') if p.is_file() or p.is_symlink()]
    result = {}
    for p in paths:
        if not include_snapshot and (p == state or staged.parent in p.parents):
            continue
        s = p.lstat()
        result[str(p)] = (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                          s.st_nlink, s.st_mtime_ns,
                          os.readlink(p) if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest())
    return result


def call(mode='apply', accepted=True):
    before = inventory(include_snapshot=False)
    started = time.monotonic()
    output = run(['env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', str(helper), mode, str(plan)])
    text = output.stdout.decode()
    after = inventory(include_snapshot=False)
    if (output.returncode == 0) != accepted or before != after:
        # Capture the failed boundary before the Go fixture's mandatory cleanup.
        # Hashes and service facts suffice; never copy credential/key contents.
        facts = {
            'mode': mode, 'exit': output.returncode, 'output': text,
            'elapsed_seconds': time.monotonic() - started,
            'before': before, 'after': after,
            'snapshot_sha256': hashlib.sha256(state.read_bytes()).hexdigest(),
            'staging': sorted(p.name for p in staged.parent.iterdir()),
            'services': run(['systemctl', 'show',
                '--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,UnitFileState',
                'sing-box.service', 'sbxr-subscription.service',
                'snap.certbot.renew.service', 'snap.certbot.renew.timer']).stdout.decode(),
        }
        failure = root / 'failure.json'
        failure.write_text(json.dumps(facts, indent=2) + '\n')
        failure.chmod(0o600)
    assert (output.returncode == 0) == accepted, (output.returncode, text)
    assert before == after, 'helper changed protected material'
    print(f'{mode} exit={output.returncode}: {text.strip()}', flush=True)
    return text


def refusal(label, mutate, restore, mode='apply'):
    try:
        mutate()
        before = inventory()
        call(mode, accepted=False)
        assert before == inventory(), label + ': refusal wrote files'
    finally:
        restore()
    print('PASS refusal: ' + label, flush=True)


def replace(p, data):
    before = p.read_bytes()
    refusal(str(p), lambda: p.write_bytes(data), lambda: p.write_bytes(before))


def menu(confirm, name):
    initial = run(['/usr/local/bin/sbxr'], input=b'0\n')
    text = initial.stdout.decode()
    match = re.search(r'(?m)^(\d+)\. Complete removal$', text)
    assert initial.returncode == 0 and match, text
    answer = 'REMOVE SBXR' if confirm else 'no'
    result = run(['/usr/local/bin/sbxr'], input=(match[1]+'\n'+answer+'\n0\n').encode())
    (root / name).write_bytes(result.stdout)
    assert result.returncode == 0, result.stdout.decode()
    return result.stdout.decode()


# Killing real processes at rename entry/exit proves staged and published retry.
# Follow threads because Go can migrate the publishing goroutine between them.
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


class Registers(ctypes.Structure):
    _fields_ = [(n,ctypes.c_ulonglong) for n in
                'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]


def ptrace(request, pid, data=0):
    argument = ctypes.c_void_p(data) if isinstance(data,int) else ctypes.cast(data,ctypes.c_void_p)
    result = libc.ptrace(request,pid,None,argument)
    if result == -1:
        raise OSError(ctypes.get_errno(), 'ptrace')
    return result


def interrupt(after, lock_creation=False):
    pid=os.fork()
    if pid==0:
        os.setsid()
        fd=os.open(str(root/('interrupt-lock.log' if lock_creation else 'interrupt-after.log' if after else 'interrupt-before.log')),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        os.dup2(fd,1);os.dup2(fd,2)
        ptrace(0,0)
        os.kill(os.getpid(),signal.SIGSTOP)
        os.execv(str(helper),[str(helper),'apply',str(plan)])
    os.waitpid(pid,0)
    # TRACESYSGOOD | TRACEFORK | TRACEVFORK | TRACECLONE | EXITKILL
    ptrace(0x4200,pid,0x10000f)
    ptrace(24,pid)
    saw_entry=set()
    interrupted=False
    try:
        while True:
            child,status=os.waitpid(-1,0x40000000)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if child==pid: break
                continue
            sig=os.WSTOPSIG(status)
            event=status>>16
            if sig==(signal.SIGTRAP|0x80):
                regs=Registers();ptrace(12,child,ctypes.byref(regs))
                # Stop at the real openat return that created the volatile
                # lock, before any snapshot publication can be attempted.
                if lock_creation and regs.orig_rax == 257 and regs.rax < (1 << 63):
                    try:
                        opened = os.readlink(f'/proc/{child}/fd/{regs.rax}')
                    except FileNotFoundError:
                        opened = ''
                    if opened == str(lock_path):
                        interrupted = True
                        break
                # Go uses renameat(2) on amd64 Linux; also recognize rename(2).
                if not lock_creation and regs.orig_rax in (82,264):
                    if child not in saw_entry:
                        saw_entry.add(child)
                        if not after:
                            interrupted=True;break
                    else:
                        assert regs.rax==0, 'rename failed'
                        interrupted=True;break
                ptrace(24,child)
            else:
                ptrace(24,child,0 if event or sig in (signal.SIGTRAP,signal.SIGSTOP) else sig)
        assert interrupted, 'helper did not reach requested filesystem boundary'
    finally:
        try: os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError: pass
        # Drain traced threads and descendants; each stopped thread must resume
        # with SIGKILL, otherwise it retains its locks and cleanup could hang.
        while True:
            try:
                child,status=os.waitpid(-1,0x40000000)
                if os.WIFSTOPPED(status): ptrace(24,child,signal.SIGKILL)
            except ChildProcessError: break
    if lock_creation:
        info = lock_path.lstat()
        assert state.read_bytes() == source and not staged.exists()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and info.st_size == 0
        print('PASS interrupted after actual protected lock creation', flush=True)
        return
    if after:
        assert state.read_bytes()==target and not staged.exists()
    else:
        assert state.read_bytes()==source and staged.read_bytes()==target
    print('PASS interrupted '+('after' if after else 'before')+' actual rename',flush=True)



# Prove the original defect through the exact public menu, before the helper.
before = inventory()
text = menu(True, 'original-before.txt')
assert 'PROXY-INSTALLATION-ACTION-REFUSED' in text and 'Subscription absence' in text, text
assert before == inventory()
print('PASS exact original executable: mismatch refuses Complete removal', flush=True)

# The runbook's protected backup command, at its exact future host path.
backup_result = run(['tar','--acls','--xattrs','-cpf',str(work/'before.tar'),'-C','/',
 'usr/local/bin/sbxr','var/lib/sbxr','etc/sing-box','var/lib/sing-box',
 'etc/letsencrypt','etc/systemd/system/sbxr-subscription.service',
 'etc/systemd/system/sbxr-subscription-firewall.service',
 'etc/systemd/system/sing-box.service.d','etc/systemd/system/snap.certbot.renew.service.d'])
assert backup_result.returncode == 0, backup_result.stdout
(work/'before.tar').chmod(0o600)
assert stat.S_IMODE((work/'before.tar').stat().st_mode) == 0o600
print('PASS protected backup at exact runbook path',flush=True)
before = inventory()
if post_reboot:
    # The original removal attempt may create the ordinary mutation lock.
    # Restore the observed absent-lock fixture before testing this handoff.
    if lock_path.exists():
        info = lock_path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and info.st_size == 0
        lock_path.unlink()
    assert 'post-reboot whole-host lock absent; apply required' in call('check', accepted=False)
    assert not lock_path.exists(), 'read-only check created a lock'
    ownership_path = Path('/var/lib/sbxr/proxy-ownership.json')
    replace(ownership_path, ownership_path.read_bytes() + b' ')
    assert not lock_path.exists(), 'changed identity created a lock'
    interrupt(False, lock_creation=True)
before = inventory()
assert 'checked: source' in call('check')
assert before == inventory(), 'check mutated files'
replace(Path('/var/lib/sbxr/installed.json'), Path('/var/lib/sbxr/installed.json').read_bytes()+b' ')
replace(Path('/var/lib/sbxr/proxy-ownership.json'), Path('/var/lib/sbxr/proxy-ownership.json').read_bytes()+b' ')
executable = Path('/usr/local/bin/sbxr')
original_executable = root / 'original-executable.fixture'
executable.rename(original_executable)
try:
    refusal('changed executable',
            lambda: (executable.write_bytes(original_executable.read_bytes()+b'x'), executable.chmod(0o755)),
            lambda: executable.unlink())
finally:
    original_executable.rename(executable)
replace(Path('/etc/sing-box/config.json'), b'{}\n')
firewall_unit = Path('/etc/systemd/system/sbxr-subscription-firewall.service')
replace(firewall_unit, firewall_unit.read_bytes() + b'# unexpected\n')
firewall_rule = ['-d', '8.8.8.8/32', '-p', 'tcp', '--dport', '8443',
                 '-m', 'comment', '--comment', 'sbxr-subscription', '-j', 'ACCEPT']
refusal('missing managed firewall rule',
        lambda: command(['iptables', '-D', 'INPUT'] + firewall_rule),
        lambda: command(['iptables', '-I', 'INPUT', '1'] + firewall_rule))
replace(Path('/var/lib/sbxr/subscription-token'), b'B'*43+b'\n')
replace(state, target+b' ')
replace(Path('/etc/letsencrypt/archive/sbxr-subscription/cert2.pem'), b'changed\n')
original_plan = plan.read_bytes()
bad_plan = json.loads(original_plan)
bad_plan['target_sha256'] = 'a'*64
refusal('target binding', lambda: plan.write_text(json.dumps(bad_plan,separators=(',',':'))+'\n'), lambda: plan.write_bytes(original_plan))
bad_plan = json.loads(original_plan)
bad_plan['service_mode'] = 'unknown'
refusal('unknown service contract', lambda: plan.write_text(json.dumps(bad_plan,separators=(',',':'))+'\n'), lambda: plan.write_bytes(original_plan))
refusal('unsafe plan', lambda: plan.chmod(0o644), lambda: plan.chmod(0o600))
lock_backup = lock_path.with_name('sbxr-recovery.fixture-backup')
assert not lock_backup.exists()
refusal('missing whole-host lock', lambda: lock_path.rename(lock_backup), lambda: lock_backup.rename(lock_path),
        mode='check' if post_reboot else 'apply')
refusal('unsafe whole-host lock', lambda: lock_path.chmod(0o666), lambda: lock_path.chmod(0o600))
lock_path.rename(lock_backup)
try:
    refusal('symlink whole-host lock', lambda: lock_path.symlink_to(lock_backup), lambda: lock_path.unlink())
    refusal('FIFO whole-host lock', lambda: os.mkfifo(lock_path, 0o600), lambda: lock_path.unlink())
finally:
    lock_backup.rename(lock_path)
lock_hardlink = lock_path.with_name('sbxr-recovery.fixture-hardlink')
refusal('hardlink whole-host lock', lambda: os.link(lock_path, lock_hardlink), lambda: lock_hardlink.unlink())
trust_path = Path('/etc/ssl/certs/sbxr-isolated.pem')
trust_backup = root / 'ca.fixture-backup'
refusal('untrusted accepted certificate', lambda: trust_path.rename(trust_backup), lambda: trust_backup.rename(trust_path))
refusal('unsafe snapshot mode' , lambda: state.chmod(0o644), lambda: state.chmod(0o600))
refusal('unsafe staging directory', lambda: staged.parent.chmod(0o777), lambda: staged.parent.chmod(0o700))
backup = root / 'snapshot.fixture-backup'
state.rename(backup)
try:
    refusal('symlink snapshot', lambda: state.symlink_to(backup), lambda: state.unlink())
finally:
    backup.rename(state)
hardlink = root / 'snapshot.fixture-hardlink'
refusal('hardlink snapshot', lambda: os.link(state, hardlink), lambda: hardlink.unlink())
refusal('foreign staging', lambda: (staged.parent/'foreign').write_text('unknown'), lambda: (staged.parent/'foreign').unlink())
refusal('partial publication staging', lambda: (staged.write_text('{"schema":'), staged.chmod(0o600)), lambda: staged.unlink())
for p, kind in [('/run/lock/sbxr.lock','flock'),
                ('/var/lib/sbxr/renewal-admission.lock','flock'),
                ('/var/lib/sbxr/renewal-writer.lock','flock'),
                ('/etc/letsencrypt/.certbot.lock','posix'),
                ('/var/lib/letsencrypt/.certbot.lock','posix'),
                ('/var/log/letsencrypt/.certbot.lock','posix')]:
    # POSIX locks belong to a process: the inventory reader must not close
    # another descriptor for the holder's inode and silently release its lock.
    holder = subprocess.Popen([sys.executable, '-c',
        "import fcntl,sys; f=open(sys.argv[1],'r+'); "
        "locking=fcntl.flock if sys.argv[2]=='flock' else fcntl.lockf; "
        "locking(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('ready',flush=True); sys.stdin.read()",
        p, kind], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert holder.stdout.readline() == b'ready\n'
        before = inventory()
        call(accepted=False)
        assert before == inventory()
    finally:
        holder.communicate(timeout=10)
        assert holder.returncode == 0
    print('PASS contention: '+p, flush=True)


def refill_active_source(seconds=60):
    if not post_reboot:
        # The original server admits a burst of six and one new request per
        # ten seconds. Check consumes one; apply consumes three. Give each
        # interruption/check/apply sequence a full known request budget.
        # This is deliberate load pacing, never retrying a refused operation.
        print(f'PACE original serving request budget: {seconds}s', flush=True)
        time.sleep(seconds)


certbot_paths = [Path(p) / '.certbot.lock' for p in
                 ['/etc/letsencrypt', '/var/lib/letsencrypt', '/var/log/letsencrypt']]
if post_reboot:
    # The observed VPS has no idle Certbot lock files. A normal successful
    # transaction creates/locks them and removes only its own empty inodes.
    for p in certbot_paths:
        assert p.read_bytes() == b''
        p.unlink()
    call()
    assert state.read_bytes() == target and all(not p.exists() for p in certbot_paths)
    print('PASS absent Certbot locks: created, retained through publication, removed on success', flush=True)
    state.write_bytes(source)

preserved=inventory(include_snapshot=False)
refill_active_source()
interrupt(False)
if post_reboot:
    # Process death can leave exactly the shared lock inodes it created.
    # Validate that explicit residue, and preserve those inodes on forward retry.
    interrupted_inventory = inventory(include_snapshot=False)
    additions = set(interrupted_inventory) - set(preserved)
    assert additions == {str(p) for p in certbot_paths}, sorted(additions)
    for p in certbot_paths:
        info = p.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and info.st_size == 0
        del interrupted_inventory[str(p)]
    assert interrupted_inventory == preserved
    preserved = inventory(include_snapshot=False)
assert 'checked: source' in call('check')
call()
assert state.read_bytes()==target and not staged.exists()
assert preserved==inventory(include_snapshot=False)
# Rebuild only the disposable source snapshot to exercise the second boundary.
state.write_bytes(source)
refill_active_source()
interrupt(True)
assert 'checked: target' in call('check')
call()
refill_active_source(30)
call()
assert state.read_bytes()==target and not staged.exists()
replace(Path('/etc/letsencrypt/archive/sbxr-subscription/cert1.pem'), b'changed old archive\n')
print('PASS idempotent target completion and preservation of file identities',flush=True)

# The exact original menu must now review, permit decline, then remove once.
refill_active_source()
preserved=inventory()
text=menu(False,'original-declined.txt')
assert 'Type REMOVE SBXR' in text and 'PROXY-INSTALLATION-ACTION-REFUSED' not in text, text
assert preserved==inventory()
text=menu(True,'original-removed.txt')
assert 'SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED' in text and 'SBXR is not installed.' in text, text
for p in ['/usr/local/bin/sbxr','/var/lib/sbxr','/var/lib/.sbxr-removal.json',
          '/etc/sing-box','/var/lib/sing-box','/usr/bin/sing-box',
          '/etc/letsencrypt/archive/sbxr-subscription','/etc/letsencrypt/live/sbxr-subscription',
          '/etc/letsencrypt/renewal/sbxr-subscription.conf',
          '/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription',
          '/etc/letsencrypt/renewal-hooks/post/sbxr-subscription',
          '/etc/apt/keyrings/sagernet.asc',
          '/etc/apt/sources.list.d/sagernet.sources',
          '/etc/systemd/system/sbxr-subscription.service',
          '/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service',
          '/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service',
          '/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf',
          '/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf',
          '/etc/systemd/system/sbxr-subscription-firewall.service']:
    assert not os.path.lexists(p), p+' remains'
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        argv = Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')
        if not argv[0]:
            continue
        executable = Path(os.readlink('/proc/'+pid+'/exe')).name.removesuffix(' (deleted)')
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            continue
        raise
    assert executable not in {'sbxr', 'sing-box', 'sbxr-snapshot-recovery'}, (pid, executable)
    assert os.path.basename(argv[0]) not in {b'sbxr', b'sing-box', b'sbxr-snapshot-recovery'}, pid
for unit in ['sing-box.service', 'sbxr-subscription-firewall.service', 'sbxr-subscription.service']:
    observed = run(['systemctl', 'show', '--property=LoadState,ActiveState,MainPID', unit])
    fields = dict(line.split('=', 1) for line in observed.stdout.decode().strip().splitlines())
    if post_reboot and unit == 'sbxr-subscription.service' and fields == {
        'LoadState': 'not-found', 'ActiveState': 'failed', 'MainPID': '0',
    }:
        # stop/disable do not clear systemd's remembered failure. The original
        # menu has completed and removed its unit/wants; clear only that exact
        # historical subscription failure as a separate maintenance cleanup.
        detail = run(['systemctl', 'show', '--property=SubState,Result,ExecMainCode,ExecMainStatus', unit])
        details = dict(line.split('=', 1) for line in detail.stdout.decode().strip().splitlines())
        assert detail.returncode in (0, 1) and details == {
            'SubState': 'failed', 'Result': 'exit-code', 'ExecMainCode': '1', 'ExecMainStatus': '1',
        }
        assert not run(['ss', '-H', '-ltnp', 'sport', '=', ':8443']).stdout
        print('original removal retained failure='+json.dumps({**fields, **details}, sort_keys=True), flush=True)
        command(['systemctl', 'reset-failed', unit])
        print('PASS maintenance cleanup: cleared exact removed subscription failure', flush=True)
        observed = run(['systemctl', 'show', '--property=LoadState,ActiveState,MainPID', unit])
        fields = dict(line.split('=', 1) for line in observed.stdout.decode().strip().splitlines())
    assert observed.returncode in (0, 1) and fields == {
        'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0',
    }, (unit, observed.returncode, fields)
    print('PASS removed unit: '+unit, flush=True)
for name in ['passwd','group']:
    assert run(['getent',name,'sing-box']).returncode==2
assert run(['systemctl','is-active','ssh.service']).stdout.strip()==b'active'
assert run(['systemctl','is-active','snap.certbot.renew.timer']).stdout.strip()==b'active'
assert run(['systemctl','show','--property=ExecStart','--value','snap.certbot.renew.service']).stdout.find(b'/usr/bin/snap run')>=0
assert not run(['ss','-H','-ltnp','sport','=',':8443']).stdout
assert b'sbxr-subscription' not in run(['iptables-save','-t','filter']).stdout
assert Path('/usr/bin/snap').exists()
for name,body in shared.items():
    assert Path(name).read_bytes()==body, 'shared ACME material changed: '+name
print('PASS exact original executable: Complete removal, SSH/timer/dependencies preserved',flush=True)
