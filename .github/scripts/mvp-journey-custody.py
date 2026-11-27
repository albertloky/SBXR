"""Durable pre-effect identity and post-reap proof for fixed fresh-window actions."""
import ctypes
import hashlib
import json
import fcntl
import os
from contextlib import contextmanager
import re
import stat

EVIDENCE = '/root/sbxr-qualification-evidence'
STAGE = '/root/sbxr-qualification-v3'
# Qualification action caps from the bounded operator runbook, in seconds.
CAPS = {'mvp-install': {'install': 60, 'setup': 240, 'details': 90, 'disclose': 90, 'check': 90},
        'mvp-subscription': {'enable-subscription': 180},
        'mvp-credentials': {'rotate-identity': 90, 'rotate-link': 90},
        'mvp-serving': {'restart-serving': 30},
        'mvp-removal': {'restart-access': 90}}
JOURNAL = STAGE+'/journey-custody.jsonl'
REMOVALS = {'complete-removal':('Complete removal','remove'), 'finish-removal':('Finish removal','none')}
RECORDER = STAGE+'/cleanup-recorder.py'
FIELDS = {'run_id', 'run_attempt', 'manifest_sha256', 'window_sha256', 'request_sha256',
          'machine_sha256', 'scenario', 'operation', 'remote_deadline'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate(intent):
    require(set(intent) == FIELDS, 'launch intent fields differ')
    require(type(intent['run_id']) is int and intent['run_id'] > 0 and
            type(intent['run_attempt']) is int and intent['run_attempt'] == 1, 'launch run or attempt')
    require(all(isinstance(intent[k], str) and re.fullmatch('[0-9a-f]{64}', intent[k])
                for k in ('manifest_sha256', 'window_sha256', 'request_sha256', 'machine_sha256')),
            'launch digest')
    cap = CAPS.get(intent['scenario'], {}).get(intent['operation'])
    if intent['scenario'] in CAPS and intent['operation'] in REMOVALS:
        cap=360
    require(cap is not None and type(intent['remote_deadline']) is int, 'unknown operation or deadline')
    return cap


def anchor(host, intent):
    cap = validate(intent)
    require(not os.path.lexists(host.path(EVIDENCE+'/result.json')), 'collector already received terminal input')
    for name in ('/root', STAGE, EVIDENCE):
        st = host.path(name).lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022,
                'unsafe authority directory')
    manifest = host.read(STAGE + '/qualification-manifest.json')
    window = host.read(STAGE + '/fresh-window-decision.json')
    request = host.read(EVIDENCE + '/request.json')
    require(digest(manifest) == intent['manifest_sha256'] and digest(window) == intent['window_sha256']
            and digest(request) == intent['request_sha256'], 'launch authority bytes differ')
    machine = digest(host.read('/etc/machine-id'))
    require(machine == intent['machine_sha256'] == json.loads(manifest)['v3_attempt']['vps_identity_sha256'],
            'launch machine differs')
    run = str(intent['run_id'])
    require(host.read(STAGE+'/staging-owned') == (run+'-1\n').encode(), 'staging owner differs')
    decision, req = json.loads(window), json.loads(request)
    w = decision['window']
    require(decision['stage'] == 'qualification-window' and decision['outcome'] == 'accepted'
            and w['workflow']['run_id'] == run and type(w['run_attempt']) is int and w['run_attempt'] == 1
            and w['manifest_sha256'] == intent['manifest_sha256']
            and req['qualification_window_sha256'] == intent['window_sha256']
            and req['qualification_manifest_sha256'] == intent['manifest_sha256']
            and req['scenario_id'] == intent['scenario'], 'current request, run or window differs')
    runtime = host.read(STAGE+'/runtime-deadline', 32)
    require(re.fullmatch(rb'[1-9][0-9]{0,9}\n', runtime), 'runtime cutoff unavailable')
    phase_end = w['finish_unix'] - 60 if intent['scenario'] == 'mvp-removal' else w['test_until_unix']
    limit = min(req['deadline_unix'], int(runtime), phase_end)
    require(type(req['deadline_unix']) is int and type(w['run_attempt']) is int and
            w['start_unix'] <= host.now() < limit, 'launch window expired')
    return cap, limit


def journal(host):
    raw=host.read(JOURNAL, 256<<10)
    require(raw.endswith(b'\n'), 'incomplete custody journal')
    header,*lines=raw.splitlines()
    expected=host.read(STAGE+'/staging-owned').strip()+b' '+digest(host.read(STAGE+'/qualification-manifest.json')).encode()
    require(header==expected and len(lines)<=80,'foreign or oversized custody journal')
    records={}
    for raw in lines:
        name, value=json.loads(raw)
        require(name not in records and canonical([name,value])==raw,'duplicate or partial custody record')
        records[name]=value
    return records


def append(host, name, value):
    # The staging owner creates this one private file. All writers hold the
    # directory lock. A torn append prevents further actions or a positive proof.
    if name in journal(host):
        raise FileExistsError('existing custody record')
    fd=os.open(host.path(JOURNAL),os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'ab') as stream:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.geteuid()
                and stat.S_IMODE(st.st_mode)==0o600,'unsafe custody journal')
        stream.write(canonical([name,value])+b'\n')
        stream.flush()
        os.fsync(fd)


def filename(intent):
    validate(intent)
    # One slot per request and operation, independent of the proposed timeout.
    slot='supported-removal' if intent['operation'] in REMOVALS else intent['operation']
    return 'launch-' + intent['request_sha256'] + '-' + slot + '.json'


def process_identity(host, pid, deadline):
    require(type(pid) is int and pid > 0 and (not host.native or pid == os.getpid()), 'launch PID')
    raw = host.path('/proc/'+str(pid)+'/stat').read_bytes()
    head, tail = raw.rsplit(b') ', 1)
    fields = tail.split()
    require(head.split(b' (', 1)[0] == str(pid).encode() and int(fields[2]) == pid
            and int(fields[3]) == pid and int(fields[19]) > 0, 'launcher needs its own session and group')
    return {'pid': pid, 'pgid': pid, 'start_ticks': int(fields[19]), 'remote_deadline': deadline,
            'boot_sha256': digest(host.virtual_read('/proc/sys/kernel/random/boot_id'))}


def begin(host, intent, pid, *, reviewed=None):
    cap, limit = anchor(host, intent)
    deadline = intent['remote_deadline']
    reserve = 1170 if intent['scenario'] == 'mvp-install' else 1470
    removing=intent['operation'] in REMOVALS
    require(removing==(reviewed is not None),'supported removal requires an independent review')
    if removing:
        reserve=320 if intent['scenario']=='mvp-install' and reviewed['http_state_possible'] is False else 620
        fresh=review_ownership(host,reviewed['copies'],reviewed['interrupted'])
        require(fresh['installed_executable_present'] and all(fresh[k]==reviewed['ownership'][k] for k in
                ('run_id','source','manifest_sha256','request_sha256','executable_sha256','authority_snapshot','prior_processes')),
                'supported removal state differs')
    test_finish=json.loads(host.read(STAGE+'/fresh-window-decision.json'))['window']['test_until_unix']
    require((removing or deadline<=test_finish) and host.now()+cap <= deadline <= host.now()+cap+30 and deadline+15+10+reserve < limit,
            'full action and recovery window do not fit')
    records=journal(host)
    require('recovery' not in records, 'qualification work already stopped')
    for name, earlier in records.items():
        if not name.startswith('launch-'):
            continue
        if name==filename(intent):
            raise FileExistsError('existing launch: inspect without replay')
        require(earlier['intent']['operation'] not in REMOVALS, 'supported removal already attempted')
        require(removing or records.get('reaped-'+name)=={'launch_sha256':digest(canonical(earlier)), 'exit':0},
                'previous action is uncertain or failed')
    row = {'intent': dict(intent), 'process': process_identity(host, pid, deadline)}
    append(host, filename(intent), row)
    return row


def seal_reaped(host, record, status=None):
    """Only the original Linux subreaper may seal its successfully drained process tree."""
    intent, owner = record['intent'], record['process']
    require(process_identity(host, owner['pid'], intent['remote_deadline']) == owner, 'launch owner changed')
    require(journal(host)[filename(intent)] == record, 'launch journal changed')
    if host.native:
        value = ctypes.c_int()
        require(ctypes.CDLL(None).prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == 1,
                'launch owner is not the subreaper')
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise ValueError('launch owner still has children')
    append(host, 'reaped-'+filename(intent), {'launch_sha256': digest(canonical(record)), 'exit':status})


def reconcile(host, copies, current):
    """Compare independently retained copies with every durable journal on this run."""
    anchor(host, current)
    require(copies and len(copies) <= 32, 'launch inventory missing or too large')
    names = {filename(row['intent']) for row in copies}
    records = journal(host)
    actual = {name for name in records if name.startswith('launch-')}
    require(len(names) == len(copies) and actual == names and filename(current) in names,
            'partial or changed launch inventory')
    rows = []
    for row in copies:
        intent = row['intent']
        require(all(intent[k] == current[k] for k in ('run_id','run_attempt','manifest_sha256',
                    'machine_sha256','window_sha256')), 'foreign launch identity')
        if filename(intent) == filename(current):
            require(intent == current, 'interrupted launch intent differs')
        name = filename(intent)
        raw = canonical(records[name])
        require(raw == canonical(row), 'operator and host launch receipts differ')
        seal = records.get('reaped-'+name, {})
        require(set(seal)=={'launch_sha256','exit'} and seal['launch_sha256']==digest(raw)
                and (seal['exit'] is None or type(seal['exit']) is int), 'launch quiescence unproved')
        require(row['process']['remote_deadline'] == intent['remote_deadline'], 'launch expiry differs')
        rows.append(row['process'])
    boot = digest(host.virtual_read('/proc/sys/kernel/random/boot_id'))
    observer = type(host)({'boot_sha256': boot, 'prior_processes': rows}, root=host.root,
                          command=None if host.native else host.command, now=host.now)
    observer.prior_processes_absent()
    return rows


def launch(host, intent, pid, acknowledge, action, drain, *, reviewed=None):
    """Both sides retain the owner before the first effect. An exception cannot credit success."""
    with exclusive(host):
        return launch_locked(host,intent,pid,acknowledge,action,drain,reviewed)


@contextmanager
def exclusive(host):
    fd=os.open(host.path(STAGE),os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def launch_locked(host,intent,pid,acknowledge,action,drain,reviewed):
    record = begin(host, intent, pid,reviewed=reviewed)
    status = None
    try:
        require(acknowledge(record) == digest(canonical(record)), 'launch acknowledgement differs')
        cap, limit = anchor(host, intent)
        require(host.now() + cap <= intent['remote_deadline'] < limit, 'launch acknowledgement too late')
        status=action(intent['operation'], intent['remote_deadline'])
        return status
    finally:
        drain()
        seal_reaped(host, record, status)


def review_ownership(host, copies, current):
    import datetime
    rows = reconcile(host, copies, current)
    manifest = json.loads(host.read(STAGE+'/qualification-manifest.json'))
    paths = ('/var/lib/sbxr/installed.json', '/var/lib/sbxr/proxy-ownership.json',
             '/var/lib/sbxr/.proxy-ownership.json.next', '/var/lib/.sbxr-removal.json')
    observed = host.files(paths)
    executable = host.files(['/usr/local/bin/sbxr'])['/usr/local/bin/sbxr']
    if executable is None:
        require(not any(observed.values()), 'executable absent with retained installation authority')
    else:
        installed = json.loads(host.read(paths[0]))
        release, = manifest['releases']
        identity = release['release_identity']
        require(identity['repository'] == installed['repository'] == 'albertloky/SBXR'
                and all(identity[k] == release[k] == installed[k] for k in ('tag', 'commit'))
                and installed['sequence'] == release['sequence'] and installed['architecture'] == 'amd64'
                and installed['release_index_sha256'] == identity['release_index_sha256']
                and installed['executable_sha256'] == executable, 'installed candidate differs')
    _, limit = anchor(host, current)
    require(host.files(paths) == observed, 'ownership changed during review')
    return dict(run_id=current['run_id'], source=manifest['workflow']['commit'],
                manifest_sha256=current['manifest_sha256'], request_sha256=current['request_sha256'],
                observed_at=datetime.datetime.fromtimestamp(host.now(), datetime.timezone.utc).isoformat(),
                uncertain_action_reconciled=True, process_cleanup_verified=True, prior_processes=rows,
                installed_executable_present=executable is not None, exact_installed_identity_verified=executable is not None,
                executable_sha256=executable, current_E=limit,
                authority_snapshot={p: {'sha256': v} if v else None for p,v in observed.items()})


MENU = {
    'setup': ('action', 'Start setup', 'PROXY-INSTALLATION-SETUP-COMPLETE', '--confirmation', 'yes'),
    'details': ('details', 'View details'),
    'disclose': ('disclose', 'Show client configuration', 'PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED'),
    'check': ('action', 'Check', 'SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT'),
    'enable-subscription': ('action', 'Enable subscription', 'PROXY-INSTALLATION-SUBSCRIPTION-ENABLED', '--confirmation', 'yes'),
    'rotate-identity': ('action', 'Rotate Client Identity', 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED', '--confirmation', 'yes'),
    'rotate-link': ('action', 'Rotate subscription link', 'PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED', '--confirmation', 'yes'),
}


def menu_args(operation):
    if operation not in MENU:
        raise ValueError('unknown menu operation')
    cap, = [ops[operation] for ops in CAPS.values() if operation in ops]
    return [*MENU[operation], '--timeout', str(cap)]


def packaged_action(host, intent, assets, units, startup_digest, reviewed):
    """Select one pre-reviewed operation. No executable, label or script input."""
    import subprocess
    import sys
    manifest = json.loads(host.read(STAGE + '/qualification-manifest.json'))
    op = intent['operation']
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root',
           'SBXR_QUALIFICATION_REQUEST': EVIDENCE+'/request.json',
           'SBXR_Q215_OPERATOR_DEADLINE_UNIX': str(intent['remote_deadline'])}
    # Run the existing exact_candidate / absence check without loading host shell configuration.
    check = 'prove_not_installed' if op == 'install' else 'exact_candidate'
    shell = assets['v3-packaged-live.sh'].decode()
    subprocess.run(['/usr/bin/bash', '-c', 'source /dev/stdin; '+check], input=shell.encode(),
                   stdout=subprocess.DEVNULL, env=env, check=True, timeout=10)
    if op == 'install':
        release, = manifest['releases']
        require(digest(host.read(STAGE+'/v3-qualification-transport.sh')) ==
                digest(assets['v3-qualification-transport.sh']), 'staged installer transport differs')
        argv = ['/usr/bin/bash', STAGE+'/v3-qualification-transport.sh', 'install', release['tag']]
    elif op in REMOVALS:
        label,confirm=REMOVALS[op]
        recorder=host.read(RECORDER,65536)
        require(digest(recorder)==digest(assets['mvp-observe.py']), 'staged cleanup recorder differs')
        env.update(SBXR_QUALIFICATION_DRAFT='/root/mvp-observation-draft.json',SBXR_QUALIFICATION_CLOCK=RECORDER,
                   SBXR_QUALIFICATION_CLOCK_SHA256=digest(recorder))
        argv=[sys.executable,'-I','-B','-c',assets['v3-menu-session.py'].decode(),'safety-cleanup',label,
              'SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED','--confirmation',confirm,'--timeout','360',
              '--cleanup-cutoff',str(reviewed['cutoff']),'--cleanup-reserve',str(660 if reviewed['http_state_possible'] else 360)]
    elif op in MENU:
        argv = [sys.executable, '-I', '-B', '-c', assets['v3-menu-session.py'].decode(), *menu_args(op)]
    elif op in ('restart-serving', 'restart-access'):
        # Check the exact running unit/fragment and every current drop-in before restart.
        names = ['sbxr-subscription.service'] if op == 'restart-serving' else ['sing-box.service','sbxr-subscription.service']
        host.scope['expected_units'] = units
        host.deadline = intent['remote_deadline']
        dropin = '/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf'
        if os.path.lexists(host.path(dropin)):
            owner = json.loads(host.read('/var/lib/sbxr/proxy-ownership.json'))
            require(owner['proxy_startup']['drop_in_sha256'] == startup_digest, 'foreign startup authority')
            units['sing-box.service']['dropins'] = {dropin: startup_digest}
        for name in names:
            owned, state = host.unit(name)
            require(owned and state['ActiveState']=='active', 'restart requires an active owned service')
        _,_,states=host.observe()
        host.candidate_processes(states)
        argv = ['/usr/bin/systemctl', 'restart', *names]
    else:
        raise ValueError('unsupported packaged operation')
    return argv, env


def host_launch(host, intent, assets, units, startup_digest, acknowledge, reviewed=None):
    """Dedicated Linux session. A lost stream or negative action exit never grants replay."""
    import signal
    import sys
    import time
    import subprocess
    require(host.native and signal.getsignal(signal.SIGCHLD) != signal.SIG_IGN, 'dedicated Linux owner required')
    if os.getsid(0) != os.getpid():
        os.setsid()
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'Linux child subreaper unavailable')
    runner = {'__name__': 'operator_supervisor'}
    menu = {'__name__': 'packaged_menu'}
    exec(compile(assets['mvp-operator-run.py'], 'operator-supervisor', 'exec'), runner)
    exec(compile(assets['v3-menu-session.py'], 'packaged-menu', 'exec'), menu)
    def drain():
        end = time.monotonic()+5
        while time.monotonic() < end:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                menu['kill_adopted_children']()
                time.sleep(.01)
        raise ValueError('descendant cleanup uncertain')

    def execute(operation, deadline):
        # Consult the real recorder (unsealed, current request and active technical time).
        mode='cleanup-deadline' if reviewed is not None else 'operation-deadline'
        r = subprocess.run([sys.executable, '-I', '-B', '-', mode,
                            '--request', EVIDENCE+'/request.json', '--draft', '/root/mvp-observation-draft.json'],
                           input=assets['mvp-observe.py'], capture_output=True, timeout=5, check=True)
        require(re.fullmatch(rb'[0-9]+\n', r.stdout) and int(r.stdout) > deadline, 'recorder deadline differs')
        argv, env = packaged_action(host, intent, assets, units, startup_digest, reviewed)
        anchor(host, intent)
        cap = validate(intent)
        require(host.now()+cap <= deadline, 'full action cap no longer fits')
        os.environ.clear()
        os.environ.update(env)
        # All work shares this process's monotonic and absolute stop deadline.
        return runner['run_bounded'](argv, deadline+10.001, cap, 0)
    return launch(host, intent, os.getpid(), acknowledge, execute, drain,reviewed=reviewed)
