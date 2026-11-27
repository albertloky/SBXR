"""Closed host protocol for the fresh-window operator. All program bytes come from its frozen checkout."""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
import time


def require(value, reason):
    if not value:
        raise ValueError(reason)


def module(assets, name):
    # Names are constants in this module. No executable bytes come from a request.
    scope = {'__name__': 'reviewed_provider', '__file__': name}
    exec(compile(assets[name], name, 'exec'), scope)
    return scope


def clock(host, intent, assets, operation):
    recorder = assets['mvp-observe.py']
    cmd = [sys.executable, '-I', '-B', '-', operation+'-deadline',
           '--request', str(host.path('/root/sbxr-qualification-evidence/request.json')),
           '--draft', str(host.path('/root/mvp-observation-draft.json'))]
    p = subprocess.run(cmd, input=recorder, capture_output=True, timeout=5, check=True)
    return int(p.stdout)


def dispatch(request, assets, host, *, acknowledge=None, owner=None):
    c = module(assets, 'mvp-journey-custody.py')
    op, intent, deadline = request['phase'], request['intent'], request['deadline']
    require(type(deadline) in (int,float) and math.isfinite(deadline) and host.now()<deadline, 'phase deadline')
    scope = request.get('scope', {})
    if op == 'transport':
        require(scope['binding']['run_id']==intent['run_id'] and scope['machine_sha256']==intent['machine_sha256']
                and scope['binding']['manifest_sha256']==intent['manifest_sha256'], 'post-transport identity differs')
        host.scope=scope
        while host.native and host.now()<deadline-90 and os.path.lexists(host.path(c['STAGE'])):
            time.sleep(min(2, max(0,deadline-90-host.now())))
        return host.transport(deadline)
    _, limit = c['anchor'](host, intent)
    draft_path='/root/mvp-observation-draft.json'
    runtime_path=c['STAGE']+'/runtime-deadline'
    initial=(host.read(draft_path),host.read(runtime_path))
    limit = min(clock(host, intent, assets, 'operation' if op=='launch' else 'cleanup'), limit)
    c['anchor'](host,intent)
    require(initial==(host.read(draft_path),host.read(runtime_path)),'clock draft or runtime changed during observation')
    require(host.now()<deadline<=limit, 'phase outside current authority')
    if op=='clock':
        return dict(effective_deadline_unix=limit, request_sha256=intent['request_sha256'],
                    run_id=intent['run_id'], scenario_id=intent['scenario'])
    if op in ('launch','remove'):
        reviewed=request.get('reviewed')
        require((op=='remove')==(intent['operation'] in c['REMOVALS'])==(reviewed is not None),'cleanup role differs')
        if reviewed is not None:
            earlier=reviewed['interrupted']
            require(all(earlier[k]==intent[k] for k in ('run_id','run_attempt','machine_sha256','manifest_sha256',
                        'request_sha256','window_sha256','scenario')) and reviewed['cutoff']<=limit
                    and type(reviewed['http_state_possible']) is bool and (reviewed['http_state_possible'] or intent['scenario']=='mvp-install'),
                    'approved removal binding differs')
        if host.native:
            status=c['host_launch'](host,intent,assets,request['units'],request['startup_sha256'],acknowledge,reviewed)
        else:
            require(owner is not None, 'explicit fixture owner required')
            pid, action, drain=owner
            status=c['launch'](host,intent,pid,acknowledge,action,drain,reviewed=reviewed)
        return {'exit':status}
    if op=='absence':
        rows=c['reconcile'](host,request['copies'],intent)
        require(intent['operation'] in c['REMOVALS'] and rows,'removal identity absent')
        result=absence(host,assets,request['units'],deadline)
        return dict(result,request_sha256=intent['request_sha256'],observed_at=host.now())
    if op=='ownership' or op=='freeze':
        review=c['review_ownership'](host,request['copies'],intent)
        review['current_E']=limit
        if op=='ownership':
            return review
        policy=request['policy']
        require(policy['machine_sha256']==intent['machine_sha256'] and policy['original_cutoff']<=limit,
                'freeze authority differs')
        f=module(assets,'mvp-containment-freeze.py')
        with c['exclusive'](host):
            require(c['reconcile'](host,request['copies'],intent)==review['prior_processes'],'journey changed before freeze')
            scope=f['freeze'](type(host),review,request['binding'],policy,root=host.root,
                             command=None if host.native else host.command,now=host.now,deadline=deadline)
            c['append'](host,'recovery',{'intent':intent,'scope_sha256':c['digest'](c['canonical'](scope)),
                                         'reviewed_at':scope['reviewed_at']})
        return {'review':review,'scope':scope}
    if op not in ('review','stop','verify','submit'):
        raise ValueError('unknown recovery operation')
    rows=c['reconcile'](host,request['copies'],intent)
    require(scope['prior_processes']==rows and scope['machine_sha256']==intent['machine_sha256']
            and all(scope['binding'][k]==intent[k] for k in ('run_id','manifest_sha256','request_sha256')),
            'frozen recovery scope differs')
    with c['exclusive'](host):
        ledger=c['journal'](host)
        frozen=ledger['recovery']
        original={**scope,'reviewed_at':frozen['reviewed_at']}
        require(frozen['intent']==intent and c['digest'](c['canonical'](original))==frozen['scope_sha256'],
                'scope differs from independent host freeze')
        if op!='review':
            require('reviewed' in ledger and scope['reviewed_at']==ledger['reviewed'], 'review timestamp differs')
        if op in ('stop','submit'):
            if op=='submit':
                require('stopped' in ledger,'host stop not observed')
            c['append'](host,op+'-intent',{'scope_sha256':frozen['scope_sha256']})
    host.scope=scope
    if op=='submit':
        host.verify(deadline)
        n=request['notice']
        f=module(assets,'finalize-failure.py')
        expected=f['notice'](f['canonical'](n['failure']),scope['binding'],intent['scenario'],intent['window_sha256'])
        require(f['canonical'](expected)==f['canonical'](n),'terminal notice differs')
        # The collector never sees partial bytes. Refuse concurrent submissions,
        # even via a dangling link, and preserve uncertainty on disconnect.
        ack=host.path(c['EVIDENCE']+'/recorded-'+hashlib.sha256(f['canonical'](n)).hexdigest())
        require(not os.path.lexists(ack),'collector acknowledgement already present')
        fd=os.open(host.path(c['EVIDENCE']+'/retained-failure.tmp'),
                   os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            out.write(f['canonical'](n))
            out.flush()
            os.fsync(fd)
        require(c['anchor'](host,intent)[1]>=deadline,'request changed before submission')
        directory=host.path(c['EVIDENCE'])
        publish(directory, 'retained-failure.tmp', 'result.json')
        while host.now()<deadline:
            try:
                st=ack.lstat()
                require(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700 and st.st_uid==os.geteuid()
                        and not any(ack.iterdir()),'foreign collector acknowledgement')
                return {'failure_recorded':True, 'failure_sha256':scope['binding']['failure_sha256'],
                        'qualification_passed':False}
            except FileNotFoundError:
                time.sleep(.1)
        raise TimeoutError('terminal disposition unknown')
    if op=='review':
        result=host.review(deadline)
    elif op=='stop':
        result=host.stop(deadline,request['commands'])
    else:
        result=host.verify(deadline)
        result['preservation']=host.preservation()
    at=host.now()
    if op in ('review','stop'):
        with c['exclusive'](host):
            c['append'](host, 'reviewed' if op=='review' else 'stopped', at)
    return dict(result,observed_at=at)




def absence(host,assets,units,deadline):
    # Prove all additional HTTP/service resources, independent of any menu result.
    names=('/usr/local/bin/sbxr','/usr/bin/sing-box','/var/lib/sbxr','/var/lib/.sbxr-removal.json',
           '/etc/sing-box','/var/lib/sing-box','/etc/systemd/system/sbxr-subscription.service',
           '/etc/systemd/system/sbxr-subscription-firewall.service',
           '/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service',
           '/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service',
           '/etc/systemd/system/multi-user.target.wants/sing-box.service')
    require(not any(os.path.lexists(host.path(p)) for p in names),'owned resource remains')
    host.scope={'expected_units':units}
    host.deadline=deadline
    owned,absent,states=host.observe()
    require(not owned and set(absent)=={'sing-box.service','sbxr-subscription.service'},'owned unit remains')
    host.candidate_processes(states,stopped=True)
    require(not host.run(['/usr/bin/ss','-H','-ltn','sport = :443 or sport = :8443']).strip(),'public listener remains')
    rules=host.run(['/usr/sbin/iptables-save','-t','filter']).splitlines()
    require('*filter' in rules and 'COMMIT' in rules, 'filter table observation incomplete')
    for line in rules:
        if line.startswith('-A '):
            fields=shlex.split(line)
            require(('--comment','sbxr-subscription') not in zip(fields,fields[1:]), 'subscription firewall rule remains')
    # The maintained probe also checks legacy remnants, dpkg/holds and group/account.
    if host.native:
        subprocess.run(['/usr/bin/bash','-c','set -eu; source /dev/stdin; prove_not_installed'],
                       input=assets['v3-packaged-live.sh'],stdout=subprocess.DEVNULL,
                       timeout=min(60,deadline-host.now()),check=True,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    else:
        # Fixtures supply the same closed OS observation by its fixed operation name.
        require(host.run(['fixture-prove-not-installed'])=='absent','packaged absence refused')
    return {'product_absent':True,'absent_units':absent,'candidate_pids':[],'open_test_ports':[]}


def publish(directory, source, target):
    # Both the protected collector and any concurrent operator see either an absent
    # result or one complete single-link file. Unknown destinations always refuse.
    import ctypes
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith('linux'):
            rc = libc.renameat2(fd, source.encode(), fd, target.encode(), 1)  # RENAME_NOREPLACE
        elif sys.platform == 'darwin':
            rc = libc.renameatx_np(fd, source.encode(), fd, target.encode(), 4)  # RENAME_EXCL (fixture)
        else:
            raise ValueError('atomic exclusive publication unavailable')
        if rc != 0:
            raise OSError(ctypes.get_errno(), 'exclusive result publication failed')
        os.fsync(fd)
    finally:
        os.close(fd)


def serve(assets):
    first=sys.stdin.buffer.readline((2 << 20)+1)
    require(0<len(first)<=2 << 20 and first.endswith(b'\n'),'invalid request size')
    request=json.loads(first)
    host=module(assets,'mvp-containment-host.py')['Host']({})
    def timeout(*_):
        raise TimeoutError('host phase expired')
    signal.signal(signal.SIGALRM,timeout)
    remaining=request['deadline']-time.time()
    require(0<remaining<=1350, 'invalid host phase budget')
    signal.setitimer(signal.ITIMER_REAL,remaining)
    def acknowledge(record):
        print(json.dumps({'receipt':record},separators=(',',':')),flush=True)
        line=sys.stdin.buffer.readline(66)
        require(len(line)==65 and line.endswith(b'\n'),'missing operator acknowledgement')
        return line[:-1].decode('ascii')
    # Product stdout can contain a credential: keep it on a separate private
    # channel, never interleave it with the JSON ownership receipt.
    if request['phase'] in ('launch','remove'):
        control=os.dup(1)
        def launch_ack(record):
            value=acknowledge(record)
            os.dup2(2,1)
            return value
        try:
            result=dispatch(request,assets,host,acknowledge=launch_ack)
        finally:
            sys.stdout.flush()
            os.dup2(control,1)
            os.close(control)
    else:
        result=dispatch(request,assets,host)
    print(json.dumps(result,allow_nan=False,separators=(',',':')),flush=True)
