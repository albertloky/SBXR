"""Transport only the frozen, fixed fresh-window recovery operations and their data."""
import base64
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
import zlib

PROVIDERS = ('remote.py','review-cleanup.py','outside-run.py','direct-control.py','finalize-failure.py')
ASSETS = ('qualification-window-authority.py','mvp-recovery-endpoint.py','mvp-journey-custody.py',
          'mvp-containment-host.py','mvp-containment-freeze.py','mvp-operator-run.py','v3-menu-session.py',
          'v3-packaged-live.sh','v3-qualification-transport.sh','mvp-observe.py','finalize-failure.py')
PHASES = {'launch','remove','absence','clock','ownership','freeze','review','stop','verify','submit','transport'}
HERE = Path(__file__).resolve().parent


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def private(path, limit=16<<20):
    p=Path(path)
    require(p.is_absolute() and p.resolve(strict=True)==p,'linked or noncanonical local path')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1
                and not st.st_mode & 0o077 and st.st_size<=limit,'nonprivate local input')
        raw=f.read(limit+1)
        require(len(raw)==st.st_size and p.lstat().st_ctime_ns==st.st_ctime_ns,'changed local input')
    return raw


def save(path, doc):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as s:
        s.write(canonical(doc))
        s.flush()
        os.fsync(s.fileno())
    parent=os.open(Path(path).parent,os.O_DIRECTORY|os.O_NOFOLLOW|os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def bound_candidate(*, post_transport=False):
    cfg=json.loads(private(HERE/'preparation.json'))
    live=HERE.parent/'live'
    require(live.resolve(strict=True)==live and stat.S_IMODE(live.stat().st_mode)==0o700
            and live.stat().st_uid==os.getuid(),'unsafe live directory')
    mpath=live/'qualification-manifest.json'
    wpath=live/'fresh-window-decision.json'
    mraw=private(mpath)
    wraw=private(wpath)
    manifest=json.loads(mraw)
    window=json.loads(wraw)['window']
    run=window['workflow']['run_id']
    auth_path=HERE/'operator-source/qualification-window-authority.py'
    raw=private(auth_path)
    require(sha(raw)==cfg['provider_pins']['operator-source/qualification-window-authority.py'],'authority helper changed')
    a={'__name__':'operator_authority'}
    exec(compile(raw,str(auth_path),'exec'),a)
    original=a['origin'](mpath,cfg['origin_run_id'])
    a['verify_window'](wpath,run)
    approval=json.loads(private(live/'operator-approval.json'))
    require(approval['run_id']==int(run) and approval['run_attempt']==1 and approval['host']==cfg['host']
            and approval['window_sha256']==sha(wraw) and approval['manifest_sha256']==sha(mraw)
            and approval['operator_commit']==window['workflow']['commit']
            and type(approval['job_id']) is int and approval['job_id']>0,'operator approval differs')
    if not post_transport:
        require(a['live'](run)==approval['job_id'],'protected job differs')
    require(private(mpath)==mraw and private(wpath)==wraw and sha(mraw)==cfg['manifest_sha256']
            and original['workflow']==manifest['workflow']==window['origin']
            and window['release']==manifest['releases'][0] and window['manifest_sha256']==sha(mraw)
            and cfg['source']==manifest['workflow']['commit'] and cfg['machine_sha256']==manifest['v3_attempt']['vps_identity_sha256']
            and run!=cfg['origin_run_id'] and cfg['approved_window_start']==window['start_unix']
            and cfg['test_finish_unix']==window['test_until_unix'] and cfg['cleanup_finish_unix']==window['finish_unix']
            and window['start_unix']<=time.time()<window['finish_unix'],'signed candidate, machine or window differs')
    return cfg,int(run),{'manifest_sha256':sha(mraw),'window_sha256':sha(wraw),'job_id':approval['job_id']}


def frozen_assets(cfg):
    blobs={}
    for name in ASSETS:
        path='operator-source/'+name
        raw=private(HERE/path)
        require(sha(raw)==cfg['provider_pins'][path],'changed fixed provider '+name)
        blobs[name]=raw
    return blobs


def ssh(cfg, assets):
    live=HERE.parent/'live'
    host=str(ipaddress.IPv4Address(cfg['host']))
    identity=live/'ssh.key'
    known=live/'known_hosts'
    # Neither the received protocol nor SSH configuration can set executable
    # paths, a proxy command, a destination, or a trust override.
    for path in (identity,known):
        require(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode) and
                path.stat().st_uid==os.getuid() and path.stat().st_nlink==1 and
                not path.stat().st_mode & 0o077,'unsafe SSH identity/trust path')
    require(private(known) and sha(private(known))==json.loads(private(live/'ssh-trust.json'))['known_hosts_sha256'],
            'SSH trust changed')
    # Only these reviewed source files feed this bootstrap. Wire messages contain JSON.
    compressed=base64.b64encode(zlib.compress(repr(assets).encode(),9)).decode()
    bootstrap=("import base64,zlib,ast;assets=ast.literal_eval(zlib.decompress(base64.b64decode('"+
               compressed+"')).decode());exec(compile(assets['mvp-recovery-endpoint.py'],'endpoint','exec'));serve(assets)")
    return ['/usr/bin/ssh','-F','/dev/null','-T','-i',str(identity),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
            '-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+str(known),
            '-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=3',
            '-o','ServerAliveCountMax=1','root@'+host,'/usr/bin/python3 -I -B -c '+shlex.quote(bootstrap)]


def call(cfg,run,proof,request):
    # The timer covers pipe writes, acknowledgement reads and the final reply.
    # The remote owner separately enforces the expiry if the SSH process dies.
    remaining=request['deadline']-time.time()
    require(math.isfinite(remaining) and 0<remaining<=1350, 'transport deadline')
    old=signal.getsignal(signal.SIGALRM)
    previous,interval=signal.getitimer(signal.ITIMER_REAL)
    require(previous==interval==0,'nested transport timer')
    def expired(*_):
        raise TimeoutError('transport deadline; inspect without replay')
    signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,remaining)
    try:
        return _call(cfg,run,proof,request)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,old)


def _call(cfg,run,proof,request):
    op=request['phase']
    require(op in PHASES,'unknown recovery operation')
    intent=request['intent']
    require(intent['run_id']==run and intent['run_attempt']==1 and intent['machine_sha256']==cfg['machine_sha256']
            and all(intent[k]==proof[k] for k in ('manifest_sha256','window_sha256')), 'local authority mismatch')
    assets=frozen_assets(cfg)
    custody={'__name__':'journey_custody'}
    exec(compile(assets['mvp-journey-custody.py'],'custody','exec'),custody)
    name=custody['filename'](intent)
    live=HERE.parent/'live'
    until=request['deadline']
    require(math.isfinite(until) and time.time()<until<=cfg['cleanup_finish_unix'], 'transport deadline')
    if op in ('launch','remove'):
        save(live/('intent-'+name),intent)
    log=live/(op+'-'+name+'.stderr')
    with os.fdopen(os.open(log,os.O_CREAT|os.O_APPEND|os.O_WRONLY|os.O_NOFOLLOW,0o600),'ab') as err:
        st=os.fstat(err.fileno())
        require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.getuid() and st.st_nlink==1,'unsafe capture')
        process=subprocess.Popen(ssh(cfg,assets),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,bufsize=0)
        try:
            raw=canonical(request)+b'\n'
            require(len(raw)<=2<<20,'request exceeds bound')
            view=memoryview(raw)
            while view:
                count=process.stdin.write(view)
                require(count is not None and count>0,'incomplete request write')
                view=view[count:]
            process.stdin.flush()
            if op in ('launch','remove'):
                # Bound the full fixed-size acknowledgement, including a peer
                # which sends one byte and then disconnects.
                line=bytearray()
                while len(line)<8192 and time.time()<until:
                    if not select.select([process.stdout],[],[],max(0,until-time.time()))[0]:
                        break
                    ch=os.read(process.stdout.fileno(),1)
                    if not ch or ch==b'\n':
                        break
                    line+=ch
                row=json.loads(line)['receipt']
                require(row['intent']==intent and row['process']['remote_deadline']==intent['remote_deadline'],
                        'remote launch receipt differs')
                save(live/name,row)
                process.stdin.write(sha(canonical(row)).encode()+b'\n')
                process.stdin.flush()
            output,_=process.communicate(timeout=max(.01,until-time.time()))
            require(process.returncode==0 and len(output)<=2<<20 and time.time()<until,
                    'remote outcome uncertain, inspect without replay')
            return json.loads(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()


def copies(live):
    intents={p.name[len('intent-'):] for p in live.glob('intent-launch-*.json')}
    paths=sorted(live.glob('launch-*.json'))
    require(intents and intents=={p.name for p in paths},'operator launch inventory incomplete')
    records=[]
    for path in paths:
        row=json.loads(private(path))
        require(row['intent']==json.loads(private(live/('intent-'+path.name))),'local launch intent differs')
        records.append(row)
    return records
