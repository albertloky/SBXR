#!/usr/bin/env python3
"""Pinned concrete phase callers, supervised by the maintained operator runner.

No command runs on import. The binding selects one reviewed Python caller per
phase; the caller verifies actual producer evidence and returns one JSON object.
Native and fixture bindings are distinct. The same bytes, invocation, journal,
deadline and refusal path are used in offline subprocess rehearsals.
"""
import hashlib
import json
import math
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
import time
import threading

PHASES = ('clock','ownership','stop-services','verify-host','stop-outside',
          'restore-client','verify-retained','record-failure','verify-transport')


def require(value, message):
    if not value: raise ValueError(message)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def read(path, limit=16 << 20):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());require(stat.S_ISREG(a.st_mode) and a.st_nlink==1
            and a.st_uid==os.getuid() and not a.st_mode & 0o022 and a.st_size<=limit,'unsafe caller/evidence file')
        raw=f.read(limit+1);b=os.fstat(f.fileno())
    keys=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
    require(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(path.lstat(),k) for k in keys),'caller/evidence changed')
    return raw


def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(value,f,sort_keys=True,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())


class Callers:
    def __init__(self, scope, manifest, directory, runner):
        self.scope=scope;self.manifest=manifest;self.directory=Path(directory);self.runner=Path(runner)
        require(manifest['binding']==scope['binding'],'caller candidate binding')
        require(manifest['origin'] in ('native','fixture'),'caller origin')
        require(set(manifest['callers'])==set(PHASES),'complete caller map required')
        require(digest(read(runner))==manifest['runner_sha256'],'supervisor changed')
        st=self.directory.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,'private caller directory')
        self.used=set()
        for caller in manifest['callers'].values():self.verify(caller)

    def verify(self,caller):
        require(set(caller)=={'path','sha256','dependencies'},'caller contract')
        raw=read(caller['path']);require(digest(raw)==caller['sha256'],'caller bytes changed')
        require(isinstance(caller['dependencies'],dict),'dependency pins')
        for path,sha in caller['dependencies'].items():require(digest(read(path))==sha,'caller dependency changed')
        return raw

    def run(self,action,deadline,commands=()):
        require(threading.current_thread() is threading.main_thread(),'caller must own signal handling')
        require(action in PHASES and action not in self.used,'unknown/repeated phase')
        require(type(deadline) in (int,float) and math.isfinite(deadline),'phase deadline')
        end=self.scope['final_cutoff'] if action=='verify-transport' else min(self.scope[k] for k in ('original_cutoff','signed_finish','runtime_finish'))
        require(deadline+10<end,'phase would overrun original cutoff')
        caller=self.manifest['callers'][action];source=self.verify(caller)
        require(digest(read(self.runner))==self.manifest['runner_sha256'],'supervisor changed before launch')
        require(time.time()+.5<deadline,'phase budget exhausted before launch')
        payload=self.directory/(action+'-input.json')
        save(payload,{'scope':self.scope,'action':action,'deadline':deadline,'commands':commands,
                      'origin':self.manifest['origin'],'dependencies':caller['dependencies']})
        self.used.add(action)
        # Execute the checked source bytes, not a subsequently replaceable script.
        bootstrap="import sys;__file__=sys.argv.pop(1);exec(compile("+repr(source)+",__file__,'exec'))"
        timeout=deadline-time.time()-.25
        argv=[sys.executable,'-B',str(self.runner),'--run-directory',str(self.directory),
              '--label',action,'--cutoff-unix',str(deadline+10),'--timeout',str(timeout),'--reserve','0','--',
              sys.executable,'-B','-c',bootstrap,caller['path'],str(payload)]
        parent=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        received=[];previous={}
        def interrupted(signum, frame):
            received.append(signum)
            if parent.poll() is None:parent.send_signal(signum)
        try:
            for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
                previous[signum]=signal.signal(signum,interrupted)
            try:
                outer_out,outer_err=parent.communicate(timeout=max(.1,deadline+11-time.time()))
            except subprocess.TimeoutExpired:
                parent.terminate()
                try:parent.communicate(timeout=11)
                except subprocess.TimeoutExpired:raise RuntimeError('supervisor outcome uncertain; inspect without replay')
                raise TimeoutError('caller deadline exceeded; inspect remote outcome')
        finally:
            for signum,handler in previous.items():signal.signal(signum,handler)
        receipt={'action':action,'exit':parent.returncode,'deadline':deadline,
                 'signals':received,'at':time.time(),'outer_stderr_sha256':digest(outer_err),'origin':self.manifest['origin']}
        save(self.directory/(action+'-supervisor.json'),receipt)
        require(not received,'caller interrupted; no replay')
        require(parent.returncode==0,'caller failed/timeout/interrupted; no replay')
        require(time.time()<deadline+10,'caller returned after stop allowance')
        output=read(self.directory/(action+'.operator.stdout'),1 << 20)
        value=json.loads(output)
        require(value.get('origin')==self.manifest['origin'],'fixture/native evidence origin differs')
        require(value.get('binding')==self.scope['binding'],'caller result candidate differs')
        return value
