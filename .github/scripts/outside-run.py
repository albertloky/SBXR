"""Run-private outside client ownership. Only the process holding the child stops and reaps it."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

LABELS={'initial','replacement','rotated'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(path, doc):
    fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_EXCL|os.O_CREAT,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(doc,out,sort_keys=True,allow_nan=False)
        out.flush()
        os.fsync(out.fileno())
    directory=os.open(path.parent,os.O_DIRECTORY|os.O_NOFOLLOW|os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read(path):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        st=os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
                and st.st_uid==os.getuid() and st.st_size<=65536,'outside receipt identity')
        return json.loads(f.read(65537))


@contextmanager
def locked(root):
    fd=os.open(root,os.O_DIRECTORY|os.O_NOFOLLOW|os.O_RDONLY)
    try:
        st=os.fstat(fd)
        require(root.resolve(strict=True)==root and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,
                'outside registry directory')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def initialize(root,binding):
    with locked(root):
        require(not list(root.iterdir()),'outside registry must start empty')
        write(root/'registry.json',binding)


def visible_group(group):
    # A fresh OS observation independent of the client owner's wait result.
    result=subprocess.run(['/bin/ps','-axo','pgid='],check=True,capture_output=True,timeout=2)
    groups=[int(g) for g in result.stdout.split()]
    require(groups and os.getpgrp() in groups,'outside process inventory unavailable')
    return group in groups


def supervise(root,binding,label,spawn,deadline,*,on_registered=None):
    require(label in LABELS and time.time()<deadline,'outside launch label or deadline')
    with locked(root):
        require(read(root/'registry.json')==binding and not os.path.lexists(root/'closed.json'),'outside registry closed or foreign')
        write(root/('intent-'+label+'.json'),binding)
        child=spawn()
    row={'binding':binding,'label':label,'pid':child.pid}
    try:
        require(os.getpgid(child.pid)==child.pid,'outside child requires a dedicated group')
        write(root/('owner-'+label+'.json'),row)
        if on_registered:
            on_registered(label,row)
        while time.time()<deadline and child.poll() is None:
            stop=root/('stop-'+label+'.json')
            if os.path.lexists(stop):
                require(read(stop)==row,'foreign outside stop request')
                break
            time.sleep(.05)
    finally:
        # Popen retains or has already reaped this actual child. No PID from
        # the evidence directory is signalled. Native launch prohibits forking.
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
    require(not visible_group(child.pid),'outside child group remains')
    write(root/('reaped-'+label+'.json'),row)


def stop_clients(root,binding,labels,deadline):
    with locked(root):
        require(read(root/'registry.json')==binding,'outside registry identity differs')
        require(len(set(labels))==len(labels) and set(labels)<=LABELS
                and {'intent-'+s+'.json' for s in labels}=={p.name for p in root.glob('intent-*.json')},
                'outside client inventory differs')
        if os.path.lexists(root/'closed.json'):
            require(read(root/'closed.json')==binding,'outside close identity differs')
        else:
            write(root/'closed.json',binding)
        rows={}
        for label in labels:
            require(read(root/('intent-'+label+'.json'))==binding,'foreign outside client intent')
            row=read(root/('owner-'+label+'.json'))
            require(set(row)=={'pid','label','binding'} and row['label']==label and row['binding']==binding
                    and type(row['pid']) is int and row['pid']>1,'outside process identity')
            rows[label]=row
            path=root/('stop-'+label+'.json')
            if os.path.lexists(path):
                require(read(path)==row,'outside stop identity differs')
            else:
                write(path,row)
    for label,row in rows.items():
        path=root/('reaped-'+label+'.json')
        while time.time()<deadline-2 and not os.path.lexists(path):
            time.sleep(.05)
        require(read(path)==row and time.time()<deadline and not visible_group(row['pid']),
                'outside client not independently reaped')
    return {'all_owned_children_reaped':True,'stopped_labels':labels}


def run_client(root,binding,label,deadline,program,config,expected,*,log):
    # The reviewed launch site binds the current signed outside binary and the
    # exact run-private configuration. No argv, shell, host or script interface.
    require(sys.platform=='darwin' and label in LABELS and program.name=='sing-box'
            and expected['binding']==binding and config==root.parent/('outside-'+label+'.json')
            and expected['label']==label, 'outside launch binding')
    for path,key in ((program,'executable_sha256'),(config,'config_sha256')):
        st=path.lstat()
        require(path.resolve(strict=True)==path and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.getuid()
                and not st.st_mode & 0o022 and (key!='config_sha256' or stat.S_IMODE(st.st_mode)==0o600)
                and hashlib.sha256(path.read_bytes()).hexdigest()==expected[key],'outside binary or configuration differs')
    def spawn():
        return subprocess.Popen(['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny process-fork)',
                                 str(program),'run','-c',str(config)],start_new_session=True,
                                stdin=subprocess.DEVNULL,stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin','HOME':str(root)})
    supervise(root,binding,label,spawn,deadline)


def program_pids(record):
    """Read executable identity only. On macOS prove absence independently of the registry."""
    import ctypes
    import errno
    path=Path(record['source_file'])
    st=path.lstat()
    require(sys.platform=='darwin' and path.name=='sing-box' and path.resolve(strict=True)==path
            and stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o022
            and st.st_size==record['size'] and hashlib.sha256(path.read_bytes()).hexdigest()==record['sha256'],
            'outside executable differs from preflight')
    processes=subprocess.run(['/bin/ps','-axo','uid=,pid='],check=True,capture_output=True,timeout=2)
    lookup=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True).proc_pidpath
    matches=set()
    seen=set()
    for line in processes.stdout.splitlines():
        uid,pid=map(int,line.split())
        if uid!=os.getuid():
            continue
        seen.add(pid)
        buf=ctypes.create_string_buffer(4096)
        if lookup(pid,buf,len(buf))<=0:
            try:
                os.kill(pid,0)
            except ProcessLookupError:
                continue
            raise ValueError('outside process identity unavailable')
        target=Path(os.fsdecode(buf.value))
        try:
            if target.samefile(path):
                matches.add(pid)
        except FileNotFoundError:
            raise ValueError('outside executable vanished during readback') from None
    require(os.getpid() in seen,'outside process inventory incomplete')
    return matches
