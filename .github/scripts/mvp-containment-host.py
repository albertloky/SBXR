#!/usr/bin/env python3
"""Concrete stop-only host operations. Import inert; all effects need bound scope.

Native scope is produced from a freshly verified candidate/ownership review, not
accepted as authentication on its own. The operator wrapper checks that producer
and pins these bytes before transport. Fixtures supply an explicit non-root tree
and a command adapter; there is no implicit fallback from native to fixture.
"""
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

UNITS = ('sbxr-subscription.service', 'sing-box.service')
PROPS = ('LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath', 'DropInPaths',
         'MainPID', 'ControlPID', 'ControlGroup', 'KillMode', 'TimeoutStopUSec',
         'ExecStop', 'ExecStopPost', 'SendSIGKILL', 'TriggeredBy', 'RequiredBy', 'WantedBy')
AUTHORITY = ('/var/lib/sbxr/installed.json', '/var/lib/sbxr/proxy-ownership.json',
             '/var/lib/sbxr/.proxy-ownership.json.next', '/var/lib/.sbxr-removal.json')


def require(value, reason):
    if not value: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def seconds(raw):
    pieces = re.findall(r'(\d+(?:\.\d+)?)(us|ms|min|s|h)', raw)
    require(pieces and ''.join(a+b for a,b in pieces) == raw.replace(' ', ''), 'unknown unit stop timeout')
    return sum(float(a)*{'us':.000001,'ms':.001,'s':1,'min':60,'h':3600}[b] for a,b in pieces)


def properties(raw):
    rows = raw.splitlines(); result = {}
    for row in rows:
        key, value = row.split('=', 1)
        require(key in PROPS and key not in result, 'unknown/duplicate unit property')
        result[key] = value
    require(set(result) == set(PROPS), 'incomplete systemd observation')
    return result


class Host:
    def __init__(self, scope, *, root=Path('/'), command=None, now=time.time):
        self.scope, self.root, self.now = scope, Path(root), now
        require(self.root.is_absolute(), 'absolute root required')
        self.native = self.root == Path('/')
        if self.native:
            require(command is None and os.geteuid() == 0 and os.uname().sysname == 'Linux', 'native Linux/root required')
        else:
            require(command is not None and self.root.is_dir() and not self.root.is_symlink(), 'explicit fixture adapter required')
        self.command = command or self.native_command
        self.deadline = None

    def path(self, name):
        require(isinstance(name,str) and name.startswith('/') and '..' not in Path(name).parts, 'absolute owned path')
        return self.root / name.lstrip('/')

    def read(self, name, limit=128 << 20):
        path = self.path(name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            a = os.fstat(f.fileno())
            require(stat.S_ISREG(a.st_mode) and a.st_uid == (0 if self.native else os.getuid())
                    and a.st_nlink == 1 and not a.st_mode & 0o022 and a.st_size <= limit, 'unsafe owned file')
            raw=f.read(limit+1); b=os.fstat(f.fileno())
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
        require(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(path.lstat(),k) for k in fields), 'owned file changed')
        return raw

    def virtual_read(self, name, limit=4096):
        allowed = {'/proc/sys/kernel/random/boot_id'} | {
            '/sys/fs/cgroup/system.slice/'+u+'/cgroup.procs' for u in UNITS}
        require(name in allowed, 'virtual read outside fixed inventory')
        fd=os.open(self.path(name),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_uid==(0 if self.native else os.getuid()), 'virtual file owner/type')
            data=stream.read(limit+1)
        require(len(data)<=limit,'virtual file too large')
        return data

    def candidate_processes(self, states, stopped=False):
        allowed={}
        for name,p in states.items():
            for key in ('MainPID','ControlPID'):
                require(p[key].isdigit(),'invalid service PID')
                if int(p[key]):allowed[int(p[key])]=name
        seen=[]
        for proc in self.path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                exe=os.readlink(proc/'exe')
                if exe not in ('/usr/bin/sing-box','/usr/local/bin/sbxr'):continue
                cgroup=(proc/'cgroup').read_text().splitlines()
                pid=int(proc.name)
                require(not stopped and pid in allowed
                        and '0::/system.slice/'+allowed[pid] in cgroup, 'unowned/remaining candidate process')
                seen.append(pid)
            except FileNotFoundError:continue
        require(stopped or set(seen)==set(allowed),'service PID not independently observed')
        return seen

    def files(self, names):
        return {name: sha(self.read(name)) if os.path.lexists(self.path(name)) else None for name in names}

    def native_command(self, argv, timeout):
        # Children share the independently supervised remote foreground group.
        require(argv[0] in ('/usr/bin/systemctl','/usr/bin/ss','/usr/sbin/iptables-save','/usr/sbin/ip6tables-save','/usr/bin/dpkg-query','/usr/bin/apt-mark','/usr/bin/getent'), 'command not allowed')
        p=subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        require(len(p.stdout)+len(p.stderr) <= 1 << 20, 'oversized command output')
        require(p.returncode == 0, 'host command failed: '+argv[0])
        return p.stdout

    def run(self, argv, cap=8):
        remaining=self.deadline-self.now()
        require(remaining>1, 'host action deadline')
        return self.command(argv, min(cap, remaining-0.5))

    def guard(self, deadline, *, fresh_review=True):
        require(type(deadline) in (float,int) and math.isfinite(deadline), 'deadline type')
        require(deadline <= self.scope['effective_deadline'] and self.now() < deadline, 'deadline expired/extended')
        self.deadline=deadline
        require(sha(self.read('/etc/machine-id'))==self.scope['machine_sha256'], 'machine changed')
        require(sha(self.virtual_read('/proc/sys/kernel/random/boot_id'))==self.scope['boot_sha256'], 'boot changed')
        require(self.read('/root/sbxr-qualification-v3/staging-owned')==(str(self.scope['binding']['run_id'])+'-1\n').encode(), 'run ownership changed')
        require(sha(self.read('/root/sbxr-qualification-v3/qualification-manifest.json'))==self.scope['binding']['manifest_sha256'], 'manifest changed')
        require(set(self.scope['authority_files'])==set(AUTHORITY), 'authority inventory incomplete')
        require(self.files(AUTHORITY)==self.scope['authority_files'], 'reviewed authority changed')
        if self.scope['executable_sha256'] is None:
            require(not os.path.lexists(self.path('/usr/local/bin/sbxr')) and all(v is None for v in self.scope['authority_files'].values()), 'no-executable state is not empty')
        else:
            require(sha(self.read('/usr/local/bin/sbxr'))==self.scope['executable_sha256'], 'installed executable changed')
        require(self.files(self.scope['retained_files'])==self.scope['retained_files'], 'retained data changed')
        if fresh_review:
            require(0 <= self.now()-self.scope['reviewed_at'] <= 120, 'ownership review stale')
        self.prior_processes_absent()

    def prior_processes_absent(self):
        rows=self.scope['prior_processes']
        require(rows, 'prior process reconciliation missing')
        for row in rows:
            require(row['boot_sha256']==self.scope['boot_sha256'] and all(type(row[k]) is int and row[k]>0 for k in ('pid','pgid','start_ticks')), 'prior process identity invalid')
        for item in self.path('/proc').iterdir():
            if not item.name.isdigit(): continue
            try:
                raw=(item/'stat').read_text(); parts=raw[raw.rfind(')')+2:].split()
                pgid=int(parts[2]); ticks=int(parts[19]); environment=(item/'environ').read_bytes()
                later=(item/'stat').read_text().split(')')[-1].split()
                require(int(later[19])==ticks, 'process changed while inspecting')
            except FileNotFoundError: continue
            for row in rows:
                require(not (int(item.name)==row['pid'] and ticks==row['start_ticks']) and pgid != row['pgid'], 'prior process/group still present')
                token=('SBXR_Q215_OPERATOR_DEADLINE_UNIX='+str(row['remote_deadline'])).encode()
                require(token not in environment.split(b'\0'), 'prior detached child remains')

    def unit(self, name):
        require(name in UNITS, 'foreign service')
        raw=self.run(['/usr/bin/systemctl','show',name,'--property='+','.join(PROPS)])
        p=properties(raw)
        if p['LoadState']=='not-found':
            require(p['ActiveState']=='inactive' and p['MainPID']==p['ControlPID']=='0'
                    and p['FragmentPath']==p['DropInPaths']=='', 'partial absent service')
            pin=self.scope['expected_units'][name]
            require(not any(os.path.lexists(self.path(x)) for x in pin['fragment_paths']), 'unloaded service fragment remains')
            folder=self.path('/etc/systemd/system/'+name+'.d')
            require(not os.path.lexists(folder) or folder.is_dir() and not folder.is_symlink() and not any(folder.iterdir()), 'absent service has drop-ins')
            return None, p
        require(p['LoadState']=='loaded', 'unresolved service load')
        pin=self.scope['expected_units'][name]
        require(p['FragmentPath'] in pin['fragment_paths'], 'foreign fragment path')
        require(sha(self.read(p['FragmentPath']))==pin['fragment_sha256'], 'foreign fragment bytes')
        dropins=p['DropInPaths'].split()
        require(len(dropins)==len(set(dropins)) and set(dropins)==set(pin['dropins']), 'foreign drop-ins')
        require(all(sha(self.read(path))==digest for path,digest in pin['dropins'].items()), 'changed drop-in')
        # Inspect the directory too: an un-reloaded foreign drop-in still refuses.
        folder=self.path('/etc/systemd/system/'+name+'.d')
        if folder.exists():
            require(folder.is_dir() and not folder.is_symlink(), 'unsafe drop-in directory')
            require({str(Path('/etc/systemd/system')/(name+'.d')/x.name) for x in folder.iterdir()}==set(dropins), 'unloaded drop-in present')
        require(p['ExecStop']==p['ExecStopPost']=='' and p['KillMode']=='control-group'
                and p['SendSIGKILL']=='yes', 'unreviewed stop semantics')
        timeout=seconds(p['TimeoutStopUSec']);require(0<timeout<=90, 'service stop exceeds cap')
        require(p['TriggeredBy']==p['RequiredBy']=='' and p['WantedBy'] in ('','multi-user.target'), 'unreviewed automatic activation')
        require(p['ActiveState'] in ('active','inactive','failed') and (p['ActiveState']!='active' or int(p['MainPID'])>0), 'unresolved service transition')
        require(p['ControlGroup'] in ('','/system.slice/'+name), 'foreign cgroup')
        return {'fragment_sha256':pin['fragment_sha256'],'dropins':pin['dropins'],
                'exec_stop':[],'exec_stop_post':[],'kill_mode':'control-group','timeout_stop_seconds':timeout}, p

    def observe(self):
        owned={};absent=[];states={}
        for name in UNITS:
            value,states[name]=self.unit(name)
            if value is None: absent.append(name)
            else: owned[name]=value
        return owned,absent,states

    def review(self, deadline):
        self.guard(deadline,fresh_review=False);owned,absent,states=self.observe()
        self.candidate_processes(states)
        preservation=self.preservation()
        return {'preservation':preservation,'owned_units':owned,'absent_units':absent,'prior_uncertain':False,
                'foreign_processes':[],'retained_files':self.files(self.scope['retained_files'])}

    def stop(self, deadline, commands):
        self.guard(deadline)
        initial,_,_=self.observe()
        if not initial:
            require(not commands, 'empty installation cannot have stop commands')
            return {'stopped_units':[]}
        require(self.scope['executable_sha256'] is not None,'unexpected service without installed authority')
        lock_path=self.path('/run/lock/sbxr.lock')
        fd=os.open(lock_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            st=os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==(0 if self.native else os.getuid()), 'unsafe existing mutation lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            owned,_,_=self.observe()
            expected=tuple(('/usr/bin/systemctl','disable','--now',name) for name in UNITS if name in owned)
            require(tuple(tuple(c) for c in commands)==expected, 'stop scope changed')
            stopped=[]
            for argv in expected:
                self.guard(deadline,fresh_review=False);self.unit(argv[-1])
                self.run(list(argv),cap=110)
                stopped.append(argv[-1])
            require(self.files(self.scope['retained_files'])==self.scope['retained_files'], 'stop changed retained data')
            return {'stopped_units':stopped}
        finally: os.close(fd)

    def verify(self, deadline):
        # The prior review may be old after two real systemd stops; immutable
        # anchors still bind the action. Fresh unit/process facts below are mandatory.
        scope=self.scope
        self.guard(deadline,fresh_review=False)
        return self.stopped_facts()

    def stopped_facts(self):
        scope=self.scope
        owned,absent,states=self.observe()
        for name in owned:
            p=states[name]
            require(p['ActiveState']=='inactive' and p['UnitFileState']=='disabled'
                    and p['MainPID']==p['ControlPID']=='0' and p['WantedBy']=='', 'service remains active/enabled or activated')
        self.candidate_processes(states,stopped=True)
        listeners=self.run(['/usr/bin/ss','-H','-ltn','sport = :443 or sport = :8443'])
        require(not listeners.strip(), 'test listener remains')
        # A stopped main PID is insufficient: inspect all cgroup members.
        for name in owned:
            group=self.path('/sys/fs/cgroup/system.slice/'+name+'/cgroup.procs')
            if group.exists():require(not self.virtual_read('/sys/fs/cgroup/system.slice/'+name+'/cgroup.procs').strip(), 'service cgroup remains populated')
        return {'inactive_disabled_units':list(owned),'absent_units':absent,'candidate_pids':[],
                'open_test_ports':[],'retained_files':self.files(scope['retained_files'])}

    def preserved_metadata(self,name):
        path=self.path(name);before=path.lstat()
        result=dict(dev=before.st_dev,ino=before.st_ino,uid=before.st_uid,gid=before.st_gid,
                    mode=oct(stat.S_IMODE(before.st_mode)),nlink=before.st_nlink,size=before.st_size)
        if stat.S_ISREG(before.st_mode):result.update(kind='regular',sha256=sha(self.read(name)))
        elif stat.S_ISDIR(before.st_mode):result['kind']='directory'
        elif stat.S_ISLNK(before.st_mode):result.update(kind='symlink',target=os.readlink(path))
        else:raise ValueError('unsupported preserved file type')
        after=path.lstat()
        require(all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')),'preserved path changed')
        return result

    def preserved_inventory(self):
        names=self.scope['unrelated_files'];require(len(names)<=4096,'preserved inventory exceeds bound')
        files={}
        for name in names:
            require(self.now()<self.deadline,'preserved inventory deadline')
            files[name]=self.preserved_metadata(name) if os.path.lexists(self.path(name)) else None
        # A fixed file list alone cannot detect a new member in retained evidence.
        archives={}
        for name in ('/root/sbxr-qualification-evidence-q212-41958829811','/root/sbxr-qualification-evidence-q213-42023983739','/var/lib/sbxr-rust-t1'):
            if name not in names:continue
            base=self.path(name);members=[]
            if os.path.lexists(base):
                members.append(name)
                if base.is_dir() and not base.is_symlink():
                    for folder,dirs,children in os.walk(base,followlinks=False):
                        require(self.now()<self.deadline,'preserved archive deadline')
                        members.extend('/'+str((Path(folder)/x).relative_to(self.root)) for x in dirs+children)
                        require(len(members)<=4096,'preserved archive exceeds bound')
            archives[name]=sorted(members)
        return files,archives

    def preservation(self):
        commands={
            'packages':['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'],
            'holds':['/usr/bin/apt-mark','showhold'],
            'accounts':['/usr/bin/getent','passwd'],
            'groups':['/usr/bin/getent','group'],
        }
        result={key:sha(self.run(argv).encode()) for key,argv in commands.items()}
        for key,argv in [('firewall',['/usr/sbin/iptables-save']),('ip6firewall',['/usr/sbin/ip6tables-save'])]:
            raw=self.run(argv)
            normalized='\n'.join(re.sub(r'\[\d+:\d+\]','[0:0]',line) for line in raw.splitlines() if not line.startswith('#'))
            result[key]=sha(normalized.encode());result[key+'_normalized']=normalized
        result['files'],result['archive_members']=self.preserved_inventory()
        return result

    def transport(self, deadline):
        require(deadline<=self.scope['final_cutoff'] and self.now()<deadline,'final deadline')
        self.deadline=deadline
        require(sha(self.read('/etc/machine-id'))==self.scope['machine_sha256'] and sha(self.virtual_read('/proc/sys/kernel/random/boot_id'))==self.scope['boot_sha256'],'post-transport machine/boot changed')
        require(self.files(AUTHORITY)==self.scope['authority_files'] and self.files(self.scope['retained_files'])==self.scope['retained_files'],'retained installation changed after rollback')
        self.stopped_facts()
        require(not os.path.lexists(self.path('/root/sbxr-qualification-v3')),'transport staging remains')
        require(not os.path.lexists(self.path('/usr/local/share/ca-certificates/sbxr-qualification-v3.crt')),'test CA remains')
        require(sha(self.read('/etc/ssl/certs/ca-certificates.crt'))==self.scope['original_ca_bundle_sha256'],'system trust not restored')
        require(b'sbxr-qualification-v3' not in self.read('/etc/hosts'),'temporary hosts entry remains')
        nat=self.run(['/usr/sbin/iptables-save','-t','nat'])
        require('*nat' in nat and 'COMMIT' in nat and 'sbxr-qualification-v3' not in nat,'temporary routing unproved')
        result=self.run(['/usr/bin/systemctl','show','sbxr-qualification-v3.service','--property=LoadState,ActiveState,MainPID,ControlPID'])
        require(dict(line.split('=',1) for line in result.splitlines())=={'LoadState':'not-found','ActiveState':'inactive','MainPID':'0','ControlPID':'0'},'gateway service remains')
        require(not self.run(['/usr/bin/ss','-H','-ltn','sport = :443 or sport = :8443 or sport = :9443']).strip(),'transport/test listener remains')
        aliases=self.path('/etc/ssl/certs')
        require(not any('sbxr-qualification-v3' in p.name or p.is_symlink() and 'sbxr-qualification-v3' in os.readlink(p) for p in aliases.iterdir()), 'test CA alias remains')
        return {'gateway_stopped':True,'test_ca_absent':True,'test_hosts_entry_absent':True,'test_redirect_absent':True,'post_preservation':self.preservation()}
