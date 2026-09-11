#!/usr/bin/env python3
"""Rehearse external controls in isolated Linux fixtures; never run the product.

The snap checks run only `--version` in a unique transient fixture service with
persistent egress denial. No installed SBXR or official renewal unit is started.
The resulting report is readiness input, never live qualification evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
TESTS = ['exec-gate', 'network-guard', 'systemd-guard', 'combined-deny',
         'combined-release', 'snap-chain-deny', 'snap-chain-release',
         'syscall-python', 'syscall-go', 'syscall-go-child', 'syscall-sequence', 'identity-startup', 'flock', 'route',
         'firewall', 'sandbox-token-probe', 'protected-open-probe',
         'helper-unit-tests', 'entry-point-rehearsal']

def source_hashes():
    paths = [path for path in HERE.rglob('*')
             if path.is_file() and path.suffix in ('.py', '.sh', '.go', '.md')]
    paths += [HERE.parent/'v3-packaged-live.sh', HERE.parent/'v3-candidate-dispatch.sh',
              HERE.parent/'v3-recurring-evidence.sh',
              HERE.parents[2]/'docs/acceptance/v4-operator-procedures.md',
              HERE.parents[2]/'docs/acceptance/evidence-assembly.md']
    return {os.path.relpath(path, HERE): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}

def run(args):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('root Linux fixture environment required')
    before = source_hashes()
    interpreter = Path(args.interpreter).resolve(strict=True)
    fixture = Path(args.fixture).resolve(strict=True)
    py = sys.executable
    command = lambda name: [py, str(HERE/('rehearse-'+name+'.py'))]
    cases = [command('exec-gate'), command('network-guard'), command('systemd-guard'),
             command('combined-hold'), command('combined-hold')+[py,'direct','--release'],
             command('combined-hold')+[str(interpreter),'--snap-renew-version'],
             command('combined-hold')+[str(interpreter),'--snap-renew-version','--release'],
             command('syscall-gate'), command('syscall-gate')+[str(fixture)],
             command('syscall-gate')+[str(fixture),'--with-child','--repeat','6'],
             command('syscall-sequence')+[str(fixture)], command('identity-startup'), command('flock'),
             command('route'), ['unshare','-n','--']+command('firewall'),
             ['/bin/bash',str(HERE/'rehearse-sandbox-token-probe.sh')],
             ['/bin/bash',str(HERE/'rehearse-protected-open-probe.sh')],
             [py,'-m','unittest','discover','-s',str(HERE),'-p','test_*.py'],
             ['/bin/bash',str(HERE/'rehearse.sh')]]
    results=[]
    for name, argv in zip(TESTS,cases):
        started=time.time()
        result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
        log_path=Path(args.output).with_name(Path(args.output).name+'.'+name+'.log')
        log_fd=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(log_fd,'wb') as stream: stream.write(result.stdout)
        results.append({'name':name,'exit_code':result.returncode,
                        'duration_seconds':round(time.time()-started,3),'output_file':log_path.name,
                        'output_sha256':hashlib.sha256(result.stdout).hexdigest()})
        print(json.dumps({'fixture':name,'passed':result.returncode == 0}),flush=True)
        if result.returncode:
            # Fixture output contains synthetic values only, but do not expose
            # subprocess arguments or environmental data in the report.
            raise RuntimeError('fixture failed: '+name)
    if source_hashes() != before: raise ValueError('helpers changed during rehearsal')
    report={'schema':'sbxr-v4-linux-rehearsal-v1','live_evidence':False,
            'completed_unix':int(time.time()),'platform':platform.platform(),
            'runtime':{'system':platform.system(),'machine':platform.machine(),'uid':os.geteuid()},
            'source_sha256':before,'interpreter':str(interpreter),
            'interpreter_sha256':hashlib.sha256(interpreter.read_bytes()).hexdigest(),
            'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(), 'tests':results}
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream: json.dump(report,stream,sort_keys=True); stream.write('\n')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interpreter',required=True)
    parser.add_argument('--fixture',required=True)
    parser.add_argument('--output',required=True)
    try: run(parser.parse_args())
    except Exception as error:
        print(json.dumps({'state':'refused','error_type':type(error).__name__}),file=sys.stderr)
        sys.exit(1)
