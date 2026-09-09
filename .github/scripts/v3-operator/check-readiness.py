#!/usr/bin/env python3
"""Verify exact rehearsal inputs before V4 candidate preparation.

Requires an isolated Linux rehearsal report supplied by the operator and reruns
the local entry-point suite. This never creates live qualification evidence.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('linux_rehearsal',HERE/'rehearse-linux.py')
linux=importlib.util.module_from_spec(spec)
spec.loader.exec_module(linux)

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate report key')
        result[key]=value
    return result

def validate(report, now=None):
    if report.get('schema') != 'sbxr-v4-linux-rehearsal-v1' or report.get('live_evidence') is not False:
        raise ValueError('invalid rehearsal report')
    completed=report.get('completed_unix')
    age=(time.time() if now is None else now)-completed if type(completed) is int else -1
    if not 0 <= age <= 86400: raise ValueError('fresh Linux rehearsal required')
    if report.get('source_sha256') != linux.source_hashes():
        raise ValueError('operator sources differ from Linux rehearsal')
    tests=report.get('tests')
    if not isinstance(tests,list) or [test.get('name') for test in tests] != linux.TESTS:
        raise ValueError('Linux rehearsal coverage incomplete')
    if any(type(test.get('exit_code')) is not int or test['exit_code'] != 0 for test in tests):
        raise ValueError('Linux rehearsal failed')
    return True

def main():
    path=Path(os.environ['SBXR_OPERATOR_REHEARSAL_REPORT'])
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_size > 1024*1024:
        raise ValueError('protected rehearsal report required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        current=os.fstat(stream.fileno())
        if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns) != (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns):
            raise ValueError('rehearsal report changed')
        body=stream.read()
        report=json.loads(body,object_pairs_hook=unique)
        validate(report)
        subprocess.run(['/bin/bash',str(HERE/'rehearse.sh')],check=True)
        after=path.lstat()
        final=os.fstat(stream.fileno())
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if identity(info) != identity(after) or identity(info) != identity(final):
            raise ValueError('rehearsal report changed')
        stream.seek(0)
        if stream.read() != body:
            raise ValueError('rehearsal report changed')
        validate(report)
    print(json.dumps({'schema':'sbxr-v4-operator-readiness-v1','ready':True,
                      'live_evidence':False,'linux_report_sha256':hashlib.sha256(body).hexdigest()}))

if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'schema':'sbxr-v4-operator-readiness-v1','ready':False,
                          'live_evidence':False,'error_type':type(error).__name__}),file=sys.stderr)
        sys.exit(1)
