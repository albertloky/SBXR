"""Read the formal cleanup clock through the already bound containment transport."""
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import time

# The maintained recorder is streamed as data and run only in cleanup-deadline
# mode. The receiving host has no caller-selected command or filesystem path.
HOST_CLOCK = r'''
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

os.chdir('/')
stage = Path('root/sbxr-qualification-v3')
request = Path('root/sbxr-qualification-evidence/request.json')
draft = Path('root/mvp-observation-draft.json')

def read(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1
                or st.st_mode & 0o022 or private and stat.S_IMODE(st.st_mode) != 0o600):
            raise ValueError('unsafe clock input')
        data = stream.read((16 << 20) + 1)
    if not 0 < len(data) <= 16 << 20:
        raise ValueError('clock input size')
    return data

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def inputs():
    for directory in (Path('root'), stage, request.parent):
        st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError('unsafe clock directory')
    return (read(stage/'staging-owned'), read(stage/'qualification-manifest.json'),
            read(stage/'fresh-window-decision.json'), read(request, True),
            read(stage/'runtime-deadline', True), read('etc/machine-id'), sha(read(draft, True)))

initial = inputs()
owner, manifest_raw, decision_raw, request_raw, runtime_raw, machine, _ = initial
manifest = json.loads(manifest_raw)
decision = json.loads(decision_raw)
window = decision['window']
q = json.loads(request_raw)
if (owner != f'{run}-1\n'.encode() or sha(manifest_raw) != cfg['manifest_sha256']
        or sha(machine) != manifest['v3_attempt']['vps_identity_sha256']
        or manifest['workflow']['run_id'] != cfg['origin_run_id'] or str(run) == cfg['origin_run_id']
        or window['workflow']['run_id'] != str(run) or type(window['run_attempt']) is not int
        or window['run_attempt'] != 1 or window['origin'] != manifest['workflow']
        or window['release'] != manifest['releases'][0] or window['manifest_sha256'] != sha(manifest_raw)
        or (decision['schema'], decision['stage'], decision['outcome'], window['schema']) !=
           ('sbxr-release-qualification-decision-v1','qualification-window','accepted','sbxr-qualification-window-v1')
        or (window['start_unix'], window['test_until_unix'], window['finish_unix']) !=
           (cfg['approved_window_start'], cfg['test_finish_unix'], cfg['cleanup_finish_unix'])
        or sha(request_raw) != request_pin or q['qualification_manifest_sha256'] != sha(manifest_raw)
        or q['qualification_window_sha256'] != sha(decision_raw) or q['scenario_id'] != scenario
        or not re.fullmatch(rb'[1-9][0-9]{0,9}\n', runtime_raw)):
    raise ValueError('clock run, request, machine or window differs')
# Match the collector's M5 restoration row. Entry and its supervisor still
# enforce any earlier cutoff in the approved scope for every invocation.
limit = min(int(runtime_raw), phase_cutoff, q['deadline_unix'])
if not window['start_unix'] <= time.time() < limit:
    raise ValueError('inactive cleanup window')
result = subprocess.run([sys.executable, '-I', '-B', '-', 'cleanup-deadline', '--request', str(request),
                         '--draft', str(draft)], input=recorder, capture_output=True,
                        timeout=min(10, limit-time.time()))
if result.returncode or not re.fullmatch(rb'[0-9]+\n', result.stdout):
    raise ValueError('recorder refused cleanup clock')
end = min(limit, int(result.stdout))
if inputs() != initial or not window['start_unix'] <= time.time() < end:
    raise ValueError('clock inputs changed or expired')
print(json.dumps({'effective_deadline_unix': end, 'request_sha256': sha(request_raw),
                  'run_id': run, 'scenario_id': scenario, 'runtime_deadline_unix': int(runtime_raw)}))
'''


def read_bound_clock(scenario, cfg, binding, invoke):
    """Entry supplies its previously authenticated identity and phase-bounded transport."""
    if scenario not in ('mvp-install', 'mvp-subscription', 'mvp-credentials', 'mvp-serving', 'mvp-removal'):
        raise ValueError('unsupported clock scenario')
    run = binding['run_id']
    if type(run) is not int or run <= 0 or binding['manifest_sha256'] != cfg['manifest_sha256']:
        raise ValueError('authenticated candidate differs from preparation')
    path = Path(__file__).parent / 'operator-source/mvp-observe.py'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o022:
            raise ValueError('unsafe prepared recorder')
        recorder = stream.read(65537)
    if len(recorder) > 65536 or hashlib.sha256(recorder).hexdigest() != cfg['cleanup_clock_sha256']:
        raise ValueError('reviewed recorder bytes changed')
    fields = ('origin_run_id', 'manifest_sha256', 'approved_window_start', 'test_finish_unix', 'cleanup_finish_unix')
    fixed = {key: cfg[key] for key in fields}
    phase_cutoff = cfg['cleanup_finish_unix'] - 60 if scenario == 'mvp-removal' else cfg['test_finish_unix']
    header = (f'cfg={fixed!r}\nrun={run!r}\nscenario={scenario!r}\n'
              f"request_pin={binding['request_sha256']!r}\nphase_cutoff={phase_cutoff!r}\nrecorder={recorder!r}\n")
    code, out, _ = invoke('containment-clock', ['python3', '-B', '-'], (header + HOST_CLOCK).encode(),
                          timeout=80, reserve=0, cutoff=phase_cutoff)
    if code:
        raise ValueError('cleanup clock transport refused')
    value = json.loads(out)
    if (value['run_id'] != run or value['scenario_id'] != scenario
            or not re.fullmatch('[0-9a-f]{64}', value['request_sha256'])
            or type(value['effective_deadline_unix']) is not int
            or not time.time() < value['effective_deadline_unix'] <= phase_cutoff):
        raise ValueError('invalid cleanup clock observation')
    return value
