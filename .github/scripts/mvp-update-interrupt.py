#!/usr/bin/env python3
"""Interrupt an unchanged packaged Update at its successful directory fsync.

Linux/root operator control, not an updater or an acceptance recorder. The
expected hashes come from independently verified source/candidate material.
Never writes product files, changes syscall results, or repairs a failed run.
See docs/acceptance/ordinary-recurring-live.md before use.
"""

import argparse
import ctypes
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time


PRODUCT = Path('/usr/local/bin/sbxr')
STATE = Path('/var/lib/sbxr')
WINDOW = Path('/root/sbxr-mvp-log-parent')
WRAPPER_HASH = '56fab3f89dbed0dbb668f296a33ac8b512e8676edb5962a796a45bbc649123de'
FIELDS = ('prior_executable_sha256', 'prior_installed_record_sha256',
          'candidate_executable_sha256', 'candidate_installed_record_sha256',
          'ownership_sha256')
OPTIONS = 0x10001f  # EXITKILL, TRACESYSGOOD, FORK/VFORK/CLONE/EXEC
WALL = 0x40000000
MARKER = 'SBXR_UPDATE_INTERRUPTED '


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def exact_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def private_read(path, mode=0o600, links=1, limit=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == mode and before.st_nlink == links
                and before.st_size <= limit and not os.listxattr(fd), 'unsafe-file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            body = stream.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(body) <= limit and identity(before) == identity(after), 'file-changed')
        return body
    finally:
        os.close(fd)


def expected(path):
    value = json.loads(private_read(path), object_pairs_hook=exact_object)
    require(set(value) == set(FIELDS), 'expectation-fields')
    require(all(isinstance(value[k], str) and re.fullmatch('[0-9a-f]{64}', value[k])
                for k in FIELDS), 'expectation-digests')
    return value


def file_hash(path, mode=0o600, links=1):
    return digest(private_read(path, mode, links, 128 * 1024 * 1024))


def ownership_hash():
    path = STATE / 'proxy-ownership.json'
    if not os.path.lexists(path):
        return digest(b'')
    return file_hash(path)


def initial_proof(wanted):
    require(file_hash(PRODUCT, 0o755) == wanted['prior_executable_sha256'], 'source-executable')
    require(file_hash(STATE / 'installed.json') == wanted['prior_installed_record_sha256'], 'source-record')
    require(ownership_hash() == wanted['ownership_sha256'], 'source-ownership')
    for path in (STATE / 'update.json', STATE / '.update.json.next',
                 STATE / '.installed.json.prior', STATE / '.installed.json.candidate',
                 PRODUCT.parent / '.sbxr-update-prior', PRODUCT.parent / '.sbxr-update-candidate'):
        require(not os.path.lexists(path), 'existing-transaction')


def checkpoint_proof(wanted, checkpoint):
    record = json.loads(private_read(STATE / 'update.json'), object_pairs_hook=exact_object)
    require(record == dict(wanted, schema=2, checkpoint=checkpoint), 'checkpoint-mismatch')
    require(ownership_hash() == wanted['ownership_sha256'], 'ownership-changed')
    prior_links = 2 if checkpoint == 'Prepared' else 1
    require(file_hash(PRODUCT.parent / '.sbxr-update-prior', 0o755, prior_links)
            == wanted['prior_executable_sha256'], 'prior-executable-changed')
    require(file_hash(STATE / '.installed.json.prior')
            == wanted['prior_installed_record_sha256'], 'prior-record-changed')
    prefix = 'prior' if checkpoint == 'Prepared' else 'candidate'
    require(file_hash(PRODUCT, 0o755, prior_links if checkpoint == 'Prepared' else 1)
            == wanted[prefix + '_executable_sha256'], 'active-executable-mismatch')
    require(file_hash(STATE / 'installed.json')
            == wanted[prefix + '_installed_record_sha256'], 'active-record-mismatch')
    if checkpoint == 'Prepared':
        require(file_hash(PRODUCT.parent / '.sbxr-update-candidate', 0o755)
                == wanted['candidate_executable_sha256'], 'candidate-executable-mismatch')
        require(file_hash(STATE / '.installed.json.candidate')
                == wanted['candidate_installed_record_sha256'], 'candidate-record-mismatch')
    with open('/run/lock/sbxr.lock', 'rb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise Refused('mutation-lock-not-held')
    return digest(private_read(STATE / 'update.json'))


def ptrace(request, pid, addr=0, data=0):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    argument = ctypes.c_void_p(data) if isinstance(data, int) else ctypes.cast(data, ctypes.c_void_p)
    result = libc.ptrace(request, pid, ctypes.c_void_p(addr), argument)
    if result == -1:
        raise OSError(ctypes.get_errno(), 'ptrace')
    return result


def trace(boundary, expectation, deadline):
    wanted = expected(expectation)
    initial_proof(wanted)
    source_info = PRODUCT.stat()
    checkpoint = {'precommit': 'Prepared', 'postcommit': 'Committed'}[boundary]
    cancelled = []
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, lambda sig, _frame: cancelled.append(sig))
    leader = os.fork()
    if leader == 0:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(signum, signal.SIG_DFL)
        ptrace(0, 0)  # TRACEME before exec; no source modification/preload.
        os.kill(os.getpid(), signal.SIGSTOP)
        # Same narrow product-child boundary as mvp-protected-menu.sh; keep
        # this tracer's and the permission wrapper's private masks untouched.
        os.umask(0o022)
        os.execv(str(PRODUCT), [str(PRODUCT)])
    traced, pending = {leader}, {}
    hit = None
    try:
        pid, status = os.waitpid(leader, 0)
        require(os.WIFSTOPPED(status), 'trace-start')
        ptrace(0x4200, pid, data=OPTIONS)
        ptrace(24, pid)  # SYSCALL
        while traced:
            require(not cancelled and time.monotonic() < deadline, 'trace-cancelled-or-expired')
            pid, status = os.waitpid(-1, WALL | os.WNOHANG)
            if not pid:
                time.sleep(0.0005)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                traced.discard(pid)
                pending.pop(pid, None)
                require(pid != leader, 'product-exited-before-boundary')
                continue
            traced.add(pid)
            sig, event = os.WSTOPSIG(status), status >> 16
            if event in (1, 2, 3):  # fork/vfork/clone includes Go OS threads.
                child = ctypes.c_ulong()
                ptrace(0x4201, pid, data=ctypes.byref(child))
                traced.add(child.value)
            elif event == 4:  # exec may collapse a nonleader thread's TID.
                former = ctypes.c_ulong()
                ptrace(0x4201, pid, data=ctypes.byref(former))
                if former.value != pid:
                    traced.discard(former.value)
                    pending.pop(former.value, None)
            elif sig == signal.SIGTRAP | 0x80:
                info = ctypes.create_string_buffer(88)
                size = ptrace(0x420e, pid, 88, info)  # GET_SYSCALL_INFO
                require(size >= 24, 'syscall-info-unavailable')
                raw = info.raw
                arch = struct.unpack_from('=I', raw, 4)[0]
                require(arch in (0xc000003e, 0xc00000b7), 'syscall-architecture')
                if raw[0] == 1:  # entry: nr + six arguments, no guessed toggling
                    require(size >= 80, 'short-syscall-entry')
                    number, fd = struct.unpack_from('=QQ', raw, 24)
                    pending.pop(pid, None)
                    if number == (74 if arch == 0xc000003e else 82):
                        try:
                            opened = os.stat(f'/proc/{pid}/fd/{fd}')
                            directory = STATE.stat()
                            if (opened.st_dev, opened.st_ino) == (directory.st_dev, directory.st_ino):
                                pending[pid] = fd
                        except FileNotFoundError:
                            pass
                elif raw[0] == 2:
                    require(size >= 33, 'short-syscall-exit')
                    fd = pending.pop(pid, None)
                    if fd is not None and struct.unpack_from('=q', raw, 24)[0] == 0:
                        # The mutating thread is still stopped at syscall exit:
                        # no runtime completion/cleanup can race this proof.
                        try:
                            record = json.loads(private_read(STATE / 'update.json'),
                                                object_pairs_hook=exact_object)
                        except FileNotFoundError:
                            record = None
                        if record and record.get('checkpoint') == checkpoint:
                            status_lines = Path(f'/proc/{pid}/status').read_text().splitlines()
                            require(f'Tgid:\t{leader}' in status_lines, 'checkpoint-not-product')
                            running = Path(f'/proc/{leader}/exe').stat()
                            require((running.st_dev, running.st_ino) == (source_info.st_dev, source_info.st_ino),
                                    'source-process-executable-changed')
                            record_digest = checkpoint_proof(wanted, checkpoint)
                            hit = dict(boundary=boundary, checkpoint=checkpoint,
                                       update_record_sha256=record_digest, syscall='fsync',
                                       syscall_result=0, source_executable_sha256=wanted['prior_executable_sha256'],
                                       candidate_executable_sha256=wanted['candidate_executable_sha256'])
                            break
            ptrace(24, pid, data=0 if event or sig in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80) else sig)
        require(hit is not None, 'boundary-not-observed')
    finally:
        # Kill traced product threads/children only; leave the permission
        # wrapper and its supervisor alive to finish their own restoration.
        for pid in traced:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        cleanup_deadline = time.monotonic() + 10
        while True:
            try:
                pid, status = os.waitpid(-1, WALL | os.WNOHANG)
            except ChildProcessError:
                break
            require(time.monotonic() < cleanup_deadline, 'trace-cleanup-expired')
            if not pid:
                time.sleep(0.001)
            elif os.WIFSTOPPED(status):
                os.kill(pid, signal.SIGKILL)
                ptrace(24, pid, data=signal.SIGKILL)
    require(hit is not None, 'boundary-not-observed')
    require(digest(private_read(STATE / 'update.json')) == hit['update_record_sha256'],
            'checkpoint-changed-after-death')
    hit['observed_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(MARKER + json.dumps(hit, sort_keys=True, separators=(',', ':')), flush=True)


def main():
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'root-linux-required')
    # The reviewed menu directory has an exact four-file inventory. Importing
    # its driver must not leave __pycache__ or another unreviewed host artifact.
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser()
    parser.add_argument('boundary', choices=('precommit', 'postcommit'))
    parser.add_argument('--expectation', required=True)
    parser.add_argument('--transcript', required=True)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--protected-log-parent', action='store_true')
    if len(sys.argv) > 1 and sys.argv[1] == '_trace':
        require(len(sys.argv) == 5, 'trace-arguments')
        require(sys.argv[2] in ('precommit', 'postcommit'), 'trace-boundary')
        require(time.monotonic() < float(sys.argv[4]) <= time.monotonic() + 1800, 'trace-deadline')
        trace(sys.argv[2], sys.argv[3], float(sys.argv[4]))
        return
    args = parser.parse_args()
    require(0 < args.timeout <= 1800, 'timeout-invalid')
    deadline = time.monotonic() + args.timeout
    request_path = os.environ.get('SBXR_QUALIFICATION_REQUEST')
    if request_path:
        request = json.loads(private_read(request_path, limit=65536), object_pairs_hook=exact_object)
        require(set(request) == {'scenario_id', 'not_before', 'deadline_unix',
                                 'scenario_limit_seconds', 'qualification_manifest_sha256',
                                 'required_checks'}, 'request-fields')
        require(re.fullmatch(r'source-v[0-9]+\.[0-9]+\.[0-9]+-' + args.boundary,
                             request.get('scenario_id', '')), 'request-scenario')
        require(type(request.get('deadline_unix')) is int, 'request-deadline')
        require(isinstance(request['not_before'], str) and
                re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', request['not_before']), 'request-start')
        start = datetime.datetime.strptime(request['not_before'], '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=datetime.timezone.utc).timestamp()
        require(start <= time.time() and request['scenario_limit_seconds'] == 1800 and
                0 <= request['deadline_unix'] - start <= 1800, 'request-window')
        deadline = min(deadline, time.monotonic() + request['deadline_unix'] - time.time())
    require(time.monotonic() < deadline, 'request-expired')
    initial_proof(expected(args.expectation))
    driver = WINDOW / 'v3-menu-session.py' if args.protected_log_parent else Path(__file__).with_name('v3-menu-session.py')
    if args.protected_log_parent:
        private_read(driver, limit=65536)
    spec = importlib.util.spec_from_file_location('menu', driver)
    menu = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(menu)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'subreaper-unavailable')
    cancelled = []
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, lambda sig, _frame: cancelled.append(sig))
    command = [sys.executable, str(Path(__file__).resolve()), '_trace', args.boundary,
               str(Path(args.expectation).resolve()), str(deadline)]
    if args.protected_log_parent:
        wrapper = WINDOW / 'with-protected-log-parent.sh'
        require(digest(private_read(wrapper, 0o700, limit=65536)) == WRAPPER_HASH, 'wrapper-identity')
        log = Path('/var/log/letsencrypt')
        info = log.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and not os.listxattr(log), 'protected-certbot-log-required')
        command = ['/usr/bin/bash', str(wrapper), 'run', str(WINDOW / 'window.state'), '--'] + command
    fd = os.open(args.transcript, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as sink:
        require(time.monotonic() < deadline, 'deadline-before-launch')
        session = menu.MenuSession(command, sink, deadline, lambda: bool(cancelled),
                                   protected_wrapper=args.protected_log_parent)
        try:
            session.choose('Update')
            session.expect_prompt(menu.PROMPTS['Update'], review_code=menu.REVIEW_CODES['Update'])
            session.write('y\n')
            while True:
                line = session.stream.line(session.deadline)
                require(line is not None, 'exit-before-interruption')
                if line.startswith(MARKER):
                    receipt = json.loads(line[len(MARKER):], object_pairs_hook=exact_object)
                    require(receipt['boundary'] == args.boundary, 'receipt-boundary')
                    break
                require(not line.startswith('Code: '), 'update-refused-or-missed-boundary')
            session.finish()
        except BaseException:
            session.stop()
            raise
    print(MARKER + json.dumps(receipt, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Detailed product output stays in the private transcript. A refusal
        # never authorizes Recover, permission restoration, or evidence reuse.
        reason = str(error) if isinstance(error, Refused) else type(error).__name__
        print('SBXR_UPDATE_INTERRUPT_REFUSED reason=' + reason, file=sys.stderr)
        if len(sys.argv) > 1 and sys.argv[1] == '_trace':
            print('SBXR_UPDATE_INTERRUPT_REFUSED reason=' + reason, flush=True)
        raise SystemExit(1)
