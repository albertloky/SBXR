#!/usr/bin/env python3
import fcntl
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix='sbxr-flock-fixture-') as directory:
    path = Path(directory, 'lock')
    path.write_bytes(b'unchanged\n')
    path.chmod(0o600)
    before = path.stat()
    holder = subprocess.Popen([sys.executable, str(Path(__file__).with_name('hold-flock.py')), str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert select.select([holder.stdout], [], [], 5)[0]
        assert json.loads(holder.stdout.readline())['state'] == 'held'
        with path.open() as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                raise AssertionError('lock not held')
            except BlockingIOError:
                pass
        holder.stdin.write('release\n')
        holder.stdin.flush()
        assert holder.wait(timeout=5) == 0
        with path.open() as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
        after = path.stat()
        assert (before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode)
        assert path.read_bytes() == b'unchanged\n'
        print('actual BSD flock contention, release and preservation: pass')
    finally:
        if holder.poll() is None:
            holder.kill()
        holder.wait()
