#!/usr/bin/env python3
"""Bounded external BSD flock holder; never creates or writes the lock file."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import sys


def hold(path, timeout):
    if sys.platform != 'linux' or os.geteuid() != 0 or not 1 <= timeout <= 120 or not os.path.isabs(path):
        raise ValueError('Linux root and bounded absolute lock path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > 4096:
            raise ValueError('unsafe existing lock file')
        body = os.read(fd, 4097)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.lstat(path)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('lock path replaced')
        tick = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
        print(json.dumps({'state': 'held', 'pid': os.getpid(), 'start_tick': tick,
                          'device': before.st_dev, 'inode': before.st_ino, 'sha256': hashlib.sha256(body).hexdigest()}), flush=True)
        if not select.select([sys.stdin], [], [], timeout)[0] or sys.stdin.readline() != 'release\n':
            raise ValueError('explicit release required within deadline')
        current = os.lstat(path)
        os.lseek(fd, 0, os.SEEK_SET)
        if (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid, current.st_size) != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_size) or os.read(fd, 4097) != body:
            raise ValueError('held lock file changed')
        fcntl.flock(fd, fcntl.LOCK_UN)
        print('{"state":"released"}', flush=True)
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path')
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()
    try:
        hold(args.path, args.timeout)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__}), flush=True)
        sys.exit(1)
