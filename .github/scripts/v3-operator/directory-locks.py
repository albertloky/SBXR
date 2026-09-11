#!/usr/bin/env python3
"""Hold Certbot's three real POSIX directory locks for scenario 23."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import stat
import sys


PATHS = (
    "/etc/letsencrypt/.certbot.lock",
    "/var/lib/letsencrypt/.certbot.lock",
    "/var/log/letsencrypt/.certbot.lock",
)


class DirectoryLocks:
    def __init__(self, paths=PATHS, owner_uid: int = 0):
        self.paths = tuple(paths)
        self.owner_uid = owner_uid
        self.descriptors: list[tuple[str, int, dict, bool]] = []

    @staticmethod
    def metadata(descriptor: int) -> dict:
        info = os.fstat(descriptor)
        value = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            value.update(block)
        after = os.fstat(descriptor)
        before_identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                           info.st_gid, info.st_nlink, info.st_size,
                           info.st_mtime_ns, info.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                          after.st_gid, after.st_nlink, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
        if before_identity != after_identity:
            raise RuntimeError("Certbot lock changed while hashing")
        return {"device": info.st_dev, "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                "gid": info.st_gid, "nlink": info.st_nlink, "size": info.st_size,
                "sha256": value.hexdigest()}

    def acquire(self) -> list[dict]:
        try:
            for raw_path in self.paths:
                path = Path(raw_path)
                created = False
                try:
                    before = path.lstat()
                except FileNotFoundError:
                    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    created = True
                    before = os.fstat(descriptor)
                else:
                    if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.owner_uid or
                            before.st_nlink != 1 or before.st_mode & 0o022):
                        raise RuntimeError(f"unsafe Certbot lock: {raw_path}")
                    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.owner_uid or
                        before.st_nlink != 1 or before.st_mode & 0o022):
                    os.close(descriptor)
                    if created:
                        os.unlink(path)
                    raise RuntimeError(f"unsafe Certbot lock: {raw_path}")
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    os.close(descriptor)
                    raise RuntimeError(f"Certbot lock identity changed: {raw_path}")
                try:
                    fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except Exception:
                    os.close(descriptor)
                    if created:
                        current = path.lstat()
                        if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                            path.unlink()
                    raise
                after = path.lstat()
                if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                    os.close(descriptor)
                    raise RuntimeError(f"Certbot lock path changed: {raw_path}")
                try:
                    metadata = self.metadata(descriptor)
                except Exception:
                    # lockf succeeded, but the descriptor is not tracked yet.
                    # Closing it is required to release the process's lock.
                    os.close(descriptor)
                    if created:
                        try:
                            current = path.lstat()
                            if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                                path.unlink()
                        except FileNotFoundError:
                            pass
                    raise
                self.descriptors.append((raw_path, descriptor, metadata, created))
        except Exception:
            self.release()
            raise
        return [{"path": path, **metadata, "mode": f"{metadata['mode']:04o}", "created": created}
                for path, _, metadata, created in self.descriptors]

    def revalidate(self) -> None:
        for raw_path, descriptor, metadata, _ in self.descriptors:
            opened = self.metadata(descriptor)
            current = os.lstat(raw_path)
            if opened != metadata or (metadata["device"], metadata["inode"]) != (current.st_dev, current.st_ino):
                raise RuntimeError(f"held Certbot lock identity changed: {raw_path}")

    def release(self) -> None:
        while self.descriptors:
            raw_path, descriptor, metadata, created = self.descriptors.pop()
            try:
                if created:
                    current = os.lstat(raw_path)
                    if (current.st_dev, current.st_ino) != (metadata["device"], metadata["inode"]) or current.st_size != 0:
                        raise RuntimeError(f"created Certbot lock changed: {raw_path}")
                    os.unlink(raw_path)
                fcntl.lockf(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=90)
    options = parser.parse_args(arguments)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("root on Linux is required")
    if not 1 <= options.timeout <= 180:
        parser.error("timeout must be 1..180 seconds")
    locks = DirectoryLocks()
    def release_and_exit(_signum, _frame):
        locks.release()
        raise SystemExit(128 + _signum)

    signal.signal(signal.SIGTERM, release_and_exit)
    signal.signal(signal.SIGINT, release_and_exit)
    acquired = locks.acquire()
    print(json.dumps({"schema": "sbxr-v4-certbot-directory-locks-v1", "pid": os.getpid(),
                      "locks": acquired}, sort_keys=True, separators=(",", ":")), flush=True)
    readable, _, _ = select.select([sys.stdin], [], [], options.timeout)
    line = sys.stdin.readline() if readable else ""
    if line == "release\n":
        locks.revalidate()
        released = [{"path": path, **metadata, "mode": f"{metadata['mode']:04o}",
                     "created": created}
                    for path, _, metadata, created in locks.descriptors]
        locks.release()
        print(json.dumps({"schema": "sbxr-v4-certbot-directory-locks-released-v1",
                          "pid": os.getpid(), "locks": released},
                         sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    locks.release()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
