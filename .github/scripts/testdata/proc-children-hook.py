"""Emulate only the optional kernel child-list read; processes/signals are real."""
import builtins
import io
import os
import sys


if sys.argv[0] == "-" or sys.argv[0].endswith("/v3-menu-session.py"):
    original_open = builtins.open

    def children_open(file, *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)) and os.fsdecode(file) == f"/proc/self/task/{os.getpid()}/children":
            mode = os.environ["SBXR_TEST_CHILDREN_MODE"]
            with original_open(os.environ["SBXR_TEST_CHILDREN_OBSERVED"], "a") as observed:
                observed.write(mode + "\n")
            if mode == "missing":
                raise FileNotFoundError("optional task children interface absent")
            assert mode == "listed"
            children = []
            for entry in os.listdir("/proc"):
                if not entry.isdecimal():
                    continue
                try:
                    with original_open(f"/proc/{entry}/stat") as stream:
                        tail = stream.read().rsplit(") ", 1)[1].split()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if int(tail[1]) == os.getpid():
                    children.append(entry)
            # A stale/unowned entry must not make the controller signal a
            # sibling. Ownership is checked by the real kernel waitid call.
            children.append(os.environ["SBXR_TEST_UNRELATED_PID"])
            return io.StringIO(" ".join(children))
        return original_open(file, *args, **kwargs)

    builtins.open = children_open
