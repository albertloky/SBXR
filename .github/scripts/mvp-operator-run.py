#!/usr/bin/env python3
"""Launch a local operator command with private, disjoint outer logs.

This only reserves local logs and execs the supplied command. It does not
observe, submit, retry, or qualify a journey. Use a fresh acceptance directory.
"""
import argparse
import os
from pathlib import Path
import re
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    command = options.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", options.label):
        parser.error("a command and a simple artifact label are required")
    directory = options.run_directory
    if not directory.is_dir():
        parser.error("run directory must already exist")
    captures = [directory / (options.label + suffix)
                for suffix in (".private", ".stderr", ".receipt.json")]
    logs = [directory / (options.label + suffix)
            for suffix in (".operator.stdout", ".operator.stderr")]
    if any(os.path.lexists(path) for path in captures + logs):
        parser.error("operator log or inner capture already exists; command not launched")
    os.umask(0o077)
    opened = []
    try:
        for path in logs:
            opened.append((path, path.open("xb", buffering=0)))
    except OSError:
        for _, stream in opened:
            stream.close()
        parser.error("could not reserve operator logs; command not launched")
    # Replace this process so stdin, cwd, exit status and cancellation remain
    # the supplied command's. No extra supervisor or detached child is added.
    for descriptor, (_, stream) in zip((1, 2), opened):
        os.dup2(stream.fileno(), descriptor)
        stream.close()
    try:
        os.execvp(command[0], command)
    except OSError:
        print("could not launch operator command", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
