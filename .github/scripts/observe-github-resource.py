#!/usr/bin/env python3
"""Classify one GitHub GET as present, explicit 404 absence, or unavailable."""

import json
import re
import subprocess
import sys


def observe(endpoint):
    if not re.fullmatch(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(releases/(?:[1-9][0-9]*|latest|tags/[^\s?#]+)|git/ref/tags/[^\s?#]+)", endpoint):
        raise ValueError("GitHub observation endpoint refused")
    result = subprocess.run(["gh", "api", "--include", endpoint], capture_output=True, timeout=60)
    response = result.stdout.replace(b"\r\n", b"\n")
    headers, separator, body = response.partition(b"\n\n")
    first = headers.split(b"\n", 1)[0]
    status = re.fullmatch(rb"HTTP/[12](?:\.\d)? ([1-5][0-9]{2})(?: [^\n]*)?", first)
    if not separator or status is None:
        raise ValueError("GitHub observation unavailable")
    code = int(status[1])
    if code == 404 and result.returncode == 1:
        return {"state": "absent", "value": None}
    if code != 200 or result.returncode != 0 or len(body) > 4 << 20:
        raise ValueError("GitHub observation unavailable")
    value = json.loads(body)
    if not isinstance(value, dict) or not value:
        raise ValueError("GitHub observation refused")
    return {"state": "present", "value": value}


def main():
    if len(sys.argv) != 2:
        raise ValueError("GitHub observation arguments refused")
    print(json.dumps(observe(sys.argv[1]), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        print("GitHub resource observation unavailable or refused", file=sys.stderr)
        sys.exit(2)
