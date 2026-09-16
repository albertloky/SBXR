#!/usr/bin/env python3
"""Download one authenticated asset; callers still verify its identity and bytes."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def download(repository, asset_id, destination):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[1-9][0-9]*", asset_id):
        raise ValueError("expected a repository and numeric release asset ID")
    destination = Path(destination)
    # Same filesystem for atomic replacement. A failed read never exposes its
    # incomplete body at the caller's destination, including during cleanup.
    with tempfile.TemporaryDirectory(prefix=".asset-download-", dir=destination.parent) as directory:
        body = Path(directory) / "body"
        for attempt in (1, 2):
            with body.open("wb") as output:
                result = subprocess.run(
                    ["gh", "api", f"repos/{repository}/releases/assets/{asset_id}",
                     "--method", "GET", "-H", "Accept: application/octet-stream"],
                    stdout=output, stderr=subprocess.PIPE,
                    env={**os.environ, "GH_DEBUG": ""})
            if result.returncode == 0:
                body.replace(destination)
                return 0
            error = result.stderr.decode("utf-8", errors="replace").strip()
            # gh may include a signed redirect URL in its transport error. Keep
            # the cause and byte count in Actions logs without that credential.
            safe_error = re.sub(r'https?://[^\s"<>]+', "[redacted-url]", error)
            print(f"Asset {asset_id} download attempt {attempt}/2 failed "
                  f"(exit {result.returncode}, {body.stat().st_size} bytes discarded): {safe_error}",
                  file=sys.stderr)
            # v3.1.73 failed on this exact read error. One new connection can
            # recover it safely because this is GET, not a release mutation.
            # Re-enter the API to obtain a fresh redirect; never resume a body.
            reset = re.fullmatch(r'(?:Get "[^\r\n]+": )?read tcp [^\r\n]+: read: connection reset by peer', error)
            if attempt == 2 or not reset:
                return result.returncode if result.returncode > 0 else 1
            print(f"Asset {asset_id}: retrying the interrupted GET once from byte zero.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: download-release-asset.py REPOSITORY ASSET_ID DESTINATION")
        sys.exit(download(*sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"Asset download failed: {error}", file=sys.stderr)
        sys.exit(1)
