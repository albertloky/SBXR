#!/usr/bin/env python3
"""Assemble already-built native archives into four verified assets, offline.

No native product execution, signing, networking or publication. Existing output
files are never replaced. Partial output remains for inspection after failure.
"""
import argparse
import json
from pathlib import Path
import subprocess
import os
import stat


def invoke(tool, command, values):
    argv = [str(tool), command]
    for key, value in values.items():
        argv += ["--" + key, str(value)]
    result = subprocess.run(argv, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def assemble(args):
    output = Path(args.output).absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    common = dict(tag=args.tag, commit=args.commit, sequence=args.sequence)
    digests = {}
    for arch in ("amd64", "arm64"):
        path = Path(getattr(args, arch))
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,"rb") as source:
            before=os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=256<<20:
                raise ValueError("archive file refused")
            raw=source.read((256<<20)+1)
            after=os.fstat(source.fileno())
            identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_nlink,st.st_mtime_ns,st.st_ctime_ns)
            if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(os.stat(path,follow_symlinks=False)):
                raise ValueError("archive changed")
        copied=output/f"sbxr-linux-{arch}.tar.gz"
        with copied.open("xb") as target:
            target.write(raw)
        result=invoke(args.tool,"inspect-archive",dict(common,architecture=arch,archive=copied))
        if result.get("outcome")!="inspected-local" or result.get("architecture")!=arch:
            raise ValueError("archive verification refused")
        digests[arch]=result["executable_sha256"]
    invoke(args.tool, "bootstrap", dict(common, **{"amd64-executable-sha256": digests["amd64"], "arm64-executable-sha256": digests["arm64"], "output": output / "install.sh"}))
    invoke(args.tool, "index", dict(common, directory=output, output=output / "release-index.json"))
    for arch in ("amd64", "arm64"):
        if invoke(args.tool, "verify-package", dict(directory=output, architecture=arch))["outcome"] != "consistent-local":
            raise ValueError("structural verification refused")
    if sorted(p.name for p in output.iterdir()) != ["install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"]:
        raise ValueError("four assets required")
    print(json.dumps({"outcome": "assembled-local", "scope": "structural agreement only"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["tool", "tag", "commit", "sequence", "amd64", "arm64", "output"]:
        parser.add_argument("--" + name, required=True)
    try:
        assemble(parser.parse_args())
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError):
        raise SystemExit("rust-package/assembly refused")


if __name__ == "__main__":
    main()
