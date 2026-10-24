#!/usr/bin/env python3
"""Create an exact committed source-only archive locally; never upload.

Committed public/synthetic test fixtures are source inputs and remain included.
Generated targets, scratch, credentials and local files are never imported.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def excluded(name):
    path = PurePosixPath(name)
    forbidden = {".git", ".scratch", "node_modules", "__pycache__", ".aws", ".codex", ".ssh"}
    build_output = path.parts[0] == "target" or path.parts[:3] == ("tooling", "rust-package", "target")
    return build_output or bool(set(path.parts) & forbidden) or path.name in {".env", "credentials", "config.json.secret"} or path.name.endswith((".pyc", ".pyo", ".DS_Store"))


def snapshot(root, commit, destination):
    root = Path(root).resolve()
    destination = Path(destination).absolute()
    if destination.is_symlink():
        raise FileExistsError("source output symlink refused")
    if not re.fullmatch("[0-9a-f]{40}", commit) or git(root, "rev-parse", "HEAD").decode().strip() != commit or git(root, "status", "--porcelain").strip():
        raise ValueError("exact clean final commit required")
    # Git objects alone supply data. Never tar the live working directory.
    raw = git(root, "archive", "--format=tar", commit)
    files = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        for member in source.getmembers():
            if member.isdir():
                continue
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.isfile():
                raise ValueError("source member kind refused")
            if excluded(member.name):
                continue
            body = source.extractfile(member).read()
            files.append((member.name, body, 0o755 if member.mode & 0o111 else 0o644))
    files.sort()
    manifest = {"schema": "sbxr-rust-source-v1", "commit": commit,
                "provenance": "exact committed Git objects, original Go reference retained",
                "exclusions": [".git", ".scratch", "target/build outputs", "local/untracked files", "credential/configuration roots"],
                "fixtures": "Committed public and synthetic test fixtures included for offline reproducibility; no deployed credentials",
                "files": [{"path": name, "mode": format(mode, "04o"), "size": len(body), "sha256": hashlib.sha256(body).hexdigest()} for name, body, mode in files]}
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    destination.mkdir(mode=0o700, exist_ok=False)
    name = "sbxr-rust-" + commit[:12] + "-source.tar.gz"
    archive = destination / name
    prefix = "sbxr-rust-" + commit[:12] + "/"
    with archive.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as target:
                for path, body, mode in files + [("SOURCE-MANIFEST.json", manifest_bytes, 0o644)]:
                    member = tarfile.TarInfo(prefix + path)
                    member.size, member.mode, member.uid, member.gid, member.mtime = len(body), mode, 0, 0, 0
                    target.addfile(member, io.BytesIO(body))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    identity = {"schema": "sbxr-rust-source-archive-v1", "commit": commit, "archive": name,
                "size": archive.stat().st_size, "sha256": digest, "source_files": len(files),
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "uploaded": False}
    (destination / "SOURCE-MANIFEST.json").write_bytes(manifest_bytes)
    (destination / "archive.json").write_text(json.dumps(identity, sort_keys=True, indent=2) + "\n")
    (destination / "SHA256SUMS").write_text(digest + "  " + name + "\n")
    return identity


def verify(root, commit, manifest_sha256):
    root=Path(root).resolve()
    manifest_path=root/"SOURCE-MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 4 << 20:
        raise ValueError("source manifest file refused")
    raw=manifest_path.read_bytes()
    if not re.fullmatch("[0-9a-f]{40}",commit) or not re.fullmatch("[0-9a-f]{64}",manifest_sha256) or hashlib.sha256(raw).hexdigest()!=manifest_sha256:
        raise ValueError("externally pinned source manifest required")
    def unique(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError("duplicate source manifest key")
            result[key]=value
        return result
    manifest=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(manifest,dict) or set(manifest)!={"schema","commit","provenance","exclusions","fixtures","files"} or manifest.get("schema")!="sbxr-rust-source-v1" or manifest.get("commit")!=commit or not isinstance(manifest.get("files"),list):
        raise ValueError("source commit refused")
    declared=set()
    for entry in manifest["files"]:
        if not isinstance(entry,dict) or set(entry)!={"path","mode","size","sha256"} or not isinstance(entry["path"],str) or not entry["path"] or entry["path"]=="." or not isinstance(entry["mode"],str) or entry["mode"] not in {"0644","0755"} or type(entry["size"]) is not int or entry["size"]<0 or not isinstance(entry["sha256"],str) or not re.fullmatch("[0-9a-f]{64}",entry["sha256"]):
            raise ValueError("source manifest entry refused")
        name=entry["path"]; path=PurePosixPath(name)
        if not path.parts or path.as_posix()!=name or path.is_absolute() or ".." in path.parts or name in declared or name=="SOURCE-MANIFEST.json" or excluded(name):
            raise ValueError("source path refused")
        declared.add(name)
        candidate=root.joinpath(*path.parts)
        for parent in [candidate,*candidate.parents]:
            if parent==root: break
            if parent.is_symlink(): raise ValueError("source symlink refused")
        before=candidate.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size!=entry["size"]:
            raise ValueError("source file refused")
        digest=hashlib.sha256()
        with candidate.open("rb") as source:
            while data:=source.read(65536): digest.update(data)
        if digest.hexdigest()!=entry["sha256"]: raise ValueError("source hash mismatch")
    actual=set()
    for directory,dirs,files in os.walk(root,followlinks=False):
        relative=Path(directory).relative_to(root)
        if any((Path(directory)/d).is_symlink() for d in dirs):
            raise ValueError("source directory symlink refused")
        dirs[:]=[d for d in dirs if d not in {".git",".scratch","__pycache__"} and (relative/d).parts not in {("target",),("tooling","rust-package","target")}]
        for file in files:
            name=(relative/file).as_posix()
            if file.endswith((".pyc",".pyo")): continue
            if name!="SOURCE-MANIFEST.json":actual.add(name)
    if actual!=declared: raise ValueError("missing or extra source files")
    return {"outcome":"verified-source-local","commit":commit,"files":len(declared),"authenticated_release":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ["root", "commit"]:
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--output")
    parser.add_argument("--verify-manifest-sha256")
    args = parser.parse_args()
    try:
        if args.verify_manifest_sha256 and not args.output:
            result=verify(args.root,args.commit,args.verify_manifest_sha256)
        elif args.output and not args.verify_manifest_sha256:
            result=snapshot(args.root,args.commit,args.output)
        else: raise ValueError("select exactly one source action")
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError):
        raise SystemExit("rust-source/snapshot refused; existing output is preserved")


if __name__ == "__main__":
    main()
