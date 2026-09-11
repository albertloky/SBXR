#!/usr/bin/env python3
"""Prove a fresh capability-free account cannot open protected Scenario 24 paths."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile

PATH_SCHEMA = "sbxr-v4-protected-open-paths-v1"
ZERO_CAPABILITY_FIELDS = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}

# The operator bundle commonly lives below /root. Stream this fixed, secret-free
# child over stdin so the temporary account never needs traverse access to that
# bundle or a copied executable in its otherwise empty runtime directory.
CHILD_PROGRAM = r'''
import errno,json,os,pathlib,stat,sys
runtime=sys.argv[1]
paths=sys.argv[2:]
if os.getuid()==0 or os.geteuid()==0 or os.getgroups(): raise SystemExit(10)
info=os.stat(runtime)
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_gid!=os.getgid() or stat.S_IMODE(info.st_mode)!=0o700 or any(pathlib.Path(runtime).iterdir()): raise SystemExit(11)
os.chdir(runtime)
wanted={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}
values={}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
    name,sep,value=line.partition(':')
    if sep and name in wanted: values[name]=value.strip()
if set(values)!=wanted or any(values[name]!='0000000000000000' for name in wanted-{'NoNewPrivs'}) or values['NoNewPrivs']!='1': raise SystemExit(12)
refused=[]
for path in paths:
    try: descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
    except OSError as error:
        if error.errno not in (errno.EACCES,errno.EPERM): raise SystemExit(13)
        refused.append({'path':path,'errno':errno.errorcode[error.errno]})
    else:
        os.close(descriptor)
        raise SystemExit(14)
print(json.dumps({'capabilities_zero':True,'no_new_privileges':True,'private_runtime_empty':True,'protected_reads_refused':len(refused),'refusals':refused},separators=(',',':'),sort_keys=True))
'''


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def status_fields(pid="self"):
    wanted = ZERO_CAPABILITY_FIELDS | {"NoNewPrivs"}
    values = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, separator, value = line.partition(":")
        if separator and name in wanted:
            values[name] = value.strip()
    if (set(values) != wanted or any(values[name] != "0000000000000000" for name in ZERO_CAPABILITY_FIELDS)
            or values["NoNewPrivs"] != "1"):
        raise ValueError("capability containment refused")
    return values


def object_identity(path):
    info = os.lstat(path)
    result = {
        "path": path, "device": info.st_dev, "inode": info.st_ino,
        "kind": "symlink" if stat.S_ISLNK(info.st_mode) else "fifo" if stat.S_ISFIFO(info.st_mode)
                else "file" if stat.S_ISREG(info.st_mode) else "other",
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid,
        "gid": info.st_gid, "nlink": info.st_nlink, "size": info.st_size,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }
    if stat.S_ISLNK(info.st_mode):
        target = os.stat(path)
        result["resolved_path"] = os.path.realpath(path)
        result["resolved_device"] = target.st_dev
        result["resolved_inode"] = target.st_ino
        result["resolved_mode"] = format(stat.S_IMODE(target.st_mode), "04o")
        result["resolved_uid"] = target.st_uid
        result["resolved_gid"] = target.st_gid
        result["resolved_nlink"] = target.st_nlink
        result["resolved_size"] = target.st_size
        result["resolved_mtime_ns"] = target.st_mtime_ns
        result["resolved_ctime_ns"] = target.st_ctime_ns
    return result


def load_paths(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError("protected path inventory refused")
    with open(path, "r", encoding="utf-8") as stream:
        value = json.load(stream, object_pairs_hook=unique)
    paths = value.get("paths") if isinstance(value, dict) and value.get("schema") == PATH_SCHEMA else None
    if (set(value) != {"schema", "paths"} or not isinstance(paths, list) or not paths or
            len(paths) != len(set(paths)) or any(not isinstance(item, str) or not os.path.isabs(item) for item in paths)):
        raise ValueError("protected path inventory shape refused")
    for item in paths:
        if not os.path.lexists(item):
            raise ValueError("protected object missing before probe")
        if os.path.islink(item) and not os.path.exists(item):
            raise ValueError("protected symlink target missing before probe")
    return sorted(paths)


def load_spec_paths(path):
    scanner_path = Path(__file__).with_name("secret-containment.py")
    spec = importlib.util.spec_from_file_location("protected_open_inventory", scanner_path)
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    return scanner.probe_paths(scanner.validate_spec(path, require_root=True))


def child_run(paths, runtime):
    if os.getuid() == 0 or os.geteuid() == 0 or os.getgroups():
        raise ValueError("unprivileged identity refused")
    runtime_info = os.stat(runtime)
    if (not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_uid != os.getuid() or
            runtime_info.st_gid != os.getgid() or stat.S_IMODE(runtime_info.st_mode) != 0o700 or
            any(Path(runtime).iterdir())):
        raise ValueError("private empty runtime refused")
    os.chdir(runtime)
    status_fields()
    refused = []
    for path in paths:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as error:
            if error.errno not in {errno.EACCES, errno.EPERM}:
                raise ValueError("protected open was not a permission refusal") from error
            refused.append({"path": path, "errno": errno.errorcode[error.errno]})
        else:
            os.close(descriptor)
            raise ValueError("protected open unexpectedly succeeded")
    return {"capabilities_zero": True, "no_new_privileges": True,
            "private_runtime_empty": True, "protected_reads_refused": len(refused),
            "refusals": refused}


def account_absent(name):
    try:
        pwd.getpwnam(name)
    except KeyError:
        return True
    return False


def run(paths_file=None, spec_path=None, runtime_parent="/run"):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("live Linux root required")
    if bool(paths_file) == bool(spec_path):
        raise ValueError("exactly one protected path source required")
    paths = load_paths(paths_file) if paths_file else load_spec_paths(spec_path)
    before = [object_identity(path) for path in paths]
    name = "sbxr24-" + secrets.token_hex(6)
    if not re.fullmatch(r"sbxr24-[0-9a-f]{12}", name) or not account_absent(name):
        raise ValueError("temporary account collision")
    parent = os.lstat(runtime_parent)
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        raise ValueError("runtime parent refused")
    runtime = None
    account_created = False
    primary_error = None
    result = None
    try:
        subprocess.run(["/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
                        "--shell", "/usr/sbin/nologin",
                        "--gid", "nogroup", name], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        account_created = True
        account = pwd.getpwnam(name)
        if account.pw_name != name or account.pw_dir not in {"/nonexistent", "/"} or account.pw_shell != "/usr/sbin/nologin":
            raise ValueError("temporary account identity refused")
        if os.getgrouplist(name, account.pw_gid) != [account.pw_gid]:
            raise ValueError("temporary account has supplementary groups")
        runtime = tempfile.mkdtemp(prefix=name + ".", dir=runtime_parent)
        os.chown(runtime, account.pw_uid, account.pw_gid)
        os.chmod(runtime, 0o700)
        command = ["/usr/bin/setpriv", "--reuid=" + str(account.pw_uid), "--regid=" + str(account.pw_gid),
                   "--clear-groups", "--bounding-set=-all", "--no-new-privs",
                   sys.executable, "-", runtime, *paths]
        completed = subprocess.run(command, input=CHILD_PROGRAM.encode(), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False, timeout=30)
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 1 << 20:
            raise ValueError("unprivileged protected-open probe refused")
        child = json.loads(completed.stdout, object_pairs_hook=unique)
        if (child.get("protected_reads_refused") != len(paths) or
                {item.get("path") for item in child.get("refusals", [])} != set(paths) or
                child.get("capabilities_zero") is not True or child.get("no_new_privileges") is not True or
                child.get("private_runtime_empty") is not True):
            raise ValueError("unprivileged protected-open result refused")
        after = [object_identity(path) for path in paths]
        if after != before:
            raise ValueError("protected object metadata changed during probe")
        result = {"account": name, "account_uid": account.pw_uid,
                  "metadata_unchanged": True, "objects": before,
                  "protected_reads_refused": len(paths), "capabilities_zero": True,
                  "no_new_privileges": True, "no_supplementary_groups": True,
                  "private_runtime_empty": True,
                  "schema": "sbxr-v4-protected-open-probe-v1"}
    except Exception as error:
        primary_error = error
    finally:
        cleanup_errors = []
        if runtime is not None:
            try:
                os.rmdir(runtime)
            except Exception as error:
                cleanup_errors.append(error)
        if account_created:
            try:
                subprocess.run(["/usr/sbin/userdel", name], check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20)
            except Exception as error:
                cleanup_errors.append(error)
        if runtime is not None and os.path.lexists(runtime):
            cleanup_errors.append(ValueError("temporary runtime remains"))
        if not account_absent(name):
            cleanup_errors.append(ValueError("temporary account remains"))
        if cleanup_errors:
            raise ValueError("temporary probe cleanup refused") from cleanup_errors[0]
    if primary_error:
        raise primary_error
    result["account_removed"] = True
    result["runtime_removed"] = True
    return result


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths-file")
    parser.add_argument("--spec")
    parser.add_argument("--runtime-parent", default="/run")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--runtime")
    parser.add_argument("--path", action="append", default=[])
    args = parser.parse_args(argv)
    if args.child:
        if args.paths_file or args.spec or not args.runtime or not args.path:
            raise ValueError("child arguments refused")
        result = child_run(args.path, args.runtime)
    else:
        if bool(args.paths_file) == bool(args.spec) or args.runtime or args.path:
            raise ValueError("operator arguments refused")
        result = run(args.paths_file, args.spec, args.runtime_parent)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print('{"protected_open_probe_failed":true}', file=sys.stderr)
        raise SystemExit(1)
