#!/usr/bin/env python3
"""Prove the live Subscription Serving sandbox cannot open protected inputs."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

def process_start_tick(pid, proc="/proc"):
    body = Path(proc, str(pid), "stat").read_text()
    return int(body[body.rfind(")") + 2:].split()[19])

def status_fields(pid, proc="/proc"):
    wanted = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    result = {}
    for line in Path(proc, str(pid), "status").read_text().splitlines():
        key, separator, value = line.partition(":")
        if separator and key in wanted:
            result[key] = value.strip()
    if set(result) != wanted or any(int(result[key], 16) != 0 for key in wanted if key.startswith("Cap")) or result["NoNewPrivs"] != "1":
        raise ValueError("live capability containment")
    return result

def identity(unit, executable, arguments, fragment):
    shown = subprocess.run(["systemctl", "show", unit, "--property=MainPID,ActiveState,LoadState,FragmentPath"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    values = dict(line.split("=", 1) for line in shown.stdout.splitlines())
    pid = int(values.get("MainPID", "0"))
    if values != {"MainPID":str(pid), "ActiveState":"active", "LoadState":"loaded", "FragmentPath":fragment} or pid <= 1:
        raise ValueError("service identity")
    if not os.path.samefile(f"/proc/{pid}/exe", executable):
        raise ValueError("executable identity")
    command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
    if command != [item.encode() for item in [executable] + arguments]:
        raise ValueError("argument identity")
    if f"0::/system.slice/{unit}" not in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        raise ValueError("cgroup identity")
    status_fields(pid)
    executable_info = os.stat(f"/proc/{pid}/exe")
    return {"pid":pid, "start_tick":process_start_tick(pid), "exe_device":executable_info.st_dev, "exe_inode":executable_info.st_ino, "mount_namespace":os.readlink(f"/proc/{pid}/ns/mnt")}

def host_object(path, kind, mode):
    info = os.lstat(path)
    checker = stat.S_ISREG if kind == "file" else stat.S_ISDIR
    links_safe = info.st_nlink == 1 if kind == "file" else not any(Path(path).iterdir())
    if not checker(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or info.st_uid != 0 or info.st_gid != 0 or not links_safe:
        raise ValueError("protected host object")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    os.close(descriptor)

def probe(pid, paths):
    code = """import os,sys
ok=True
for path in sys.argv[1:]:
 try:
  descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
 except OSError:
  continue
 else:
  os.close(descriptor);ok=False
sys.exit(42 if ok else 0)
"""
    command = ["/usr/bin/nsenter", f"--mount=/proc/{pid}/ns/mnt", f"--root=/proc/{pid}/root", "--wd=/", "--",
               "/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
               "/usr/bin/python3", "-c", code] + paths
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 42 or result.stdout or result.stderr:
        raise ValueError("protected read was not refused")

def run(args):
    if os.geteuid() != 0:
        raise ValueError("root observation required")
    host_object(args.token, "file", 0o600); host_object(args.staging, "directory", 0o700)
    before = identity(args.unit, args.executable, args.argument, args.fragment)
    probe(before["pid"], [args.token, args.staging])
    after = identity(args.unit, args.executable, args.argument, args.fragment)
    if before != after:
        raise ValueError("service changed during observation")
    return {"capabilities_zero":True,"main_pid":before["pid"],"mount_namespace":before["mount_namespace"],"no_new_privileges":True,"protected_reads_refused":2,"schema":"sbxr-v3-sandbox-token-probe-v1","start_tick":before["start_tick"],"unit":args.unit}

def main(argv):
    parser = argparse.ArgumentParser(); parser.add_argument("--unit", required=True); parser.add_argument("--fragment", required=True); parser.add_argument("--executable", required=True); parser.add_argument("--argument", action="append", default=[]); parser.add_argument("--token", required=True); parser.add_argument("--staging", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", args.unit) or any(not os.path.isabs(path) for path in (args.fragment,args.executable,args.token,args.staging)):
        raise ValueError("argument boundary")
    print(json.dumps(run(args), separators=(",", ":"), sort_keys=True))

if __name__ == "__main__":
    try: main(sys.argv[1:])
    except Exception: print('{"sandbox_probe_failed":true}', file=sys.stderr); raise SystemExit(1)
