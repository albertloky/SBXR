#!/usr/bin/env python3
"""Fail-closed scanner for V3 secret-containment evidence surfaces."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse

SCHEMA = "sbxr-v3-secret-containment-spec-v1"
SECRET_SCHEMA = "sbxr-v3-known-secrets-v1"
SURFACES = {"runner", "vps", "mac", "terminal", "workflow", "retained"}
MAX_FILE = 128 << 20
MAX_PROCESS_FIELD = 4 << 20
PROHIBITED = (re.compile(br"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
              re.compile(br"Authorization\s*:\s*(?:Bearer|Basic)\s+", re.I))

class CoverageError(Exception):
    pass

class SecretFound(Exception):
    pass

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError("duplicate JSON key")
        result[key] = value
    return result

def document(path, schema):
    target = Path(path)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise CoverageError("unsafe input object")
    body = read_regular(target)
    value = json.loads(body, object_pairs_hook=unique)
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise CoverageError("input schema")
    return value

def secret_variants(value):
    variants = {value}
    for encoded in (base64.b64encode(value), base64.urlsafe_b64encode(value)):
        variants.add(encoded); variants.add(encoded.rstrip(b"="))
    escaped = urllib.parse.quote_from_bytes(value, safe="").encode("ascii")
    variants.add(escaped)
    variants.add(re.sub(br"%[0-9A-F]{2}", lambda match: match.group(0).lower(), escaped))
    try:
        text = value.decode("utf-8")
        variants.add(urllib.parse.quote_plus(text, safe="").encode("ascii"))
        variants.add(json.dumps(text, ensure_ascii=True)[1:-1].encode("ascii"))
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    return tuple(item for item in variants if len(item) >= 8)

def load_secrets(path, require_root=True):
    info = os.lstat(path)
    if require_root and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise CoverageError("known-secret protection")
    data = document(path, SECRET_SCHEMA)
    if set(data) != {"schema", "secrets"} or not isinstance(data["secrets"], list) or not data["secrets"]:
        raise CoverageError("known-secret shape")
    identifiers, values, result = set(), set(), []
    kinds = {"private-key":0, "client-uuid":0, "subscription-credential":0, "qualification-secret":0}
    for item in data["secrets"]:
        if not isinstance(item, dict) or set(item) != {"id", "kind", "value"} or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", item["id"] or "") or item["kind"] not in kinds or not isinstance(item["value"], str):
            raise CoverageError("known-secret entry")
        value = item["value"].encode("utf-8")
        if item["id"] in identifiers or value in values or len(value) < 8 or len(value) > 65536:
            raise CoverageError("known-secret uniqueness")
        if item["kind"] == "client-uuid" and re.fullmatch(rb"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value) is None:
            raise CoverageError("known Client UUID shape")
        if item["kind"] in {"private-key", "subscription-credential"} and re.fullmatch(rb"[A-Za-z0-9_-]{43}", value) is None:
            raise CoverageError("known credential shape")
        identifiers.add(item["id"]); values.add(value); kinds[item["kind"]] += 1; result.extend(secret_variants(value))
    if any(kinds[kind] < 2 for kind in ("private-key", "client-uuid", "subscription-credential")) or kinds["qualification-secret"] < 1:
        raise CoverageError("known-secret category coverage")
    return tuple(set(result)), kinds

def scan_bytes(body, variants):
    if any(variant in body for variant in variants) or any(pattern.search(body) for pattern in PROHIBITED):
        raise SecretFound("protected content detected")

def read_regular(path, limit=MAX_FILE):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CoverageError("capture is not regular")
        body = bytearray()
        while len(body) <= limit:
            block = os.read(descriptor, min(1 << 20, limit + 1 - len(body)))
            if not block: break
            body.extend(block)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(body) > limit or identity(before) != identity(after):
            raise CoverageError("capture changed or exceeded bound")
        return bytes(body)
    finally:
        os.close(descriptor)

def capture_files(path):
    target = Path(path)
    info = target.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise CoverageError("capture symlink")
    if stat.S_ISREG(info.st_mode):
        return [target]
    if not stat.S_ISDIR(info.st_mode):
        raise CoverageError("capture root kind")
    files = []
    def failed(error):
        raise CoverageError("unreadable capture root") from error
    for root, directories, names in os.walk(target, followlinks=False, onerror=failed):
        for name in directories + names:
            child = Path(root, name)
            if child.is_symlink():
                raise CoverageError("capture symlink")
        files.extend(Path(root, name) for name in names)
    if not files:
        raise CoverageError("empty capture root")
    return sorted(files)

def validate_spec(path, require_root=False):
    info = os.lstat(path)
    if require_root and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise CoverageError("spec protection")
    spec = document(path, SCHEMA)
    required = {"schema", "captures", "units", "proc_root", "protected_objects", "preserved_objects", "cleanup_paths", "cleanup_processes"}
    if set(spec) != required or spec["proc_root"] != "/proc":
        raise CoverageError("spec shape")
    if not isinstance(spec["captures"], list) or not isinstance(spec["units"], list):
        raise CoverageError("spec collections")
    observed = {item.get("surface") for item in spec["captures"] if isinstance(item, dict)}
    if observed != SURFACES:
        raise CoverageError("capture coverage incomplete")
    paths = []
    for item in spec["captures"]:
        if set(item) != {"surface", "path"} or item["surface"] not in SURFACES or not os.path.isabs(item["path"]):
            raise CoverageError("capture declaration")
        paths.append(os.path.realpath(item["path"]))
    if len(paths) != len(set(paths)):
        raise CoverageError("capture paths must be distinct")
    if not spec["units"] or any(not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", unit) for unit in spec["units"]) or len(spec["units"]) != len(set(spec["units"])):
        raise CoverageError("unit coverage")
    return spec

def require_secret_outside_captures(secret_path, spec):
    secret = os.path.realpath(secret_path)
    for item in spec["captures"]:
        capture = os.path.realpath(item["path"])
        if secret == capture or os.path.isdir(capture) and os.path.commonpath([secret, capture]) == capture:
            raise CoverageError("known-secret file overlaps a capture")

def scan_captures(spec, variants):
    counts = {surface: 0 for surface in sorted(SURFACES)}
    for item in spec["captures"]:
        for path in capture_files(item["path"]):
            scan_bytes(read_regular(path), variants); counts[item["surface"]] += 1
    return counts

def scan_processes(proc_root, variants):
    pids = sorted((path for path in Path(proc_root).iterdir() if path.name.isdigit()), key=lambda path: int(path.name))
    scanned = 0
    for process in pids:
        for name in ("cmdline", "environ"):
            try:
                body = read_regular(process / name, MAX_PROCESS_FIELD)
            except FileNotFoundError:
                if process.exists(): raise CoverageError("process surface vanished incompletely")
                break
            except PermissionError as error:
                raise CoverageError("unreadable process surface") from error
            scan_bytes(body, variants); scanned += 1
    if not scanned:
        raise CoverageError("process coverage empty")
    return scanned

def scan_units(units, variants):
    for unit in units:
        show = subprocess.run(["systemctl", "show", unit, "--property=LoadState,FragmentPath,DropInPaths,ExecStart,Environment,EnvironmentFiles"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        cat = subprocess.run(["systemctl", "cat", unit], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if show.returncode != 0 or cat.returncode != 0 or b"LoadState=loaded" not in show.stdout:
            raise CoverageError("unit coverage incomplete")
        environment_files = next((line for line in show.stdout.splitlines() if line.startswith(b"EnvironmentFiles=")), None)
        if environment_files != b"EnvironmentFiles=":
            raise CoverageError("unit environment-file coverage incomplete")
        scan_bytes(show.stdout, variants); scan_bytes(cat.stdout, variants)
    return len(units)

def inspect_object(item, preserved=False):
    allowed = {"path", "state", "kind", "mode", "uid", "gid", "nlink"} | ({"sha256"} if preserved else set())
    if not isinstance(item, dict) or set(item) != allowed or not os.path.isabs(item["path"]) or item["state"] != "present":
        raise CoverageError("object declaration")
    info = os.lstat(item["path"])
    kinds = {"file": stat.S_ISREG, "directory": stat.S_ISDIR}
    if item["kind"] not in kinds or not kinds[item["kind"]](info.st_mode) or stat.S_IMODE(info.st_mode) != int(item["mode"], 8) or info.st_uid != item["uid"] or info.st_gid != item["gid"] or info.st_nlink != item["nlink"]:
        raise CoverageError("object protection mismatch")
    if preserved and (item["kind"] != "file" or hashlib.sha256(read_regular(item["path"])).hexdigest() != item["sha256"]):
        raise CoverageError("preserved object mismatch")

def check_protection(spec):
    if not spec["protected_objects"] or not spec["preserved_objects"]:
        raise CoverageError("object coverage incomplete")
    for item in spec["protected_objects"]: inspect_object(item)
    for item in spec["preserved_objects"]: inspect_object(item, True)
    return len(spec["protected_objects"]), len(spec["preserved_objects"])

def process_start_tick(pid):
    body = Path(f"/proc/{pid}/stat").read_text()
    return int(body[body.rfind(")") + 2:].split()[19])

def check_cleanup(spec):
    if not spec["cleanup_paths"] or not spec["cleanup_processes"]:
        raise CoverageError("cleanup coverage incomplete")
    for path in spec["cleanup_paths"]:
        if not isinstance(path, str) or not os.path.isabs(path) or os.path.lexists(path):
            raise CoverageError("qualification path remains")
    for item in spec["cleanup_processes"]:
        if not isinstance(item, dict) or set(item) != {"pid", "start_tick"} or not isinstance(item["pid"], int) or not isinstance(item["start_tick"], int):
            raise CoverageError("cleanup process declaration")
        try: current = process_start_tick(item["pid"])
        except FileNotFoundError: continue
        if current == item["start_tick"]:
            raise CoverageError("qualification process remains")
    return len(spec["cleanup_paths"]), len(spec["cleanup_processes"])

def main(argv):
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan"); scan.add_argument("--known-secrets", required=True); scan.add_argument("--spec", required=True)
    protect = sub.add_parser("protection"); protect.add_argument("--spec", required=True)
    cleanup = sub.add_parser("cleanup"); cleanup.add_argument("--spec", required=True)
    args = parser.parse_args(argv)
    if args.command == "scan":
        spec = validate_spec(args.spec, require_root=True); require_secret_outside_captures(args.known_secrets, spec); variants, secret_kinds = load_secrets(args.known_secrets)
        captures = scan_captures(spec, variants); processes = scan_processes(spec["proc_root"], variants); units = scan_units(spec["units"], variants)
        result = {"capture_files":captures,"known_secret_kinds":secret_kinds,"process_fields":processes,"prohibited_patterns_absent":True,"schema":"sbxr-v3-secret-scan-result-v1","units":units,"variants_absent":True}
    elif args.command == "protection":
        protected, preserved = check_protection(validate_spec(args.spec, require_root=True)); result = {"protected_objects":protected,"preserved_objects":preserved,"schema":"sbxr-v3-protection-result-v1"}
    else:
        paths, processes = check_cleanup(validate_spec(args.spec, require_root=True)); result = {"cleanup_paths_absent":paths,"cleanup_processes_absent":processes,"schema":"sbxr-v3-cleanup-result-v1"}
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))

if __name__ == "__main__":
    try: main(sys.argv[1:])
    except SecretFound: print('{"secret_containment_failed":true,"stage":"secret-detected"}', file=sys.stderr); raise SystemExit(1)
    except Exception: print('{"secret_containment_failed":true,"stage":"coverage-incomplete"}', file=sys.stderr); raise SystemExit(1)
