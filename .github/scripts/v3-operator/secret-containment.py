#!/usr/bin/env python3
"""Fail closed over an attested, exhaustive Scenario 24 attempt inventory."""
import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.parse

SCHEMA = "sbxr-v4-secret-containment-spec-v2"
SECRET_SCHEMA = "sbxr-v3-known-secrets-v1"
SURFACES = {"runner", "vps", "mac", "terminal", "workflow", "retained"}
CORE_ROOTS = {"operator-state", "operator-evidence", "transport"}
FIXED_UNITS = {"sing-box.service", "sbxr-subscription.service",
               "snap.certbot.renew.service"}
MAX_FILE = 128 << 20
MAX_PROCESS_FIELD = 4 << 20
SHA256 = re.compile(r"[0-9a-f]{64}")
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


def read_regular(path, limit=MAX_FILE, expected=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CoverageError("capture is not regular")
        if expected is not None:
            check_declared_metadata(expected, before, "opened capture identity mismatch")
        body = bytearray()
        while len(body) <= limit:
            block = os.read(descriptor, min(1 << 20, limit + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns, value.st_mode,
                                  value.st_uid, value.st_gid, value.st_nlink)
        if len(body) > limit or identity(before) != identity(after):
            raise CoverageError("capture changed or exceeded bound")
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise CoverageError("capture path replaced during read")
        return bytes(body)
    finally:
        os.close(descriptor)


def document(path, schema):
    target = Path(path)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise CoverageError("unsafe input object")
    value = json.loads(read_regular(target), object_pairs_hook=unique)
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise CoverageError("input schema")
    return value


def secret_variants(value):
    variants = {value}
    for encoded in (base64.b64encode(value), base64.urlsafe_b64encode(value)):
        variants.add(encoded)
        variants.add(encoded.rstrip(b"="))
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
    kinds = {"private-key": 0, "client-uuid": 0, "subscription-credential": 0,
             "qualification-secret": 0}
    for item in data["secrets"]:
        if (not isinstance(item, dict) or set(item) != {"id", "kind", "value"} or
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", item.get("id", "")) or
                item.get("kind") not in kinds or not isinstance(item.get("value"), str)):
            raise CoverageError("known-secret entry")
        value = item["value"].encode("utf-8")
        if item["id"] in identifiers or value in values or not 8 <= len(value) <= 65536:
            raise CoverageError("known-secret uniqueness")
        if item["kind"] == "client-uuid" and not re.fullmatch(
                rb"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value):
            raise CoverageError("known Client UUID shape")
        if item["kind"] in {"private-key", "subscription-credential"} and not re.fullmatch(
                rb"[A-Za-z0-9_-]{43}", value):
            raise CoverageError("known credential shape")
        identifiers.add(item["id"])
        values.add(value)
        kinds[item["kind"]] += 1
        result.extend(secret_variants(value))
    if any(kinds[kind] < 2 for kind in ("private-key", "client-uuid", "subscription-credential")) or kinds["qualification-secret"] < 1:
        raise CoverageError("known-secret category coverage")
    return tuple(set(result)), kinds


def scan_bytes(body, variants):
    if any(value in body for value in variants) or any(pattern.search(body) for pattern in PROHIBITED):
        raise SecretFound("protected content detected")


def default_bindings():
    required = ("SBXR_OPERATOR_STATE_DIR", "SBXR_OPERATOR_EVIDENCE_DIR",
                "SBXR_TRANSPORT_ROOT", "SBXR_QUALIFICATION_MANIFEST", "SBXR_TRANSPORT_UNIT",
                "SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS")
    if any(not os.environ.get(name) for name in required):
        raise CoverageError("live inventory bindings missing")
    return {
        "roots": {"operator-state": os.path.realpath(os.environ[required[0]]),
                  "operator-evidence": os.path.realpath(os.environ[required[1]]),
                  "transport": os.path.realpath(os.environ[required[2]])},
        "manifest": os.path.realpath(os.environ[required[3]]),
        "transport_credential": os.path.realpath(Path(os.environ[required[2]], "gateway.key")),
        "transport_unit": os.environ[required[4]],
        "known_secrets": os.path.realpath(os.environ[required[5]]),
        "subscription_token": "/var/lib/sbxr/subscription-token",
        "ownership_record": "/var/lib/sbxr/proxy-ownership.json",
        "configuration": "/etc/sing-box/config.json",
        "certificate_link": "/etc/letsencrypt/live/sbxr-subscription/privkey.pem",
        "certificate_archive": "/etc/letsencrypt/archive/sbxr-subscription",
        "config_gid": grp.getgrnam("sing-box").gr_gid,
        "root_uid": 0,
        "root_gid": 0,
    }


def under(path, root):
    try:
        return os.path.commonpath([path, root]) == root and path != root
    except ValueError:
        return False


def metadata(info):
    return {"device": info.st_dev, "inode": info.st_ino,
            "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid,
            "gid": info.st_gid, "nlink": info.st_nlink, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def check_declared_metadata(item, info, message="inventory identity mismatch"):
    keys = {"device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}
    if any(item.get(key) != value for key, value in metadata(info).items()) or not keys <= set(item):
        raise CoverageError(message)


def check_retained_directory_identity(item, info, message):
    expected = {"device": info.st_dev, "inode": info.st_ino,
                "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                "uid": info.st_uid, "gid": info.st_gid}
    if any(item.get(key) != value for key, value in expected.items()):
        raise CoverageError(message)


def root_map(spec, bindings):
    roots = spec.get("authoritative_roots")
    if not isinstance(roots, list):
        raise CoverageError("authoritative roots missing")
    result = {}
    required_roles = CORE_ROOTS | {"capture-" + surface for surface in SURFACES}
    for item in roots:
        if (not isinstance(item, dict) or set(item) != {"role", "path"} or
                item["role"] in result or not os.path.isabs(item["path"])):
            raise CoverageError("authoritative root declaration")
        info = os.lstat(item["path"])
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != bindings.get("root_uid", 0) or
                info.st_gid != bindings.get("root_gid", 0) or stat.S_IMODE(info.st_mode) & 0o077):
            raise CoverageError("authoritative root protection")
        path = os.path.realpath(item["path"])
        result[item["role"]] = path
    if set(result) != required_roles:
        raise CoverageError("authoritative root coverage incomplete")
    if any(result[role] != bindings["roots"][role] for role in CORE_ROOTS):
        raise CoverageError("authoritative root binding mismatch")
    core_paths = [result[role] for role in CORE_ROOTS]
    if any(left == right or under(left, right) or under(right, left)
           for index, left in enumerate(core_paths) for right in core_paths[index + 1:]):
        raise CoverageError("authoritative core roots overlap")
    evidence = result["operator-evidence"]
    capture_roots = [result["capture-" + surface] for surface in SURFACES]
    if (len(set(capture_roots)) != len(capture_roots) or
            any(not under(path, evidence) for path in capture_roots) or
            any(under(left, right) or under(right, left)
                for index, left in enumerate(capture_roots) for right in capture_roots[index + 1:])):
        raise CoverageError("capture root outside protected evidence root")
    return result


def inventory_files(root):
    files = []
    def failed(error):
        raise CoverageError("unreadable authoritative root") from error
    for current, directories, names in os.walk(root, followlinks=False, onerror=failed):
        for name in directories + names:
            if Path(current, name).is_symlink():
                raise CoverageError("capture root contains symlink")
        for name in names:
            path = Path(current, name)
            if not path.is_file():
                raise CoverageError("capture root contains non-file")
            files.append(os.path.realpath(path))
    return sorted(files)


def inventory_objects(roots):
    """Return every non-root object in possibly overlapping authority roots."""
    root_paths = set(roots.values())
    found = {}
    for root in {roots[role] for role in CORE_ROOTS - {"operator-evidence"}}:
        def failed(error):
            raise CoverageError("unreadable cleanup authority root") from error
        for current, directories, names in os.walk(root, followlinks=False, onerror=failed):
            for name in directories + names:
                path = os.path.join(current, name)
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    raise CoverageError("cleanup authority root contains symlink")
                if path in root_paths:
                    continue
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISFIFO(info.st_mode)):
                    raise CoverageError("cleanup authority root contains unsupported object")
                found[path] = info
    return found


def process_ancestors(pid, proc_root="/proc"):
    result = set()
    while pid > 1 and pid not in result:
        result.add(pid)
        try:
            lines = Path(proc_root, str(pid), "status").read_text().splitlines()
        except FileNotFoundError:
            break
        parent = next((line for line in lines if line.startswith("PPid:")), None)
        if parent is None:
            break
        pid = int(parent.split()[1])
    return result


def argument_under_root(cmdline, roots):
    for raw in cmdline.split(b"\0"):
        if not raw:
            continue
        argument = os.fsdecode(raw)
        candidates = [argument]
        if argument.startswith("-") and "=" in argument:
            candidates.append(argument.split("=", 1)[1])
        for candidate in candidates:
            if os.path.isabs(candidate):
                resolved = os.path.realpath(candidate)
                if any(resolved == root or under(resolved, root) for root in roots):
                    return True
    return False


def relevant_processes(bindings, proc_root="/proc", current_pid=None):
    """Discover live attempt-related processes without treating host processes as cleanup."""
    excluded = process_ancestors(current_pid or os.getpid(), proc_root)
    roots = tuple(bindings["roots"].values())
    protected_groups = {"/system.slice/sing-box.service",
                        "/system.slice/sbxr-subscription.service",
                        "/system.slice/" + bindings["transport_unit"]}
    helper_group = re.compile(r"/system\.slice/sbxr-(?:v4|qualification|operator|probe)[A-Za-z0-9_.@-]*\.service")
    result = {}
    for entry in Path(proc_root).iterdir():
        if not entry.name.isdigit() or int(entry.name) in excluded:
            continue
        pid = int(entry.name)
        try:
            cgroup_lines = (entry / "cgroup").read_text().splitlines()
            cgroup = next(line.removeprefix("0::") for line in cgroup_lines if line.startswith("0::"))
            executable = (entry / "exe").stat()
            tick = process_identity(pid, proc_root)[0]
            executable_path = os.path.realpath(entry / "exe")
            cwd = os.path.realpath(entry / "cwd")
            cmdline = read_regular(entry / "cmdline", MAX_PROCESS_FIELD)
        except (FileNotFoundError, PermissionError, StopIteration):
            continue
        source = None
        if cgroup in protected_groups:
            source = "protected-cgroup"
        elif helper_group.fullmatch(cgroup):
            source = "dedicated-cgroup"
        elif any(under(executable_path, root) for root in roots):
            source = "attempt-root-executable"
        elif any(under(cwd, root) or cwd == root for root in roots):
            source = "attempt-root-cwd"
        elif argument_under_root(cmdline, roots):
            source = "attempt-root-argv"
        if source:
            identity = (pid, tick, executable.st_dev, executable.st_ino, cgroup)
            result[identity] = source
    return result


def validate_capture_inventory(inventory, roots):
    entries = inventory.get("captures")
    if not isinstance(entries, list) or not entries:
        raise CoverageError("capture inventory missing")
    declared = {}
    required = {"path", "root", "surface", "sha256", "device", "inode", "mode", "uid", "gid",
                "nlink", "size", "mtime_ns", "ctime_ns"}
    for item in entries:
        if (not isinstance(item, dict) or set(item) != required or item["path"] in declared or
                item["surface"] not in SURFACES or item["root"] != "capture-" + item["surface"] or
                not os.path.isabs(item["path"]) or not SHA256.fullmatch(item["sha256"])):
            raise CoverageError("capture inventory declaration")
        path = os.path.realpath(item["path"])
        if not under(path, roots[item["root"]]):
            raise CoverageError("capture outside authoritative surface root")
        declared[path] = item
    actual = set()
    for surface in SURFACES:
        actual.update(inventory_files(roots["capture-" + surface]))
    if set(declared) != actual:
        raise CoverageError("capture inventory omits or invents files")
    if {item["surface"] for item in declared.values()} != SURFACES:
        raise CoverageError("capture surface inventory empty")
    return declared


def validate_cleanup_inventory(inventory, roots, bindings, cleanup_phase=False):
    paths = inventory.get("cleanup_paths")
    retained = inventory.get("retained_paths")
    processes = inventory.get("cleanup_processes")
    if (not isinstance(paths, list) or not paths or not isinstance(retained, list) or not retained or
            not isinstance(processes, list)):
        raise CoverageError("cleanup inventory incomplete")
    allowed_roots = {"operator-state", "transport"}
    identity_keys = {"device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}
    required_path = {"path", "root", "kind"} | identity_keys
    seen = set()
    for item in paths:
        resolved = os.path.realpath(item.get("path", "")) if isinstance(item, dict) else ""
        if (not isinstance(item, dict) or set(item) != required_path or item["root"] not in allowed_roots or
                item["kind"] not in {"file", "fifo", "directory"} or not os.path.isabs(item["path"]) or
                resolved in seen or not under(resolved, roots[item["root"]])):
            raise CoverageError("cleanup path declaration")
        seen.add(resolved)
    retained_required = {"path", "root", "kind", "classification", "sha256"} | identity_keys
    allowed_protected = {os.path.realpath(bindings["transport_credential"]),
                         os.path.realpath(bindings["manifest"])}
    for item in retained:
        resolved = os.path.realpath(item.get("path", "")) if isinstance(item, dict) else ""
        if (not isinstance(item, dict) or set(item) != retained_required or resolved in seen or
                item["root"] not in allowed_roots or not os.path.isabs(item["path"]) or
                not under(resolved, roots[item["root"]]) or
                item["kind"] not in {"file", "directory"}):
            raise CoverageError("retained path declaration")
        if item["kind"] == "directory":
            if item["classification"] != "directory" or item["sha256"] is not None:
                raise CoverageError("retained directory declaration")
        elif item["classification"] == "scan-retained":
            if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
                raise CoverageError("retained scan digest declaration")
        elif item["classification"] == "protected-authority":
            if (resolved not in allowed_protected or
                    not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"])):
                raise CoverageError("retained protected authority declaration")
        else:
            raise CoverageError("retained classification refused")
        seen.add(resolved)

    actual = inventory_objects(roots)
    if set(actual) - seen:
        raise CoverageError("cleanup inventory omits root object")
    retained_by_path = {os.path.realpath(item["path"]): item for item in retained}
    cleanup_by_path = {os.path.realpath(item["path"]): item for item in paths}
    for path, info in actual.items():
        item = retained_by_path.get(path) or cleanup_by_path.get(path)
        expected_kind = {"file": stat.S_ISREG, "fifo": stat.S_ISFIFO,
                         "directory": stat.S_ISDIR}[item["kind"]]
        if not expected_kind(info.st_mode):
            raise CoverageError("root inventory kind mismatch")
        if cleanup_phase and path in retained_by_path and item["kind"] == "directory":
            check_retained_directory_identity(item, info, "retained directory identity mismatch")
        else:
            check_declared_metadata(item, info, "root inventory identity mismatch")
    missing_retained = set(retained_by_path) - set(actual)
    missing_cleanup = set(cleanup_by_path) - set(actual)
    if missing_retained or (missing_cleanup and not cleanup_phase):
        raise CoverageError("root inventory declared object missing")

    required_process = {"pid", "start_tick", "executable_device", "executable_inode",
                        "cgroup", "classification", "source"}
    process_classes = {"cleanup", "retained-product", "retained-transport"}
    process_sources = {"protected-cgroup", "dedicated-cgroup", "attempt-root-executable",
                       "attempt-root-cwd", "attempt-root-argv"}
    for item in processes:
        if (not isinstance(item, dict) or set(item) != required_process or
                type(item["pid"]) is not int or item["pid"] <= 1 or
                any(type(item[key]) is not int or item[key] <= 0
                    for key in {"start_tick", "executable_device", "executable_inode"}) or
                not isinstance(item["cgroup"], str) or not item["cgroup"].startswith("/") or
                item["classification"] not in process_classes or item["source"] not in process_sources):
            raise CoverageError("cleanup process declaration")
        product_groups = {"/system.slice/sing-box.service", "/system.slice/sbxr-subscription.service"}
        if item["classification"] == "retained-product" and item["cgroup"] not in product_groups:
            raise CoverageError("retained product process provenance refused")
        if (item["classification"] == "retained-transport" and
                item["cgroup"] != "/system.slice/" + bindings["transport_unit"]):
            raise CoverageError("retained transport process provenance refused")
        if item["classification"] in {"retained-product", "retained-transport"} and item["source"] != "protected-cgroup":
            raise CoverageError("retained service process source refused")
        if item["classification"] == "cleanup" and (item["cgroup"] in product_groups or
                item["cgroup"] == "/system.slice/" + bindings["transport_unit"] or
                item["source"] == "protected-cgroup"):
            raise CoverageError("protected service cannot be cleanup")
        if (item["classification"] == "cleanup") != (item["source"] != "protected-cgroup"):
            raise CoverageError("process cleanup classification refused")
    if len({(item["pid"], item["start_tick"]) for item in processes}) != len(processes):
        raise CoverageError("duplicate cleanup process")
    current = relevant_processes(bindings)
    declared = {(item["pid"], item["start_tick"], item["executable_device"], item["executable_inode"], item["cgroup"]): item
                for item in processes}
    if set(current) - set(declared):
        raise CoverageError("process inventory omits live qualification process")
    for identity, item in declared.items():
        if identity in current and current[identity] != item["source"]:
            raise CoverageError("process inventory provenance changed")
        if identity not in current and (item["classification"] != "cleanup" or not cleanup_phase):
            raise CoverageError("declared process identity missing")
    return paths, retained, processes


def object_rules(bindings):
    uid, gid = bindings.get("root_uid", 0), bindings.get("root_gid", 0)
    return {
        "subscription-token": (bindings.get("subscription_token", "/var/lib/sbxr/subscription-token"), "file", 0o600, uid, gid),
        "ownership-record": (bindings.get("ownership_record", "/var/lib/sbxr/proxy-ownership.json"), "file", 0o600, uid, gid),
        "configuration": (bindings.get("configuration", "/etc/sing-box/config.json"), "file", 0o640, uid, bindings["config_gid"]),
        "certificate-private-link": (bindings.get("certificate_link", "/etc/letsencrypt/live/sbxr-subscription/privkey.pem"), "symlink", None, uid, gid),
        "qualification-manifest": (bindings["manifest"], "file", 0o600, uid, gid),
        "transport-credential": (bindings["transport_credential"], "file", 0o600, uid, gid),
        "known-secrets": (bindings["known_secrets"], "file", 0o600, uid, gid),
    }


def validate_objects(spec, inventory, bindings):
    objects = spec.get("protected_objects")
    preserved = spec.get("preserved_objects")
    if not isinstance(objects, list) or not isinstance(preserved, list) or not preserved:
        raise CoverageError("object coverage incomplete")
    by_role = {}
    base = {"role", "path", "kind", "mode", "uid", "gid", "nlink", "sha256"}
    for item in objects:
        allowed = base | ({"target", "resolved_path"} if isinstance(item, dict) and item.get("kind") == "symlink" else set())
        if not isinstance(item, dict) or set(item) != allowed or item.get("role") in by_role:
            raise CoverageError("protected object declaration")
        by_role[item["role"]] = item
    rules = object_rules(bindings)
    pipe_paths = {item["path"] for item in inventory["cleanup_paths"] if item["kind"] == "fifo"}
    pipe_roles = {"private-pipe:" + str(index) for index in range(len(pipe_paths))}
    if set(by_role) != set(rules) | pipe_roles | {"certificate-private-target"}:
        raise CoverageError("canonical protected object coverage incomplete")
    for role, (path, kind, mode, uid, gid) in rules.items():
        item = by_role[role]
        if item["path"] != path or item["kind"] != kind or item["uid"] != uid or item["gid"] != gid or item["nlink"] != 1:
            raise CoverageError("canonical protected object mismatch")
        if mode is not None and item["mode"] != format(mode, "04o"):
            raise CoverageError("canonical protected object mode mismatch")
    link = by_role["certificate-private-link"]
    if (not isinstance(link.get("target"), str) or not isinstance(link.get("resolved_path"), str) or
            link["resolved_path"] != os.path.realpath(link["path"]) or
            not under(link["resolved_path"], bindings.get("certificate_archive", "/etc/letsencrypt/archive/sbxr-subscription"))):
        raise CoverageError("private certificate link target mismatch")
    target = by_role["certificate-private-target"]
    if (os.path.realpath(target["path"]) != link["resolved_path"] or target["kind"] != "file" or target["mode"] != "0600" or
            target["uid"] != bindings.get("root_uid", 0) or
            target["gid"] != bindings.get("root_gid", 0) or target["nlink"] != 1):
        raise CoverageError("private certificate target mismatch")
    declared_pipes = {item["path"] for role, item in by_role.items() if role.startswith("private-pipe:")}
    if declared_pipes != pipe_paths or any(by_role[role]["kind"] != "fifo" or by_role[role]["mode"] != "0600" or
                                           by_role[role]["uid"] != bindings.get("root_uid", 0) or
                                           by_role[role]["gid"] != bindings.get("root_gid", 0)
                                           for role in by_role if role.startswith("private-pipe:")):
        raise CoverageError("private pipe protection coverage incomplete")
    preserved_roles = set()
    for item in preserved:
        if (not isinstance(item, dict) or set(item) != base or
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", item.get("role", "")) or
                item["role"] in preserved_roles or not os.path.isabs(item.get("path", "")) or
                item.get("kind") != "file" or item.get("nlink") != 1 or
                not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"])):
            raise CoverageError("preserved object declaration")
        preserved_roles.add(item["role"])
    protected_paths = {item["path"] for item in objects}
    inventory_paths = ({item["path"] for item in inventory["captures"]} |
                       {item["path"] for item in inventory["cleanup_paths"]} |
                       {item["path"] for item in inventory["retained_paths"]})
    if any(item["path"] in protected_paths or item["path"] in inventory_paths for item in preserved):
        raise CoverageError("preserved object overlaps qualification inventory")
    return objects, preserved


def validate_spec(path, require_root=False, bindings=None, cleanup_phase=False):
    info = os.lstat(path)
    if require_root and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise CoverageError("spec protection")
    spec = document(path, SCHEMA)
    required = {"schema", "authoritative_roots", "attempt_inventory", "units", "proc_root",
                "protected_objects", "preserved_objects", "external_surface_attestation"}
    if set(spec) != required or spec["proc_root"] != "/proc":
        raise CoverageError("spec shape")
    bindings = bindings or default_bindings()
    roots = root_map(spec, bindings)
    spec_path = os.path.realpath(path)
    capture_roots = [roots["capture-" + surface] for surface in SURFACES]
    if (not under(spec_path, roots["operator-evidence"]) or
            any(spec_path == root or under(spec_path, root) for root in capture_roots)):
        raise CoverageError("spec outside dedicated evidence authority")
    inventory = spec["attempt_inventory"]
    if not isinstance(inventory, dict) or set(inventory) != {"captures", "cleanup_paths", "retained_paths", "cleanup_processes"}:
        raise CoverageError("attempt inventory shape")
    captures = validate_capture_inventory(inventory, roots)
    cleanup_paths, retained_paths, cleanup_processes = validate_cleanup_inventory(
        inventory, roots, bindings, cleanup_phase=cleanup_phase)
    expected_units = FIXED_UNITS | {bindings["transport_unit"]}
    if (bindings["transport_unit"] in FIXED_UNITS or set(spec["units"]) != expected_units or
            any(not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", unit) for unit in spec["units"])):
        raise CoverageError("required unit coverage incomplete")
    attestation = spec["external_surface_attestation"]
    if (not isinstance(attestation, dict) or
            set(attestation) != {"complete", "client_cleanup_complete", "attested_by", "attested_at"} or
            attestation["complete"] is not True or attestation["client_cleanup_complete"] is not True or
            not isinstance(attestation["attested_by"], str) or
            not attestation["attested_by"].strip() or not isinstance(attestation["attested_at"], str) or
            not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", attestation["attested_at"])):
        raise CoverageError("external surface attestation missing")
    objects, preserved = validate_objects(spec, inventory, bindings)
    spec["_validated"] = {"roots": roots, "captures": captures, "cleanup_paths": cleanup_paths,
                          "retained_paths": retained_paths, "cleanup_processes": cleanup_processes,
                          "objects": objects, "bindings": bindings,
                          "preserved": preserved}
    return spec


def require_secret_outside_captures(secret_path, spec):
    secret = os.path.realpath(secret_path)
    cleanup = {os.path.realpath(item["path"]) for item in spec["_validated"]["cleanup_paths"]}
    if secret in spec["_validated"]["captures"]:
        raise CoverageError("known-secret file overlaps a capture")
    if secret not in cleanup:
        raise CoverageError("known-secret cleanup omitted from inventory")


def scan_captures(spec, variants):
    counts = {surface: 0 for surface in sorted(SURFACES)}
    for path, item in sorted(spec["_validated"]["captures"].items()):
        body = read_regular(path, expected=item)
        if hashlib.sha256(body).hexdigest() != item["sha256"]:
            raise CoverageError("capture digest mismatch")
        scan_bytes(body, variants)
        counts[item["surface"]] += 1
    if any(value == 0 for value in counts.values()):
        raise CoverageError("capture surface inventory empty")
    return counts


def scan_retained_inventory(spec, variants):
    scanned = 0
    for item in spec["_validated"]["retained_paths"]:
        info = os.lstat(item["path"])
        check_declared_metadata(item, info, "retained inventory identity mismatch")
        if item["kind"] == "directory":
            continue
        body = read_regular(item["path"], expected=item)
        if hashlib.sha256(body).hexdigest() != item["sha256"]:
            raise CoverageError("retained inventory digest mismatch")
        if item["classification"] == "scan-retained":
            scan_bytes(body, variants)
            scanned += 1
    if not scanned:
        raise CoverageError("retained scan inventory empty")
    return scanned


def scan_processes(proc_root, variants):
    pids = sorted((path for path in Path(proc_root).iterdir() if path.name.isdigit()), key=lambda path: int(path.name))
    scanned = 0
    for process in pids:
        for name in ("cmdline", "environ"):
            try:
                body = read_regular(process / name, MAX_PROCESS_FIELD)
            except FileNotFoundError:
                if process.exists():
                    raise CoverageError("process surface vanished incompletely")
                break
            except PermissionError as error:
                raise CoverageError("unreadable process surface") from error
            scan_bytes(body, variants)
            scanned += 1
    if not scanned:
        raise CoverageError("process coverage empty")
    return scanned


def scan_units(units, variants):
    for unit in sorted(units):
        show = subprocess.run(["systemctl", "show", unit,
            "--property=LoadState,FragmentPath,DropInPaths,ExecStart,Environment,EnvironmentFiles"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        cat = subprocess.run(["systemctl", "cat", unit], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=False)
        if show.returncode or cat.returncode or b"LoadState=loaded" not in show.stdout:
            raise CoverageError("unit coverage incomplete")
        environment_files = next((line for line in show.stdout.splitlines()
                                  if line.startswith(b"EnvironmentFiles=")), None)
        if environment_files != b"EnvironmentFiles=":
            raise CoverageError("unit environment-file coverage incomplete")
        scan_bytes(show.stdout, variants)
        scan_bytes(cat.stdout, variants)
    return len(units)


def inspect_object(item, preserved=False):
    info = os.lstat(item["path"])
    expected = {"file": stat.S_ISREG, "directory": stat.S_ISDIR,
                "fifo": stat.S_ISFIFO, "symlink": stat.S_ISLNK}
    if item["kind"] not in expected or not expected[item["kind"]](info.st_mode):
        raise CoverageError("object protection kind mismatch")
    if (item["mode"] != format(stat.S_IMODE(info.st_mode), "04o") or info.st_uid != item["uid"] or
            info.st_gid != item["gid"] or info.st_nlink != item["nlink"]):
        raise CoverageError("object protection mismatch")
    if item["kind"] == "symlink":
        if os.readlink(item["path"]) != item["target"] or os.path.realpath(item["path"]) != item["resolved_path"]:
            raise CoverageError("object symlink changed")
    elif item["kind"] == "file":
        if hashlib.sha256(read_regular(item["path"])).hexdigest() != item["sha256"]:
            raise CoverageError("object digest mismatch")
    elif item["sha256"] is not None:
        raise CoverageError("non-file object digest declaration")
    if preserved and item["kind"] != "file":
        raise CoverageError("preserved object must be a file")


def check_protection(spec):
    for item in spec["_validated"]["objects"]:
        inspect_object(item)
    for item in spec["_validated"]["preserved"]:
        inspect_object(item, True)
    return len(spec["_validated"]["objects"]), len(spec["_validated"]["preserved"])


def process_identity(pid, proc_root="/proc"):
    body = Path(proc_root, str(pid), "stat").read_text()
    tick = int(body[body.rfind(")") + 2:].split()[19])
    executable = os.stat(Path(proc_root, str(pid), "exe"))
    return tick, executable.st_dev, executable.st_ino


def check_cleanup(spec):
    for item in spec["_validated"]["cleanup_paths"]:
        if os.path.lexists(item["path"]):
            raise CoverageError("qualification path remains")
    cleanup_processes = [item for item in spec["_validated"]["cleanup_processes"]
                         if item["classification"] == "cleanup"]
    for item in cleanup_processes:
        try:
            current = process_identity(item["pid"])
        except FileNotFoundError:
            continue
        expected = (item["start_tick"], item["executable_device"], item["executable_inode"])
        if current == expected:
            raise CoverageError("qualification process remains")
    for item in spec["_validated"]["retained_paths"]:
        info = os.lstat(item["path"])
        if item["kind"] == "directory":
            check_retained_directory_identity(item, info, "retained object changed during cleanup")
        else:
            check_declared_metadata(item, info, "retained object changed during cleanup")
        if item["kind"] == "file" and hashlib.sha256(read_regular(item["path"], expected=item)).hexdigest() != item["sha256"]:
            raise CoverageError("retained object digest changed during cleanup")
    validate_cleanup_inventory(spec["attempt_inventory"], spec["_validated"]["roots"],
                               spec["_validated"]["bindings"], cleanup_phase=True)
    return len(spec["_validated"]["cleanup_paths"]), len(cleanup_processes)


def cleanup_inventory(spec):
    """Remove only exact, inventoried qualification objects and processes."""
    stopped = 0
    for item in (value for value in spec["_validated"]["cleanup_processes"]
                 if value["classification"] == "cleanup"):
        try:
            current = process_identity(item["pid"])
        except FileNotFoundError:
            continue
        expected = (item["start_tick"], item["executable_device"], item["executable_inode"])
        if current != expected:
            raise CoverageError("cleanup process identity changed")
        identity = (item["pid"], *expected, item["cgroup"])
        live = relevant_processes(spec["_validated"]["bindings"])
        if live.get(identity) != item["source"]:
            raise CoverageError("cleanup process provenance changed")
        os.kill(item["pid"], signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                current = process_identity(item["pid"])
            except FileNotFoundError:
                break
            if current != expected:
                break
            time.sleep(0.05)
        else:
            raise CoverageError("qualification process did not stop")
        stopped += 1
    paths = spec["_validated"]["cleanup_paths"]
    ordered = ([item for item in paths if item["kind"] != "directory"] +
               sorted((item for item in paths if item["kind"] == "directory"),
                      key=lambda item: item["path"].count("/"), reverse=True))
    removed = 0
    for item in ordered:
        try:
            info = os.lstat(item["path"])
        except FileNotFoundError:
            continue
        expected_kind = {"file": stat.S_ISREG, "fifo": stat.S_ISFIFO, "directory": stat.S_ISDIR}[item["kind"]]
        if (not expected_kind(info.st_mode) or info.st_dev != item["device"] or info.st_ino != item["inode"] or
                format(stat.S_IMODE(info.st_mode), "04o") != item["mode"] or info.st_uid != item["uid"] or
                info.st_gid != item["gid"] or
                (item["kind"] != "directory" and info.st_nlink != item["nlink"])):
            raise CoverageError("cleanup path identity changed")
        if item["kind"] != "directory":
            check_declared_metadata(item, info, "cleanup path identity changed")
        if item["kind"] == "directory":
            # Removing inventoried child directories changes their parent's
            # link count. Its stable identity is checked above; rmdir also
            # refuses any unexpected child that appeared during cleanup.
            os.rmdir(item["path"])
        else:
            os.unlink(item["path"])
        removed += 1
    return removed, stopped


def probe_paths(spec):
    return sorted({item["path"] for item in spec["_validated"]["objects"]})


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--known-secrets", required=True)
    scan.add_argument("--spec", required=True)
    for command in (sub.add_parser("protection"), sub.add_parser("remove-inventory"),
                    sub.add_parser("cleanup"), sub.add_parser("probe-paths")):
        command.add_argument("--spec", required=True)
    args = parser.parse_args(argv)
    spec = validate_spec(args.spec, require_root=True,
                         cleanup_phase=args.command == "cleanup")
    if args.command == "scan":
        require_secret_outside_captures(args.known_secrets, spec)
        variants, secret_kinds = load_secrets(args.known_secrets)
        captures = scan_captures(spec, variants)
        retained = scan_retained_inventory(spec, variants)
        processes = scan_processes(spec["proc_root"], variants)
        units = scan_units(spec["units"], variants)
        result = {"capture_files": captures, "retained_inventory_files": retained,
                  "known_secret_kinds": secret_kinds,
                  "process_fields": processes, "prohibited_patterns_absent": True,
                  "schema": "sbxr-v4-secret-scan-result-v2", "units": units,
                  "variants_absent": True, "external_surface_attested": True,
                  "external_client_cleanup_attested": True}
    elif args.command == "protection":
        protected, preserved = check_protection(spec)
        result = {"protected_objects": protected, "preserved_objects": preserved,
                  "schema": "sbxr-v4-protection-result-v2"}
    elif args.command == "remove-inventory":
        paths, processes = cleanup_inventory(spec)
        result = {"removed_paths": paths, "stopped_processes": processes,
                  "schema": "sbxr-v4-inventory-removal-result-v1"}
    elif args.command == "cleanup":
        paths, processes = check_cleanup(spec)
        result = {"cleanup_paths_absent": paths, "cleanup_processes_absent": processes,
                  "schema": "sbxr-v4-cleanup-result-v2"}
    else:
        result = {"paths": probe_paths(spec), "schema": "sbxr-v4-protected-open-paths-v1"}
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SecretFound:
        print('{"secret_containment_failed":true,"stage":"secret-detected"}', file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print('{"secret_containment_failed":true,"stage":"coverage-incomplete"}', file=sys.stderr)
        raise SystemExit(1)
