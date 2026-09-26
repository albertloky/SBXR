#!/usr/bin/env python3
"""Read-only MVP per-menu observations. Stream this file; do not stage it.

This is an operator prerequisite check, not product authority, candidate
verification, complete footprint absence, or a passing acceptance observation.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


class Refused(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def command(*args, missing=False):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30,
                            env=dict(os.environ, LC_ALL="C", TZ="UTC"))
    if missing and result.returncode == 1:
        return None
    require(result.returncode == 0, "command-failed:" + args[0])
    return result.stdout.strip()


def digest(path):
    with open(path, "rb") as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
        return value.hexdigest()


def metadata(path):
    info = os.lstat(path)
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode)),
            "links": info.st_nlink, "directory": stat.S_ISDIR(info.st_mode),
            "symlink": stat.S_ISLNK(info.st_mode),
            "xattrs": os.listxattr(path, follow_symlinks=False)}


def protected_file(path, mode=None, *, allow_hardlinks=False):
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and (allow_hardlinks or info.st_nlink == 1) and not info.st_mode & 0o022
            and (mode is None or stat.S_IMODE(info.st_mode) == mode)
            and not os.listxattr(path, follow_symlinks=False), "unsafe-file:" + str(path))


RECOVERY_PHASES = {"recovery-precommit": "Prepared", "recovery-postcommit": "Committed"}
RECOVERY_FIELDS = {"prior_executable_sha256", "prior_installed_record_sha256",
                   "candidate_executable_sha256", "candidate_installed_record_sha256",
                   "ownership_sha256"}
TRANSACTION_PATHS = ("/var/lib/sbxr/update.json", "/var/lib/sbxr/.update.json.next",
                     "/var/lib/sbxr/.installed.json.prior", "/var/lib/sbxr/.installed.json.candidate",
                     "/usr/local/bin/.sbxr-update-prior", "/usr/local/bin/.sbxr-update-candidate")


def exact_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate-json-key")
        value[key] = item
    return value


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def recovery_observation(phase, expected, wanted, window_seconds, request_path):
    """Admit ONLY the two exact, quiescent controller checkpoints for Recover.

    Hashes are reviewed inputs, never learned from transaction staging. This
    does not prove the earlier interruption, run Recover, or replace its own
    public review/admission. Normal protected_file still requires one link.
    """
    require(phase in RECOVERY_PHASES and type(wanted) is dict and set(wanted) == RECOVERY_FIELDS,
            "recovery-expectation-fields")
    require(all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in wanted.values()),
            "recovery-expectation-digests")
    require(wanted["prior_executable_sha256"] != wanted["candidate_executable_sha256"],
            "recovery-identical-releases")
    identities = {}
    def read(path, mode=0o600, links=1, limit=65536, sha256=None):
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) == mode and before.st_nlink == links
                    and 0 < before.st_size <= limit and not os.listxattr(stream.fileno()),
                    "unsafe-recovery-file:" + str(path))
            body = stream.read(limit + 1)
            require(len(body) <= limit and file_identity(before) == file_identity(os.fstat(stream.fileno()))
                    == file_identity(os.lstat(path)), "recovery-file-changed")
        if sha256 is not None:
            require(hashlib.sha256(body).hexdigest() == sha256, "recovery-digest:" + str(path))
        identities[path] = file_identity(before)
        return body

    raw_request = read(request_path)
    request = json.loads(raw_request, object_pairs_hook=exact_object)
    require(type(request) is dict and set(request) == {
        "deadline_unix", "not_before", "qualification_manifest_sha256", "required_checks",
        "scenario_id", "scenario_limit_seconds"}, "recovery-request-fields")
    bound_manifest = expected.get("qualification_manifest_sha256")
    require(type(bound_manifest) is str and re.fullmatch(r"[0-9a-f]{64}", bound_manifest)
            and request["qualification_manifest_sha256"] == bound_manifest, "recovery-request-manifest")
    boundary = phase.removeprefix("recovery-")
    require(type(request["scenario_id"]) is str
            and re.fullmatch(r"source-v[0-9]+\.[0-9]+\.[0-9]+-" + boundary, request["scenario_id"]),
            "recovery-request-scenario")
    require(type(request["not_before"]) is str
            and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", request["not_before"]),
            "recovery-request-start")
    start = dt.datetime.strptime(request["not_before"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
    require(type(request["deadline_unix"]) is int and type(request["scenario_limit_seconds"]) is int
            and request["scenario_limit_seconds"] == 1800
            and 0 < request["deadline_unix"] - start <= 1800
            and start <= time.time() and time.time() + window_seconds <= request["deadline_unix"],
            "recovery-request-window")
    for directory in ("/var/lib/sbxr", "/usr/local/bin"):
        info = metadata(Path(directory))
        require(info["directory"] and info["uid"] == info["gid"] == 0
                and not int(info["mode"], 8) & 0o022 and not info["xattrs"], "recovery-parent")
    checkpoint = RECOVERY_PHASES[phase]
    raw_record = read("/var/lib/sbxr/update.json", limit=4096)
    record = json.loads(raw_record, object_pairs_hook=exact_object)
    require(type(record) is dict and type(record.get("schema")) is int
            and record == dict(wanted, schema=2, checkpoint=checkpoint), "recovery-checkpoint")
    owner = json.loads(read("/var/lib/sbxr/proxy-ownership.json", sha256=wanted["ownership_sha256"]),
                       object_pairs_hook=exact_object)
    require(type(owner) is dict and type(owner.get("schema")) is int and owner["schema"] == 2
            and owner.get("phase") == "Running" and owner.get("unfinished_direction") == "none",
            "recovery-ownership")
    prefix = "prior" if checkpoint == "Prepared" else "candidate"
    links = 2 if checkpoint == "Prepared" else 1
    executable = Path("/usr/local/bin/sbxr")
    prior = Path("/usr/local/bin/.sbxr-update-prior")
    read(executable, 0o755, links, 128 << 20, wanted[prefix + "_executable_sha256"])
    read(prior, 0o755, links, 128 << 20, wanted["prior_executable_sha256"])
    require((identities[executable][:2] == identities[prior][:2]) == (checkpoint == "Prepared"),
            "recovery-prior-hardlink")
    active = read("/var/lib/sbxr/installed.json", limit=4096,
                  sha256=wanted[prefix + "_installed_record_sha256"])
    prior_record = read("/var/lib/sbxr/.installed.json.prior", limit=4096,
                        sha256=wanted["prior_installed_record_sha256"])
    absent = [Path("/var/lib/sbxr/.update.json.next")]
    if checkpoint == "Prepared":
        read("/usr/local/bin/.sbxr-update-candidate", 0o755, 1, 128 << 20,
             wanted["candidate_executable_sha256"])
        candidate_record = read("/var/lib/sbxr/.installed.json.candidate", limit=4096,
                                sha256=wanted["candidate_installed_record_sha256"])
        require(active == prior_record, "recovery-active-record")
    else:
        candidate_record = active
        absent += [Path("/usr/local/bin/.sbxr-update-candidate"), Path("/var/lib/sbxr/.installed.json.candidate")]
    require(not any(os.path.lexists(p) for p in absent), "recovery-unexpected-staging")
    pair = []
    for kind, raw in (("prior", prior_record), ("candidate", candidate_record)):
        installed = json.loads(raw, object_pairs_hook=exact_object)
        require(type(installed) is dict and set(installed) == {
            "schema", "repository", "tag", "commit", "release_index_sha256", "sequence",
            "architecture", "executable_sha256"} and type(installed["schema"]) is int
            and installed["schema"] == 1 and installed["repository"] == "albertloky/SBXR"
            and installed["architecture"] == "amd64" and type(installed["sequence"]) is int
            and installed["sequence"] > 0 and type(installed["tag"]) is str
            and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", installed["tag"])
            and type(installed["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", installed["commit"])
            and type(installed["release_index_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", installed["release_index_sha256"])
            and installed["executable_sha256"] == wanted[kind + "_executable_sha256"], "recovery-installed-record")
        pair.append(installed)
    require(request["scenario_id"] == "source-" + pair[0]["tag"] + "-" + boundary
            and pair[1]["sequence"] > pair[0]["sequence"], "recovery-release-route")
    require(all(file_identity(os.lstat(p)) == identity for p, identity in identities.items())
            and not any(os.path.lexists(p) for p in absent), "recovery-files-changed")
    require(time.time() + window_seconds <= request["deadline_unix"], "recovery-request-window")
    return {"checkpoint": checkpoint, "update_record_sha256": hashlib.sha256(raw_record).hexdigest(),
            "request_sha256": hashlib.sha256(raw_request).hexdigest(), "scenario_id": request["scenario_id"],
            "qualification_manifest_sha256": bound_manifest, "bound_material_verified": True}


def ownership_identity(receipt):
    return " ".join(str(receipt[key]) for key in
                    ("repository", "name", "version", "architecture", "size", "sha256"))


def snap_observation(expected):
    snaps = {}
    for name in ("certbot", "core24", "snapd"):
        lines = command("snap", "list", name).splitlines()
        require(len(lines) == 2, "snap-list")
        fields = lines[1].split()
        require(len(fields) >= 3 and fields[0] == name and fields[2].isdigit(), "snap-list")
        path = Path("/var/lib/snapd/snaps") / (name + "_" + fields[2] + ".snap")
        # snapd's content cache hard-links package images. Their identity is
        # the reviewed receipt below, not a one-link private-file invariant.
        protected_file(path, allow_hardlinks=True)
        snaps[name] = {"version": fields[1], "revision": fields[2],
                       "snap_sha256": digest(path), "snap_size": path.stat().st_size}
    require(snaps == expected, "snap-receipt-drift")
    return snaps


def package_observation(phase, expected, recovery=None):
    receipt = expected["proxy_package"]
    # Inspect dpkg regardless of the download artifact's presence. Successful
    # installPackage removes that artifact; Running requires an installed hold.
    raw = command("dpkg-query", "--show",
                  "--showformat=${Version}\t${Architecture}\t${Status}\n",
                  "sing-box", missing=True)
    artifact = Path("/var/lib/sbxr/sing-box_1.13.19_amd64.deb")
    require(not os.path.lexists(artifact), "temporary-package-artifact")
    ownership = Path("/var/lib/sbxr/proxy-ownership.json")
    renewal = Path("/var/lib/sbxr/renewal-attempts.json")
    executable = Path("/usr/local/bin/sbxr")
    installed = Path("/var/lib/sbxr/installed.json")
    binary = Path("/usr/bin/sing-box")
    if phase != "running" and phase not in RECOVERY_PHASES:
        require(raw in (None, "unknown ok not-installed"), "unexpected-proxy-package")
        for path in (ownership, renewal, binary):
            require(not os.path.lexists(path), "unexpected-owned-path:" + str(path))
        for path in (executable, installed):
            if phase == "not-set-up":
                protected_file(path)
            else:
                require(not os.path.lexists(path), "unexpected-installed-path:" + str(path))
        return None
    require(raw == "\t".join((receipt["version"], receipt["architecture"], "hold ok installed")),
            "installed-proxy-package")
    if phase in RECOVERY_PHASES:
        require(recovery is not None and recovery["checkpoint"] == RECOVERY_PHASES[phase],
                "recovery-proof-required")
        # Only the exact bound pair above may have the Prepared two-link shape.
        # The proxy binary and every other protected file retain one-link checks.
        protected = (binary,)
    else:
        require(not any(os.path.lexists(Path(p)) for p in TRANSACTION_PATHS), "unexpected-update-transaction")
        protected = (executable, installed, binary)
    for path in protected:
        protected_file(path)
    require(digest(binary) == expected["installed_binary_sha256"], "installed-proxy-binary")
    protected_file(ownership, 0o600)
    record = json.loads(ownership.read_text())
    require(record["phase"] == "Running" and record["unfinished_direction"] == "none",
            "ownership-phase")
    identity = ownership_identity(receipt)
    require(record["proxy_package_identity"] == identity, "ownership-package")
    # Renewal diagnostics are independent of the removed download artifact.
    if os.path.lexists(renewal):
        protected_file(renewal, 0o600)
        evidence = json.loads(renewal.read_text())
        require("attempts" in evidence, "renewal-evidence")
        attempts = evidence["attempts"]
        require(attempts is None or isinstance(attempts, list), "renewal-evidence")
        require(all(isinstance(a, dict) and isinstance(a.get("completion"), dict)
                    for a in (attempts or [])), "incomplete-renewal")
    return {"version": receipt["version"], "architecture": receipt["architecture"],
            "status": "hold ok installed", "binary_sha256": expected["installed_binary_sha256"],
            "ownership_package_identity": identity}


OPERATOR_MODES = {"mvp-protected-menu.sh": 0o700,
                  "with-protected-log-parent.sh": 0o700,
                  "protected_command_supervisor.py": 0o600,
                  "v3-menu-session.py": 0o600}


def log_observation():
    return {"log_parent": metadata("/var/log"),
            "log_children": {p.name: metadata(p) for p in sorted(Path("/var/log").iterdir())
                             if p.is_dir() or p.is_symlink()}}


def observe(phase, expected, window_seconds, recovery_expected=None,
            request_path="/root/sbxr-qualification-evidence/request.json"):
    require(sys.platform.startswith("linux") and os.geteuid() == 0, "root-linux-required")
    require(0 < window_seconds <= 900, "menu-window-bound")
    require((phase in RECOVERY_PHASES) == (recovery_expected is not None), "recovery-phase-input")
    receipt = expected["proxy_package"]
    require(receipt["name"] == "sing-box" and receipt["version"] == "1.13.19"
            and receipt["architecture"] == "amd64", "unsupported-proxy-package")
    require(set(expected["operator_sha256"]) == set(OPERATOR_MODES), "operator-manifest")
    require(set(expected["snap_packages"]) == {"certbot", "core24", "snapd"}, "snap-manifest")
    root = Path("/root/sbxr-mvp-log-parent")
    info = metadata(root)
    require(info["directory"] and info["uid"] == info["gid"] == 0
            and info["mode"] == "0o700" and not info["xattrs"], "operator-directory")
    # Also refuses retained state/FIFOs, including broken symlinks.
    require({p.name for p in root.iterdir()} == set(OPERATOR_MODES), "operator-directory-contents")
    for name, mode in OPERATOR_MODES.items():
        protected_file(root / name, mode)
        require(digest(root / name) == expected["operator_sha256"][name], "operator-file-identity:" + name)
    logs = log_observation()
    parent = logs["log_parent"]
    require(parent["directory"] and parent["uid"] == 0 and parent["mode"] == "0o775"
            and not parent["xattrs"], "original-log-parent")
    require(all(logs[key] == expected[key] for key in logs), "log-directory-drift")
    for name in ("/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt"):
        info = metadata(name)
        require(info["directory"] and info["uid"] == 0
                and not int(info["mode"], 8) & 0o022 and not info["xattrs"], "certbot-directory")
    snaps = snap_observation(expected["snap_packages"])
    changes = command("snap", "changes").splitlines()
    require(all(len(line.split()) >= 2 and line.split()[1] in ("Done", "Error", "Undone", "Hold")
                for line in changes[1:] if line.strip()), "active-snap-change")
    next_timer = command("systemctl", "show", "snap.certbot.renew.timer", "-p", "NextElapseUSecRealtime", "--value")
    timer_unix = int(command("date", "-d", next_timer, "+%s"))
    refresh = command("snap", "refresh", "--time")
    next_lines = [line[5:].strip() for line in refresh.splitlines() if line.startswith("next:")]
    require(len(next_lines) == 1, "snap-refresh-time")
    match = re.fullmatch(r"(today|tomorrow) at (\d\d):(\d\d) UTC", next_lines[0])
    require(match is not None, "snap-refresh-time")
    now = dt.datetime.now(dt.timezone.utc)
    refresh_time = now.replace(hour=int(match[2]), minute=int(match[3]), second=0, microsecond=0)
    refresh_time += dt.timedelta(days=match[1] == "tomorrow")
    require(min(timer_unix, refresh_time.timestamp()) > time.time() + window_seconds, "scheduled-event-overlap")
    require(command("systemctl", "is-active", "snap.certbot.renew.timer") == "active", "timer-inactive")
    require(command("systemctl", "is-enabled", "snap.certbot.renew.timer") == "enabled", "timer-disabled")
    require(command("systemctl", "show", "snap.certbot.renew.service", "-p", "ActiveState", "--value") == "inactive", "renewal-service-active")
    locks = Path("/proc/locks").read_text().splitlines()
    for name in ("/run/lock/sbxr.lock", "/etc/letsencrypt/.certbot.lock",
                 "/var/lib/letsencrypt/.certbot.lock", "/var/log/letsencrypt/.certbot.lock"):
        if os.path.lexists(name):
            protected_file(name)
            info = os.lstat(name)
            identity = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
            require(not any(identity in line.split() for line in locks), "held-lock:" + name)
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            args = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except (FileNotFoundError, ProcessLookupError):
            continue
        # No command lines in output: these can contain client credentials.
        require(not re.search(r"certbot|v3-menu-session|protected_command_supervisor|with-protected-log-parent|mvp-protected-menu|mvp-update-interrupt", args, re.I),
                "active-writer-pid:" + proc.name)
        if phase in RECOVERY_PHASES:
            require(args.strip() != "/usr/local/bin/sbxr", "active-recovery-menu-pid:" + proc.name)
    recovery = (recovery_observation(phase, expected, recovery_expected, window_seconds, request_path)
                if phase in RECOVERY_PHASES else None)
    package = package_observation(phase, expected, recovery)
    require(log_observation() == logs, "log-directory-drift-during-observation")
    result = dict(logs, checked_at=dt.datetime.now(dt.timezone.utc).isoformat(), phase=phase,
                snap_packages=snaps, next_timer=next_timer, snap_refresh=refresh,
                installed_proxy_package=package, operator_files_verified=True,
                locks_unheld=True, writers_idle=True, window_seconds=window_seconds)
    if recovery is not None:
        result["recovery"] = recovery
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("not-installed", "not-set-up", "running", "removed", *RECOVERY_PHASES))
    parser.add_argument("expectation_base64", help="reviewed local expectation JSON, base64 encoded")
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--recovery-expectation-base64", help="independently reviewed five-field interruption expectation")
    parser.add_argument("--request", default="/root/sbxr-qualification-evidence/request.json")
    args = parser.parse_args()
    try:
        expected = json.loads(base64.b64decode(args.expectation_base64, validate=True), object_pairs_hook=exact_object)
        recovery = (json.loads(base64.b64decode(args.recovery_expectation_base64, validate=True), object_pairs_hook=exact_object)
                    if args.recovery_expectation_base64 is not None else None)
        result = observe(args.phase, expected, args.window_seconds, recovery, args.request)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Refused as error:
        print("MVP_WINDOW_REFUSED " + str(error), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired):
        print("MVP_WINDOW_REFUSED unreadable-or-invalid-observation", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
