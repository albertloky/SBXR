#!/usr/bin/env python3
"""Capture and validate an Owner-reviewed record of the actual Karing UI journey.

The macOS capture mode inventories native captures and the installed/package
identity without controlling Karing or requesting permissions. The validation
mode binds the Owner's semantic review to those retained bytes.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import shutil
import stat
import sys


SCHEMA = "sbxr-v4-karing-reviewed-capture-v1"
RESULT_SCHEMA = "sbxr-v4-karing-evidence-result-v1"
NATIVE_SCHEMA = "sbxr-v4-karing-native-capture-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_NATIVE_SIZE = 2_000_000_000
EVENTS = (
    "initial-settings", "profile-imported", "initial-node-latency",
    "manual-same-link-refresh", "due-five-minute-auto-refresh",
    "auto-refresh-disabled", "server-old-credential-refused",
    "revoked-node-latency-refused", "same-link-replacement-refresh",
    "replacement-node-latency", "https-outage-refresh-refused",
    "https-outage-node-latency", "same-link-recovery-refresh",
    "complete-removal", "outside-access-refused", "removed-node-latency-refused",
    "full-owned-absence", "test-profile-cleanup", "final-settings",
)


class Refusal(ValueError):
    pass


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal("duplicate JSON key")
        value[key] = item
    return value


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def protected(path: Path) -> bytes:
    if not path.is_absolute():
        raise Refusal("absolute reviewed capture path required")
    before = path.lstat()
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or
            stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 2_000_000):
        raise Refusal("one-link mode-0600 reviewed capture required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        raw = os.read(fd, 2_000_001)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != opened.st_size):
        raise Refusal("reviewed capture changed while reading")
    current = path.lstat()
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise Refusal("reviewed capture path replaced")
    return raw


def artifact_digest(path: Path, expected_size=None) -> tuple[str, int]:
    if not path.is_absolute():
        raise Refusal("absolute native capture path required")
    before = path.lstat()
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size <= 0 or before.st_size > MAX_NATIVE_SIZE or
            expected_size is not None and before.st_size != expected_size):
        raise Refusal("bounded one-link native capture file required")
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if identity(opened) != identity(after) or identity(opened) != identity(current):
        raise Refusal("native capture changed while reading")
    return digest.hexdigest(), opened.st_size


def media_type(path: Path) -> str:
    types = {".jpeg": "image/jpeg", ".jpg": "image/jpeg", ".png": "image/png",
             ".mov": "video/quicktime", ".mp4": "video/mp4"}
    try:
        return types[path.suffix.lower()]
    except KeyError as error:
        raise Refusal("native capture must be PNG, JPEG, MOV, or MP4") from error


def verify_media(path: Path, declared: str):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        header = os.read(fd, 16)
    finally:
        os.close(fd)
    valid = ((declared == "image/png" and header.startswith(b"\x89PNG\r\n\x1a\n")) or
             (declared == "image/jpeg" and header.startswith(b"\xff\xd8\xff")) or
             (declared in ("video/mp4", "video/quicktime") and len(header) >= 12 and header[4:8] == b"ftyp"))
    if not valid:
        raise Refusal("native capture bytes do not match declared media type")


def atomic_copy(source: Path, destination: Path):
    if destination.exists() or destination.is_symlink():
        raise Refusal("native capture destination already exists")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_NATIVE_SIZE:
            raise Refusal("bounded regular native source required")
        with os.fdopen(os.dup(source_fd), "rb") as reader, os.fdopen(os.dup(destination_fd), "wb") as writer:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Refusal("native source changed while copying")
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def capture_native(manifest_path: Path, request_path: Path, package_path: Path, app_path: Path,
                   artifact_paths: list[Path], output_directory: Path) -> dict:
    if sys.platform != "darwin" or platform.machine() != "arm64" or not artifact_paths:
        raise Refusal("macOS arm64 and at least one existing native capture required")
    manifest_raw, request_raw = protected(manifest_path), protected(request_path)
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    request = json.loads(request_raw, object_pairs_hook=unique)
    manifest_sha, request_sha = hashlib.sha256(manifest_raw).hexdigest(), hashlib.sha256(request_raw).hexdigest()
    package = manifest.get("v3_attempt", {}).get("packages", {}).get("karing", {})
    if (request.get("scenario_id") != "karing-final" or request.get("qualification_manifest_sha256") != manifest_sha or
            request.get("scenario_limit_seconds") != 7200 or package.get("architecture") != "macos-arm64"):
        raise Refusal("current signed Karing request required")
    package_sha, package_size = artifact_digest(package_path)
    if package_sha != package.get("sha256") or package_size != package.get("size"):
        raise Refusal("native package bytes differ from signed package")
    if not app_path.is_absolute() or app_path.is_symlink() or not app_path.is_dir():
        raise Refusal("installed Karing application bundle required")
    info_path = app_path / "Contents" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    bundle_id, short_version, build_version = (info.get("CFBundleIdentifier"),
                                                info.get("CFBundleShortVersionString"),
                                                info.get("CFBundleVersion"))
    executable_name = info.get("CFBundleExecutable")
    if (bundle_id != "com.nebula.karing" or not all(isinstance(value, str) and value for value in
                                                     (short_version, build_version, executable_name)) or
            package.get("version") not in (short_version, short_version + "." + build_version)):
        raise Refusal("installed Karing bundle identity differs from signed package")
    executable_sha, _ = artifact_digest((app_path / "Contents" / "MacOS" / executable_name).resolve())
    if output_directory.exists() or output_directory.is_symlink() or not output_directory.is_absolute():
        raise Refusal("new absolute native capture directory required")
    output_directory.mkdir(mode=0o700)
    artifacts = []
    try:
        for index, source in enumerate(artifact_paths, 1):
            kind = media_type(source)
            name = f"25-karing-native-{index:02d}{source.suffix.lower()}"
            destination = output_directory / name
            atomic_copy(source, destination)
            verify_media(destination, kind)
            sha256, size = artifact_digest(destination)
            artifacts.append({"media_type": kind, "name": name, "sha256": sha256, "size": size})
        captured_at = datetime.now(timezone.utc)
        if captured_at.timestamp() > request.get("deadline_unix", 0):
            raise Refusal("native capture exceeded signed Karing deadline")
        value = {"schema": NATIVE_SCHEMA, "scenario_id": "karing-final",
                 "qualification_manifest_sha256": manifest_sha, "request_sha256": request_sha,
                 "captured_at": captured_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                 "capture_method": "owner-operated-native-macos-capture",
                 "package_receipt": {"name": package_path.name, "sha256": package_sha, "size": package_size},
                 "application_receipt": {"bundle_identifier": bundle_id, "short_version": short_version,
                                           "build_version": build_version, "executable_sha256": executable_sha},
                 "artifacts": artifacts}
        destination = output_directory / "25-karing-native-capture.json"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, canonical(value)); os.fsync(fd)
        finally:
            os.close(fd)
        return value
    except Exception:
        for path in output_directory.iterdir():
            path.unlink()
        output_directory.rmdir()
        raise


def instant(value, label):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Refusal(label + ": canonical UTC timestamp required")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise Refusal(label + ": invalid timestamp") from error


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refusal(label + ": exact object shape required")


def validate_native(value, raw, root: Path, manifest_sha: str, request_sha: str, package: dict,
                    first_event, last_event, deadline: int):
    exact(value, ("application_receipt", "artifacts", "capture_method", "captured_at", "package_receipt",
                  "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema"), "native capture")
    if (canonical(value) != raw or value["schema"] != NATIVE_SCHEMA or value["scenario_id"] != "karing-final" or
            value["capture_method"] != "owner-operated-native-macos-capture" or
            value["qualification_manifest_sha256"] != manifest_sha or value["request_sha256"] != request_sha):
        raise Refusal("current canonical native capture manifest required")
    exact(value["package_receipt"], ("name", "sha256", "size"), "native package receipt")
    receipt = value["package_receipt"]
    if (not isinstance(receipt["name"], str) or Path(receipt["name"]).name != receipt["name"] or
            receipt["sha256"] != package.get("sha256") or receipt["size"] != package.get("size")):
        raise Refusal("actual native package identity differs from signed package")
    exact(value["application_receipt"], ("build_version", "bundle_identifier", "executable_sha256", "short_version"),
          "installed application receipt")
    application = value["application_receipt"]
    if (application["bundle_identifier"] != "com.nebula.karing" or
            not all(isinstance(application[key], str) and application[key] for key in ("build_version", "short_version")) or
            not SHA256.fullmatch(application.get("executable_sha256", "")) or
            package.get("version") is not None and package["version"] not in
            (application["short_version"], application["short_version"] + "." + application["build_version"])):
        raise Refusal("installed native Karing identity differs")
    captured = instant(value["captured_at"], "native capture completion")
    if captured < first_event or captured < last_event or captured.timestamp() > deadline:
        raise Refusal("native capture lies outside reviewed journey")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise Refusal("retained native capture artifacts required")
    retained = {}
    for index, artifact in enumerate(artifacts):
        exact(artifact, ("media_type", "name", "sha256", "size"), f"native artifact {index}")
        name = artifact["name"]
        if (not isinstance(name, str) or Path(name).name != name or name in retained or
                artifact["media_type"] not in {"image/jpeg", "image/png", "video/mp4", "video/quicktime"} or
                not SHA256.fullmatch(artifact.get("sha256", "")) or
                type(artifact.get("size")) is not int or artifact["size"] <= 0):
            raise Refusal("exact native capture artifact inventory required")
        path = root / name
        try:
            if stat.S_IMODE(path.lstat().st_mode) != 0o600:
                raise Refusal("mode-0600 retained native capture required")
            verify_media(path, artifact["media_type"])
            sha256, size = artifact_digest(path, artifact["size"])
        except OSError as error:
            raise Refusal("retained native capture unavailable") from error
        if sha256 != artifact["sha256"] or size != artifact["size"]:
            raise Refusal("retained native capture bytes differ")
        retained[name] = sha256
    return retained


def validate(doc, raw, manifest, manifest_raw, request, request_raw, native, native_raw, native_root: Path):
    exact(doc, ("capture_method", "events", "final", "initial", "node", "package",
                "native_capture_sha256", "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema"),
          "reviewed capture")
    if doc["schema"] != SCHEMA or doc["scenario_id"] != "karing-final" or doc["capture_method"] != "owner-reviewed-manual-karing-ui":
        raise Refusal("actual manual Karing capture required")
    manifest_sha, request_sha = hashlib.sha256(manifest_raw).hexdigest(), hashlib.sha256(request_raw).hexdigest()
    attempt = manifest.get("v3_attempt", {})
    if (request.get("scenario_id") != "karing-final" or request.get("qualification_manifest_sha256") != manifest_sha or
            request.get("scenario_limit_seconds") != 7200 or attempt.get("karing_limit_seconds") != 7200):
        raise Refusal("current signed 7200-second Karing request required")
    if doc["qualification_manifest_sha256"] != manifest_sha or doc["request_sha256"] != request_sha:
        raise Refusal("capture authority differs")
    package = attempt["packages"]["karing"]
    if doc["package"] != package:
        raise Refusal("installed Karing package differs from signed package")
    exact(doc["initial"], ("application_settings_sha256", "dns_sha256", "profile_list_sha256",
                           "routing_sha256", "selected_server_sha256", "tun_sha256"), "initial settings")
    if doc["final"] != doc["initial"] or any(not SHA256.fullmatch(v) for v in doc["initial"].values()):
        raise Refusal("selected server or persistent Karing settings changed")
    exact(doc["node"], ("display_name", "initial_nonsecret_fields_sha256", "profile_id_sha256",
                        "remote_profile_count", "replacement_nonsecret_fields_sha256", "server_count", "type"), "node")
    node = doc["node"]
    if (not isinstance(node["display_name"], str) or not node["display_name"] or
            node["remote_profile_count"] != 1 or node["server_count"] != 1 or node["type"] != "vless-reality" or
            node["initial_nonsecret_fields_sha256"] != node["replacement_nonsecret_fields_sha256"] or
            not SHA256.fullmatch(node["profile_id_sha256"]) or not SHA256.fullmatch(node["initial_nonsecret_fields_sha256"])):
        raise Refusal("one stable VLESS Reality node was not proved")
    events = doc["events"]
    if not isinstance(events, list) or [item.get("kind") for item in events if isinstance(item, dict)] != list(EVENTS):
        raise Refusal("exact ordered Karing event set required")
    event_keys = {"kind", "native_artifacts", "observed_at", "outcome", "profile_id_sha256", "selected_server_sha256"}
    prior = instant(request["not_before"], "request.not_before")
    by_kind = {}
    for index, event in enumerate(events):
        exact(event, event_keys, f"event {index}")
        at = instant(event["observed_at"], f"event {index}")
        if at < prior or at.timestamp() > request["deadline_unix"]:
            raise Refusal("Karing event order or original deadline differs")
        prior = at
        if (event["profile_id_sha256"] != node["profile_id_sha256"] or
                event["selected_server_sha256"] != doc["initial"]["selected_server_sha256"] or
                not isinstance(event["native_artifacts"], list) or not event["native_artifacts"] or
                any(not isinstance(name, str) for name in event["native_artifacts"])):
            raise Refusal("Karing event selected server or profile differs")
        by_kind[event["kind"]] = event
    expected = {
        "initial-settings": "captured", "profile-imported": "one-node-matched",
        "initial-node-latency": "fresh-success", "manual-same-link-refresh": "advanced-same-link",
        "due-five-minute-auto-refresh": "genuinely-due-and-advanced", "auto-refresh-disabled": "disabled-before-rotation",
        "server-old-credential-refused": "outside-target-healthy-and-server-refused",
        "revoked-node-latency-refused": "fresh-failure-with-old-cached-uuid",
        "same-link-replacement-refresh": "uuid-only-replacement",
        "replacement-node-latency": "fresh-success", "https-outage-refresh-refused": "cached-node-preserved",
        "https-outage-node-latency": "fresh-success", "same-link-recovery-refresh": "advanced-same-link",
        "complete-removal": "software-lifecycle-complete-removal-completed",
        "outside-access-refused": "old-new-proxy-and-link-refused",
        "removed-node-latency-refused": "fresh-failure", "full-owned-absence": "proved",
        "test-profile-cleanup": "profile-and-temporary-secrets-removed", "final-settings": "equal-initial",
    }
    if any(by_kind[k]["outcome"] != value for k, value in expected.items()):
        raise Refusal("one or more actual Karing outcomes differ")
    if (instant(by_kind["due-five-minute-auto-refresh"]["observed_at"], "auto refresh").timestamp() -
            instant(by_kind["manual-same-link-refresh"]["observed_at"], "manual refresh").timestamp() < 300):
        raise Refusal("automatic refresh was not genuinely five-minute due")
    if doc["native_capture_sha256"] != hashlib.sha256(native_raw).hexdigest():
        raise Refusal("reviewed events are not bound to native capture manifest")
    retained = validate_native(native, native_raw, native_root, manifest_sha, request_sha, package,
                               instant(events[0]["observed_at"], "first event"),
                               instant(events[-1]["observed_at"], "last event"), request["deadline_unix"])
    referenced = {name for event in events for name in event["native_artifacts"]}
    if referenced != set(retained) or any(name not in retained for name in referenced):
        raise Refusal("every retained native artifact and reviewed event must be bound")
    if canonical(doc) != raw:
        raise Refusal("canonical reviewed capture bytes required")
    return {"schema": RESULT_SCHEMA, "reviewed_capture_sha256": hashlib.sha256(raw).hexdigest(),
            "native_capture_sha256": hashlib.sha256(native_raw).hexdigest(),
            "started_at": events[0]["observed_at"], "completed_at": events[-1]["observed_at"],
            "event_timestamps": {item["kind"]: item["observed_at"] for item in events},
            "native_artifact_sha256": retained, "package_sha256": package["sha256"],
            "profile_id_sha256": node["profile_id_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-native", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--native-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--artifact", action="append", type=Path, default=[])
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args()
    if args.capture_native:
        required = (args.manifest, args.request, args.package, args.app, args.output_directory)
        if args.input or args.native_manifest or args.native_root or any(value is None for value in required):
            raise Refusal("exact native capture arguments required")
        result = capture_native(args.manifest, args.request, args.package, args.app, args.artifact, args.output_directory)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return
    if not args.input or not args.native_manifest or not args.native_root or any((args.manifest, args.request, args.package, args.app, args.artifact, args.output_directory)):
        raise Refusal("reviewed input, native manifest, and native root required")
    capture_raw = protected(args.input)
    native_raw = protected(args.native_manifest)
    manifest_raw = protected(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]))
    request_raw = protected(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]))
    capture = json.loads(capture_raw, object_pairs_hook=unique)
    native = json.loads(native_raw, object_pairs_hook=unique)
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    request = json.loads(request_raw, object_pairs_hook=unique)
    result = validate(capture, capture_raw, manifest, manifest_raw, request, request_raw, native, native_raw, args.native_root)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"state": "refused", "error_type": type(error).__name__}, sort_keys=True, separators=(",", ":")))
        raise SystemExit(1)
