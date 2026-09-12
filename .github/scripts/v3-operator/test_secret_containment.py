#!/usr/bin/env python3
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import urllib.parse

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("secret_containment", ROOT / "secret-containment.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SecretContainmentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Temporary files can inherit their parent group (for example wheel on
        # macOS /private/tmp), rather than the process's primary group.
        owner = self.root.stat()
        self.uid, self.gid = owner.st_uid, owner.st_gid
        self.state = self.directory("state")
        self.evidence = self.directory("evidence")
        self.transport = self.directory("transport")
        self.captures = {}
        capture_entries = []
        roots = [{"role": "operator-state", "path": str(self.state)},
                 {"role": "operator-evidence", "path": str(self.evidence)},
                 {"role": "transport", "path": str(self.transport)}]
        for surface in sorted(scanner.SURFACES):
            folder = self.directory("evidence/" + surface)
            roots.append({"role": "capture-" + surface, "path": str(folder)})
            path = folder / "capture.log"
            path.write_text("safe " + surface + "\n")
            path.chmod(0o600)
            self.captures[surface] = path
            capture_entries.append(self.capture_item(path, surface))

        self.token = self.file("token", 0o600)
        self.ownership = self.file("ownership", 0o600)
        self.configuration = self.file("configuration", 0o640)
        self.manifest = self.file("manifest", 0o600)
        self.credential = self.file("transport/gateway.key", 0o600)
        self.known = self.file("state/24-known-secrets.json", 0o600)
        self.retained = self.file("state/retained-safe.log", 0o600)
        archive = self.directory("archive")
        live = self.directory("live")
        self.private_target = self.file("archive/privkey1.pem", 0o600)
        self.private_link = live / "privkey.pem"
        self.private_link.symlink_to(Path("../archive/privkey1.pem"))
        self.pipe = self.state / "private-input.fifo"
        os.mkfifo(self.pipe, 0o600)
        self.preserved = self.file("unrelated", 0o600)

        cleanup = [self.cleanup_item(self.known, "operator-state", "file"),
                   self.cleanup_item(self.pipe, "operator-state", "fifo")]
        retained = [self.retained_item(self.retained, "operator-state", "scan-retained"),
                    self.retained_item(self.credential, "transport", "protected-authority")]
        self.process = {"pid": 99999999, "start_tick": 1, "executable_device": 1,
                        "executable_inode": 1,
                        "cgroup": "/system.slice/sbxr-v4-helper.service",
                        "classification": "cleanup", "source": "dedicated-cgroup"}
        objects = [
            self.object_item("subscription-token", self.token),
            self.object_item("ownership-record", self.ownership),
            self.object_item("configuration", self.configuration),
            self.object_item("certificate-private-link", self.private_link),
            self.object_item("certificate-private-target", self.private_target),
            self.object_item("qualification-manifest", self.manifest),
            self.object_item("transport-credential", self.credential),
            self.object_item("known-secrets", self.known),
            self.object_item("private-pipe:0", self.pipe),
        ]
        self.value = {
            "schema": scanner.SCHEMA,
            "authoritative_roots": roots,
            "attempt_inventory": {"captures": capture_entries, "cleanup_paths": cleanup,
                                  "retained_paths": retained,
                                  "cleanup_processes": [self.process]},
            "units": sorted(scanner.FIXED_UNITS | {"sbxr-qualification-v3.service"}),
            "proc_root": "/proc", "protected_objects": objects,
            "preserved_objects": [self.object_item("unrelated-user-data", self.preserved)],
            "external_surface_attestation": {"complete": True, "client_cleanup_complete": True,
                                               "attested_by": "operator",
                                               "attested_at": "2026-09-11T00:00:00Z"},
        }
        self.bindings = {
            "roots": {"operator-state": os.path.realpath(self.state),
                      "operator-evidence": os.path.realpath(self.evidence),
                      "transport": os.path.realpath(self.transport)},
            "manifest": str(self.manifest), "transport_credential": str(self.credential),
            "known_secrets": str(self.known),
            "transport_unit": "sbxr-qualification-v3.service",
            "config_gid": self.gid, "root_uid": self.uid, "root_gid": self.gid,
            "subscription_token": str(self.token), "ownership_record": str(self.ownership),
            "configuration": str(self.configuration), "certificate_link": str(self.private_link),
            "certificate_archive": os.path.realpath(archive),
        }

    def directory(self, relative):
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
        return path

    def file(self, relative, mode):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((relative + " body").encode())
        path.chmod(mode)
        return path

    def capture_item(self, path, surface):
        return {"path": str(path), "root": "capture-" + surface, "surface": surface,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **scanner.metadata(path.stat())}

    def cleanup_item(self, path, root, kind):
        info = path.lstat()
        return {"path": str(path), "root": root, "kind": kind, **scanner.metadata(info)}

    def retained_item(self, path, root, classification):
        info = path.lstat()
        kind = "directory" if path.is_dir() else "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
        return {"path": str(path), "root": root, "kind": kind,
                "classification": classification, "sha256": digest,
                **scanner.metadata(info)}

    def object_item(self, role, path):
        info = path.lstat()
        if path.is_symlink():
            return {"role": role, "path": str(path), "kind": "symlink",
                    "mode": format(info.st_mode & 0o7777, "04o"), "uid": info.st_uid,
                    "gid": info.st_gid, "nlink": info.st_nlink, "sha256": None,
                    "target": os.readlink(path), "resolved_path": os.path.realpath(path)}
        kind = "fifo" if path.is_fifo() else "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
        return {"role": role, "path": str(path), "kind": kind,
                "mode": format(info.st_mode & 0o7777, "04o"), "uid": info.st_uid,
                "gid": info.st_gid, "nlink": info.st_nlink, "sha256": digest}

    def write_spec(self, value=None):
        path = self.evidence / "spec.json"
        path.write_text(json.dumps(value or self.value))
        path.chmod(0o600)
        return path

    @staticmethod
    def process_inventory(value):
        return {(item["pid"], item["start_tick"], item["executable_device"],
                 item["executable_inode"], item["cgroup"]): item["source"]
                for item in value["attempt_inventory"]["cleanup_processes"]}

    def validate(self, value=None, relevant=None, cleanup_phase=False):
        value = value or self.value
        relevant = self.process_inventory(value) if relevant is None else relevant
        with mock.patch.object(scanner, "relevant_processes", return_value=relevant):
            return scanner.validate_spec(self.write_spec(value), bindings=self.bindings,
                                         cleanup_phase=cleanup_phase)

    def check_cleanup(self, checked, relevant=None):
        with mock.patch.object(scanner, "relevant_processes",
                               return_value={} if relevant is None else relevant):
            return scanner.check_cleanup(checked)

    def test_plain_base64_and_url_encodings_are_detected_without_match_output(self):
        secret = b"opaque+/ qualification secret"
        variants = scanner.secret_variants(secret)
        encoded = [secret, base64.b64encode(secret), base64.urlsafe_b64encode(secret).rstrip(b"="),
                   urllib.parse.quote_from_bytes(secret, safe="").encode()]
        for body in encoded:
            with self.subTest(body=body[:6]), self.assertRaisesRegex(scanner.SecretFound, "protected content"):
                scanner.scan_bytes(b"prefix " + body + b" suffix", variants)

    def test_known_secret_input_requires_each_rotated_category(self):
        values = [
            {"id": "private-1", "kind": "private-key", "value": "A" * 43},
            {"id": "private-2", "kind": "private-key", "value": "B" * 43},
            {"id": "uuid-1", "kind": "client-uuid", "value": "11111111-1111-4111-8111-111111111111"},
            {"id": "uuid-2", "kind": "client-uuid", "value": "22222222-2222-4222-8222-222222222222"},
            {"id": "subscription-1", "kind": "subscription-credential", "value": "C" * 43},
            {"id": "subscription-2", "kind": "subscription-credential", "value": "D" * 43},
            {"id": "transport", "kind": "qualification-secret", "value": "qualification-only-token"},
        ]
        path = self.root / "secrets.json"
        path.write_text(json.dumps({"schema": scanner.SECRET_SCHEMA, "secrets": values}))
        variants, kinds = scanner.load_secrets(path, require_root=False)
        self.assertEqual(kinds["private-key"], 2)
        self.assertIn(b"A" * 43, variants)
        path.write_text(json.dumps({"schema": scanner.SECRET_SCHEMA, "secrets": values[:-2] + values[-1:]}))
        with self.assertRaisesRegex(scanner.CoverageError, "category coverage"):
            scanner.load_secrets(path, require_root=False)

    def test_inventory_rejects_omitted_capture_and_digest_drift(self):
        extra = self.captures["mac"].parent / "omitted.log"
        extra.write_text("safe")
        with self.assertRaisesRegex(scanner.CoverageError, "omits or invents"):
            self.validate()
        extra.unlink()
        checked = self.validate()
        self.captures["mac"].write_text("changed")
        with self.assertRaisesRegex(scanner.CoverageError, "identity mismatch|digest mismatch"):
            scanner.scan_captures(checked, ())

    def test_capture_read_rejects_replacement_between_declaration_and_open(self):
        checked = self.validate()
        path = self.captures["mac"]
        replacement = path.parent / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        original_open = scanner.os.open

        def replace_then_open(target, flags):
            if os.path.realpath(target) == os.path.realpath(path) and replacement.exists():
                os.replace(replacement, path)
            return original_open(target, flags)

        with mock.patch.object(scanner.os, "open", side_effect=replace_then_open), \
                self.assertRaisesRegex(scanner.CoverageError, "opened capture identity mismatch"):
            scanner.scan_captures(checked, ())

    def test_cleanup_root_walk_rejects_unlisted_file_and_fifo(self):
        for relative, make in (
            ("state/unlisted", lambda path: path.write_text("safe")),
            ("transport/unlisted.fifo", lambda path: os.mkfifo(path, 0o600)),
        ):
            path = self.root / relative
            make(path)
            with self.subTest(relative=relative), \
                    self.assertRaisesRegex(scanner.CoverageError, "omits root object"):
                self.validate()
            path.unlink()

    def test_process_walk_rejects_unlisted_live_helper(self):
        current = self.process_inventory(self.value)
        current[(44444, 9, 8, 7, "/system.slice/sbxr-probe-extra.service")] = "dedicated-cgroup"
        with self.assertRaisesRegex(scanner.CoverageError, "omits live qualification process"):
            self.validate(relevant=current)

    def test_process_discovery_excludes_controller_ancestry_and_finds_helper(self):
        proc = self.directory("proc")
        for pid, parent in ((50, 1), (100, 50)):
            folder = self.directory("proc/" + str(pid))
            (folder / "status").write_text(f"Name:\tcontrol\nPPid:\t{parent}\n")

        helper = self.directory("proc/200")
        (helper / "cgroup").write_text("0::/system.slice/sbxr-v4-helper.service\n")
        (helper / "stat").write_text("200 (helper) " + " ".join(["S"] + ["1"] * 18 + ["123"]))
        (helper / "cmdline").write_bytes(b"helper\0")
        (helper / "exe").symlink_to(Path("/bin/sh"))
        (helper / "cwd").symlink_to(self.root, target_is_directory=True)
        executable = (helper / "exe").stat()

        found = scanner.relevant_processes(self.bindings, proc_root=proc, current_pid=100)
        expected = (200, 123, executable.st_dev, executable.st_ino,
                    "/system.slice/sbxr-v4-helper.service")
        self.assertEqual(found, {expected: "dedicated-cgroup"})

    def test_process_argv_discovery_requires_an_exact_path_argument(self):
        authority = os.path.realpath(self.state)
        root = os.fsencode(authority)
        self.assertFalse(scanner.argument_under_root(b"echo\0prefix=" + root + b"/job\0", (authority,)))
        self.assertTrue(scanner.argument_under_root(b"helper\0" + root + b"/job\0", (authority,)))
        self.assertTrue(scanner.argument_under_root(b"helper\0--spec=" + root + b"/job\0", (authority,)))

    def test_required_units_roots_and_external_attestation_are_not_optional(self):
        for mutation, message in (
            (lambda value: value["units"].remove("sing-box.service"), "required unit"),
            (lambda value: value["authoritative_roots"].pop(), "root coverage"),
            (lambda value: value["external_surface_attestation"].update(complete=False), "attestation"),
        ):
            value = copy.deepcopy(self.value)
            mutation(value)
            with self.subTest(message=message), self.assertRaisesRegex(scanner.CoverageError, message):
                self.validate(value)

    def test_canonical_objects_include_resolved_private_key_and_every_pipe(self):
        self.assertEqual(scanner.check_protection(self.validate()), (9, 1))
        for role in ("subscription-token", "certificate-private-target", "transport-credential", "private-pipe:0"):
            value = copy.deepcopy(self.value)
            value["protected_objects"] = [item for item in value["protected_objects"] if item["role"] != role]
            with self.subTest(role=role), self.assertRaisesRegex(scanner.CoverageError, "canonical protected"):
                self.validate(value)

    def test_zero_discovered_helpers_and_private_pipes_are_valid(self):
        value = copy.deepcopy(self.value)
        value["attempt_inventory"]["cleanup_paths"] = [
            item for item in value["attempt_inventory"]["cleanup_paths"]
            if item["kind"] != "fifo"]
        value["attempt_inventory"]["cleanup_processes"] = []
        value["protected_objects"] = [
            item for item in value["protected_objects"]
            if not item["role"].startswith("private-pipe:")]
        self.pipe.unlink()
        checked = self.validate(value, relevant={})
        self.assertEqual(scanner.cleanup_inventory(checked), (1, 0))
        self.assertEqual(self.check_cleanup(checked), (1, 0))

    def test_cleanup_is_derived_from_exact_inventory(self):
        checked = self.validate()
        self.assertEqual(scanner.scan_retained_inventory(checked, ()), 1)
        with self.assertRaisesRegex(scanner.CoverageError, "path remains"):
            self.check_cleanup(checked)
        self.assertEqual(scanner.cleanup_inventory(checked), (2, 0))
        self.assertEqual(self.check_cleanup(checked), (2, 1))
        self.validate(relevant={}, cleanup_phase=True)

    def test_retained_directory_survives_child_cleanup_metadata_change(self):
        folder = self.directory("state/session")
        child = self.file("state/session/private.tmp", 0o600)
        self.value["attempt_inventory"]["cleanup_paths"].append(
            self.cleanup_item(child, "operator-state", "file"))
        self.value["attempt_inventory"]["retained_paths"].append(
            self.retained_item(folder, "operator-state", "directory"))
        checked = self.validate()
        self.assertEqual(scanner.cleanup_inventory(checked), (3, 0))
        self.assertEqual(self.check_cleanup(checked), (3, 1))
        self.validate(relevant={}, cleanup_phase=True)

    def test_nested_cleanup_directories_allow_child_link_count_changes(self):
        folder = self.directory("state/private-session")
        child = self.directory("state/private-session/child")
        leaf = self.file("state/private-session/child/private.tmp", 0o600)
        for path, kind in ((folder, "directory"), (child, "directory"), (leaf, "file")):
            self.value["attempt_inventory"]["cleanup_paths"].append(
                self.cleanup_item(path, "operator-state", kind))
        checked = self.validate()
        self.assertEqual(scanner.cleanup_inventory(checked), (5, 0))
        self.assertEqual(self.check_cleanup(checked), (5, 1))
        self.assertFalse(folder.exists())

    def test_post_cleanup_rewalk_rejects_new_object_and_process(self):
        checked = self.validate()
        scanner.cleanup_inventory(checked)
        unexpected = self.state / "late-output"
        unexpected.write_text("safe")
        with self.assertRaisesRegex(scanner.CoverageError, "omits root object"):
            self.check_cleanup(checked)
        unexpected.unlink()

        live = {(44444, 9, 8, 7, "/system.slice/sbxr-probe-late.service"):
                "dedicated-cgroup"}
        with self.assertRaisesRegex(scanner.CoverageError, "omits live qualification process"):
            self.check_cleanup(checked, relevant=live)

    def test_command_lifecycle_scans_removes_and_revalidates(self):
        path = self.write_spec()
        original_validate = scanner.validate_spec

        def validate_for_main(target, require_root=False, bindings=None, cleanup_phase=False):
            relevant = {} if cleanup_phase else self.process_inventory(self.value)
            with mock.patch.object(scanner, "relevant_processes", return_value=relevant):
                return original_validate(target, bindings=self.bindings,
                                         cleanup_phase=cleanup_phase)

        outputs = []
        categories = {"private-key": 2, "client-uuid": 2,
                      "subscription-credential": 2, "qualification-secret": 1}
        with mock.patch.object(scanner, "validate_spec", side_effect=validate_for_main), \
                mock.patch.object(scanner, "load_secrets", return_value=((), categories)), \
                mock.patch.object(scanner, "scan_processes", return_value=4), \
                mock.patch.object(scanner, "scan_units", return_value=4), \
                mock.patch.object(scanner, "relevant_processes", return_value={}):
            for arguments in (
                ["protection", "--spec", str(path)],
                ["probe-paths", "--spec", str(path)],
                ["scan", "--known-secrets", str(self.known), "--spec", str(path)],
                ["remove-inventory", "--spec", str(path)],
                ["cleanup", "--spec", str(path)],
            ):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    scanner.main(arguments)
                outputs.append(json.loads(stream.getvalue()))

        self.assertEqual(outputs[2]["retained_inventory_files"], 1)
        self.assertEqual(outputs[3]["removed_paths"], 2)
        self.assertEqual(outputs[4]["cleanup_paths_absent"], 2)
        self.assertTrue(self.retained.exists())
        self.assertTrue(self.credential.exists())

    def test_product_process_cannot_be_cleanup_or_killed(self):
        value = copy.deepcopy(self.value)
        process = value["attempt_inventory"]["cleanup_processes"][0]
        process.update(cgroup="/system.slice/sing-box.service",
                       classification="retained-product", source="protected-cgroup")
        invalid = copy.deepcopy(value)
        invalid["attempt_inventory"]["cleanup_processes"][0]["classification"] = "cleanup"
        with self.assertRaisesRegex(scanner.CoverageError, "protected service cannot be cleanup"):
            self.validate(invalid)

        checked = self.validate(value)
        with mock.patch.object(scanner.os, "kill") as kill:
            self.assertEqual(scanner.cleanup_inventory(checked), (2, 0))
        kill.assert_not_called()

    def test_cleanup_refuses_replaced_object(self):
        checked = self.validate()
        self.known.unlink()
        self.known.write_text("replacement")
        self.known.chmod(0o600)
        with self.assertRaisesRegex(scanner.CoverageError, "identity changed"):
            scanner.cleanup_inventory(checked)

    def test_private_key_and_authorization_headers_are_always_prohibited(self):
        for body in (b"-----BEGIN PRIVATE KEY-----", b"authorization: Bearer redacted",
                     b"Authorization : Basic redacted"):
            with self.assertRaises(scanner.SecretFound):
                scanner.scan_bytes(body, ())


if __name__ == "__main__":
    unittest.main()
