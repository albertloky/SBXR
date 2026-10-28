"""Offline tooling tests: temporary Git objects and injected command runners."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("rust_" + name, TOOLS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder, snapshot = load("build_native"), load("source_snapshot")


class ReleaseTools(unittest.TestCase):
    def test_bootstrap_template_exactly_preserves_the_original_contract(self):
        original = (ROOT / "cmd/sbxr-release/bootstrap.go").read_text()
        recovery = (ROOT / "cmd/sbxr-release/bootstrap_recovery.go").read_text()
        constants = dict(re.findall(r"const (bootstrapRecovery\w+) = `([^`]*)`", recovery, re.S))
        parts = re.split(r"` \+ (bootstrapRecovery\w+) \+ `", original.split("const bootstrapBody = ", 1)[1].strip())
        self.assertEqual(len(parts), 7)
        parts[0], parts[-1] = parts[0][1:], parts[-1][:-1]
        expected = "#!/usr/bin/env bash\n" + "".join(constants[p] if i % 2 else p for i, p in enumerate(parts))
        self.assertEqual((TOOLS / "templates/install.sh.tmpl").read_text(), expected)

    def test_native_builder_refuses_the_mac_before_any_command(self):
        with patch.object(builder.platform, "system", return_value="Darwin"), patch.object(builder, "run") as run:
            with self.assertRaisesRegex(ValueError, "native Linux"):
                builder.build(argparse.Namespace(architecture="amd64"))
            run.assert_not_called()

    def test_native_plan_keeps_metadata_off_the_repository_tool_and_requires_clean_source(self):
        for architecture in ["amd64", "arm64"]:
            self.native_plan(architecture)

    def native_plan(self, architecture):
        machine, target = builder.TARGETS[architecture]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lib = root / "lib"
            lib.mkdir()
            (lib / "libstd-fixture.rlib").touch()
            args = argparse.Namespace(architecture=architecture, tag="v3.2.1", commit="a" * 40, sequence=200,
                                      output=str(root / f"sbxr-linux-{architecture}.tar.gz"))
            for fault in [None, "head", "dirty", "compiler"]:
                calls = []

                def command(argv, *, capture=False, env=None):
                    calls.append((argv, env))
                    if argv[:2] == ["git", "rev-parse"]:
                        return ("b" if fault == "head" else "a") * 40 + "\n"
                    if argv[:2] == ["git", "status"]:
                        return "?? unreviewed.rs\n" if fault == "dirty" else ""
                    if argv == ["rustc", "--version"]:
                        return "rustc 1.91.0" if fault == "compiler" else "rustc 1.90.0 (1159e78c4 2025-09-14)"
                    if argv[:3] == ["rustc", "--print", "target-libdir"]:
                        return str(lib)
                    if argv == ["rustc", "-vV"]:
                        return "host: " + ("x86_64" if architecture == "amd64" else "aarch64") + "-unknown-linux-gnu\n"
                    if argv[0] == "cargo":
                        return None
                    return json.dumps({"outcome": "packaged-local", "architecture": architecture})

                with patch.object(builder.platform, "system", return_value="Linux"), patch.object(builder.platform, "machine", return_value=machine), patch.object(builder.shutil, "which", return_value="fixture-tool"), patch.object(builder, "run", side_effect=command), patch("builtins.print"):
                    if fault:
                        with self.assertRaises(ValueError):
                            builder.build(args)
                        self.assertFalse(any(argv[0] == "cargo" for argv, _ in calls))
                    else:
                        builder.build(args)
                        cargo = [(argv, env) for argv, env in calls if argv[0] == "cargo"]
                        self.assertEqual(len(cargo), 2)
                        self.assertNotIn("SBXR_BUILD_COMMIT", cargo[0][1])
                        self.assertEqual(cargo[1][1].get("SBXR_BUILD_COMMIT"), "a" * 40)
                        for argv, env in cargo:
                            self.assertIn("--locked", argv)
                            self.assertIn("--offline", argv)
                            self.assertEqual(env["CC_" + target.replace("-", "_")], "musl-gcc")
                        self.assertEqual(cargo[1][0][-1], target)

    def test_source_verification_requires_declared_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "script.sh"
            source.write_bytes(b"inert source")
            commit = "a" * 40
            manifest = dict(schema="sbxr-rust-source-v1", commit=commit, provenance={}, exclusions=[], fixtures=[],
                            files=[dict(path="script.sh", mode="0755", size=len(source.read_bytes()), sha256=hashlib.sha256(source.read_bytes()).hexdigest())])
            raw = json.dumps(manifest).encode()
            (root / "SOURCE-MANIFEST.json").write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            source.chmod(0o755)
            self.assertEqual(snapshot.verify(root, commit, digest)["outcome"], "verified-source-local")
            for mode in (0o644, 0o777, 0o4755):
                source.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    snapshot.verify(root, commit, digest)

    def test_source_snapshot_is_exact_deterministic_secret_excluding_and_not_uploaded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args], stderr=subprocess.DEVNULL)

            git("init")
            (root / ".gitignore").write_text(".scratch/\n/target/\n")
            (root / "Cargo.toml").write_text("source fixture\n")
            (root / ".env").write_text("synthetic-secret-that-must-not-be-packaged")
            (root / "public-proof.bundle").write_text("inert public proof fixture")
            (root / "tests/testdata/target").mkdir(parents=True)
            (root / "tests/testdata/target/fixture.json").write_text("fixture source, not a build directory")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
            commit = git("rev-parse", "HEAD").decode().strip()
            (root / ".scratch").mkdir()
            (root / ".scratch/ignored-private").write_text("private scratch marker")
            identities = []
            for name in ["one", "two"]:
                out = root / ".scratch" / name
                result = snapshot.snapshot(root, commit, out)
                identities.append(result)
                self.assertFalse(result["uploaded"])
                raw = (out / result["archive"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), result["sha256"])
                with tarfile.open(out / result["archive"], "r:gz") as archive:
                    files = {m.name.split("/", 1)[1]: archive.extractfile(m).read() for m in archive.getmembers()}
                self.assertNotIn(".env", files)
                self.assertIn("public-proof.bundle", files)
                self.assertIn("tests/testdata/target/fixture.json", files)
                self.assertFalse(any(".scratch" in p for p in files))
                self.assertFalse(any(".git/" in p for p in files))
                extracted=root/".scratch"/("extracted-"+name)
                extracted.mkdir()
                for path,body in files.items():
                    target=extracted/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
                for entry in json.loads(files["SOURCE-MANIFEST.json"])["files"]:
                    (extracted/entry["path"]).chmod(int(entry["mode"], 8))
                self.assertEqual(snapshot.verify(extracted,commit,result["manifest_sha256"])["commit"],commit)
                (extracted/"extra.rs").write_text("unreviewed")
                with self.assertRaises(ValueError):snapshot.verify(extracted,commit,result["manifest_sha256"])
                (extracted/"extra.rs").unlink()
                (extracted/"foreign-dir").symlink_to(root/".scratch",target_is_directory=True)
                with self.assertRaises(ValueError):snapshot.verify(extracted,commit,result["manifest_sha256"])
                (extracted/"foreign-dir").unlink()
                self.assertTrue((root/".scratch/ignored-private").exists())
                with self.assertRaises(ValueError):snapshot.verify(extracted,commit,"0"*64)
                (extracted/"Cargo.toml").write_text("tampered source")
                with self.assertRaises(ValueError):snapshot.verify(extracted,commit,result["manifest_sha256"])
                manifest = json.loads(files["SOURCE-MANIFEST.json"])
                for file in manifest["files"]:
                    self.assertEqual(hashlib.sha256(files[file["path"]]).hexdigest(), file["sha256"])
                    self.assertEqual(len(files[file["path"]]), file["size"])
                self.assertFalse(any(b"secret-that-must" in body for body in files.values()))
                with self.assertRaises(FileExistsError):
                    snapshot.snapshot(root, commit, out)
                self.assertEqual((out / result["archive"]).read_bytes(), raw)
            self.assertEqual(identities[0]["sha256"], identities[1]["sha256"])
            (root / "Cargo.toml").write_text("dirty source")
            with self.assertRaisesRegex(ValueError, "clean"):
                snapshot.snapshot(root, commit, root / ".scratch/dirty")
            self.assertFalse((root / ".scratch/dirty").exists())


if __name__ == "__main__":
    unittest.main()
