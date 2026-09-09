import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("observations.py")
SPEC = importlib.util.spec_from_file_location("observations", MODULE_PATH)
observations = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(observations)


class ObservationsTest(unittest.TestCase):
    def test_absence_distinguishes_absent_file_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "file"
            regular.write_bytes(b"protected value")
            folder = root / "directory"
            folder.mkdir()
            link = root / "link"
            link.symlink_to(regular)
            self.assertEqual(observations.observe_path(str(root / "missing"))["state"], "absent")
            file_result = observations.observe_path(str(regular))
            self.assertEqual(file_result["kind"], "file")
            self.assertEqual(file_result["sha256"], "8499993769d9a8f4ffc49ba76285483d2f8efa34a702b62520fc8bed6b4c87a7")
            self.assertEqual(observations.observe_path(str(folder))["kind"], "directory")
            self.assertEqual(observations.observe_path(str(link))["kind"], "symlink")

    def test_absence_command_fails_closed_when_any_path_is_present(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch("builtins.print") as output:
            present = Path(directory) / "present"
            present.write_text("x")
            self.assertEqual(observations.main(["absence", str(present), str(present) + ".missing"]), 1)
            document = json.loads(output.call_args.args[0])
            self.assertFalse(document["all_absent"])
            self.assertEqual([item["state"] for item in document["observations"]], ["present", "absent"])

    def test_lock_observation_rejects_symlink_without_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("")
            link = root / "lock"
            link.symlink_to(target)
            with mock.patch.object(observations.os, "open", side_effect=AssertionError("must not open")):
                result = observations.observe_lock(str(link))
            self.assertEqual(result["lock_state"], "unsafe")

    def test_posix_lock_observation_reports_kernel_holder(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock"
            lock.write_text("")
            response = observations._FLOCK.pack(observations.fcntl.F_WRLCK, 0, 0, 0, 4321)
            with mock.patch.object(observations.fcntl, "fcntl", return_value=response):
                result = observations.observe_lock(str(lock))
            self.assertEqual(result["lock_state"], "locked")
            self.assertEqual(result["holder_pid"], 4321)

    def test_process_absence_is_explicit(self):
        with mock.patch.object(observations.Path, "read_text", side_effect=FileNotFoundError):
            self.assertEqual(observations.observe_process(999999)["observation"], "absent")

    def test_flock_observation_matches_device_and_inode_only(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock"
            lock.write_text("lock body")
            info = lock.stat()
            proc = Path(directory) / "locks"
            proc.write_text(
                f"1: POSIX ADVISORY WRITE 91 {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino} 0 EOF\n"
                f"2: FLOCK ADVISORY WRITE 92 {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino + 1} 0 EOF\n"
                f"3: FLOCK ADVISORY WRITE 93 {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino} 0 EOF\n"
            )
            result = observations.observe_flock(str(lock), str(proc))
            self.assertEqual(result["lock_state"], "locked")
            self.assertEqual(result["holders"], [{"mode": "WRITE", "pid": 93}])

    @unittest.skipUnless(sys.platform == "linux", "requires Linux procfs")
    def test_process_observation_hashes_arguments_without_retaining_them(self):
        secret = "qualification-secret-must-not-appear"
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", secret])
        try:
            result = observations.observe_process(child.pid)
            retained = json.dumps(result, sort_keys=True)
            self.assertEqual(result["observation"], "complete")
            self.assertGreaterEqual(result["argument_count"], 4)
            self.assertRegex(result["arguments_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(secret, retained)
            self.assertNotIn("arguments", result)
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
