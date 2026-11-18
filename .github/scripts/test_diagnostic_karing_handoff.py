"""Mac handoff with synthetic producers, real pipes and private fixture files."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("handoff", HERE / "diagnostic-karing-handoff.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
VECTORS = HERE.parents[1] / "tests/testdata/subscription_artifact"
CLIENT = (VECTORS / "client-vless.json").read_bytes()
WIRE = (VECTORS / "vless.txt").read_bytes()
IP = "198.51.100.42"
REQUEST = "2" * 64
LABEL = "SBXR-" + REQUEST[:16]
RUN = "run-24-attempt-1"
EXPECTED = WIRE.split(b"#")[0] + b"#" + LABEL.encode() + b"\n"
FRAME = b"menu\n----- BEGIN SBXR CLIENT CONFIGURATION -----\n" + CLIENT + b"----- END SBXR CLIENT CONFIGURATION -----\nCode: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED\n"


class Handoff(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.directory = self.root / ("karing-" + RUN)
        self.pins = ("1"*64, REQUEST)

    def run_fixture(self, frame=FRAME, status=0):
        command = [sys.executable, "-I", "-B", "-c",
                   "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.exit(" + str(status) + ")"]
        return h.receive(self.root, RUN, *self.pins, IP, int(time.time())+600, command, frame)

    def test_single_private_file_receipt_and_scoped_discard(self):
        result = self.run_fixture()
        self.assertLessEqual(result["client_until_unix"], int(time.time())+300)
        pin = result["receipt_sha256"]
        self.assertEqual((self.directory/"node.txt").read_bytes(), EXPECTED)
        self.assertEqual((self.directory/"node.txt").stat().st_mode & 0o777, 0o600)
        self.assertEqual(h.discard(self.directory, pin), "removed")
        self.assertEqual(h.discard(self.directory, pin), "absent")
        self.assertEqual([p.name for p in self.directory.iterdir()], ["receipt.json"])
        with self.assertRaises(FileExistsError):
            self.run_fixture()

    def test_failure_after_frame_keeps_no_credential(self):
        with self.assertRaises(ValueError):
            self.run_fixture(status=1)
        self.assertEqual(list(self.directory.iterdir()), [])
        with self.assertRaises(FileExistsError):
            self.run_fixture()

    def test_refuses_invalid_frames_without_publication(self):
        for data in (FRAME+FRAME, FRAME.replace(b"----- END", b"----- OTHER"),
                     FRAME.replace(IP.encode(), b"192.0.2.77"), FRAME.replace(b'"tls":', b'"tls":{},"tls":'),
                     FRAME.replace(b'"enabled":true',b'"enabled":1'), FRAME.replace(b'"chrome"',b'"other"'),
                     FRAME.replace(b'"outbounds":[', b'"route":{},"outbounds":['),
                     FRAME.replace(CLIENT,(VECTORS/"client-vless-vmess.json").read_bytes())):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                h.wire(data, IP, LABEL)

    def test_replaced_and_linked_files_refuse_removal(self):
        result = self.run_fixture()
        self.assertLessEqual(result["client_until_unix"], int(time.time())+300)
        pin = result["receipt_sha256"]
        node = self.directory/"node.txt"
        original = self.directory/"extra"
        os.link(node, original)
        with self.assertRaises((ValueError,OSError)):
            h.discard(self.directory, pin)
        original.unlink()
        node.rename(original)
        node.write_bytes(EXPECTED)
        node.chmod(0o600)
        with self.assertRaises((ValueError,OSError)):
            h.discard(self.directory, pin)
        self.assertTrue(node.exists())

    def test_interrupted_publication_and_wrong_receipt_preserve_other_files(self):
        sentinel = self.root / "original.txt"
        sentinel.write_bytes(b"unchanged")
        with patch.object(h.os, "fsync", side_effect=[None, InterruptedError("fixture")]):
            with self.assertRaises(InterruptedError):
                self.run_fixture()
        self.assertFalse((self.directory / "node.txt").exists())
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        with self.assertRaises(ValueError):
            h.discard(self.directory, "f"*64)

    def test_no_start_without_margin_and_pipe_overrun_stops_writer(self):
        with self.assertRaises(ValueError):
            h.receive(self.root, RUN, *self.pins, IP, int(time.time())+60, ["not-a-program"], b"")
        self.assertFalse(self.directory.exists())
        cmd = [sys.executable, "-I", "-c", "import os,time; os.write(1,b'x'*70000); time.sleep(30)"]
        start = time.monotonic()
        with self.assertRaises(ValueError):
            h.receive(self.root, RUN, *self.pins, IP, int(time.time())+600, cmd, b"")
        self.assertLess(time.monotonic()-start, 5)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
