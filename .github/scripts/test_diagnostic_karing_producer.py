"""Exercise the producer envelope under a private fixture root, without SSH."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from test_v3_packaged_live_menu_disclosure import FIXTURE

HERE = Path(__file__).resolve().parent
ATTEMPT = "run-999003-attempt-1"


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


class KaringProducer(unittest.TestCase):
    def setUp(self):
        self.make = module("diagnostic-karing-producer").command
        self.now = int(time.time())
        self.args = dict(host="192.0.2.9", port=2222, identity="/private/test id",
                         known_hosts="/private/known hosts", attempt_id=ATTEMPT,
                         manifest_sha256="a"*64, request_sha256="b"*64, cutoff=self.now+1100)

    def test_direct_pinned_transport(self):
        argv, body = self.make(**self.args)
        self.assertEqual(argv[0], "/usr/bin/ssh")
        for token in ("-T", "-4", "-a", "-x", "root@192.0.2.9", "2222", 'IdentityFile="/private/test id"',
                      "ClearAllForwardings=yes", "IdentityAgent=none", "IdentitiesOnly=yes",
                      "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null",
                      'UserKnownHostsFile="/private/known hosts"'):
            self.assertIn(token, argv)
        self.assertEqual(argv[argv.index("-F")+1], "/dev/null")
        compile(body, "<producer>", "exec")
        for key, bad in (("host", "example.com"), ("port", True), ("attempt_id", "../other"),
                         ("manifest_sha256", "1"), ("known_hosts", "/foo %h"), ("identity", "relative"),
                         ("cutoff", 1.5)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.make(**dict(self.args, **{key:bad}))

    def test_missing_named_key_never_falls_back_to_personal_default_keys(self):
        argv, _ = self.make(**self.args)
        # -G prints the local parsed configuration and exits before connecting.
        result = subprocess.run([argv[0], "-G", *argv[1:]], capture_output=True, text=True, check=True)
        keys = [s for s in result.stdout.splitlines() if s.startswith("identityfile ")]
        self.assertEqual(keys, ["identityfile /private/test id"])

    def prepare(self, one_node=True, executable=FIXTURE):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.fs = Path(temp.name).resolve()
        self.machine = self.fs / "etc/machine-id"
        self.machine.parent.mkdir()
        self.machine.write_bytes(b"1234567890abcdef1234567890abcdef\n")
        transport = self.fs / "root/sbxr-qualification-v3"
        transport.mkdir(parents=True)
        self.runtime = transport / "runtime-deadline"
        self.runtime.write_text(str(self.now+2700)+"\n")
        self.runtime.chmod(0o600)
        self.exe = self.fs / "usr/local/bin/sbxr"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_text(executable)
        self.exe.chmod(0o700)
        tag, commit = "v9.9.9", "f"*40
        rid = dict(repository="albertloky/SBXR", tag=tag, commit=commit, release_index_sha256="d"*64)
        installed = self.fs / "var/lib/sbxr/installed.json"
        installed.parent.mkdir(parents=True)
        installed.write_text(json.dumps(dict(rid, sequence=99, architecture="amd64",
                                             executable_sha256=digest(self.exe.read_bytes()))))
        window = dict(mode="karing-one-node", start_unix=self.now-5,
                      test_until_unix=self.now-5+7200, finish_unix=self.now-5+10800)
        if not one_node:
            del window["mode"]
        manifest = dict(schema="sbxr-qualification-manifest-v3", mode="v3", source_state="v3-subscription-clean",
                        releases=[dict(release_identity=rid, tag=tag, commit=commit, sequence=99)],
                        v3_attempt=dict(attempt_id=ATTEMPT, diagnostic=window, vps_identity_sha256=digest(self.machine.read_bytes()),
                                        required_scenarios=["mvp-install"], scenario_limit_seconds=2700 if one_node else 1800))
        self.manifest = transport / "qualification-manifest.json"
        self.manifest.write_text(json.dumps(manifest))
        self.manifest.chmod(0o600)
        collector = module("disclosure-diagnostic")
        clock = (HERE / "mvp-observe.py").read_bytes()
        stage = dict(clock=clock, clock_sha256=digest(clock)) if one_node else {}
        directory = Path(collector.prepare(self.fs / "root", self.manifest, self.now, **stage)["directory"])
        self.request = directory / "request.json"
        self.draft = directory / "observation-draft.json"
        self.clock = directory / "mvp-observe.py" if one_node else HERE / "mvp-observe.py"
        subprocess.run([sys.executable, "-B", str(self.clock), "start", "--request", str(self.request),
                        "--draft", str(self.draft)], check=True, capture_output=True)
        self.args.update(manifest_sha256=digest(self.manifest.read_bytes()), request_sha256=digest(self.request.read_bytes()))

    def produce(self):
        _, body = self.make(**self.args)
        return subprocess.run([sys.executable, "-I", "-B", "-"], input=body, cwd=self.fs,
                              env=dict(os.environ, SBXR_MENU_FIXTURE_ROOT=str(self.fs), SBXR_MENU_FIXTURE_MODE="rust"),
                              capture_output=True, timeout=10)

    def test_simulated_driver_transcript_and_exact_menu_choice(self):
        self.prepare()
        result = self.produce()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"----- BEGIN SBXR CLIENT CONFIGURATION -----", result.stdout)
        self.assertIn(b'"credential": "test-only"', result.stdout)
        self.assertIn(b"PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED", result.stdout)
        events = [json.loads(line) for line in (self.fs / "events.jsonl").read_text().splitlines()]
        self.assertEqual([e["number"] for e in events if e["event"] == "selected"], ["3"])
        self.assertEqual([e["number"] for e in events if e["event"] == "exit"], ["0"])

    def test_disclosure_to_private_node_profile_receipt_and_scoped_discard(self):
        vectors = HERE.parents[1] / "tests/testdata/subscription_artifact"
        client = (vectors / "client-vless.json").read_text().rstrip()
        fixture = FIXTURE.replace(
            'print(json.dumps({"outbounds":[{"type":"fixture","credential":"test-only"}]}))',
            "print(" + repr(client) + ")")
        self.prepare(executable=fixture)
        self.args["host"] = json.loads(client)["outbounds"][0]["server"]
        _, program = self.make(**self.args)
        # Supply the generated program unchanged. Only the transport changes:
        # this local subprocess starts at the synthetic host filesystem root.
        launcher = ("import os,sys; os.chdir(sys.argv[1]); "
                    "os.environ.update(SBXR_MENU_FIXTURE_ROOT=sys.argv[1],SBXR_MENU_FIXTURE_MODE='rust'); "
                    "os.execv(sys.executable,[sys.executable,'-I','-B','-'])")
        command = [sys.executable, "-I", "-B", "-c", launcher, str(self.fs)]
        handoff = module("diagnostic-karing-handoff")
        mac = self.fs / "mac"
        mac.mkdir(mode=0o700)
        result = handoff.receive(mac, ATTEMPT, self.args["manifest_sha256"], self.args["request_sha256"],
                                 self.args["host"], self.args["cutoff"], command, program)
        directory = mac / ("karing-" + ATTEMPT)
        pin = result["receipt_sha256"]
        self.assertEqual(pin, digest((directory / "receipt.json").read_bytes()))
        label = "SBXR-" + self.args["request_sha256"][:16]
        expected = (vectors / "vless.txt").read_bytes().split(b"#")[0] + b"#" + label.encode() + b"\n"
        node = directory / "node.txt"
        self.assertEqual(node.read_bytes(), expected)
        self.assertEqual(node.stat().st_mode & 0o777, 0o600)
        args = SimpleNamespace(handoff_dir=directory, receipt_sha256=pin, request_sha256=self.args["request_sha256"])
        self.assertEqual(module("diagnostic-karing-profile").wire(args, ATTEMPT, label),
                         (expected, result["client_until_unix"]))
        self.assertEqual(handoff.discard(directory, pin), "removed")
        self.assertEqual(list(directory.iterdir()), [directory / "receipt.json"])

    def test_blocked_receiver_does_not_strand_remote_menu(self):
        self.prepare(executable=FIXTURE.replace('print("----- BEGIN', 'print("x"*900000)\nprint("----- BEGIN'))
        _, body = self.make(**self.args)
        env = dict(os.environ, SBXR_MENU_FIXTURE_ROOT=str(self.fs), SBXR_MENU_FIXTURE_MODE="rust")
        # Supply program from a fixture file so the test can withhold stdout
        # reads entirely. The production caller sends the same bytes over SSH.
        program = self.fs / "program.py"
        program.write_bytes(body)
        with program.open("rb") as source, subprocess.Popen(
                [sys.executable, "-I", "-B", "-"], stdin=source, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, cwd=self.fs, env=env) as child:
            try:
                self.assertNotEqual(child.wait(timeout=4), 0)
            finally:
                # Closing the receiver restores progress even on the red case.
                child.stdout.close()
                child.wait(timeout=10)

    def test_authentic_disclosure_only_scope_refuses_export(self):
        self.prepare(one_node=False)
        result = self.produce()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.fs / "events.jsonl").exists())

    def test_earlier_remote_runtime_refuses_stale_local_cutoff(self):
        self.prepare()
        self.runtime.write_text(str(self.now+2500)+"\n")
        result = self.produce()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.fs / "events.jsonl").exists())

    def test_changed_bindings_refuse_before_menu(self):
        self.prepare()
        for path, change in (
                (self.machine, lambda b:b.replace(b"1", b"2")),
                (self.exe, lambda b:b+b"\n"), (self.clock, lambda b:b+b"\n"),
                (self.manifest, lambda b:b+b" "), (self.request, lambda b:b+b" "),
                (self.draft, lambda b:b.replace(self.args["request_sha256"].encode(), b"a"*64)),
                (self.runtime, lambda _:str(self.now+1500+90).encode()+b"\n")):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(change(original))
                try:
                    result = self.produce()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertFalse((self.fs / "events.jsonl").exists())
                finally:
                    path.write_bytes(original)
        self.args["cutoff"] = self.now+90
        self.assertNotEqual(self.produce().returncode, 0)
        self.assertFalse((self.fs / "events.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
