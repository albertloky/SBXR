"""Exercise CI command ordering with inert tools; never install or download."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]


class SetupCI(unittest.TestCase):
    def run_setup(self, mode="native", machine="x86_64", failure="", system="Linux", release="24.04"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "calls.jsonl"
            stub = "#!" + sys.executable + "\n" + r'''import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps([name, *args]) + "\n")
if name == "uname":
    print(os.environ["SYSTEM"] if args == ["-s"] else os.environ["MACHINE"])
elif name == "lsb_release":
    print("Ubuntu" if args == ["-is"] else os.environ["RELEASE"])
elif name == "sudo":
    assert args[0] == "apt-get"
    if os.environ["FAILURE"] and os.environ["FAILURE"] in args:
        sys.exit(100)
'''
            for name in ("uname", "rustup", "cargo", "sudo", "lsb_release"):
                path = root / name
                path.write_text(stub)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ":/usr/bin:/bin", CALLS=str(log),
                       SYSTEM=system, MACHINE=machine, FAILURE=failure, RELEASE=release)
            result = subprocess.run(["/bin/bash", str(TOOLS / "setup-ci.sh"), mode],
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_amd64_uses_same_authenticated_sources_for_update_and_install(self):
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [call for call in calls if call[0] == "sudo"]
        options = ["-o", "Dir::Etc::sourcelist=" + str(TOOLS / "ubuntu-amd64.sources"),
                   "-o", "Dir::Etc::sourceparts=-"]
        self.assertEqual(apt, [["sudo", "apt-get", *options, "update", "--error-on=any"],
                              ["sudo", "apt-get", *options, "install", "--yes",
                               "--no-install-recommends", "musl-tools", "cmake", "make", "perl"]])
        stanzas = (TOOLS / "ubuntu-amd64.sources").read_text().strip().split("\n\n")
        actual = [dict(line.split(": ", 1) for line in stanza.splitlines()) for stanza in stanzas]
        self.assertEqual(actual, [dict(Types="deb", URIs=url, Suites=suites,
            Components="main restricted universe multiverse", Architectures="amd64",
            **{"Signed-By": "/usr/share/keyrings/ubuntu-archive-keyring.gpg"})
            for url, suites in [("https://archive.ubuntu.com/ubuntu/", "noble noble-updates noble-backports"),
                                ("https://security.ubuntu.com/ubuntu/", "noble-security")]])

    def test_arm64_keeps_runner_sources_and_requires_complete_update(self):
        result, calls = self.run_setup(machine="aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [call for call in calls if call[0] == "sudo"]
        self.assertEqual(apt[0], ["sudo", "apt-get", "update", "--error-on=any"])
        self.assertIn(["rustup", "target", "add", "--toolchain", "1.90.0", "aarch64-unknown-linux-musl"], calls)

    def test_failed_update_or_install_stops_without_retry_or_build(self):
        for failure in ("update", "install"):
            with self.subTest(failure=failure):
                result, calls = self.run_setup(failure=failure)
                self.assertEqual(result.returncode, 100)
                self.assertFalse(any(call[0] == "cargo" or call[:2] == ["rustup", "target"] for call in calls))
                self.assertEqual(len([call for call in calls if call[0] == "sudo"]),
                                 1 if failure == "update" else 2)

    def test_wrong_ubuntu_release_refuses_before_apt(self):
        result, calls = self.run_setup(release="22.04")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "sudo" for call in calls))

    def test_tools_mode_never_uses_apt(self):
        result, calls = self.run_setup(mode="tools")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("sudo", "lsb_release") for call in calls))

    def test_mac_refuses_before_provisioning(self):
        result, calls = self.run_setup(system="Darwin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [["uname", "-s"]])


if __name__ == "__main__":
    unittest.main()
