#!/usr/bin/env python3
"""Exercise asset downloads with the real gh client and a local TCP reset."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest


SCRIPTS = Path(__file__).resolve().parent
GH = shutil.which("gh")
PAYLOAD = b"\x00verified asset\n" * 131072
SECRET = "fixture-signed-url-secret"


class AssetServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, directory, responses):
        super().__init__(("127.0.0.1", 0), AssetHandler)
        self.server_port = self.server_address[1]
        self.directory = directory
        self.responses = list(responses)
        self.requests = []
        self.partial_observed = False
        self.metadata = None


class AssetHandler(socketserver.BaseRequestHandler):
    def respond(self, status, data=b"", *, content_type="application/octet-stream", location=None, size=None):
        headers = [f"HTTP/1.1 {status} Fixture", "Connection: close",
                   f"Content-Type: {content_type}", f"Content-Length: {len(data) if size is None else size}"]
        if location:
            headers.append(f"Location: {location}")
        self.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + data)

    def handle(self):
        self.request.settimeout(10)
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            request += chunk
        lines = request.decode().split("\r\n")
        method, path, _ = lines[0].split()
        if method != "GET":
            self.respond(405)
            return
        headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
        if headers.get("Authorization") != "token fixture-only-token":
            self.respond(401)
            return
        server = self.server
        server.requests.append((path, headers.get("Accept")))
        if path in ("/repos/fixture/repo/releases/7", "/repos/fixture/repo/releases?per_page=100"):
            self.respond(200, json.dumps(server.metadata).encode(), content_type="application/json")
            return
        if path == "/repos/fixture/repo/releases/assets/42":
            self.respond(302, location=f"http://127.0.0.1:{server.server_port}/asset?sig={SECRET}&request={len(server.requests)}")
            return
        response = server.responses.pop(0) if server.responses else "unexpected-request"
        if isinstance(response, int):
            # An HTTP error containing the transport words must not be retried.
            self.respond(response, b'{"message":"read tcp fixture: read: connection reset by peer"}',
                         content_type="application/json")
            return
        if response in ("reset", "partial-reset"):
            if response == "partial-reset":
                self.respond(200, PAYLOAD[:len(PAYLOAD) // 2], size=len(PAYLOAD))
                # Wait for evidence of streaming, not an arbitrary delay before RST.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if any(p.stat().st_size == len(PAYLOAD) // 2 for p in server.directory.glob(".asset-download-*/body")):
                        server.partial_observed = True
                        break
                    time.sleep(0.005)
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.request.close()
            return
        self.respond(200, response if isinstance(response, bytes) else PAYLOAD if response == "success" else b"corrupt")


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(GH, "gh is required: these are real HTTP/subprocess tests")
        self.directory = tempfile.TemporaryDirectory(prefix="asset-download-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # This shim only redirects the real gh process to the local fixture. It
        # does not implement HTTP, inject exit codes, or simulate downloaded bytes.
        shim = self.bin / "gh"
        shim.write_text("#!/usr/bin/env python3\nimport os, sys\n"
                        "args = sys.argv[1:]\n"
                        "assert args[0] == 'api' and args[1].startswith('repos/fixture/repo/')\n"
                        "args[1] = os.environ['FIXTURE_URL'] + '/' + args[1]\n"
                        "os.execv(os.environ['FIXTURE_GH'], ['gh'] + args)\n")
        shim.chmod(0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not (k.upper().endswith("_PROXY") or k.startswith(("GH_", "GITHUB_")))}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        GH_TOKEN="fixture-only-token", GH_ENTERPRISE_TOKEN="fixture-only-token",
                        GH_CONFIG_DIR=str(self.root / "gh-config"),
                        GH_PROMPT_DISABLED="1", FIXTURE_GH=GH,
                        GITHUB_REPOSITORY="fixture/repo")

    def serve(self, responses):
        server = AssetServer(self.root, responses)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(close)
        self.env["FIXTURE_URL"] = f"http://127.0.0.1:{server.server_port}"
        return server

    def run_download(self):
        result = subprocess.run(["python3", str(SCRIPTS / "download-release-asset.py"),
                                 "fixture/repo", "42", str(self.root / "asset")],
                                env=self.env, capture_output=True, timeout=15)
        self.assertNotIn(SECRET.encode(), result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(self.root.glob(".asset-download-*")), [])
        return result

    def assert_requests(self, server, count):
        api = [p for p, _ in server.requests if p.startswith("/repos/fixture/repo/releases/assets/")]
        redirects = [p for p, _ in server.requests if p.startswith("/asset?")]
        self.assertEqual(len(api), count, server.requests)
        self.assertEqual(len(set(redirects)), count, "every attempt must request a fresh redirect")
        self.assertTrue(all(accept == "application/octet-stream" for _, accept in server.requests))

    def test_success_is_one_request(self):
        server = self.serve(["success"])
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "asset").read_bytes(), PAYLOAD)
        self.assert_requests(server, 1)

    def test_reset_before_headers_recovers_and_redacts_signed_url(self):
        server = self.serve(["reset", "success"])
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"connection reset by peer", result.stderr)
        self.assertIn(b"[redacted-url]", result.stderr)
        self.assertEqual((self.root / "asset").read_bytes(), PAYLOAD)
        self.assert_requests(server, 2)

    def test_partial_reset_starts_from_empty_file(self):
        server = self.serve(["partial-reset", "success"])
        result = self.run_download()
        self.assertTrue(server.partial_observed, "fixture did not reach streaming boundary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "asset").read_bytes(), PAYLOAD)
        self.assert_requests(server, 2)

    def test_two_resets_fail_and_preserve_existing_destination(self):
        for failure in ("reset", "partial-reset"):
            with self.subTest(failure=failure):
                server = self.serve([failure, failure, "success"])
                (self.root / "asset").write_bytes(b"previous complete file")
                result = self.run_download()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.count(b"connection reset by peer"), 2)
                self.assertEqual((self.root / "asset").read_bytes(), b"previous complete file")
                self.assert_requests(server, 2)

    def test_http_refusals_are_not_retried(self):
        for status in (401, 403, 404, 429, 500, 502):
            with self.subTest(status=status):
                server = self.serve([status, "success"])
                result = self.run_download()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"HTTP {status}".encode(), result.stderr)
                self.assertFalse((self.root / "asset").exists())
                self.assert_requests(server, 1)

    def test_recheck_preserves_hash_and_identity_validation(self):
        for response, valid_identity, valid_size, ok, count in (
                ("success", True, True, True, 2),
                ("corrupt", True, True, False, 1),
                ("success", False, True, False, 0),
                ("success", True, False, False, 0)):
            with self.subTest(response=response, identity=valid_identity, size=valid_size):
                server = self.serve(["reset", response] if ok else [response])
                digest = hashlib.sha256(PAYLOAD).hexdigest()
                commit = "1" * 40
                expected = {"tag": "v1.2.3", "commit": commit, "release_id": 7,
                            "release_identity": {"repository": "fixture/repo", "tag": "v1.2.3",
                                                 "commit": commit, "release_index_sha256": "2" * 64},
                            "assets": [{"name": "sbxr-linux-amd64.tar.gz", "size": len(PAYLOAD), "sha256": digest}]}
                server.metadata = {"id": 7, "tag_name": "v1.2.3" if valid_identity else "v9.9.9",
                                   "target_commitish": commit,
                                   "assets": [{"id": 42, "name": "sbxr-linux-amd64.tar.gz",
                                               "size": len(PAYLOAD) if valid_size else 1}]}
                (self.root / "expected.json").write_text(json.dumps(expected))
                result = subprocess.run(["bash", str(SCRIPTS / "recheck-qualified-release.sh"),
                                         str(self.root / "expected.json"), str(self.root / "checked"),
                                         str(self.root / "metadata.json"), "partial"],
                                        env=self.env, capture_output=True, timeout=15)
                self.assertEqual(result.returncode == 0, ok, result.stderr)
                self.assertNotIn(SECRET.encode(), result.stderr)
                self.assertEqual(sum(p.startswith("/asset?") for p, _ in server.requests), count)

    def test_release_history_downloads_from_its_temporary_directory(self):
        index = {"schema": 1, "repository": "fixture/repo", "tag": "v1.2.3",
                 "commit": "1" * 40, "sequence": 17}
        data = json.dumps(index).encode()
        digest = hashlib.sha256(data).hexdigest()
        server = self.serve(["reset", data])
        server.metadata = [{"id": 7, "tag_name": index["tag"], "target_commitish": index["commit"],
                            "draft": False, "prerelease": False, "immutable": True,
                            "assets": [{"id": 42, "name": "release-index.json", "size": len(data),
                                        "digest": "sha256:" + digest}]}]
        result = subprocess.run(["bash", ".github/scripts/release-history.sh", str(self.root / "history.json")],
                                cwd=SCRIPTS.parents[1], env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads((self.root / "history.json").read_bytes())
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["sequence"], 17)
        self.assertEqual(facts[0]["index"]["sha256"], digest)
        self.assertNotIn(SECRET.encode(), result.stderr)
        self.assertEqual(sum(p.startswith("/asset?") for p, _ in server.requests), 2)


if __name__ == "__main__":
    unittest.main()
