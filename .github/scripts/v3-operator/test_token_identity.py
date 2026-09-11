import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("08-enable-schema1-finish.sh")


class SubscriptionTokenIdentityTests(unittest.TestCase):
    def verify(self, token, authority):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription-token"
            path.write_bytes(token)
            return subprocess.run(
                [
                    "/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    'source "$1"; verify_subscription_token_identity "$2" "$3"',
                    "bash",
                    str(SCRIPT),
                    str(path),
                    authority,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_token_identity_matches_product_credential_semantics(self):
        credential = b"A" * 43
        authority = hashlib.sha256(credential).hexdigest()

        self.assertEqual(self.verify(credential + b"\n", authority).returncode, 0)

        for token in (b"B" + credential[1:] + b"\n", credential + b"\n\n"):
            with self.subTest(token=token):
                self.assertNotEqual(self.verify(token, authority).returncode, 0)


if __name__ == "__main__":
    unittest.main()
