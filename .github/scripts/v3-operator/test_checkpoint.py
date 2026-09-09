import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('syscall_gate',Path(__file__).with_name('syscall-gate.py'))
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

@unittest.skipUnless(os.geteuid() == 0, 'protected Linux checkpoint is root-owned')
class Checkpoint(unittest.TestCase):
    def test_private_unique_regular_record_only(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root,'record')
            path.write_text('{"phase":"ready"}')
            path.chmod(0o600)
            self.assertEqual(g.checkpoint(path)[1], {'phase':'ready'})
            for body in ['{"phase":"ready","phase":"ready"}', '', 'x' * 1048577]:
                path.write_text(body)
                with self.assertRaises((ValueError, OSError)): g.checkpoint(path)
            path.write_text('{}'); path.chmod(0o644)
            with self.assertRaises(ValueError): g.checkpoint(path)
            link=Path(root,'link'); link.symlink_to(path)
            with self.assertRaises(OSError): g.checkpoint(link)
            path.chmod(0o600); os.link(path,Path(root,'hardlink'))
            with self.assertRaises(ValueError): g.checkpoint(path)
            with self.assertRaises(ValueError): g.checkpoint(Path(root))

if __name__ == '__main__': unittest.main()
