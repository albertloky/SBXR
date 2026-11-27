from contextlib import contextmanager
import ctypes
import errno
import hashlib
import os
import shutil
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


class OutsideCustody(unittest.TestCase):
    def test_incomplete_signature_display_cannot_exclude_a_running_process(self):
        hashes=runpy.run_path(str(HERE/'outside-run.py'))['image_cdhashes']
        digest=b'01'*20
        display=b'CandidateCDHash sha256='+digest+b'\nHash choices=sha256\n'
        with patch.object(subprocess,'check_output',return_value=b'arm64\n'):
            for info in (display+b'Total signatures=2\nChosen signature=1\n',
                         display.replace(b'choices=sha256',b'choices=sha1,sha256')):
                result=subprocess.CompletedProcess([],0,stderr=info)
                with self.subTest(info=info), patch.object(subprocess,'run',return_value=result):
                    with self.assertRaisesRegex(ValueError,'identity incomplete'):
                        hashes(Path('/fixture/sing-box'))

    @unittest.skipUnless(sys.platform=='darwin', 'requires Darwin process and code-signing metadata')
    def test_unlinked_process_does_not_hide_the_pinned_executable(self):
        inspect=runpy.run_path(str(HERE/'outside-run.py'))['program_pids']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            program=root/'sing-box'
            shutil.copy('/bin/cat',program)
            record={'source_file':str(program),'size':program.stat().st_size,
                    'sha256':hashlib.sha256(program.read_bytes()).hexdigest()}

            # Keep each disposable executable blocked on its own empty stdin.
            # Its kernel text identity survives unlinking the executable.
            @contextmanager
            def launch(path):
                with subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, start_new_session=True) as child:
                    try:
                        yield child
                    finally:
                        child.communicate(timeout=3)

            def unlink_running(path, process):
                path.unlink()
                buf=ctypes.create_string_buffer(4096)
                lookup=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True).proc_pidpath
                self.assertLessEqual(lookup(process.pid,buf,len(buf)),0)
                self.assertEqual(ctypes.get_errno(),errno.ENOENT)
                self.assertIsNone(process.poll())

            other=root/'other'
            shutil.copy('/usr/bin/wc',other)
            with launch(other) as unrelated:
                unlink_running(other,unrelated)
                self.assertEqual(inspect(record),set())
                with launch(program) as intended:
                    self.assertEqual(inspect(record),{intended.pid})
                self.assertEqual(inspect(record),set())

                duplicate=root/'other-copy'
                shutil.copy(program,duplicate)
                with launch(duplicate) as ambiguous:
                    unlink_running(duplicate,ambiguous)
                    with self.assertRaisesRegex(ValueError,'identity unresolved'):
                        inspect(record)

                shutil.copy(program,duplicate)
                with launch(program) as intended:
                    unlink_running(program,intended)
                    duplicate.rename(program)  # Same pinned bytes, different inode.
                    # Darwin may report the restored pathname or ENOENT.
                    # Both outcomes must block admission while the child runs.
                    try:
                        self.assertEqual(inspect(record),{intended.pid})
                    except ValueError as error:
                        self.assertEqual(str(error),'outside process identity unresolved')

    def test_parent_reaps_only_its_registered_client_and_rejects_untracked_or_foreign_rows(self):
        api=runpy.run_path(str(HERE/'outside-run.py'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            binding={'run_id':88,'manifest_sha256':'a'*64,'host':'192.0.2.10','window_sha256':'b'*64}
            api['initialize'](root,binding)
            with self.assertRaises(ValueError):
                api['stop_clients'](root,binding,['foreign'],time.time()+3)
            with self.assertRaises(ValueError):
                api['stop_clients'](root,{**binding,'run_id':89},[],time.time()+3)
            proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(6)'],start_new_session=True)
            try:
                def stop_order(label,row):
                    api['write'](root/('stop-'+label+'.json'),row)
                api['supervise'](root,binding,'initial',lambda:proc,time.time()+4,on_registered=stop_order)
                self.assertIsNotNone(proc.returncode)
                self.assertTrue(api['stop_clients'](root,binding,['initial'],time.time()+3)['all_owned_children_reaped'])
                self.assertFalse(api['visible_group'](proc.pid))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__=='__main__':
    unittest.main()
