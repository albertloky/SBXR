"""Pure inventory parser/decision tests; never call the BPF syscall."""
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('inventory',Path(__file__).with_name('dns-child-resource-inventory.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class InventoryTests(unittest.TestCase):
    def test_ids_stop_at_enoent(self):
        self.assertEqual(m.ids(11,lambda c,p:{0:3,3:7,7:None}[p],5,lambda:0),[3,7])
    def test_id_reuse_or_order_refused(self):
        with self.assertRaises(ValueError):m.ids(11,lambda c,p:3,5,lambda:0)
    def test_deadline(self):
        with self.assertRaises(ValueError):m.ids(11,lambda c,p:None,5,lambda:5)
    def test_denial_not_empty_snapshot(self):
        def denied(c,p):raise PermissionError()
        with self.assertRaises(PermissionError):m.ids(11,denied,5,lambda:0)
    def test_comparison_never_claims_perf_coverage(self):
        b={'schema':1,'boot_id':'00000000-0000-0000-0000-000000000001','bpf_ids':{'programs':[],'maps':[],'links':[]},'uprobe_events':[],'perf_fd_coverage':'not established by this inventory'}
        self.assertIn('still requires',m.compare(b,b))
        with self.assertRaises(ValueError):m.compare(b,dict(b,boot_id='b'))
        with self.assertRaises(ValueError):m.compare(dict(b,bpf_ids={}),dict(b,bpf_ids={}))


if __name__=='__main__':unittest.main()
