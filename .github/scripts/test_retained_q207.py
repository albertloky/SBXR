import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('inventory', HERE / 'inspect-retained-q207.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Inventory(unittest.TestCase):
    def exercise(self, failure=None):
        expected = copy.deepcopy(m.EXPECTED)
        blobs = {a['name']: b'inert fixture' for a in expected['assets']}
        blobs['release-index.json'] = json.dumps(dict(repository=m.REPOSITORY, tag=expected['tag'], sequence=expected['sequence'], commit=expected['source'])).encode()
        for a in expected['assets']:
            a['size'] = len(blobs[a['name']])
            a['digest'] = 'sha256:' + hashlib.sha256(blobs[a['name']]).hexdigest()
        value = dict(id=expected['release_id'], tag_name=expected['tag'], target_commitish=expected['source'], draft=True, prerelease=False, body='Qualification pending.', assets=expected['assets'])
        if failure == 'identity': value['draft'] = False
        if failure == 'assets': value['assets'] = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = dict(value=value, blobs={str(a['id']): blobs[a['name']].hex() for a in expected['assets']}, failure=failure)
            (root / 'fixture.json').write_text(json.dumps(fixture))
            fake = root / 'gh'
            fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['FIXTURE'])
f=json.loads(p.read_text()); args=sys.argv[1:]
with p.with_suffix('.calls').open('a') as out: out.write(json.dumps(args)+'\\n')
assert args[0]=='api'
if args[1]=='--include':
    assert len(args)==3
    endpoint=args[2]
    assert endpoint.startswith('repos/albertloky/SBXR/')
    if '/releases/' in endpoint:
        if f['failure']=='denial': print('HTTP/2 403 Forbidden\\n\\n{}'); sys.exit(1)
        print('HTTP/2 200 OK\\n\\n'+json.dumps(f['value']))
    else:
        assert '/git/ref/tags/' in endpoint
        if f['failure']=='ref': print('HTTP/2 200 OK\\n\\n{"object":{}}'); sys.exit(0)
        print('HTTP/2 404 Not Found\\n\\n{}'); sys.exit(1)
else:
    assert args[2:]==['--method','GET','-H','Accept: application/octet-stream']
    assert args[1].startswith('repos/albertloky/SBXR/releases/assets/')
    if f['failure']=='asset-denial': sys.exit(1)
    data=bytes.fromhex(f['blobs'][args[1].split('/')[-1]])
    if f['failure']=='bytes': data+=b'x'
    sys.stdout.buffer.write(data)
''')
            fake.chmod(0o700)
            with patch.object(m, 'EXPECTED', expected), patch.dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'], FIXTURE=str(root/'fixture.json')):
                if failure:
                    with self.assertRaises(ValueError): m.inspect(root/'out')
                else: self.assertEqual(m.inspect(root/'out')['status'], 'verified')
            calls = [json.loads(x) for x in (root/'fixture.calls').read_text().splitlines()]
            self.assertEqual(len(calls), len({json.dumps(x) for x in calls}), 'no retries')
            self.assertEqual(json.loads((root/'out/result.json').read_text())['status'], 'failed' if failure else 'verified')
            if failure=='denial': self.assertEqual(len(calls),1)
            if failure=='asset-denial': self.assertEqual(len(calls),4)
            if not failure: self.assertEqual(len(calls),7)

    def test_success(self): self.exercise()
    def test_refusals(self):
        for failure in ('identity','assets','denial','ref','asset-denial','bytes'):
            with self.subTest(failure=failure): self.exercise(failure)

    def test_workflow_graph(self):
        text=(HERE.parent/'workflows/candidate.yml').read_text()
        blocks=dict(re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)',text.split('\njobs:\n')[1],re.M|re.S))
        self.assertEqual(set(blocks),{'preflight','rust-native','build','drafts','sign','acceptance-vps','owner-exception','live89-correction','cleanup-unqualified'})
        for name, block in blocks.items():
            if name!='cleanup-unqualified': self.assertIn('!inputs.inventory_only',block.splitlines()[0])
        block=blocks['cleanup-unqualified']
        self.assertIn("always() && github.ref == 'refs/heads/main' && (inputs.inventory_only ||",block.splitlines()[0])
        self.assertIn('timeout-minutes: ${{ inputs.inventory_only && 10 || 360 }}',block)
        steps=re.split(r'^      - ',block.split('    steps:\n')[1],flags=re.M)[1:]
        self.assertEqual(len(steps),9)
        self.assertTrue(steps[0].startswith('uses: actions/checkout@'))
        self.assertIn('if: inputs.inventory_only',steps[1])
        self.assertIn('run: python3 .github/scripts/inspect-retained-q207.py',steps[1])
        self.assertIn('if: always() && inputs.inventory_only',steps[2])
        for step in steps[3:]: self.assertIn('if: ${{ !inputs.inventory_only',step)
        self.assertIn('      inventory_only:\n        description:',text)
        self.assertIn('        type: boolean\n        required: false\n        default: false',text)
        self.assertNotIn('id-token:',block)

if __name__=='__main__': unittest.main()
