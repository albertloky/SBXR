"""Archive-data-only inspection; requires dissect.squashfs and backports.zstd."""
import hashlib
import struct
import sys
from pathlib import Path
from dissect.squashfs import SquashFS
from dissect.util.stream import RangeStream
p=Path(sys.argv[1]);output=Path(sys.argv[2]);output.mkdir(exist_ok=True)
with p.open('rb') as f:
    data=f.read(192000000)
    if len(data)!=191439568 or hashlib.sha256(data).hexdigest()!='3eefba1c9338a8f981af349b4904e03a82adb257c5eb8dd5fd484675333b1f1a':
        raise ValueError('official asset bytes differ from reviewed digest')
    offsets=[];pos=0
    while True:
        pos=data.find(b'hsqs',pos)
        if pos<0:break
        if len(data)>pos+96 and struct.unpack_from('<HH',data,pos+28)==(4,0):offsets.append(pos)
        pos+=4
    if offsets!=[824016]:raise ValueError('unexpected SquashFS layout')
    fs=SquashFS(RangeStream(f,offsets[0],len(data)-offsets[0]))
    stack=[('',fs.root)];paths=[];count=0
    while stack:
        parent,node=stack.pop();count+=1
        if count>10000:raise ValueError('archive directory bound')
        for n in node.iterdir():
            if n.name in ('.','..'):continue
            path=parent+'/'+n.name
            if n.is_dir():stack.append((path,n));continue
            if path != '/AppRun' and not path.endswith('/bin/bpftrace'):continue
            if n.is_symlink():raise ValueError('selected entry is symlink')
            blob=n.open().read(300000001)
            if len(blob)>300000000:raise ValueError('entry size bound')
            name='inner-bpftrace.elf' if n.name=='bpftrace' else 'AppRun.data'
            with (output/name).open('wb') as out:out.write(blob)
            paths.append(f'{path} -> {name} {len(blob)} {hashlib.sha256(blob).hexdigest()}')
    (output/'archive-paths.txt').write_text('squashfs offset 824016\n'+'\n'.join(paths)+'\n')
    print('\n'.join(paths))
