"""Read-only x86-64 BPF ID/uprobe inventory. No attach, load, pin, or delete.

This does not enumerate every perf-event FD or certify kernel cleanup by itself.
It is independent corroborating evidence alongside complete owned-process reaping.
"""
import argparse
import ctypes
import errno
import json
from pathlib import Path
import platform
import re
import time


def ids(command, next_id, deadline, clock=time.monotonic):
    found=[];previous=0
    for _ in range(4097):
        if clock()>=deadline:raise ValueError('inventory-deadline')
        value=next_id(command,previous)
        if value is None:return found
        if value<=previous or len(found)>=4096:raise ValueError('inventory-bound-order')
        found.append(value);previous=value
    raise ValueError('inventory-bound')


def kernel_next(command, previous):
    # linux/bpf.h: start_id,next_id,open_flags; GET_NEXT_ID returns no FD.
    attr=(ctypes.c_uint32*3)(previous,0,0)
    libc=ctypes.CDLL(None,use_errno=True)
    result=libc.syscall(ctypes.c_long(321),ctypes.c_int(command),ctypes.byref(attr),ctypes.c_uint(12))
    if result<0:
        error=ctypes.get_errno()
        if error==errno.ENOENT:return None
        raise OSError(error,'BPF inventory refused')
    return attr[1]


def snapshot(next_id=kernel_next, clock=time.monotonic):
    if platform.machine()!='x86_64':raise ValueError('architecture')
    deadline=clock()+5
    def collect():return {name:ids(cmd,next_id,deadline,clock) for name,cmd in [('programs',11),('maps',12),('links',31)]}
    first=collect()
    with Path('/sys/kernel/tracing/uprobe_events').open() as f:uprobes=f.read(65537)
    if len(uprobes)>65536:raise ValueError('uprobe-inventory-bound')
    second=collect()
    if first!=second:raise ValueError('concurrent-resource-change')
    return {'schema':1,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'bpf_ids':first,'uprobe_events':sorted(uprobes.splitlines()),
            'perf_fd_coverage':'not established by this inventory'}


def compare(before,after):
    keys={'schema','boot_id','bpf_ids','uprobe_events','perf_fd_coverage'}
    if set(before)!=keys or set(after)!=keys or before['schema']!=1 or after['schema']!=1:
        raise ValueError('inventory-schema')
    for item in (before,after):
        if not isinstance(item['boot_id'],str) or not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',item['boot_id']):
            raise ValueError('inventory-boot-id')
        if not isinstance(item['bpf_ids'],dict) or set(item['bpf_ids'])!={'programs','maps','links'}:
            raise ValueError('inventory-id-types')
        for values in item['bpf_ids'].values():
            if not isinstance(values,list) or len(values)>4096 or any(type(v)!=int or v<=0 or v>0xffffffff for v in values) or values!=sorted(set(values)):
                raise ValueError('inventory-id-values')
        rows=item['uprobe_events']
        if not isinstance(rows,list) or any(not isinstance(v,str) or '\n' in v for v in rows) or sum(len(v)+1 for v in rows)>65536:
            raise ValueError('inventory-uprobes')
        if item['perf_fd_coverage']!='not established by this inventory':raise ValueError('inventory-coverage')
    if before!=after:raise ValueError('resource-baseline-not-restored')
    return 'BPF ID/uprobe baseline restored; perf FD coverage still requires independent evidence'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--read-approved',action='store_true')
    args=p.parse_args()
    if not args.read_approved:p.error('future target read approval required')
    print(json.dumps(snapshot(),sort_keys=True))


if __name__=='__main__':main()
