#!/usr/bin/env python3
"""Linux x86_64 cgroup v2 egress deny guard for isolated rehearsals.

Legacy cgroup attachment persists after this process dies. Detach requires the
same program fd; use from a supervising rehearsal, never against system.slice.
"""
import ctypes
import errno
import os
import platform
from pathlib import Path
import struct


class EgressGuard:
    def __init__(self, directory, *, managed_renewal=False):
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise ValueError('Linux x86_64 required')
        path = Path(directory)
        if not (managed_renewal and path == Path('/sys/fs/cgroup/system.slice/snap.certbot.renew.service')) and (path.parent not in (Path('/sys/fs/cgroup'), Path('/sys/fs/cgroup/system.slice')) or not path.name.startswith('sbxr-fixture-')):
            raise ValueError('only a disposable sbxr-fixture cgroup is supported')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.cgroup = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.program = -1
        self.attached = False
        try:
            # Refuse an existing attachment instead of replacing another owner.
            query = ctypes.create_string_buffer(144)
            struct.pack_into('=IIIIQI', query, 0, self.cgroup, 1, 0, 0, 0, 0)
            self.call(16, query)  # PROG_QUERY
            if struct.unpack_from('=I', query, 24)[0] != 0:
                raise ValueError('existing egress program')
            # BPF_PROG_TYPE_CGROUP_SKB; return 0 => drop every outgoing packet.
            instructions = ctypes.create_string_buffer(struct.pack('=BBhiBBhi', 0xb7, 0, 0, 0, 0x95, 0, 0, 0))
            license = ctypes.create_string_buffer(b'GPL\0')
            attr = ctypes.create_string_buffer(144)
            struct.pack_into('=IIQQ', attr, 0, 8, 2, ctypes.addressof(instructions), ctypes.addressof(license))
            self.program = self.call(5, attr)  # BPF_PROG_LOAD
            attr = ctypes.create_string_buffer(144)
            struct.pack_into('=IIII', attr, 0, self.cgroup, self.program, 1, 0)  # INET_EGRESS
            self.call(8, attr)  # PROG_ATTACH; no override or multi-attach
            self.attached = True
            self.ids = self.program_ids()
            if len(self.ids) != 1:
                raise ValueError('expected one egress program')
        except BaseException:
            self.close()
            raise

    def call(self, operation, attr):
        result = self.libc.syscall(321, operation, ctypes.byref(attr), 144)
        if result < 0:
            raise OSError(ctypes.get_errno(), 'BPF control refused')
        return result

    def program_ids(self):
        ids = (ctypes.c_uint32 * 16)()
        attr = ctypes.create_string_buffer(144)
        struct.pack_into('=IIIIQI', attr, 0, self.cgroup, 1, 0, 0, ctypes.addressof(ids), 16)
        self.call(16, attr)
        count = struct.unpack_from('=I', attr, 24)[0]
        if count > 16:
            raise ValueError('too many egress programs')
        return tuple(ids[:count])

    def verify(self):
        if not self.attached or self.program_ids() != self.ids:
            raise ValueError('egress protection changed')

    def close(self):
        if self.attached:
            attr = ctypes.create_string_buffer(144)
            struct.pack_into('=IIII', attr, 0, self.cgroup, self.program, 1, 0)
            try:
                self.call(9, attr)  # PROG_DETACH exact program
            except OSError as error:
                # systemd can remove the now-empty test cgroup on stop; its
                # attachments then disappear with it. Never detach a new inode.
                if error.errno != errno.ENOENT or not os.readlink('/proc/self/fd/%d' % self.cgroup).endswith(' (deleted)'):
                    raise
            self.attached = False
        if self.program >= 0:
            os.close(self.program)
            self.program = -1
        if self.cgroup >= 0:
            os.close(self.cgroup)
            self.cgroup = -1
