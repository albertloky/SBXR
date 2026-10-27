# bpftrace 0.23.0: provenance and no-mount build assessment

Checked during isolated diagnostic preparation on 2026-10-27. No tracer execution,
installation, mounts, chroot/unshare or security changes occurred.

## Required provenance, without an invented signature gate

The reviewed [observer instructions](../../.github/scripts/dns-child-observer.md)
require independently verified build provenance and an exact approved digest;
the [wrapper](../../.github/scripts/dns-child-observer-run.py) also requires the
0.23.0 attachment notification contract. Neither mandates a particular signature
or attestation format. An official vendor release is an established distribution
source. A local digest pins bytes; it is not cryptographic build attestation.

The [official release](https://github.com/bpftrace/bpftrace/releases/tag/v0.23.0)
resolves to source commit `01e806d24c61f996f1809e1e991646311499db4f`. Its `bpftrace`
asset, id `240658814`, is a 191,439,568-byte x86-64 AppImage:

`3eefba1c9338a8f981af349b4904e03a82adb257c5eb8dd5fd484675333b1f1a`

The API returned no asset digest/signature, and a public digest-attestation lookup
returned 404. The commit was unsigned. Those facts do not establish unsafe origin
or a permission denial. The [pinned release workflow](https://github.com/bpftrace/bpftrace/blob/01e806d24c61f996f1809e1e991646311499db4f/.github/workflows/release.yml)
builds/uploads release assets; it has no attestation step. No reproducible rebuild
or cryptographic source-to-binary binding was established here.

## Archive and binary inspection

The [data-only inspector](../../.github/scripts/inspect-bpftrace-appimage.py) uses
Dissect SquashFS 1.12 and backports.zstd 1.8.0, installed in a workspace prefix.
It verifies the pinned outer digest and reads the v4 filesystem at offset 824016.
It executes neither AppImage nor extraction switches and mounts nothing.

Inner tracer path:
`/nix/store/cavhgpscmkkyg39hmjpgr7pbmcwawn1c-bpftrace/bin/bpftrace`.
Its size is 4,129,224 bytes; SHA-256:
`72cfbbf403d9d1ba118892dc8ee94beb875be2ab5b68cdd79c8e665456cc7540`.

Static disassembly found `BPFtrace::run` at `0x54a2b0`, attachment calls at
`0x54a93f` and `0x54aace`, notification `getenv` at `0x54aba0`, print at
`0x54abbc` and flush at `0x54abc4`. Empty attachment branches take failure paths.
This agrees with the narrow ordering in the [pinned source](https://github.com/bpftrace/bpftrace/blob/01e806d24c61f996f1809e1e991646311499db4f/src/bpftrace.cpp#L977-L1032).
It is not a complete equivalence proof or runtime attachment evidence.

The actual launch constraint is its absolute Nix interpreter/RUNPATH. Its bundled
[AppRun source](https://github.com/danobi/nix-appimage/blob/74e44691812b4f220e84fd89895931ff4f904a03/apprun.c)
creates a mount namespace, uses tmpfs/bind mounts and chroots. It cannot be assumed
to satisfy the existing no-mount boundary. The inner binary is not independently
relocatable merely because it can be extracted.

## Ordinary source-build feasibility

The [pinned build configuration](https://github.com/bpftrace/bpftrace/blob/01e806d24c61f996f1809e1e991646311499db4f/CMakeLists.txt)
requires LLVM/Clang development files (supported LLVM 16–20), BCC, libbpf >=1.5,
libelf, Cereal, Bison and Flex. The [installation guide](https://github.com/bpftrace/bpftrace/blob/01e806d24c61f996f1809e1e991646311499db4f/INSTALL.md)
describes normal builds; its system-install and kernel-setting commands were not
executed and grant no authorization here.

Existing builder: GCC/G++ 14.2, Make, pkg-config, workspace CMake 4.4.4, zlib headers,
glibc 2.41; approximately 27 GiB free disk. LLVM 17/19 shared runtime libraries are
present, but LLVM/Clang headers, development CMake configuration, `llvm-config`
and compiler tools are absent. BCC, libbpf and libelf development headers, Cereal,
Bison and Flex are also absent. Runtime shared libraries are not a complete SDK.

A conventional bpftrace-only compile cannot proceed with these inputs. Building
or provisioning the LLVM/Clang SDK and dependency stack is a separate substantial
bootstrap; no such expensive build was started. A matching target libc/C++ ABI or
compatible sysroot must also be selected before calling a result portable.

Next concrete prerequisite: supply a workspace-local supported LLVM/Clang SDK,
BCC, libbpf >=1.5 and libelf development libraries, Cereal, Bison and Flex from
recognized upstream/registry sources, with compatible target ABI. Then configure
an ordinary non-AppImage release build under a workspace prefix, leaving tests,
manual generation and optional integrations off where upstream supports it.
Inspect resulting ELF interpreter/RUNPATH and notification control flow before any
execution. No wrapper version relaxation, loader trick, mount workaround or
substitution of 0.20.2 is included.

The earlier apt metadata probe was denied access to
`/etc/apt/apt.conf.d/80-applied-apt-retries`. That read was not retried, rerouted or
bypassed; no apt command was used for this source-build assessment.
