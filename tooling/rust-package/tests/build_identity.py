#!/usr/bin/env python3
"""Offline compiler/linker mechanics, not native or authenticated release proof.

Uses existing rustc, its lld and clang, never executes the generated ELF.
The no_std LLVM fixture uses the installed GNU core library; the second fixture
is assembled for arm64. Both carry synthetic musl statements solely to exercise
section retention and the offline package verifier. Neither is an SBXR build.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("root", "run", "rustc", "linker", "clang", "package"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    run = Path(args.run).resolve()
    run.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=run) as temporary:
        check(args, root, run, Path(temporary))


def check(args, root, run, work):
    commit = "a" * 40
    checks = []

    def command(argv, env=None, succeeds=True):
        done = subprocess.run(argv, cwd=root, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        checks.append({"argv": [str(a) for a in argv], "exit": done.returncode,
                       "expected_success": succeeds})
        with (run / "commands.log").open("a") as log:
            log.write(done.stdout)
        assert (done.returncode == 0) == succeeds, done.stdout
        return done.stdout

    builder = work / "build-script"
    command([args.rustc, "--edition=2024", "build.rs", "-o", builder])
    for name, profile, target, source, compiler, succeeds in [
        ("debug", "debug", "x86_64-unknown-linux-musl", commit, args.rustc, False),
        ("darwin", "release", "aarch64-apple-darwin", commit, args.rustc, False),
        ("gnu", "release", "x86_64-unknown-linux-gnu", commit, args.rustc, False),
        ("source", "release", "x86_64-unknown-linux-musl", "A" * 40, args.rustc, False),
        ("compiler", "release", "x86_64-unknown-linux-musl", commit, "/bin/echo", False),
        ("amd64", "release", "x86_64-unknown-linux-musl", commit, args.rustc, True),
        ("arm64", "release", "aarch64-unknown-linux-musl", commit, args.rustc, True),
        ("development", "debug", "aarch64-apple-darwin", None, args.rustc, True),
    ]:
        out = work / name
        out.mkdir()
        env = os.environ.copy()
        env.update(OUT_DIR=str(out), TARGET=target, PROFILE=profile, RUSTC=compiler,
                   SBXR_RETAINED_BUILD_COMMIT="forged")
        env.pop("SBXR_BUILD_COMMIT", None)
        if source is not None:
            env["SBXR_BUILD_COMMIT"] = source
        stdout = command([builder], env=env, succeeds=succeeds)
        if not succeeds:
            assert not (out / "sbxr-build.json").exists()
        elif source is None:
            assert (out / "sbxr-build.json").read_bytes() == b""
            assert not (out / "sbxr-build.ld").exists()
            assert "cargo:rustc-env=SBXR_RETAINED_BUILD_COMMIT=\n" in stdout
        else:
            metadata = json.loads((out / "sbxr-build.json").read_bytes())
            assert metadata["target"] == target and metadata["commit"] == commit
            assert metadata["profile"] == "release"
            assert f"cargo:rustc-env=SBXR_RETAINED_BUILD_COMMIT={commit}\n" in stdout
            assert "cargo:rustc-link-arg-bin=sbxr=-Wl,-T," in stdout
    rust_source = work / "fixture.rs"
    rust_source.write_text('''#![no_std]
#![no_main]
#[used] static NAME: [u8; 8] = *b"fixture!";
#[no_mangle] pub extern "C" fn _start() -> ! {
    core::hint::black_box(&NAME);
    loop { core::hint::spin_loop(); }
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
''')
    obj = work / "amd64.o"
    command([args.rustc, "--edition=2021", "--target=x86_64-unknown-linux-gnu",
             "--emit=obj", "-Cpanic=abort", "-Copt-level=3", rust_source, "-o", obj])
    assembly = work / "arm64.s"
    assembly.write_text('''.text
.global _start
_start:
adrp x0, fixture_value
add x0, x0, :lo12:fixture_value
b _start
.section .rodata,"a",@progbits
fixture_value: .byte 42
.section .comment,"MS",@progbits,1
.asciz "rustc version 1.90.0 (1159e78c4 2025-09-14)"
''')
    command([args.clang, "--target=aarch64-linux-gnu", "-c", assembly, "-o", work / "arm64.o"])
    for arch in ("amd64", "arm64"):
        elf = work / f"{arch}.elf"
        script = work / arch / "sbxr-build.ld"
        command([args.linker, "-flavor", "gnu", "--gc-sections", "-static", "-e", "_start",
                 "-T", script, work / f"{arch}.o", "-o", elf])
        package = work / f"sbxr-linux-{arch}.tar.gz"
        command([args.package, "package", "--tag", "v3.2.1", "--commit", commit,
                 "--sequence", "200", "--architecture", arch, "--executable", elf,
                 "--output", package])
        bad = elf.read_bytes().replace(commit.encode(), ("b" * 40).encode(), 1)
        changed = work / f"{arch}-changed.elf"
        changed.write_bytes(bad)
        (work / f"bad-{arch}").mkdir()
        refused = command([args.package, "package", "--tag", "v3.2.1", "--commit", commit,
                 "--sequence", "200", "--architecture", arch, "--executable", changed,
                 "--output", work / f"bad-{arch}" / package.name], succeeds=False)
        assert "executable" in refused
        assert not (work / f"bad-{arch}" / package.name).exists()
    (run / "outcome.json").write_text(json.dumps({"checks": checks,
        "scope": "offline build-script/linker mechanics only; synthetic metadata, never executed",
        "native_sbxr_build": False, "authenticated": False}, indent=2) + "\n")
    print(f"{len(checks)} compiler/linker/package checks passed; no ELF executed")


if __name__ == "__main__":
    main()
