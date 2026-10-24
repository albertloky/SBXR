#!/usr/bin/env python3
"""Build one native Linux musl product archive; never install/run the product.

Provision tools/dependency caches separately. No cross-compiler guessing, remote
workflow dispatch, package installation, signing or upload occurs here.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {"amd64": ("x86_64", "x86_64-unknown-linux-musl"),
           "arm64": ("aarch64", "aarch64-unknown-linux-musl")}


def run(args, *, capture=False, env=None):
    return subprocess.run(args, cwd=ROOT, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          text=capture).stdout


def build(args):
    machine, target = TARGETS[args.architecture]
    if platform.system() != "Linux" or platform.machine() != machine:
        raise ValueError("matching native Linux builder required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag) or args.sequence <= 0:
        raise ValueError("release identity refused")
    output = Path(args.output).absolute()
    if output.name != f"sbxr-linux-{args.architecture}.tar.gz" or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("exclusive archive output required")
    for tool in ["cargo", "rustc", "git", "musl-gcc", "cmake", "make", "perl", "gzip"]:
        if shutil.which(tool) is None:
            raise ValueError("missing build prerequisite: " + tool)
    if run(["git", "rev-parse", "HEAD"], capture=True).strip() != args.commit or run(["git", "status", "--porcelain", "--untracked-files=all"], capture=True).strip():
        raise ValueError("exact clean committed source required")
    if run(["rustc", "--version"], capture=True).strip() != "rustc 1.90.0 (1159e78c4 2025-09-14)":
        raise ValueError("pinned Rust compiler required")
    library = Path(run(["rustc", "--print", "target-libdir", "--target", target], capture=True).strip())
    if not list(library.glob("libstd-*.rlib")):
        raise ValueError("missing Rust target: " + target)
    # Explicit command-local input; repository tools are not released SBXR builds.
    env = os.environ.copy()
    env.pop("SBXR_BUILD_COMMIT", None)
    env.pop("SBXR_RETAINED_BUILD_COMMIT", None)
    env["CC_" + target.replace("-", "_")] = "musl-gcc"
    env["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] = "musl-gcc"
    host = run(["rustc", "-vV"], capture=True)
    host = next(line[6:] for line in host.splitlines() if line.startswith("host: "))
    run(["cargo", "build", "--locked", "--offline", "--release", "--manifest-path", "tooling/rust-package/Cargo.toml", "--target", host], env=env)
    product_env = dict(env, SBXR_BUILD_COMMIT=args.commit)
    run(["cargo", "build", "--locked", "--offline", "--release", "--target", target], env=product_env)
    target_dir = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    tool = target_dir / host / "release/sbxr-rust-package"
    result = run([str(tool), "package", "--tag", args.tag, "--commit", args.commit,
                  "--sequence", str(args.sequence), "--architecture", args.architecture,
                  "--executable", str(target_dir / target / "release/sbxr"), "--output", str(output)], capture=True, env=env)
    value = json.loads(result)
    if value.get("outcome") != "packaged-local" or value.get("architecture") != args.architecture:
        raise ValueError("structural package verification refused")
    print(json.dumps(dict(value, commit=args.commit, target=target, compiler="rustc 1.90.0",
                          scope="native build and structural package only; no deployment or authentication"), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True, choices=TARGETS)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        build(args)
    except (ValueError, OSError, subprocess.CalledProcessError, StopIteration):
        # Compiler output is emitted normally; caller values/environment are not.
        raise SystemExit("rust-native/build refused; inspect prerequisites and compiler diagnostics")


if __name__ == "__main__":
    main()
