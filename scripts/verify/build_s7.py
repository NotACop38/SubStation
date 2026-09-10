#!/usr/bin/env python3
"""Build the pinned S7 verification plugin with the reviewed bounds fixes.

Requires git, CMake, a C++ compiler and native Zeek development headers. A source
checkout may be supplied to avoid a download; its commit and clean tree are checked.
The output directory must be new. Original source checkouts are never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = "7ebeb03a0f954541369361651d1c27d09a64b5a3"  # pragma: allowlist secret
PATCH = ROOT / "scripts/verify/patches/icsnpp-s7comm-bounds.patch"


def run(*argv: str) -> bytes:
    return subprocess.run(argv, check=True, capture_output=True, timeout=300).stdout


def verify_source(source: Path) -> None:
    if run("git", "-C", str(source), "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("S7 source is not at the qualified upstream commit")
    if run("git", "-C", str(source), "status", "--porcelain").strip():
        raise ValueError("S7 source must be clean")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="clean upstream checkout at the pinned commit")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    out = args.out.resolve()
    upstream = args.source.resolve() if args.source else out / "upstream"
    if args.source:
        if out.is_relative_to(upstream):
            raise ValueError("output must be outside the original source checkout")
        verify_source(upstream)
    out.mkdir(parents=True, exist_ok=False)
    if args.source is None:
        run(
            "git",
            "clone",
            "--no-checkout",
            "https://github.com/cisagov/icsnpp-s7comm.git",
            str(upstream),
        )
        run("git", "-C", str(upstream), "checkout", "--detach", PIN)
    verify_source(upstream)
    source = out / "source"
    source.mkdir()
    with tarfile.open(
        fileobj=io.BytesIO(run("git", "-C", str(upstream), "archive", PIN))
    ) as archive:
        for member in archive:
            name = Path(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or (not member.isdir() and not member.isfile())
            ):
                raise ValueError("unexpected upstream archive member")
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing archive member content")
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.read())
            target.chmod(member.mode & 0o777)
    # --unsafe-paths is never needed; apply only inside the new source directory.
    subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=source, check=True)
    subprocess.run(["git", "apply", str(PATCH)], cwd=source, check=True)
    build = out / "build"
    cmake_modules = run("zeek-config", "--cmake_dir").decode().strip()
    subprocess.run(
        ["cmake", "-S", str(source), "-B", str(build), f"-DCMAKE_MODULE_PATH={cmake_modules}"],
        check=True,
    )
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True)
    provenance = {
        "upstream_commit": PIN,
        "patch_sha256": hashlib.sha256(PATCH.read_bytes()).hexdigest(),
        "zeek": run("zeek", "--version").decode().strip(),
        "plugin_marker": "substation-bounds-v1",
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Build complete. ZEEK_PLUGIN_PATH={build}; prepend {source / 'scripts'} to ZEEKPATH.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
