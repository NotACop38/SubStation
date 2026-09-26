#!/usr/bin/env python3
"""Build the pinned ICSNPP S7comm plugin with the reviewed bounds fixes.

Both targets share one verified source preparation: the upstream commit and a
clean tree are checked, files come from ``git archive`` and the patch is applied
to a fresh copy. A source checkout may be supplied to avoid a download; it is
never modified.

* ``--out DIR`` builds natively with CMake against the host's Zeek (requires git,
  CMake, a C++ compiler and Zeek development headers) and records provenance.
  The output directory must be new.
* ``--docker`` builds a Zeek image with the plugin installed on top of the
  digest-pinned image the Tier-2 runner uses, and prints the image tag. The tag
  is derived from every build input, so a changed pin, patch or recipe rebuilds.
  ``make verify`` builds this image automatically when it is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = "7ebeb03a0f954541369361651d1c27d09a64b5a3"
UPSTREAM = "https://github.com/cisagov/icsnpp-s7comm.git"
PATCH = ROOT / "scripts/verify/patches/icsnpp-s7comm-bounds.patch"
DOCKERFILE = ROOT / "scripts/verify/zeek-s7comm.Dockerfile"
PLUGIN_MARKER = "substation-bounds-v1"
IMAGE_REPOSITORY = "substation-verify/zeek-s7comm"


def run(*argv: str) -> bytes:
    return subprocess.run(argv, check=True, capture_output=True, timeout=300).stdout


def verify_source(source: Path) -> None:
    if run("git", "-C", str(source), "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("S7 source is not at the qualified upstream commit")
    if run("git", "-C", str(source), "status", "--porcelain").strip():
        raise ValueError("S7 source must be clean")


def prepare_source(dest: Path, upstream: Path, *, fetch: bool) -> None:
    """Write a patched copy of the pinned upstream tree to the new ``dest``.

    With ``fetch``, first clone the pinned commit into ``upstream``; otherwise
    ``upstream`` is a caller-supplied checkout.
    """
    if fetch:
        run("git", "clone", "--no-checkout", UPSTREAM, str(upstream))
        run("git", "-C", str(upstream), "checkout", "--detach", PIN)
    verify_source(upstream)
    dest.mkdir()
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
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.read())
            target.chmod(member.mode & 0o777)
    # --unsafe-paths is never needed; apply only inside the new source directory.
    subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=dest, check=True)
    subprocess.run(["git", "apply", str(PATCH)], cwd=dest, check=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_tag(zeek_image: str) -> str:
    """Return the content-addressed tag for the S7 image built on ``zeek_image``."""
    inputs = {
        "dockerfile_sha256": _sha256(DOCKERFILE),
        "patch_sha256": _sha256(PATCH),
        "upstream_commit": PIN,
        "zeek_image": zeek_image,
    }
    digest = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    return f"{IMAGE_REPOSITORY}:{digest[:16]}"


def build_image(zeek_image: str, source: Path | None = None) -> str:
    """Build the S7 verification image on ``zeek_image``; return its tag.

    The Docker build context holds only the prepared source tree, so the build
    fetches no source code. Build output is shown only when the build fails.
    """
    tag = image_tag(zeek_image)
    with tempfile.TemporaryDirectory(prefix="substation-s7-image-") as tmp:
        work = Path(tmp)
        context = work / "context"
        context.mkdir()
        upstream = source if source is not None else work / "upstream"
        prepare_source(context / "source", upstream, fetch=source is None)
        proc = subprocess.run(
            [
                "docker",
                "build",
                "--file",
                str(DOCKERFILE),
                "--build-arg",
                f"ZEEK_IMAGE={zeek_image}",
                "--label",
                f"io.substation.icsnpp-s7comm.commit={PIN}",
                "--label",
                f"io.substation.icsnpp-s7comm.patch-sha256={_sha256(PATCH)}",
                "--label",
                f"io.substation.zeek-image={zeek_image}",
                "--tag",
                tag,
                str(context),
            ],
            capture_output=True,
            text=True,
            timeout=1800,
        )
    if proc.returncode != 0:
        output = (proc.stdout + proc.stderr).strip().splitlines()
        raise RuntimeError("docker build failed:\n" + "\n".join(output[-30:]))
    return tag


def build_native(out: Path, source: Path | None) -> None:
    """Build the plugin against the host's Zeek into the new directory ``out``."""
    upstream = source if source is not None else out / "upstream"
    if source is not None:
        if out.is_relative_to(source):
            raise ValueError("output must be outside the original source checkout")
        verify_source(source)
    out.mkdir(parents=True, exist_ok=False)
    prepared = out / "source"
    prepare_source(prepared, upstream, fetch=source is None)
    build = out / "build"
    cmake_modules = run("zeek-config", "--cmake_dir").decode().strip()
    subprocess.run(
        ["cmake", "-S", str(prepared), "-B", str(build), f"-DCMAKE_MODULE_PATH={cmake_modules}"],
        check=True,
    )
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True)
    provenance = {
        "upstream_commit": PIN,
        "patch_sha256": _sha256(PATCH),
        "zeek": run("zeek", "--version").decode().strip(),
        "plugin_marker": PLUGIN_MARKER,
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Build complete. ZEEK_PLUGIN_PATH={build}; prepend {prepared / 'scripts'} to ZEEKPATH.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--out", type=Path, help="new output directory for a native build")
    target.add_argument(
        "--docker", action="store_true", help="build the Tier-2 Zeek image and print its tag"
    )
    parser.add_argument("--source", type=Path, help="clean upstream checkout at the pinned commit")
    args = parser.parse_args()
    source = args.source.resolve() if args.source else None
    if args.docker:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from scripts.verify.run import ZEEK_IMAGE

        print(build_image(ZEEK_IMAGE, source))
        return 0
    build_native(args.out.resolve(), source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
