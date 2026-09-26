#!/usr/bin/env python3
"""Cut a Substation release locally. There is no cloud CI; this script is the pipeline.

1. **Preflight.** The working tree is clean, the target version is not older
   than the current one, its tag does not exist, and ``CHANGELOG.md`` holds
   notes under ``## [Unreleased]``.
2. **Gate.** ``make ci`` (Tier 1) and, unless ``--no-verify``, ``make verify
   VERIFY_ARGS=--require-complete`` (Tier 2), both with this interpreter.
3. **Prepare.** Set the version, promote the changelog notes, regenerate the
   committed coverage artifacts and demo transcript, stage exactly those paths
   and secret-scan the staged tree.
4. **Build.** Export the staged tree (``git checkout-index``) and build the
   sdist and wheel from that export into ``dist/``, so nothing untracked,
   ignored or left over in ``build/`` can enter a distribution.
5. **Record.** Commit the staged tree and create an annotated ``v<version>``
   tag. Nothing is pushed.

Any failure before the commit restores and unstages every path the release
touched, so the same command can be re-run once the cause is fixed.

Usage::

    python scripts/release/run.py (--version X.Y.Z | --bump {major,minor,patch})
                                  [--no-verify] [--skip-gate] [--dry-run]
"""

from __future__ import annotations

import argparse
import datetime
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Sequence
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DIST = "dist"
_PYPROJECT = "pyproject.toml"
_CHANGELOG = "CHANGELOG.md"
_DEMO_TRANSCRIPT = "docs/demo-output.txt"
_COVERAGE_DIR = "docs/coverage"
# Every path the release writes; the rollback restores exactly these.
_RELEASE_PATHS = (_PYPROJECT, _CHANGELOG, _COVERAGE_DIR, _DEMO_TRANSCRIPT)

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_PYPROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"(?P<v>[^"]+)"\s*$', re.MULTILINE)
_UNRELEASED_RE = re.compile(
    r"^## \[Unreleased\][^\n]*\n(?P<body>.*?)(?=^## \[|^\[[^\]]+\]:|\Z)",
    re.MULTILINE | re.DOTALL,
)


class ReleaseError(RuntimeError):
    """A release step failed; the release is aborted."""


# --- process / git helpers ---------------------------------------------------


def _run(cmd: list[str], *, cwd: Path | None = None) -> None:
    """Run a command, streaming its output; raise ReleaseError on failure."""
    print(f"release: $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or _REPO_ROOT)  # noqa: S603
    if result.returncode != 0:
        raise ReleaseError(f"command failed ({result.returncode}): {' '.join(cmd)}")


def _git(*args: str) -> str:
    """Run a git command in the repository and return its stripped stdout."""
    result = subprocess.run(
        ["git", *args],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReleaseError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _path(relative: str) -> Path:
    return _REPO_ROOT / relative


# --- versions and changelog --------------------------------------------------


def _parse_version(version: str, what: str) -> tuple[int, int, int]:
    match = _VERSION_RE.match(version)
    if match is None:
        raise ReleaseError(f"{what} {version!r} is not a SemVer X.Y.Z version")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _read_version() -> str:
    with _path(_PYPROJECT).open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    if not isinstance(version, str):
        raise ReleaseError("pyproject [project].version is not a string")
    return version


def _target_version(args: argparse.Namespace, current: str) -> str:
    major, minor, patch = _parse_version(current, "current version")
    if args.version is not None:
        target = str(args.version)
        if _parse_version(target, "--version") < (major, minor, patch):
            raise ReleaseError(f"--version {target} is older than the current version {current}")
        return target
    if args.bump == "major":
        return f"{major + 1}.0.0"
    if args.bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _unreleased_section(text: str) -> re.Match[str]:
    """Locate the ``[Unreleased]`` section; refuse a release without notes."""
    match = _UNRELEASED_RE.search(text)
    if match is None:
        raise ReleaseError(f"{_CHANGELOG} has no '## [Unreleased]' section")
    if not match.group("body").strip():
        raise ReleaseError(f"{_CHANGELOG} [Unreleased] is empty; record the release notes first")
    return match


def _set_version(version: str) -> None:
    path = _path(_PYPROJECT)
    text = path.read_text(encoding="utf-8")
    if _PYPROJECT_VERSION_RE.search(text) is None:
        raise ReleaseError(f"could not find the version line in {_PYPROJECT}")
    path.write_text(
        _PYPROJECT_VERSION_RE.sub(f'version = "{version}"', text, count=1), encoding="utf-8"
    )


def _promote_changelog(version: str, date: str) -> None:
    """Move the ``[Unreleased]`` notes under a new ``[version] - date`` heading."""
    path = _path(_CHANGELOG)
    text = path.read_text(encoding="utf-8")
    match = _unreleased_section(text)
    notes = match.group("body").strip("\n")
    rest = text[match.end() :]
    section = f"## [Unreleased]\n\n## [{version}] - {date}\n\n{notes}\n" + ("\n" if rest else "")
    path.write_text(text[: match.start()] + section + rest, encoding="utf-8")


# --- pipeline steps ----------------------------------------------------------


def _preflight(target: str) -> None:
    if _git("status", "--porcelain"):
        raise ReleaseError("the working tree is not clean; commit or stash changes first")
    if _git("tag", "--list", f"v{target}"):
        raise ReleaseError(f"tag v{target} already exists; choose a new version")
    _unreleased_section(_path(_CHANGELOG).read_text(encoding="utf-8"))


def _gate(args: argparse.Namespace) -> None:
    if args.skip_gate:
        print("release: --skip-gate set; NOT running make ci / make verify")
        return
    _run(["make", "ci", f"PY={sys.executable}"])
    if args.no_verify:
        print("release: --no-verify set; the Tier-2 gate did NOT run")
        return
    _run(["make", "verify", f"PY={sys.executable}", "VERIFY_ARGS=--require-complete"])


def _regenerate() -> None:
    """Rebuild the committed coverage artifacts and the demo transcript."""
    _run([sys.executable, "-m", "substation.coverage", "--out", str(_path(_COVERAGE_DIR))])
    demo = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "substation.cli", "demo"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if demo.returncode != 0:
        raise ReleaseError(f"demo failed:\n{demo.stdout}\n{demo.stderr}")
    header = (
        "# Substation demo · `make demo` output\n"
        "#\n"
        "# Generated by `make release` (scripts/release/run.py); do not edit by hand.\n"
        "# Tier-1 loop: generate -> detect -> report, pure Python.\n\n"
    )
    _path(_DEMO_TRANSCRIPT).write_text(header + demo.stdout, encoding="utf-8")


def _scan_staged() -> None:
    """Secret-scan the exact tree that will be committed."""
    _run([sys.executable, "scripts/security/secret_scan.py", "--staged"])


def _prepare(target: str) -> None:
    """Bump, promote the changelog, regenerate artifacts and stage the release paths."""
    _set_version(target)
    _promote_changelog(target, datetime.date.today().isoformat())
    _regenerate()
    _git("add", "--", *_RELEASE_PATHS)
    _scan_staged()


def _build(version: str) -> list[Path]:
    """Build the sdist and wheel from an export of the staged tree (the index)."""
    with tempfile.TemporaryDirectory(prefix="substation-release-") as scratch:
        root = Path(scratch)
        source = root / "source"
        _git("checkout-index", "--all", f"--prefix={source}/")
        out = root / "dist"
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(out),
                str(source),
            ],
            cwd=source,
        )
        built = sorted(out.iterdir())
        names = [path.name for path in built]
        if len(built) != 2 or not all(f"-{version}" in name for name in names):
            raise ReleaseError(f"expected one sdist and one wheel for {version}, built {names}")
        dist = _path(_DIST)
        dist.mkdir(exist_ok=True)
        published = []
        for path in built:
            shutil.copy2(path, dist / path.name)
            published.append(dist / path.name)
        return published


def _rollback() -> None:
    """Restore and unstage every release path (the tree was clean at preflight)."""
    print("release: rolling back the version, changelog and regenerated artifacts")
    subprocess.run(["git", "reset", "-q", "--", *_RELEASE_PATHS], cwd=_REPO_ROOT)  # noqa: S607
    for path in _RELEASE_PATHS:  # one at a time: a path missing from HEAD must not block others
        subprocess.run(  # noqa: S603
            ["git", "checkout", "-q", "HEAD", "--", path],  # noqa: S607
            cwd=_REPO_ROOT,
            capture_output=True,
        )
    subprocess.run(["git", "clean", "-fdq", "--", *_RELEASE_PATHS], cwd=_REPO_ROOT)  # noqa: S607


# --- main --------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release",
        description="Cut a local Substation release (preflight -> gate -> build -> tag).",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--version", help="Explicit target version (SemVer X.Y.Z).")
    target.add_argument(
        "--bump", choices=["major", "minor", "patch"], help="Bump the current version."
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the Tier-2 'make verify' gate (no Docker); the release is Tier-2 unverified.",
    )
    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help="Skip both gates. Use only when they just passed on this exact commit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the preflight and print the plan without changing anything.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        current = _read_version()
        target = _target_version(args, current)
        tag = f"v{target}"
        print(f"release: {current} -> {target} (tag {tag})")
        _preflight(target)
        if args.dry_run:
            print("release: preflight passed; would gate, prepare, build, commit and tag")
            return 0
        _gate(args)
        try:
            _prepare(target)
            tree = _git("write-tree")
            published = _build(target)
            _run(["git", "commit", "-q", "-m", f"Release {tag}"])
        except BaseException:
            _rollback()
            raise
        if _git("rev-parse", "HEAD^{tree}") != tree:
            raise ReleaseError("the release commit does not match the built tree; not tagging")
        _run(["git", "tag", "-a", tag, "-m", f"Substation {tag}"])
        for path in published:
            print(f"release: built {path.relative_to(_REPO_ROOT)}")
        print(f"release: done — {tag} committed and tagged locally (NOT pushed)")
        return 0
    except ReleaseError as exc:
        print(f"release: ERROR — {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
