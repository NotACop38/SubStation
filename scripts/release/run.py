#!/usr/bin/env python3
"""Cut a Substation release — LOCAL and Claude-driven (CLAUDE.md: no cloud CI).

Releases here are produced entirely on the developer's machine. There is no
GitHub Actions / cloud release pipeline (CLAUDE.md), so this script *is* the
release pipeline. It is **idempotent and repeatable**: re-running it for a
version that is already released re-syncs the generated artifacts (which are
deterministic) and exits 0 without creating a duplicate commit, changelog entry,
or tag.

Pipeline (PRD §6.9 / ENGINEERING_CHECKLIST "definition of launch-ready"):

  1. **Gate.** Re-run ``make ci`` (Tier 1) and ``make verify`` (Tier 2) — a
     release only happens over a green gate. ``--no-verify`` drops Tier 2 for
     environments without Docker; ``--skip-gate`` skips both (CI re-runs it).
  2. **Build.** Produce the sdist + wheel into ``dist/`` (``python -m build``,
     no build isolation so it uses the pinned, already-installed backend).
  3. **Regenerate committed artifacts.** Rebuild the ATT&CK-for-ICS coverage map
     + Navigator layer snapshot (``docs/coverage/``) and the demo transcript
     (``docs/demo-output.txt``) from the live registry / simulator, and stage
     them. (The raw PCAP/JSON the simulator emits stay git-ignored per repo
     policy — only the published snapshots are committed.)
  4. **Bump + changelog.** Set ``pyproject.toml``'s version to the target and
     promote ``CHANGELOG.md``'s ``[Unreleased]`` section to ``[<version>]``.
  5. **Commit + tag locally.** One release commit, then an annotated
     ``v<version>`` tag. The tag is **local** — this script never pushes.

Usage::

    python scripts/release/run.py [--version X.Y.Z | --bump {major,minor,patch}]
                                  [--no-verify] [--skip-gate] [--allow-dirty]
                                  [--dry-run]

Exit code 0 on success (including an idempotent no-op re-run), 1 on any failure.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_CHANGELOG = _REPO_ROOT / "CHANGELOG.md"
_DIST = _REPO_ROOT / "dist"
_DOCS_COVERAGE = _REPO_ROOT / "docs" / "coverage"
_DEMO_TRANSCRIPT = _REPO_ROOT / "docs" / "demo-output.txt"

_VERSION_RE = re.compile(r"^\s*\d+\.\d+\.\d+\s*$")
# The line in pyproject's [project] table; matched anchored to start of line.
_PYPROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"(?P<v>[^"]+)"\s*$', re.MULTILINE)


class ReleaseError(RuntimeError):
    """A release step failed in a way that should abort the release."""


# --- small process / git helpers ---------------------------------------------


def _run(cmd: list[str], *, dry_run: bool = False) -> None:
    """Run a command, streaming output; raise ReleaseError on non-zero exit."""
    print(f"release: $ {' '.join(cmd)}")
    if dry_run:
        return
    result = subprocess.run(cmd, cwd=_REPO_ROOT)
    if result.returncode != 0:
        raise ReleaseError(f"command failed ({result.returncode}): {' '.join(cmd)}")


def _git(*args: str, check: bool = True) -> str:
    """Run a git command and return its stripped stdout."""
    result = subprocess.run(["git", *args], cwd=_REPO_ROOT, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise ReleaseError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _tag_exists(tag: str) -> bool:
    return bool(_git("tag", "--list", tag))


# --- version handling --------------------------------------------------------


def _read_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    version = data["project"]["version"]
    if not isinstance(version, str):  # pragma: no cover - defensive
        raise ReleaseError("pyproject [project].version is not a string")
    return version


def _bump(version: str, level: str) -> str:
    if not _VERSION_RE.match(version):
        raise ReleaseError(f"current version {version!r} is not X.Y.Z; use --version")
    major, minor, patch = (int(p) for p in version.split("."))
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _write_version(new_version: str) -> bool:
    """Set pyproject's version. Return True if it changed."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    match = _PYPROJECT_VERSION_RE.search(text)
    if match is None:
        raise ReleaseError("could not find a version line in pyproject.toml")
    if match.group("v") == new_version:
        return False
    new_text = _PYPROJECT_VERSION_RE.sub(f'version = "{new_version}"', text, count=1)
    _PYPROJECT.write_text(new_text, encoding="utf-8")
    return True


def _target_version(args: argparse.Namespace, current: str) -> str:
    if args.version is not None:
        target = str(args.version)
        if not _VERSION_RE.match(target):
            raise ReleaseError(f"--version {target!r} is not a SemVer X.Y.Z string")
        return target
    return _bump(current, args.bump)


# --- changelog ---------------------------------------------------------------


def _update_changelog(version: str, date: str) -> bool:
    """Promote the [Unreleased] section to [version]. Return True if it changed.

    Idempotent: if a ``## [version]`` section already exists, do nothing.
    """
    if not _CHANGELOG.exists():
        raise ReleaseError(f"{_CHANGELOG.name} is missing; cannot record the release")
    text = _CHANGELOG.read_text(encoding="utf-8")

    if re.search(rf"^## \[{re.escape(version)}\]", text, re.MULTILINE):
        return False  # already recorded — idempotent re-run

    unreleased = re.search(
        r"^## \[Unreleased\]\s*\n(?P<body>.*?)(?=^## \[|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if unreleased is None:
        raise ReleaseError("CHANGELOG.md has no '## [Unreleased]' section to promote")

    body = unreleased.group("body").strip("\n")
    if not body.strip():
        body = "- No user-facing changes recorded for this release."

    replacement = f"## [Unreleased]\n\n## [{version}] - {date}\n\n{body}\n"
    new_text = text[: unreleased.start()] + replacement + text[unreleased.end() :]
    # Collapse any run of >2 blank lines the splice may introduce.
    new_text = re.sub(r"\n{3,}", "\n\n", new_text)
    _CHANGELOG.write_text(new_text, encoding="utf-8")
    return True


# --- pipeline steps ----------------------------------------------------------


def _gate(args: argparse.Namespace) -> None:
    if args.skip_gate:
        print("release: --skip-gate set; NOT re-running make ci / make verify")
        return
    print("release: gate — re-running make ci (Tier 1)")
    _run(["make", "ci"], dry_run=args.dry_run)
    if args.no_verify:
        print("release: --no-verify set; skipping Tier-2 'make verify' gate")
        return
    print("release: gate — re-running make verify (Tier 2)")
    _run(["make", "verify"], dry_run=args.dry_run)


def _build_distributions(args: argparse.Namespace) -> None:
    print("release: building sdist + wheel into dist/")
    # The distributions ship the library + `substation` CLI only. scenarios/,
    # detections/, and docs/coverage/ deliberately live OUTSIDE the package
    # (PRD §6.9), so the demo/coverage/detection paths run from a repo checkout,
    # not a bare wheel install (see CHANGELOG "Packaging"). This is intentional.
    # --no-isolation: use the already-installed, pinned setuptools/wheel backend
    # (keeps the build offline + deterministic, matching the Tier-1 promise).
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(_DIST),
        ],
        dry_run=args.dry_run,
    )


def _regenerate_artifacts(args: argparse.Namespace) -> None:
    print("release: regenerating committed coverage snapshot + Navigator layer")
    _run(
        [sys.executable, "-m", "substation.coverage", "--out", str(_DOCS_COVERAGE)],
        dry_run=args.dry_run,
    )
    print("release: regenerating demo transcript (docs/demo-output.txt)")
    if not args.dry_run:
        result = subprocess.run(
            [sys.executable, "-m", "substation.cli", "demo"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ReleaseError(f"demo failed:\n{result.stdout}\n{result.stderr}")
        header = (
            "# Substation demo · `make demo` output\n"
            "#\n"
            "# Generated by `make release` (scripts/release/run.py); do not edit by hand.\n"
            "# Tier-1 loop: generate -> detect -> report, pure Python.\n\n"
        )
        _DEMO_TRANSCRIPT.write_text(header + result.stdout, encoding="utf-8")
    # NB: staging happens in _commit_and_tag so a real release captures the *full*
    # intended tree (incl. any --allow-dirty source changes) and an idempotent
    # re-run over an existing tag never commits on top of it.


def _working_tree_dirty() -> bool:
    return bool(_git("status", "--porcelain"))


def _scan_staged_tree(*, dry_run: bool) -> None:
    """Re-run the secret scanner after staging the exact tree to be committed."""
    _run([sys.executable, "scripts/security/secret_scan.py"], dry_run=dry_run)


def _commit_and_tag(version: str, args: argparse.Namespace, already_released: bool) -> None:
    tag = f"v{version}"

    if already_released:
        # The tag already exists. Committing now would create a *second* "Release
        # <tag>" commit that the existing tag does not point at, and the re-synced
        # artifacts would not be part of the tagged release. So never commit here:
        # the regenerated artifacts live in the working tree for inspection only.
        if not args.dry_run and _working_tree_dirty():
            print(
                f"release: WARNING — the working tree differs from the tagged release "
                f"{tag}. Regenerated artifacts were NOT committed (the tag stays "
                "authoritative). If you intend to change the release, delete the tag "
                "and cut a new version deliberately."
            )
        else:
            print(f"release: {tag} already released; artifacts unchanged — nothing to do.")
        print(f"release: tag {tag} left in place (idempotent; NOT pushed).")
        return

    # A real release: stage the FULL intended tree (the regenerated artifacts plus
    # any --allow-dirty source changes that were just gated, built, and tested) so
    # the tagged commit is self-consistent with the wheel/sdist. dist/ and other
    # generated outputs stay out via .gitignore.
    _run(["git", "add", "-A"], dry_run=args.dry_run)
    _scan_staged_tree(dry_run=args.dry_run)
    staged = _git("diff", "--cached", "--name-only")
    if not staged and not args.dry_run:
        print("release: nothing staged — working tree already at this release")
    else:
        _run(["git", "commit", "-m", f"Release {tag}"], dry_run=args.dry_run)

    _run(["git", "tag", "-a", tag, "-m", f"Substation {tag}"], dry_run=args.dry_run)
    print(f"release: tagged {tag} locally (NOT pushed — push the tag manually if desired)")


# --- main --------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release",
        description="Cut a local Substation release (gate -> build -> artifacts -> bump -> tag).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", help="Explicit target version (SemVer X.Y.Z).")
    group.add_argument(
        "--bump",
        choices=["major", "minor", "patch"],
        default="minor",
        help="Bump level when --version is not given (default: minor).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the Tier-2 'make verify' gate (e.g. no Docker available).",
    )
    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help="Skip both gates (make ci / make verify). Use only when CI just ran.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Permit a non-clean working tree (uncommitted changes get committed).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the steps without changing files, committing, or tagging.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        current = _read_version()
        target = _target_version(args, current)
        tag = f"v{target}"
        already_released = _tag_exists(tag)

        print(f"release: current version {current} -> target {target} (tag {tag})")
        if already_released:
            print(
                f"release: {tag} already exists — idempotent re-run "
                "(re-sync artifacts; no new commit/tag/changelog entry)"
            )

        # Refuse to clobber unrelated work unless told otherwise.
        if not args.allow_dirty and not already_released:
            dirty = _git("status", "--porcelain")
            if dirty:
                raise ReleaseError(
                    "working tree is not clean; commit/stash first or pass --allow-dirty:\n" + dirty
                )

        _gate(args)

        # Bump the version BEFORE building so the sdist + wheel carry the release
        # version (idempotent re-runs already have pyproject at the target).
        date = datetime.date.today().isoformat()
        if not already_released and not args.dry_run:
            _write_version(target)
            _update_changelog(target, date)
        elif args.dry_run:
            print(f"release: would set version {target} and promote CHANGELOG ({date})")

        _build_distributions(args)
        _regenerate_artifacts(args)
        _commit_and_tag(target, args, already_released)

        print(f"release: done — {tag} is built, recorded, and tagged locally.")
        return 0
    except ReleaseError as exc:
        print(f"release: ERROR — {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
