"""Check that a Git checkout is exactly a pinned commit, with nothing hidden from status.

Tier-2 loads parser scripts straight from cached upstream checkouts, so "at the
pinned commit and clean" must hold for the files on disk, not only for what
``git status`` chooses to report. Index flags that hide edits from status
(assume-unchanged, skip-worktree) are refused, and the filesystem monitor and
untracked cache are bypassed so stale state cannot mask a change.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

__all__ = ["checkout_problem"]

_GIT = ("git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false")


def _git(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [*_GIT, "-C", str(path), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def checkout_problem(path: Path, commit: str, *, allow_untracked: bool = False) -> str | None:
    """Return why ``path`` is not a clean checkout of ``commit``, or ``None`` if it is.

    Untracked and ignored files are problems too unless ``allow_untracked``: a
    stray script beside the pinned ones can change what a package loads.
    """
    head = _git(path, "rev-parse", "HEAD")
    if head.returncode != 0:
        return f"not a Git checkout ({head.stderr.strip()})"
    if head.stdout.strip() != commit:
        return f"HEAD is {head.stdout.strip()[:12]}, not the pinned {commit[:12]}"
    flags = _git(path, "ls-files", "-v")
    if flags.returncode != 0:
        return f"cannot read the index ({flags.stderr.strip()})"
    # ls-files -v tags skip-worktree entries "S" and assume-unchanged ones in lowercase.
    hidden = [
        line[2:] for line in flags.stdout.splitlines() if line[:1] == "S" or line[:1].islower()
    ]
    if hidden:
        return f"index flags hide edits from status ({', '.join(hidden[:3])})"
    untracked = (
        ("--untracked-files=no",) if allow_untracked else ("--untracked-files=all", "--ignored")
    )
    status = _git(path, "status", "--porcelain", *untracked)
    if status.returncode != 0:
        return f"cannot read the status ({status.stderr.strip()})"
    if status.stdout.strip():
        return "the checkout has local changes" + ("" if allow_untracked else " or extra files")
    return None
