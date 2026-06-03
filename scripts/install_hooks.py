#!/usr/bin/env python3
"""Install Substation's git hooks (invoked by `make hooks`).

Copies the committed hooks under ``scripts/hooks/`` into the repository's
``.git/hooks`` directory and marks them executable. Re-running is safe; it
overwrites the managed hooks in place.

We copy rather than rely on ``core.hooksPath`` so a developer's existing hook
configuration is left untouched.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

MANAGED_HOOKS = ["pre-push"]


def _git_dir() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(out.stdout.strip()).resolve()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "scripts" / "hooks"
    hooks_dir = _git_dir() / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    for name in MANAGED_HOOKS:
        src = src_dir / name
        if not src.is_file():
            print(f"install_hooks: missing source hook {src}", file=sys.stderr)
            return 1
        dst = hooks_dir / name
        shutil.copyfile(src, dst)
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"install_hooks: installed {name} -> {dst}")

    print("install_hooks: done. 'make ci' will now run before every push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
