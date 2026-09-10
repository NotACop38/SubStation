#!/usr/bin/env python3
"""Install Substation's git hooks (invoked by `make hooks`).

Copies the committed hooks under ``scripts/hooks/`` into Git's active hooks
directory and marks them executable. Git resolves ``core.hooksPath`` and shared
worktree hooks; the setting itself is left untouched. Re-running updates managed
Substation hooks in place, but refuses to overwrite an unrelated hook or symlink.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

MANAGED_HOOKS = ["pre-push"]


def _hooks_dir(repo_root: Path) -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-path", "hooks"],  # noqa: S607
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(out.stdout.strip()).resolve()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "scripts" / "hooks"
    try:
        hooks_dir = _hooks_dir(repo_root)
        # Preflight every managed destination before changing any of them.
        for name in MANAGED_HOOKS:
            src = src_dir / name
            if not src.is_file():
                raise ValueError(f"missing source hook {src}")
            dst = hooks_dir / name
            if dst.is_symlink() or (
                dst.exists()
                and not dst.read_text(encoding="utf-8").startswith(
                    f"#!/usr/bin/env bash\n# Substation {name} hook"
                )
            ):
                raise ValueError(
                    f"preserving existing hook {dst}; integrate the Substation hook manually"
                )
        hooks_dir.mkdir(parents=True, exist_ok=True)
        for name in MANAGED_HOOKS:
            src = src_dir / name
            dst = hooks_dir / name
            if not dst.exists() or not dst.samefile(src):
                shutil.copyfile(src, dst)
            dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print(f"install_hooks: installed {name} -> {dst}")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"install_hooks: {exc}", file=sys.stderr)
        return 1

    print("install_hooks: done. 'make ci' will now run before every push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
