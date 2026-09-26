#!/usr/bin/env python3
"""Install Substation's git hooks (invoked by `make hooks`).

Renders the committed hooks under ``scripts/hooks/`` into Git's active hooks
directory, recording the interpreter that ran this script so the gate uses the
same environment on every push, and marks them executable. Git resolves
``core.hooksPath`` and shared worktree hooks; the setting itself is left
untouched, but a hooks directory outside this repository (a global
``core.hooksPath``) is refused so the gate never runs for unrelated
repositories. Re-running updates managed Substation hooks in place, but refuses
to overwrite an unrelated hook or symlink.
"""

from __future__ import annotations

import shlex
import stat
import subprocess
import sys
from pathlib import Path

MANAGED_HOOKS = ["pre-push"]
_PYTHON_PLACEHOLDER = "@PYTHON@"


def _git_path(repo_root: Path, *args: str) -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", *args],  # noqa: S607
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(out.stdout.strip()).resolve()


def _hooks_dir(repo_root: Path, src_dir: Path) -> Path:
    """Git's active hooks directory, which must belong to this repository."""
    hooks_dir = _git_path(repo_root, "--git-path", "hooks")
    git_dir = _git_path(repo_root, "--git-common-dir")
    worktree = _git_path(repo_root, "--show-toplevel")
    if not (hooks_dir.is_relative_to(git_dir) or hooks_dir.is_relative_to(worktree)):
        raise ValueError(
            f"Git's hooks directory {hooks_dir} is outside this repository "
            "(core.hooksPath is set globally or to a shared path); refusing to install "
            "a repository-specific gate there. Point core.hooksPath at this repository's "
            "hooks with 'git config --local' and re-run."
        )
    if hooks_dir == src_dir.resolve():
        raise ValueError(
            f"core.hooksPath points at the committed hook sources ({hooks_dir}); "
            "unset it and re-run so the rendered hooks do not overwrite them."
        )
    return hooks_dir


def render(template: str, python: str) -> str:
    """Substitute the recorded interpreter into a hook template."""
    if template.count(_PYTHON_PLACEHOLDER) != 1:
        raise ValueError(f"hook template must contain {_PYTHON_PLACEHOLDER} exactly once")
    return template.replace(_PYTHON_PLACEHOLDER, shlex.quote(python))


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "scripts" / "hooks"
    try:
        hooks_dir = _hooks_dir(repo_root, src_dir)
        # Render and preflight every managed destination before changing any of them.
        rendered: dict[str, str] = {}
        for name in MANAGED_HOOKS:
            src = src_dir / name
            if not src.is_file():
                raise ValueError(f"missing source hook {src}")
            rendered[name] = render(src.read_text(encoding="utf-8"), sys.executable)
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
        for name, text in rendered.items():
            dst = hooks_dir / name
            dst.write_text(text, encoding="utf-8")
            dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print(f"install_hooks: installed {name} -> {dst}")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"install_hooks: {exc}", file=sys.stderr)
        return 1

    print(f"install_hooks: done. 'make ci' will run with {sys.executable} before every push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
