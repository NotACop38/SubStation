"""Setuptools entry with a build hook that bundles detections/ and scenarios/.

Metadata lives in ``pyproject.toml``. This file only customizes ``build_py`` so
wheels/sdists ship the top-level content trees under ``substation/content/``
(see :mod:`substation.content`). Editable checkouts keep resolving the repo-root
trees via the same resolver.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

_ROOT = Path(__file__).resolve().parent
_CONTENT_NAMES = ("detections", "scenarios")


class BuildPyWithContent(build_py):
    """Copy repo-root content into ``build/lib/substation/content/`` for wheels."""

    def run(self) -> None:
        super().run()
        dest_root = Path(self.build_lib) / "substation" / "content"
        dest_root.mkdir(parents=True, exist_ok=True)
        for name in _CONTENT_NAMES:
            src = _ROOT / name
            if not src.is_dir():
                raise RuntimeError(f"build_py: missing content tree {src}")
            dest = dest_root / name
            if dest.exists() or dest.is_symlink():
                if dest.is_dir() and not dest.is_symlink():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            shutil.copytree(
                src,
                dest,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
            )


setup(cmdclass={"build_py": BuildPyWithContent})
