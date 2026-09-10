"""The sole CI push gate must be installed where Git actually looks for it."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603,S607
        ["git", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=_GIT_ENV,
    )
    return result.stdout.strip()


def _install(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(repo / "scripts/install_hooks.py")],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=10,
        env=_GIT_ENV,
    )


@pytest.fixture
def hook_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts/hooks").mkdir(parents=True)
    shutil.copyfile(_REPO / "scripts/install_hooks.py", repo / "scripts/install_hooks.py")
    shutil.copyfile(_REPO / "scripts/hooks/pre-push", repo / "scripts/hooks/pre-push")
    _git(repo, "init")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.test")
    _git(repo, "add", "scripts")
    _git(repo, "commit", "-m", "hook fixtures")
    return repo


@pytest.mark.parametrize("custom", [False, True])
def test_installer_uses_the_active_hook_directory(hook_repo: Path, custom: bool) -> None:
    if custom:
        _git(hook_repo, "config", "core.hooksPath", ".managed-hooks")
    expected = Path(_git(hook_repo, "rev-parse", "--path-format=absolute", "--git-path", "hooks"))
    result = _install(hook_repo)
    assert result.returncode == 0, result.stderr
    assert (expected / "pre-push").read_bytes() == (
        hook_repo / "scripts/hooks/pre-push"
    ).read_bytes()
    assert os.access(expected / "pre-push", os.X_OK)
    assert _install(hook_repo).returncode == 0


def test_installer_uses_shared_hooks_for_a_linked_worktree(hook_repo: Path) -> None:
    worktree = hook_repo.parent / "linked-worktree"
    _git(hook_repo, "worktree", "add", "-b", "fixture", str(worktree))
    result = _install(worktree)
    assert result.returncode == 0, result.stderr
    assert (hook_repo / ".git/hooks/pre-push").is_file()
    assert not (hook_repo / ".git/worktrees/linked-worktree/hooks").exists()


def test_installer_preserves_unrelated_existing_hook(hook_repo: Path) -> None:
    hook = hook_repo / ".git/hooks/pre-push"
    original = b"#!/bin/sh\nexit 42\n"
    hook.write_bytes(original)
    result = _install(hook_repo)
    assert result.returncode == 1
    assert "existing" in result.stderr
    assert hook.read_bytes() == original
