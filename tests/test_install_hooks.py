"""The sole CI push gate must be installed where Git actually looks for it."""

from __future__ import annotations

import os
import shlex
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


def _install(repo: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(repo / "scripts/install_hooks.py")],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=10,
        env=env or _GIT_ENV,
    )


def _rendered_hook() -> bytes:
    template = (_REPO / "scripts/hooks/pre-push").read_text(encoding="utf-8")
    return template.replace("@PYTHON@", shlex.quote(sys.executable)).encode()


@pytest.fixture
def hook_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts/hooks").mkdir(parents=True)
    shutil.copyfile(_REPO / "scripts/install_hooks.py", repo / "scripts/install_hooks.py")
    shutil.copyfile(_REPO / "scripts/hooks/pre-push", repo / "scripts/hooks/pre-push")
    # A stand-in gate that records the interpreter it was given.
    (repo / "Makefile").write_text('ci:\n\t@printf "%s\\n" "$(PY)" > "$$GATE_LOG"\n')
    _git(repo, "init")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.test")
    _git(repo, "add", "scripts", "Makefile")
    _git(repo, "commit", "-m", "hook fixtures")
    return repo


@pytest.mark.parametrize("custom", [False, True])
def test_installer_uses_the_active_hook_directory(hook_repo: Path, custom: bool) -> None:
    if custom:
        _git(hook_repo, "config", "core.hooksPath", ".managed-hooks")
    expected = Path(_git(hook_repo, "rev-parse", "--path-format=absolute", "--git-path", "hooks"))
    result = _install(hook_repo)
    assert result.returncode == 0, result.stderr
    assert (expected / "pre-push").read_bytes() == _rendered_hook()
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


def test_installer_refuses_a_hooks_path_outside_the_repository(
    hook_repo: Path, tmp_path: Path
) -> None:
    shared = tmp_path / "global-hooks"
    config = tmp_path / "gitconfig"
    config.write_text(f"[core]\n\thooksPath = {shared}\n")
    result = _install(hook_repo, {**_GIT_ENV, "GIT_CONFIG_GLOBAL": str(config)})
    assert result.returncode == 1
    assert "outside this repository" in result.stderr
    assert not shared.exists()


def test_installer_refuses_to_overwrite_the_committed_hook_sources(hook_repo: Path) -> None:
    _git(hook_repo, "config", "core.hooksPath", "scripts/hooks")
    result = _install(hook_repo)
    assert result.returncode == 1
    assert "committed hook sources" in result.stderr
    assert "@PYTHON@" in (hook_repo / "scripts/hooks/pre-push").read_text()


def _push(repo: Path, tmp_path: Path, *lines: str) -> tuple[int, str | None]:
    """Run the installed pre-push hook; return its status and the gate's interpreter."""
    log = tmp_path / "gate.log"
    log.unlink(missing_ok=True)
    result = subprocess.run(  # noqa: S603
        ["bash", str(repo / ".git/hooks/pre-push"), "origin", "https://example.test/repo"],  # noqa: S607
        cwd=repo,
        input="".join(f"{line}\n" for line in lines),
        capture_output=True,
        text=True,
        timeout=30,
        env={**_GIT_ENV, "GATE_LOG": str(log)},
    )
    return result.returncode, log.read_text().strip() if log.exists() else None


_ZERO = "0" * 40


def test_hook_gates_the_checked_out_commit_with_the_recorded_interpreter(
    hook_repo: Path, tmp_path: Path
) -> None:
    assert _install(hook_repo).returncode == 0
    head = _git(hook_repo, "rev-parse", "HEAD")
    status, gate = _push(hook_repo, tmp_path, f"refs/heads/main {head} refs/heads/main {_ZERO}")
    assert (status, gate) == (0, sys.executable)
    _git(hook_repo, "tag", "-a", "v1.0.0", "-m", "release")
    tag = _git(hook_repo, "rev-parse", "v1.0.0")
    assert tag != head
    status, gate = _push(hook_repo, tmp_path, f"refs/tags/v1.0.0 {tag} refs/tags/v1.0.0 {_ZERO}")
    assert (status, gate) == (0, sys.executable)


def test_hook_refuses_refs_it_cannot_test(hook_repo: Path, tmp_path: Path) -> None:
    assert _install(hook_repo).returncode == 0
    head = _git(hook_repo, "rev-parse", "HEAD")
    _git(hook_repo, "commit", "--allow-empty", "-m", "unpushed work")
    status, gate = _push(hook_repo, tmp_path, f"refs/heads/main {head} refs/heads/main {_ZERO}")
    assert (status, gate) == (1, None)


@pytest.mark.parametrize("change", ["tracked", "untracked"])
def test_hook_refuses_a_dirty_working_tree(hook_repo: Path, tmp_path: Path, change: str) -> None:
    assert _install(hook_repo).returncode == 0
    head = _git(hook_repo, "rev-parse", "HEAD")
    target = hook_repo / ("Makefile" if change == "tracked" else "stray.py")
    target.write_text("changed\n")
    status, gate = _push(hook_repo, tmp_path, f"refs/heads/main {head} refs/heads/main {_ZERO}")
    assert (status, gate) == (1, None)


def test_hook_skips_the_gate_for_deletions(hook_repo: Path, tmp_path: Path) -> None:
    assert _install(hook_repo).returncode == 0
    (hook_repo / "stray.py").write_text("irrelevant to a deletion\n")
    status, gate = _push(hook_repo, tmp_path, f"(delete) {_ZERO} refs/heads/old {'1' * 40}")
    assert (status, gate) == (0, None)
