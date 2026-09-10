"""Secret scanners must inspect proposed content rather than only old commits."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.security import secret_scan


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603,S607


def test_index_scan_reads_staged_bytes_even_after_worktree_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    source = repo / "new config.txt"
    # Deliberately synthetic credential shape, assembled to avoid fixture flags.
    source.write_text("api_key = '" + "AKIA" + "Z" * 16 + "'\n")
    _git(repo, "add", "--", source.name)
    source.write_text("clean working copy\n")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", repo)
    index = tmp_path / "index"
    index.mkdir()
    secret_scan._snapshot(index, staged=True)
    assert secret_scan._run_builtin(index) == 1
    assert secret_scan._run_detect_secrets(index) == 1
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    secret_scan._snapshot(worktree, staged=False)
    assert secret_scan._run_builtin(worktree) == 0


def test_worktree_scan_includes_new_nonignored_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    (repo / ".gitignore").write_text("cache/\n")
    (repo / "new.py").write_text("synthetic example\n")
    (repo / "cache").mkdir()
    (repo / "cache" / "ignored.py").write_text("ignored\n")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", repo)
    snapshot = tmp_path / "scan"
    snapshot.mkdir()
    secret_scan._snapshot(snapshot, staged=False)
    assert (snapshot / "new.py").read_text() == "synthetic example\n"
    assert not (snapshot / "cache").exists()


def test_missing_scanners_cannot_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(tmp_path, "init")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("SUBSTATION_SECRET_SCANNER", raising=False)
    monkeypatch.setattr(secret_scan, "_run_gitleaks_native", lambda _root: None)
    monkeypatch.setattr(secret_scan, "_run_detect_secrets", lambda _root: None)
    assert secret_scan.main([]) == 2
