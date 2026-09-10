"""Tests for the local release helper."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.release import run as release


def _release_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603,S607

    git("init")
    git("config", "user.name", "Synthetic Test")
    git("config", "user.email", "synthetic@example.test")
    (tmp_path / "README.md").write_text("release fixture\n")
    git("add", "README.md")
    git("commit", "-m", "fixture")
    git("tag", "v1.2.3")
    monkeypatch.setattr(release, "_REPO_ROOT", tmp_path)


def test_release_retry_requires_exact_tagged_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _release_repo(tmp_path, monkeypatch)
    release._check_release_tree("1.2.3", "1.2.3", True, False)
    (tmp_path / "README.md").write_text("different source\n")
    with pytest.raises(release.ReleaseError, match="clean tagged checkout"):
        release._check_release_tree("1.2.3", "1.2.3", True, True)
    release._git("add", "README.md")
    release._git("commit", "-m", "later work")
    with pytest.raises(release.ReleaseError, match="clean tagged checkout"):
        release._check_release_tree("1.2.3", "1.2.3", True, False)


def test_allow_dirty_cannot_omit_new_sources_from_release_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _release_repo(tmp_path, monkeypatch)
    (tmp_path / "new_module.py").write_text("value = 1\n")
    with pytest.raises(release.ReleaseError, match="commit new files"):
        release._check_release_tree("1.2.4", "1.2.3", False, True)


def test_release_gate_keeps_selected_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(release, "_run", lambda cmd, **kwargs: calls.append(cmd))
    release._gate(argparse.Namespace(skip_gate=False, no_verify=False, dry_run=False))
    assert calls == [
        ["make", "ci", f"PY={sys.executable}"],
        ["make", "verify", f"PY={sys.executable}", "VERIFY_ARGS=--require-complete"],
    ]


def test_release_scans_staged_tree_before_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(cmd: list[str], *, dry_run: bool = False) -> None:
        assert dry_run is False
        calls.append(tuple(cmd))

    def fake_git(*args: str, check: bool = True) -> str:
        assert check is True
        calls.append(("git", *args))
        if args == ("diff", "--cached", "--name-only"):
            return "credentials.txt"
        return ""

    monkeypatch.setattr(release, "_run", fake_run)
    monkeypatch.setattr(release, "_git", fake_git)

    release._commit_and_tag(
        "1.2.3", argparse.Namespace(dry_run=False, allow_dirty=False), already_released=False
    )

    assert ("git", "add", "-A") not in calls
    assert any(c[:3] == ("git", "add", "--") for c in calls)
    assert (sys.executable, "scripts/security/secret_scan.py", "--staged") in calls
    assert ("git", "diff", "--cached", "--name-only") in calls
    assert ("git", "commit", "-m", "Release v1.2.3") in calls
    assert ("git", "tag", "-a", "v1.2.3", "-m", "Substation v1.2.3") in calls
    # Secret scan must run after staging and before commit.
    scan_i = calls.index((sys.executable, "scripts/security/secret_scan.py", "--staged"))
    commit_i = calls.index(("git", "commit", "-m", "Release v1.2.3"))
    assert scan_i < commit_i


def test_release_aborts_if_staged_secret_scan_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(cmd: list[str], *, dry_run: bool = False) -> None:
        calls.append(tuple(cmd))
        if cmd == [sys.executable, "scripts/security/secret_scan.py", "--staged"]:
            raise release.ReleaseError("command failed (1): secret scan")

    monkeypatch.setattr(release, "_run", fake_run)

    with pytest.raises(release.ReleaseError, match="secret scan"):
        release._commit_and_tag(
            "1.2.3", argparse.Namespace(dry_run=False, allow_dirty=False), already_released=False
        )

    assert ("git", "add", "-A") not in calls
    assert any(c[:3] == ("git", "add", "--") for c in calls)
    assert calls[-1] == (sys.executable, "scripts/security/secret_scan.py", "--staged")


def test_retry_refuses_generated_drift_before_building(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _release_repo(tmp_path, monkeypatch)
    monkeypatch.setattr(release, "_read_version", lambda: "1.2.3")
    monkeypatch.setattr(
        release,
        "_regenerate_artifacts",
        lambda _args: (tmp_path / "README.md").write_text("different generated artifact\n"),
    )
    builds: list[object] = []
    monkeypatch.setattr(release, "_build_distributions", builds.append)
    assert release.main(["--version", "1.2.3", "--skip-gate"]) == 1
    assert builds == []


def test_allow_dirty_cannot_hide_unrelated_staged_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _release_repo(tmp_path, monkeypatch)
    outside = tmp_path / "unrelated.txt"
    outside.write_text("original\n")
    release._git("add", "unrelated.txt")
    release._git("commit", "-m", "fixture")
    outside.write_text("staged change\n")
    release._git("add", "unrelated.txt")
    outside.write_text("original\n")
    with pytest.raises(release.ReleaseError, match="outside release paths"):
        release._check_release_tree("1.2.4", "1.2.3", False, True)
