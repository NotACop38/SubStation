"""Tests for the local release helper."""

from __future__ import annotations

import argparse
import sys

import pytest
from scripts.release import run as release


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

    release._commit_and_tag("1.2.3", argparse.Namespace(dry_run=False), already_released=False)

    assert calls == [
        ("git", "add", "-A"),
        (sys.executable, "scripts/security/secret_scan.py"),
        ("git", "diff", "--cached", "--name-only"),
        ("git", "commit", "-m", "Release v1.2.3"),
        ("git", "tag", "-a", "v1.2.3", "-m", "Substation v1.2.3"),
    ]


def test_release_aborts_if_staged_secret_scan_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(cmd: list[str], *, dry_run: bool = False) -> None:
        calls.append(tuple(cmd))
        if cmd == [sys.executable, "scripts/security/secret_scan.py"]:
            raise release.ReleaseError("command failed (1): secret scan")

    monkeypatch.setattr(release, "_run", fake_run)

    with pytest.raises(release.ReleaseError, match="secret scan"):
        release._commit_and_tag("1.2.3", argparse.Namespace(dry_run=False), already_released=False)

    assert calls == [
        ("git", "add", "-A"),
        (sys.executable, "scripts/security/secret_scan.py"),
    ]
