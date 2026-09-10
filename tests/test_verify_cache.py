"""Regression coverage for Tier-2 ICSNPP cache handling."""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from typing import Any

import pytest

verify_run: Any = importlib.import_module("scripts.verify.run")


def test_drifted_icsnpp_cache_is_recloned_before_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    dest = cache / "icsnpp-modbus"
    old_hook = dest / ".git" / "hooks" / "post-checkout"
    old_hook.parent.mkdir(parents=True)
    old_hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (dest / "scripts").mkdir()

    monkeypatch.setattr(verify_run, "_CACHE", cache)
    monkeypatch.setattr(
        verify_run, "_ICSNPP", {"modbus": ("https://example.test/modbus", "abc123")}
    )
    monkeypatch.setattr(verify_run, "_at_commit", lambda _dest, _commit: False)

    def fake_run(cmd: list[str], *_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert cmd[:2] == ["git", "clone"]
        assert cmd[3] == str(dest)
        (dest / ".git").mkdir(parents=True)
        (dest / "scripts").mkdir()
        return subprocess.CompletedProcess(cmd, 0)

    def fake_checkout(checkout_dest: Path, commit: str) -> bool:
        assert checkout_dest == dest
        assert commit == "abc123"
        assert not old_hook.exists()
        return True

    monkeypatch.setattr("scripts.verify.run.subprocess.run", fake_run)
    monkeypatch.setattr(verify_run, "_checkout", fake_checkout)

    assert verify_run.ensure_icsnpp("modbus") == dest / "scripts"
    assert not old_hook.exists()


def test_cache_at_correct_commit_still_rejects_modified_parser(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.run(  # noqa: S603,S607
            ["git", *args],  # noqa: S607
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,  # noqa: S607
        ).stdout.strip()

    git("init")
    git("config", "user.name", "Synthetic Test")
    git("config", "user.email", "synthetic@example.test")
    source = tmp_path / "main.zeek"
    source.write_text("# parser fixture\n")
    git("add", "main.zeek")
    git("commit", "-m", "fixture")
    pinned = git("rev-parse", "HEAD")
    assert verify_run._at_commit(tmp_path, pinned)
    source.write_text("# changed parser\n")
    assert not verify_run._at_commit(tmp_path, pinned)
    git("restore", "main.zeek")
    (tmp_path / "extra.zeek").write_text("# injected script\n")
    assert not verify_run._at_commit(tmp_path, pinned)


@pytest.mark.parametrize("failing_probe", [0, 1])
def test_s7_plugin_probe_honors_failed_exit_status(
    monkeypatch: pytest.MonkeyPatch, failing_probe: int
) -> None:
    calls: list[list[str]] = []

    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert "shell" not in kwargs
        return subprocess.CompletedProcess(
            cmd,
            int(len(calls) - 1 == failing_probe),
            stdout="ICSNPP::S7comm (substation-bounds-v1)",
            stderr="",
        )

    monkeypatch.setattr(verify_run, "_NATIVE_ZEEK", "zeek")
    monkeypatch.setattr(verify_run.subprocess, "run", run)
    assert verify_run._s7_plugin_probe("unused") == (False, [])
    assert len(calls) == failing_probe + 1


def test_s7_plugin_requires_reviewed_bounds_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verify_run, "_NATIVE_ZEEK", "zeek")
    monkeypatch.setattr(
        verify_run.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, stdout="ICSNPP::S7comm", stderr=""
        ),
    )
    assert verify_run._s7_plugin_probe("unused") == (False, [])
