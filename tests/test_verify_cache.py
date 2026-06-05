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
