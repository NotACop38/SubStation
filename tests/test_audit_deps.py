"""Tests for the product-scoped dependency audit wrapper."""

from __future__ import annotations

import subprocess

import pytest
from scripts.security import audit_deps


def test_audit_deps_fails_closed_when_resolver_crashes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="Traceback: ensurepip died")

    monkeypatch.setattr(audit_deps, "_pinned_requirements", lambda: ["PyYAML==6.0.3"])
    monkeypatch.setattr(audit_deps, "_run", fake_run)

    assert audit_deps.main() == 2

    assert len(calls) == 1
    assert "-r" in calls[0]
    assert "--path" not in calls[0]
    captured = capsys.readouterr()
    assert "pip-audit could not complete" in captured.err
    assert "fallback" not in captured.out
    assert "fallback" not in captured.err
