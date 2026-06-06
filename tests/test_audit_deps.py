"""Tests for the product-scoped dependency audit wrapper."""

from __future__ import annotations

import subprocess

import pytest
from scripts.security import audit_deps


def test_audit_deps_falls_back_to_installed_path_when_resolver_crashes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if "-r" in cmd:
            return subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr="Traceback: ensurepip died"
            )
        return subprocess.CompletedProcess(
            cmd, 0, stdout="No known vulnerabilities found", stderr=""
        )

    monkeypatch.setattr(audit_deps, "_pinned_requirements", lambda: ["PyYAML==6.0.3"])
    monkeypatch.setattr(audit_deps, "_run", fake_run)
    monkeypatch.setattr(audit_deps, "_site_packages_path", lambda: "/opt/substation/site-packages")

    assert audit_deps.main() == 0

    assert len(calls) == 2
    assert "-r" in calls[0]
    assert "--path" in calls[1]
    captured = capsys.readouterr()
    assert "pip-audit resolver failed before completing" in captured.err
    assert "fallback OK" in captured.out
