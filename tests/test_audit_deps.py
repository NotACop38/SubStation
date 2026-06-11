"""Tests for the product-scoped dependency audit wrapper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from scripts.security import audit_deps


def test_audit_deps_resolves_closure_before_auditing_without_pip_fallback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []
    resolved_inputs: list[str] = []

    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if "pip" in cmd:
            report = Path(cmd[cmd.index("--report") + 1])
            report.write_text(
                json.dumps(
                    {
                        "install": [
                            {"metadata": {"name": "PyYAML", "version": "6.0.3"}},
                            {
                                "metadata": {
                                    "name": "typing_extensions",
                                    "version": "4.15.0",
                                }
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        resolved_inputs.append(Path(cmd[cmd.index("-r") + 1]).read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(
            cmd, 0, stdout="No known vulnerabilities found", stderr=""
        )

    monkeypatch.setattr(audit_deps, "_pinned_requirements", lambda: ["PyYAML==6.0.3"])
    monkeypatch.setattr(audit_deps, "_run", fake_run)

    assert audit_deps.main() == 0

    assert len(calls) == 2
    assert calls[0][1:4] == ["-m", "pip", "install"]
    assert "--dry-run" in calls[0]
    assert "--ignore-installed" in calls[0]
    assert calls[1][1:3] == ["-m", "pip_audit"]
    assert "--no-deps" in calls[1]
    assert "--disable-pip" in calls[1]
    assert "--path" not in calls[1]
    assert "PyYAML==6.0.3" in resolved_inputs[0]
    assert "typing_extensions==4.15.0" in resolved_inputs[0]
    captured = capsys.readouterr()
    assert "fallback" not in captured.out
    assert "fallback" not in captured.err


def test_audit_deps_fails_closed_when_dependency_resolver_crashes(
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
    assert "dependency resolver could not complete" in captured.err
    assert "fallback" not in captured.out
    assert "fallback" not in captured.err
