"""Tests for the product-scoped dependency audit wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.security import audit_deps


def test_audit_deps_fails_closed_without_a_lockfile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(audit_deps, "_pinned_requirements", lambda: ["PyYAML==6.0.3"])
    monkeypatch.setattr(audit_deps, "_LOCKFILE", Path("/nonexistent/requirements.lock"))
    monkeypatch.setattr(audit_deps, "_run", lambda cmd: calls.append(cmd))
    assert audit_deps.main() == 2
    assert calls == []
    assert "FAILED" in capsys.readouterr().err


def test_audit_deps_audits_the_committed_lockfile_strictly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "PyYAML==6.0.3 --hash=sha256:" + "a" * 64 + "\n"
        "typing_extensions==4.15.0 --hash=sha256:" + "b" * 64 + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        return subprocess.CompletedProcess(
            cmd, 0, stdout="No known vulnerabilities found", stderr=""
        )

    monkeypatch.setattr(audit_deps, "_pinned_requirements", lambda: ["PyYAML==6.0.3"])
    monkeypatch.setattr(audit_deps, "_LOCKFILE", lock)
    monkeypatch.setattr(audit_deps, "_run", fake_run)

    assert audit_deps.main() == 0
    assert len(calls) == 1
    assert calls[0][1:3] == ["-m", "pip_audit"]
    assert {"--strict", "--require-hashes", "--disable-pip", str(lock)} <= set(calls[0])
    assert "2 locked package(s) from requirements.lock" in capsys.readouterr().out


@pytest.mark.parametrize(
    "locked",
    [["PyYAML==6.0.2"], ["unrelated==1.0"], ["PyYAML>=6"], ["PyYAML==6.0.3", "pyyaml==6.0.3"]],
)
def test_dependency_audit_rejects_lock_drift(locked: list[str]) -> None:
    with pytest.raises(ValueError):
        audit_deps._check_locked_requirements(["PyYAML==6.0.3"], locked)
