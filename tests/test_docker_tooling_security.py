"""Security regressions for Docker-backed local validation tooling."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_gitleaks_docker_uses_digest_pin_and_read_only_repo_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_scan = _load_module(
        "substation_secret_scan_test", _REPO_ROOT / "scripts" / "security" / "secret_scan.py"
    )
    recorded_cmd: list[str] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal recorded_cmd
        recorded_cmd = cmd
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(secret_scan, "_docker_usable", lambda: True)
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert secret_scan._run_gitleaks_docker() == 0

    image = secret_scan.GITLEAKS_DOCKER_IMAGE
    assert "@sha256:" in image
    assert ":latest" not in image
    assert image in recorded_cmd
    assert f"{_REPO_ROOT}:/repo:ro" in recorded_cmd


def test_zeek_verifier_uses_digest_pinned_image() -> None:
    verify_run = _load_module(
        "substation_verify_run_test", _REPO_ROOT / "scripts" / "verify" / "run.py"
    )

    image = verify_run.ZEEK_IMAGE
    assert "@sha256:" in image
    assert ":latest" not in image
