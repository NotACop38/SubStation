"""The patched-parser builder verifies and preserves supplied source checkouts."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.verify import build_s7


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "source"
    path.mkdir()
    for args in (
        ["init", "--quiet"],
        ["config", "user.name", "Synthetic Test"],
        ["config", "user.email", "synthetic@example.test"],
        ["commit", "--allow-empty", "--quiet", "-m", "Synthetic source"],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603,S607
    return path


def test_wrong_source_revision_fails_before_output_creation(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "build-output"
    monkeypatch.setattr("sys.argv", ["build_s7.py", "--source", str(source), "--out", str(out)])
    with pytest.raises(ValueError, match="qualified upstream commit"):
        build_s7.main()
    assert not out.exists()


def test_dirty_source_is_rejected_without_altering_it(
    source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = build_s7.run("git", "-C", str(source), "rev-parse", "HEAD").decode().strip()
    monkeypatch.setattr(build_s7, "PIN", pin)
    build_s7.verify_source(source)
    sentinel = source / "local-change.txt"
    sentinel.write_text("retain local changes\n")
    with pytest.raises(ValueError, match="must be clean"):
        build_s7.verify_source(source)
    assert sentinel.read_text() == "retain local changes\n"


def test_output_inside_source_is_rejected_before_writing(
    source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = source / "build-output"
    monkeypatch.setattr("sys.argv", ["build_s7.py", "--source", str(source), "--out", str(out)])
    with pytest.raises(ValueError, match="outside the original"):
        build_s7.main()
    assert not out.exists()
