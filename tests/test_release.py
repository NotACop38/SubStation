"""Tests for the local release pipeline (scripts/release/run.py)."""

from __future__ import annotations

import argparse
import os
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest
from scripts.release import run as release

_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

_CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- Something users will notice.

## [1.2.3] - 2026-01-01

- Earlier notes.

[Unreleased]: https://example.test/compare/v1.2.3...HEAD
"""

_PYPROJECT = """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "fixture-project"
version = "1.2.3"

[tool.setuptools]
packages = ["fixture"]
"""


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=_GIT_ENV,
    )
    return result.stdout.strip()


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A buildable, committed project with the release paths the pipeline writes."""
    repo = tmp_path / "project"
    (repo / "fixture").mkdir(parents=True)
    (repo / "fixture/__init__.py").write_text("VALUE = 1\n")
    (repo / "pyproject.toml").write_text(_PYPROJECT)
    (repo / "CHANGELOG.md").write_text(_CHANGELOG)
    (repo / "docs/coverage").mkdir(parents=True)
    (repo / "docs/coverage/coverage.md").write_text("coverage v1\n")
    (repo / "docs/demo-output.txt").write_text("demo v1\n")
    (repo / ".gitignore").write_text("build/\ndist/\n")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fixture")
    _git(repo, "tag", "v1.2.3")
    monkeypatch.setattr(release, "_REPO_ROOT", repo)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(release, "_gate", lambda args: None)
    monkeypatch.setattr(release, "_scan_staged", lambda: None)

    def regenerate() -> None:
        (repo / "docs/coverage/coverage.md").write_text("coverage v2\n")
        (repo / "docs/coverage/new-artifact.json").write_text("{}\n")
        (repo / "docs/demo-output.txt").write_text("demo v2\n")

    monkeypatch.setattr(release, "_regenerate", regenerate)
    return repo


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {"version": None, "bump": None}
    values.update(overrides)
    return argparse.Namespace(**values)


def test_target_version() -> None:
    assert release._target_version(_args(bump="minor"), "0.1.9") == "0.2.0"
    assert release._target_version(_args(bump="major"), "0.1.9") == "1.0.0"
    assert release._target_version(_args(bump="patch"), "0.1.9") == "0.1.10"
    assert release._target_version(_args(version="0.1.9"), "0.1.9") == "0.1.9"
    with pytest.raises(release.ReleaseError, match="older than the current version"):
        release._target_version(_args(version="0.1.8"), "0.1.9")
    with pytest.raises(release.ReleaseError, match="not a SemVer"):
        release._target_version(_args(version="1.0"), "0.1.9")


def test_a_version_target_is_required() -> None:
    with pytest.raises(SystemExit):
        release._build_parser().parse_args([])


def test_changelog_promotion_keeps_history_and_link_references(project: Path) -> None:
    release._promote_changelog("1.3.0", "2026-09-26")
    text = (project / "CHANGELOG.md").read_text()
    assert text.startswith(
        "# Changelog\n\n## [Unreleased]\n\n## [1.3.0] - 2026-09-26\n\n### Fixed\n\n"
        "- Something users will notice.\n\n## [1.2.3] - 2026-01-01\n"
    )
    assert text.endswith("[Unreleased]: https://example.test/compare/v1.2.3...HEAD\n")


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (lambda repo: (repo / "fixture/__init__.py").write_text("VALUE = 2\n"), "not clean"),
        (lambda repo: (repo / "stray.txt").write_text("x\n"), "not clean"),
        (lambda repo: _git(repo, "tag", "v1.3.0"), "already exists"),
    ],
    ids=["tracked-edit", "untracked-file", "existing-tag"],
)
def test_preflight_refusals(
    project: Path,
    setup: Callable[[Path], object],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    setup(project)
    assert release.main(["--version", "1.3.0"]) == 1
    assert message in capsys.readouterr().err
    assert 'version = "1.2.3"' in (project / "pyproject.toml").read_text()


def test_preflight_refuses_empty_release_notes(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    changelog = project / "CHANGELOG.md"
    changelog.write_text(
        changelog.read_text().replace("### Fixed\n\n- Something users will notice.\n\n", "")
    )
    _git(project, "commit", "-q", "-am", "notes consumed")
    assert release.main(["--version", "1.3.0"]) == 1
    assert "[Unreleased] is empty" in capsys.readouterr().err


def test_dry_run_changes_nothing(project: Path) -> None:
    head = _git(project, "rev-parse", "HEAD")
    assert release.main(["--bump", "minor", "--dry-run"]) == 0
    assert _git(project, "rev-parse", "HEAD") == head
    assert _git(project, "status", "--porcelain") == ""
    assert _git(project, "tag", "--list", "v1.3.0") == ""


def test_a_failed_build_rolls_back_and_the_same_command_reruns(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_build = release._build

    def broken_build(version: str) -> list[Path]:
        raise release.ReleaseError("build backend exploded")

    monkeypatch.setattr(release, "_build", broken_build)
    head = _git(project, "rev-parse", "HEAD")
    assert release.main(["--version", "1.3.0"]) == 1
    assert _git(project, "rev-parse", "HEAD") == head
    assert _git(project, "status", "--porcelain") == ""
    assert _git(project, "tag", "--list", "v1.3.0") == ""

    monkeypatch.setattr(release, "_build", real_build)
    assert release.main(["--version", "1.3.0"]) == 0
    assert _git(project, "rev-parse", "HEAD~1") == head


def test_release_builds_the_committed_tree_and_tags_it(project: Path) -> None:
    # A stale file in an ignored build/ directory must not reach the wheel.
    (project / "build/lib/fixture").mkdir(parents=True)
    (project / "build/lib/fixture/stale.py").write_text("STALE = True\n")
    assert release.main(["--bump", "minor"]) == 0

    assert _git(project, "status", "--porcelain") == ""
    assert _git(project, "log", "-1", "--format=%s") == "Release v1.3.0"
    assert _git(project, "rev-parse", "v1.3.0^{commit}") == _git(project, "rev-parse", "HEAD")
    assert _git(project, "cat-file", "-t", "v1.3.0") == "tag"
    assert 'version = "1.3.0"' in _git(project, "show", "HEAD:pyproject.toml")
    assert "## [1.3.0] - " in _git(project, "show", "HEAD:CHANGELOG.md")
    assert _git(project, "show", "HEAD:docs/coverage/new-artifact.json") == "{}"

    [sdist] = (project / "dist").glob("*-1.3.0.tar.gz")
    [wheel] = (project / "dist").glob("*-1.3.0-py3-none-any.whl")
    assert sdist.is_file()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "fixture/__init__.py" in names
    assert "fixture/stale.py" not in names
