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


def test_image_tag_is_stable_and_tracks_every_build_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = "zeek/zeek:8.2@sha256:" + "0" * 64
    tag = build_s7.image_tag(base)
    assert tag == build_s7.image_tag(base)
    assert tag.startswith(f"{build_s7.IMAGE_REPOSITORY}:")
    assert build_s7.image_tag(base.replace("0", "1")) != tag

    for name in ("PATCH", "DOCKERFILE"):
        changed = tmp_path / name
        changed.write_bytes(getattr(build_s7, name).read_bytes() + b"\n# changed\n")
        with monkeypatch.context() as patch:
            patch.setattr(build_s7, name, changed)
            assert build_s7.image_tag(base) != tag


def test_image_build_context_holds_only_the_prepared_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_prepare(dest: Path, upstream: Path, *, fetch: bool) -> None:
        dest.mkdir()
        (dest / "CMakeLists.txt").write_text("project(x)\n")
        seen["fetch"] = fetch

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        context = Path(argv[-1])
        seen["context"] = sorted(p.name for p in context.iterdir())
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(build_s7, "prepare_source", fake_prepare)
    monkeypatch.setattr(subprocess, "run", fake_run)
    base = "zeek/zeek:8.2@sha256:" + "a" * 64
    tag = build_s7.build_image(base)

    argv = seen["argv"]
    assert isinstance(argv, list)
    assert argv[:2] == ["docker", "build"]
    assert f"ZEEK_IMAGE={base}" in argv
    assert argv[argv.index("--tag") + 1] == tag == build_s7.image_tag(base)
    assert seen["context"] == ["source"]
    assert seen["fetch"] is True


def test_failed_image_build_reports_the_build_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build_s7, "prepare_source", lambda dest, upstream, *, fetch: dest.mkdir())
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **_: subprocess.CompletedProcess(argv, 1, "", "E: package not found"),
    )
    with pytest.raises(RuntimeError, match="package not found"):
        build_s7.build_image("zeek/zeek:8.2@sha256:" + "b" * 64)
