"""Golden S7 fields and documentation must match the independently checked model."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from scripts import s7_examples

ROOT = Path(__file__).resolve().parents[1]


def test_s7_golden_and_documentation_match_generated_output() -> None:
    for path, expected in s7_examples.rendered(ROOT).items():
        assert path.read_text() == expected, f"stale S7 artifact: {path}"


def test_drift_check_fails_without_rewriting_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for relative in (
        "docs/schema.md",
        "tests/data/fidelity/s7/operations.yaml",
        "tests/data/events/s7/valid.jsonl",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    golden = tmp_path / "tests/data/events/s7/valid.jsonl"
    golden.write_text("{}\n")
    monkeypatch.setattr(s7_examples, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["s7_examples.py"])
    assert s7_examples.main() == 1
    assert golden.read_text() == "{}\n"
    monkeypatch.setattr("sys.argv", ["s7_examples.py", "--write"])
    assert s7_examples.main() == 0
    for path, expected in s7_examples.rendered(tmp_path).items():
        assert path.read_text() == expected
