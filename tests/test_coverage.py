"""Tests for the metadata-driven coverage generator (substation.coverage)."""

from __future__ import annotations

import json
from pathlib import Path

from substation.coverage import __main__ as coverage_main
from substation.coverage.builder import (
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    NAVIGATOR_FILENAME,
    render_all,
    render_navigator_layer,
)
from substation.detect.registry import load_registry

REGISTRY = load_registry()


def test_render_all_emits_three_artifacts() -> None:
    artifacts = render_all()
    assert set(artifacts) == {MARKDOWN_FILENAME, JSON_FILENAME, NAVIGATOR_FILENAME}


def test_markdown_table_has_every_detection() -> None:
    md = render_all()[MARKDOWN_FILENAME]
    for det in REGISTRY:
        assert det.id in md
        assert det.attack.primary.id in md
    # Header columns the task specifies are present.
    for column in ("Technique", "Tactic", "Protocol", "Engine", "Status"):
        assert column in md


def test_json_table_round_trips_and_matches_registry() -> None:
    doc = json.loads(render_all()[JSON_FILENAME])
    assert doc["domain"] == "ics-attack"
    assert doc["detection_count"] == len(REGISTRY)
    ids = [row["id"] for row in doc["detections"]]
    assert ids == [det.id for det in REGISTRY]


def test_navigator_layer_is_valid_and_scoped_to_ics() -> None:
    layer = json.loads(render_navigator_layer(REGISTRY))
    assert layer["domain"] == "ics-attack"
    assert "versions" in layer and "layer" in layer["versions"]
    # Every registry technique appears as a Navigator technique object.
    layer_ids = {t["techniqueID"] for t in layer["techniques"]}
    expected = {tech.id for det in REGISTRY for tech in det.attack.techniques}
    assert expected <= layer_ids
    for technique in layer["techniques"]:
        assert technique["score"] >= 1
        assert technique["tactic"]  # a tactic shortname for placement


def test_render_is_deterministic() -> None:
    assert render_all() == render_all()


def test_check_mode_passes_when_fresh_and_fails_when_stale(tmp_path: Path) -> None:
    # Fresh write -> --check passes.
    assert coverage_main.main(["--out", str(tmp_path)]) == 0
    assert coverage_main.main(["--check", "--out", str(tmp_path)]) == 0

    # Corrupt one artifact -> --check reports drift.
    (tmp_path / MARKDOWN_FILENAME).write_text("stale\n", encoding="utf-8")
    assert coverage_main.main(["--check", "--out", str(tmp_path)]) == 1

    # Missing directory -> --check reports drift (nothing committed yet).
    assert coverage_main.main(["--check", "--out", str(tmp_path / "absent")]) == 1
