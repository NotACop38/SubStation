"""Tests for the metadata-driven coverage generator (substation.coverage)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET  # noqa: S405 - parses our own generated SVG
from dataclasses import replace
from pathlib import Path

import pytest
from substation.coverage import __main__ as coverage_main
from substation.coverage import svg
from substation.coverage.builder import (
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    NAVIGATOR_FILENAME,
    SVG_FILENAME,
    render_all,
    render_navigator_layer,
)
from substation.detect.registry import ICS_TACTICS, load_registry

REGISTRY = load_registry()


def test_render_all_emits_four_artifacts() -> None:
    artifacts = render_all()
    assert set(artifacts) == {MARKDOWN_FILENAME, JSON_FILENAME, NAVIGATOR_FILENAME, SVG_FILENAME}


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


_SVG_NS = "{http://www.w3.org/2000/svg}"


def test_svg_columns_follow_the_canonical_tactic_order() -> None:
    assert [tid for tid, _ in svg._TACTIC_LABELS] == [tid for tid, _ in ICS_TACTICS]
    for (tid, lines), (_, name) in zip(svg._TACTIC_LABELS, ICS_TACTICS, strict=True):
        assert " ".join(lines) == name, tid


def test_svg_is_well_formed_and_shows_every_detection_once() -> None:
    root = ET.fromstring(render_all()[SVG_FILENAME])  # noqa: S314 - trusted, generated input
    assert root.tag == f"{_SVG_NS}svg"
    texts = [node.text for node in root.iter(f"{_SVG_NS}text")]
    for det in REGISTRY:
        assert texts.count(det.id) == 1, det.id
    covered = len({det.attack.tactic_id for det in REGISTRY})
    assert f"{covered}/{len(ICS_TACTICS)}" in texts
    assert str(len(REGISTRY)) in texts


def test_svg_rejects_content_it_cannot_place() -> None:
    with pytest.raises(ValueError, match="protocol"):
        svg.render_svg([replace(REGISTRY[0], protocol="bacnet")])


def test_coverage_requires_out_outside_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(coverage_main, "_CHECKOUT_OUT", tmp_path / "absent")
    monkeypatch.chdir(tmp_path)
    assert coverage_main.main([]) == 1
    assert "--out is required" in capsys.readouterr().err
    assert not (tmp_path / "docs").exists()
