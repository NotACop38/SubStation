"""Tests for the Phase-0 end-to-end no-op pipeline (generate -> detect -> report)."""

from __future__ import annotations

from pathlib import Path

from substation import cli
from substation.coverage import render_coverage_map
from substation.detect import Hit, run_detections
from substation.emit import write_artifacts
from substation.scenarios import load_scenario

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"


def test_emit_writes_empty_artifacts(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)
    assert result.pcap.exists() and result.jsonl.exists()
    assert result.pcap.read_bytes() == b""
    assert result.jsonl.read_text(encoding="utf-8") == ""
    assert result.event_count == 0
    assert result.pcap.name == "benign-poll.pcap"


def test_detect_returns_no_hits_on_empty_log(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)
    assert run_detections(result.jsonl) == []


def test_detect_handles_missing_file(tmp_path: Path) -> None:
    assert run_detections(tmp_path / "nope.jsonl") == []


def test_coverage_map_lists_exercised_detections() -> None:
    scenario = load_scenario(_EXAMPLE)
    out = render_coverage_map([scenario], [])
    assert "M1" in out and "M2" in out and "M3" in out
    assert "no hits" in out


def test_coverage_map_marks_fired() -> None:
    scenario = load_scenario(_EXAMPLE)
    out = render_coverage_map([scenario], [Hit(detection_id="M1", event_index=0)])
    fired_line = next(line for line in out.splitlines() if line.strip().startswith("M1"))
    assert "FIRED" in fired_line


def test_demo_exercises_every_stage(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["demo", "--scenario", str(_EXAMPLE), "--artifacts", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    for stage in ("[load]", "[generate]", "[detect]", "[report]"):
        assert stage in out
    assert (tmp_path / "benign-poll.jsonl").exists()


def test_demo_bad_scenario_returns_error(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nprotocol: nope\nlabel: benign\nactors: []\n", encoding="utf-8")
    rc = cli.main(["demo", "--scenario", str(bad), "--artifacts", str(tmp_path)])
    assert rc == 1
    assert "error:" in capsys.readouterr().err
