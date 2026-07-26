"""Tests for the end-to-end Tier-1 pipeline (generate -> detect -> report)."""

from __future__ import annotations

from pathlib import Path

import pytest
from substation import cli
from substation.coverage import render_coverage_map
from substation.detect import Hit, run_detections
from substation.emit import write_artifacts
from substation.scenarios import load_scenario

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"


def test_emit_writes_modbus_artifacts(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)
    assert result.pcap.exists() and result.jsonl.exists()
    assert result.pcap.read_bytes()  # a real Modbus/TCP capture, not an empty file
    assert result.event_count > 0
    assert len(result.jsonl.read_text(encoding="utf-8").splitlines()) == result.event_count
    assert result.pcap.name == "benign-poll.pcap"


def test_detect_stays_quiet_on_benign(tmp_path: Path) -> None:
    # The bundled poll is benign, so the shipped Sigma detections must stay quiet
    # on it (the low-false-positive baseline) even though the JSON log carries real
    # Modbus events.
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)
    assert run_detections(result.jsonl) == []


def test_detect_raises_on_missing_log(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_detections(tmp_path / "nope.jsonl")


def test_coverage_map_lists_registry_detections() -> None:
    # The coverage map is registry-driven: it shows every shipped detection (not
    # just the loaded scenario's), with a summary and no "FIRED" markers when no
    # hits are passed.
    scenario = load_scenario(_EXAMPLE)
    out = render_coverage_map([scenario], [])
    assert "ATT&CK-for-ICS coverage map" in out
    assert "M1" in out and "M2" in out and "M3" in out and "X1" in out
    assert "0 fired this run" in out
    assert "● FIRED" not in out


def test_coverage_map_marks_fired() -> None:
    scenario = load_scenario(_EXAMPLE)
    out = render_coverage_map([scenario], [Hit(detection_id="M1", event_index=0)])
    fired_line = next(line for line in out.splitlines() if line.strip().startswith("M1"))
    assert "FIRED" in fired_line


def test_coverage_map_marks_tier2_as_not_run_not_quiet() -> None:
    # benign-baseline lists M3/X1 under exercises.quiet, but Tier-1 never evaluates
    # them — the map must show not-run, not a misleading "quiet".
    scenario = load_scenario(_REPO_ROOT / "scenarios" / "modbus" / "benign-baseline.yaml")
    out = render_coverage_map([scenario], [])
    m3 = next(line for line in out.splitlines() if line.strip().startswith("M3"))
    x1 = next(line for line in out.splitlines() if line.strip().startswith("X1"))
    assert "not-run" in m3 and "quiet" not in m3
    assert "not-run" in x1 and "quiet" not in x1
    m1 = next(line for line in out.splitlines() if line.strip().startswith("M1"))
    assert "quiet" in m1


def test_demo_single_scenario_runs_end_to_end(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["demo", "--scenario", str(_EXAMPLE), "--artifacts", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "generate -> detect -> report" in out
    assert "ATT&CK-for-ICS coverage map" in out
    assert "benign-poll" in out
    assert (tmp_path / "benign-poll.jsonl").exists()


def test_demo_default_set_shows_quiet_and_fire(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    # The bundled demo set (no --scenario) must stay quiet on the benign baseline
    # AND fire real detections on the anomalies — Modbus + DNP3 (≥2 protocols).
    rc = cli.main(["demo", "--artifacts", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "quiet (no hits)" in out  # benign baseline stays quiet
    assert "● FIRED" in out  # at least one detection fired this run
    assert "anomalous-d1-restart" in out  # multi-protocol demo includes DNP3
    assert "fired 3 detection(s)" in out  # M1, M2, D1


def test_demo_bad_scenario_returns_error(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nprotocol: nope\nlabel: benign\nactors: []\n", encoding="utf-8")
    rc = cli.main(["demo", "--scenario", str(bad), "--artifacts", str(tmp_path)])
    assert rc == 1
    assert "error:" in capsys.readouterr().err


def test_demo_dnp3_oversized_range_returns_error_without_artifacts(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "dnp3-oversized.yaml"
    bad.write_text(
        """
name: dnp3-oversized
protocol: dnp3
label: benign
actors:
  - {id: m, role: master, host: 10.0.1.10}
  - {id: r, role: outstation, host: 10.0.1.50, port: 20000}
exchanges:
  - source: m
    target: r
    function: Read
    params:
      object_type: Binary Input With Status
      range_low: 0
      range_high: 255
      object_count: 256
""".lstrip(),
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    rc = cli.main(["demo", "--scenario", str(bad), "--artifacts", str(artifacts)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "single-frame DNP3 PCAP limit" in captured.err
    assert not (artifacts / "dnp3-oversized.jsonl").exists()
    assert not (artifacts / "dnp3-oversized.pcap").exists()
