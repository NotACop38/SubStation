"""Tests for the CLI front door: --version, list, validate, coverage, demo flags."""

from __future__ import annotations

from pathlib import Path

import pytest
import substation
from substation import cli

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENIGN = _REPO_ROOT / "scenarios" / "modbus" / "benign-baseline.yaml"
_ANOMALOUS_M1 = _REPO_ROOT / "scenarios" / "modbus" / "anomalous-m1-unauthorized-write.yaml"

# A syntactically valid scenario whose exercises contract is WRONG: a plain read
# can never fire M1 (the unauthorized-write rule), so `demo --strict` must fail.
_BROKEN_CONTRACT_YAML = """\
name: broken-contract
description: claims M1 fires on a read; the strict demo must catch the lie
protocol: modbus
label: anomalous
actors:
  - id: hmi-1
    role: hmi
    host: 10.0.0.10
  - id: plc-1
    role: plc
    host: 10.0.0.50
exchanges:
  - source: hmi-1
    target: plc-1
    function: ReadHoldingRegisters
    params: { unit_id: 1, address: 0, quantity: 2 }
exercises:
  fires: ["M1"]
"""


def test_version_flag_prints_package_version(capsys) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert substation.__version__ in capsys.readouterr().out


def test_list_shows_detections_and_scenarios(capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    # Every registered detection and every bundled scenario tree is listed.
    for det_id in ("M1", "M2", "M3", "D1", "D4", "S1", "S3", "X1"):
        assert f"  {det_id} " in out
    assert "benign-baseline" in out
    assert "dnp3-benign-baseline" in out
    assert "s7-benign-baseline" in out


def test_demo_accepts_multiple_scenarios(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(
        ["demo", "--scenario", str(_BENIGN), str(_ANOMALOUS_M1), "--artifacts", str(tmp_path)]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "benign-baseline" in out
    assert "anomalous-m1-unauthorized-write" in out
    assert "FIRED" in out  # the anomaly fires
    assert (tmp_path / "benign-baseline.jsonl").exists()
    assert (tmp_path / "anomalous-m1-unauthorized-write.jsonl").exists()


def test_demo_strict_passes_on_bundled_set(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["demo", "--strict", "--artifacts", str(tmp_path)])
    assert rc == 0
    assert "Strict contract check: OK" in capsys.readouterr().out


def test_demo_strict_fails_on_broken_contract(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    scenario = tmp_path / "broken-contract.yaml"
    scenario.write_text(_BROKEN_CONTRACT_YAML, encoding="utf-8")
    rc = cli.main(["demo", "--strict", "--scenario", str(scenario), "--artifacts", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Strict contract check FAILED" in err
    assert "expected M1 to fire but it stayed quiet" in err


def test_validate_defaults_to_golden_events(capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["validate"])
    assert rc == 0
    assert "schema: OK" in capsys.readouterr().out


def test_validate_flags_violations(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"not": "an event"}\n', encoding="utf-8")
    rc = cli.main(["validate", str(bad)])
    assert rc == 1
    assert "FAILED" in capsys.readouterr().err


def test_coverage_check_passes_on_committed_snapshot(capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["coverage", "--check", "--out", str(_REPO_ROOT / "docs" / "coverage")])
    assert rc == 0
    assert "up to date" in capsys.readouterr().out


def test_coverage_writes_artifacts(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rc = cli.main(["coverage", "--out", str(tmp_path)])
    assert rc == 0
    for name in ("coverage.md", "coverage.json", "navigator-layer.json"):
        assert (tmp_path / name).exists()
