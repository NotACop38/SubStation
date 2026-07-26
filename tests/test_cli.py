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


def test_demo_strict_fails_on_unknown_detection_id(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A typo'd exercises id must FAIL strict mode, not be skipped as 'Tier 2'."""
    scenario = tmp_path / "typo-contract.yaml"
    scenario.write_text(_BROKEN_CONTRACT_YAML.replace('fires: ["M1"]', 'fires: ["M9"]'), "utf-8")
    rc = cli.main(["demo", "--strict", "--scenario", str(scenario), "--artifacts", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Strict contract check FAILED" in err
    assert "unknown detection 'M9'" in err


def test_demo_reports_s7_errors_cleanly(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """An S7 emission error prints the clean `error:` line, like Modbus/DNP3."""
    scenario = tmp_path / "bad-s7.yaml"
    scenario.write_text(
        """\
name: bad-s7
protocol: s7comm
label: benign
actors:
  - id: eng-1
    role: ews
    host: not-an-ip
  - id: plc-1
    role: plc
    host: 10.0.2.50
exchanges:
  - source: eng-1
    target: plc-1
    function: ReadSZL
""",
        encoding="utf-8",
    )
    rc = cli.main(["demo", "--scenario", str(scenario), "--artifacts", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "not an IPv4 address" in err


def test_demo_rejects_duplicate_scenario_names_in_one_run(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """Two files sharing a scenario name would silently overwrite artifacts."""
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    yaml_text = _BROKEN_CONTRACT_YAML.replace('fires: ["M1"]', "fires: []")
    first.write_text(yaml_text, encoding="utf-8")
    second.write_text(yaml_text, encoding="utf-8")
    rc = cli.main(["demo", "--scenario", str(first), str(second), "--artifacts", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "reuses scenario name 'broken-contract'" in err
    assert "first.yaml" in err


@pytest.mark.parametrize("command", [["list"], ["demo"], ["coverage", "--check"]])
def test_content_commands_explain_missing_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
) -> None:
    """When packaged/checkout content is missing, commands must explain how to fix it."""
    from substation.content import ContentError

    def _missing() -> Path:
        raise ContentError("cannot locate Substation detections/scenarios content")

    monkeypatch.setattr("substation.content.content_root", _missing)
    monkeypatch.setattr("substation.detect.registry.content_root", _missing)
    monkeypatch.setattr(
        "substation.detect.registry.content_path",
        lambda *parts: (_ for _ in ()).throw(ContentError("missing")),
    )
    rc = cli.main([*command, "--artifacts", str(tmp_path)] if command == ["demo"] else command)
    assert rc == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "wheel" in err or "checkout" in err


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


def test_pipe_closed_early_exits_quietly() -> None:
    """`substation list | head -0` must exit 141 with no traceback.

    The read end is closed BEFORE the child starts, so the EPIPE is
    deterministic regardless of pipe-buffer capacity or stdout buffering mode
    (the in-`try` flush guarantees the handler sees it even when block-buffered).
    """
    import os
    import subprocess
    import sys

    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "substation.cli", "list"],
        stdout=write_fd,
        stderr=subprocess.PIPE,
        cwd=str(_REPO_ROOT),
    )
    os.close(write_fd)
    _, stderr_bytes = proc.communicate(timeout=60)
    stderr = stderr_bytes.decode()
    assert proc.returncode == 141, f"expected quiet SIGPIPE exit, got {proc.returncode}: {stderr}"
    assert "Traceback" not in stderr and "Exception ignored" not in stderr, stderr
