"""Detection and CI must fail on invalid inputs, not silently report success."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from substation.cli import main as cli_main
from substation.detect import run_detections
from substation.emit import write_artifacts
from substation.scenarios import load_scenario
from substation.schema import SchemaValidationError, iter_jsonl_errors
from substation.schema.__main__ import main as schema_main


@pytest.mark.parametrize("line", ["null", "[]", "{}", "42", '{"ts":NaN}', '{"ts":0,"ts":1}'])
def test_detection_rejects_malformed_telemetry(tmp_path: Path, line: str) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_text(line + "\n")
    with pytest.raises(SchemaValidationError, match=r"invalid.jsonl:1:"):
        run_detections(path)


def test_schema_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.jsonl"
    path.write_text('{"proto":"modbus","proto":"dnp3"}\n')
    assert "duplicate JSON key" in " ".join(iter_jsonl_errors(path))


def test_schema_gate_requires_input_files(tmp_path: Path) -> None:
    assert schema_main([str(tmp_path)]) == 1


def test_detect_cli_evaluates_normalized_logs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Path(__file__).resolve().parents[1]
    scenario = load_scenario(repo / "scenarios/modbus/anomalous-m1-span-beyond-policy.yaml")
    emitted = write_artifacts(scenario, tmp_path)
    assert cli_main(["detect", str(emitted.jsonl), "--detection", "M1"]) == 0
    output = capsys.readouterr()
    assert '"event_index": 0' in output.out
    assert '"detection_id": "M1"' in output.out
    assert "Tier-2 rules not run" in output.err
    assert cli_main(["detect", str(emitted.jsonl), "--detection", "X1"]) == 1


def test_detect_cli_rejects_invalid_file_without_partial_results(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{}\n")
    assert cli_main(["detect", str(bad)]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "bad.jsonl:1:" in output.err


@pytest.mark.parametrize("command", ["detect", "validate"])
@pytest.mark.parametrize(
    "data",
    [pytest.param(b"\xff\n", id="encoding"), pytest.param(b"[" * 20_000, id="nesting")],
)
def test_cli_reports_invalid_encoding_and_nesting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str, data: bytes
) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_bytes(data)
    assert cli_main([command, str(path)]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "invalid.jsonl:1:" in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("command", ["detect", "validate"])
@pytest.mark.parametrize("limit", ["bytes", "lines"])
def test_cli_enforces_input_caps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str, limit: str
) -> None:
    from substation.detect import MAX_JSONL_BYTES, MAX_JSONL_LINES

    path = tmp_path / "too-large.jsonl"
    with path.open("wb") as stream:
        if limit == "bytes":
            stream.truncate(MAX_JSONL_BYTES + 1)
        else:
            stream.write(b"\n" * (MAX_JSONL_LINES + 1))
    assert cli_main([command, str(path)]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "load cap" in output.err


@pytest.mark.parametrize("command", ["detect", "validate"])
def test_cli_rejects_fifo_without_waiting_for_a_writer(tmp_path: Path, command: str) -> None:
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes unavailable on this platform")
    fifo = tmp_path / "events.jsonl"
    os.mkfifo(fifo, 0o600)
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "substation.cli", command, str(fifo)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert proc.returncode == 1
    assert not proc.stdout
    assert "regular file" in proc.stderr


def test_detect_does_not_publish_hits_before_later_input_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Path(__file__).resolve().parents[1]
    scenario = load_scenario(repo / "scenarios/modbus/anomalous-m1-unauthorized-write.yaml")
    good = write_artifacts(scenario, tmp_path).jsonl
    bad = tmp_path / "invalid.jsonl"
    bad.write_bytes(b"\xff\n")
    assert cli_main(["detect", str(good), str(bad)]) == 1
    assert not capsys.readouterr().out


def test_reader_bounds_a_file_that_grows_after_opening(tmp_path: Path) -> None:
    from substation.schema import iter_jsonl_lines

    path = tmp_path / "growing.jsonl"
    path.write_bytes(b"\n")
    lines = iter_jsonl_lines(path, max_bytes=4)
    assert next(lines) == (1, "\n")
    with path.open("ab") as stream:
        stream.write(b" " * 100)
    with pytest.raises(SchemaValidationError, match="4 byte load cap"):
        next(lines)


def test_reader_limits_count_bytes_and_physical_lines(tmp_path: Path) -> None:
    from substation.schema import iter_jsonl_lines

    path = tmp_path / "unicode.jsonl"
    path.write_text("\n\u00e9\n", encoding="utf-8")
    assert list(iter_jsonl_lines(path, max_bytes=4, max_lines=2)) == [(1, "\n"), (2, "\u00e9\n")]
    with pytest.raises(SchemaValidationError, match="3 byte load cap"):
        list(iter_jsonl_lines(path, max_bytes=3))
    with pytest.raises(SchemaValidationError, match="1 line load cap"):
        list(iter_jsonl_lines(path, max_lines=1))


@pytest.mark.parametrize("jobs", ["1", "8"])
def test_ci_does_not_repair_stale_coverage_before_checking(tmp_path: Path, jobs: str) -> None:
    repo = Path(__file__).resolve().parents[1]
    (tmp_path / "Makefile").write_text((repo / "Makefile").read_text())
    # Instrument the existing orchestration in an isolated directory. The drift
    # failure must remain visible in serial and parallel make invocations.
    (tmp_path / "stale").write_text("stale snapshot")
    (tmp_path / "probes.mk").write_text(
        "check-python format-check lint type test schema security:\n\t@true\n"
        "coverage-build:\n\t@rm -f stale\n"
        "coverage-check:\n\t@test ! -f stale\n"
    )
    result = subprocess.run(  # noqa: S603,S607
        ["make", "-j", jobs, "-f", "Makefile", "-f", "probes.mk", "ci"],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert (tmp_path / "stale").read_text() == "stale snapshot"
