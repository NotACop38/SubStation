"""Sensor transactions must retain independent values, outcomes and provenance."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from substation.cli import main
from substation.schema import SchemaValidationError, validate_event


def sensor_record(**changes: Any) -> dict[str, Any]:
    record = {
        "ts": 123.25,
        "uid": "Cexternal",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 43000,
        "id.resp_h": "192.0.2.50",
        "id.resp_p": 502,
        "tid": 17,
        "unit": 4,
        "func": "READ_HOLDING_REGISTERS",
        "address": 8,
        "quantity": 2,
        "response_values": [49152, 7],
        "matched": True,
    }
    return {**record, **changes}


def test_matched_transaction_projects_both_sides_without_inventing_timing(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    source = tmp_path / "modbus_detailed.log"
    source.write_text(json.dumps(sensor_record()) + "\n")
    request, response = load_modbus_log(source)
    for event in (request, response):
        validate_event(event)
        assert event["ts"] == 123.25
        assert event["observation"] == {
            "source": "icsnpp-modbus",
            "kind": "transaction_projection",
            "line": 1,
            "timestamp": "transaction",
        }
        assert event["detail"]["address"] == 8
        assert event["detail"]["quantity"] == 2
    assert request["is_orig"] is True and response["is_orig"] is False
    assert "response_values" not in request["detail"]
    assert response["detail"]["response_values"] == [49152, 7]


def test_tsv_matches_json_and_preserves_vector_order(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    row = sensor_record()
    keys = list(row)
    types = [
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "count",
        "count",
        "string",
        "count",
        "count",
        "vector[count]",
        "bool",
    ]
    tsv = tmp_path / "sensor.log"
    tsv.write_text(
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        "#path\tmodbus_detailed\n#fields\t"
        + "\t".join(keys)
        + "\n#types\t"
        + "\t".join(types)
        + "\n"
        + "\t".join(
            "49152,7" if isinstance(v, list) else "T" if v is True else str(v) for v in row.values()
        )
        + "\n"
    )
    jsonl = tmp_path / "sensor.jsonl"
    jsonl.write_text(json.dumps(row) + "\n")
    observed = load_modbus_log(tsv)
    expected = load_modbus_log(jsonl)
    for events in (observed, expected):
        for event in events:
            event.pop("observation")
    assert observed == expected


def test_exception_outcome_is_not_a_successful_response(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    row = sensor_record(exception_code="ILLEGAL_DATA_ADDRESS")
    row.pop("response_values")
    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(row) + "\n")
    request, response = load_modbus_log(source)
    assert not request["is_exception"]
    assert response["func_code"] == 131
    assert response["func_name"] == "READ_HOLDING_REGISTERS_EXCEPTION"
    assert response["error"] == response["detail"]["exception_code"] == "ILLEGAL_DATA_ADDRESS"
    validate_event(response)


@pytest.mark.parametrize(
    "change",
    [
        {"matched": False},
        {"matched": 1},
        {"quantity": True},
        {"response_values": [1]},
        {"id.orig_h": "untrusted.example"},
        {"func": "DIAGNOSTICS"},
        {"unexpected": "field"},
    ],
)
def test_unsupported_or_ambiguous_records_fail(tmp_path: Path, change: dict[str, Any]) -> None:
    from substation.ingest.modbus import load_modbus_log

    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record(**change)) + "\n")
    with pytest.raises(SchemaValidationError):
        load_modbus_log(source)


def test_import_does_not_truncate_an_existing_output_on_later_error(tmp_path: Path) -> None:
    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record()) + "\n{}\n")
    out = tmp_path / "events.jsonl"
    out.write_text("keep original\n")
    assert main(["import-modbus", str(source), "--out", str(out)]) == 1
    assert out.read_text() == "keep original\n"


def test_field_comparison_detects_changed_values_and_missing_responses(tmp_path: Path) -> None:
    from substation.ingest.modbus import compare_modbus_events, load_modbus_log

    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record()) + "\n")
    expected = load_modbus_log(source)
    actual = copy.deepcopy(expected)
    actual[1]["detail"]["response_values"].reverse()
    assert compare_modbus_events(expected, actual)
    assert compare_modbus_events(expected, expected[:1])
    assert not compare_modbus_events(expected, expected)


@pytest.mark.parametrize(
    "body",
    [
        '{"ts": 1, "ts": 2}',
        '{"ts": NaN}',
        "#separator \\x20\n",
        "#separator \\x09\n#fields\tts\tts\n#types\ttime\ttime\n1\t2\n",
        "",
    ],
)
def test_malformed_sensor_inputs_fail(tmp_path: Path, body: str) -> None:
    from substation.ingest.modbus import load_modbus_log

    source = tmp_path / "sensor.log"
    source.write_text(body)
    with pytest.raises(SchemaValidationError):
        load_modbus_log(source)


def test_unknown_functions_without_direction_are_rejected(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    request = sensor_record(func="unknown-66")
    for field in ("matched", "address", "quantity", "response_values"):
        request.pop(field)
    response = {**request, "func": "unknown-194", "exception_code": "ILLEGAL_FUNCTION"}
    source = tmp_path / "sensor.log"
    source.write_text("\n".join(map(json.dumps, [request, response])))
    with pytest.raises(SchemaValidationError, match="unsupported function"):
        load_modbus_log(source)


def test_sensor_truncated_vectors_keep_the_transaction(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    # Zeek logs at most 100 elements per vector by default; a legal 125-register
    # read then logs quantity 125 with only 100 response values.
    read = sensor_record(quantity=125, response_values=list(range(100)))
    write = sensor_record(
        func="WRITE_MULTIPLE_REGISTERS",
        quantity=110,
        request_values=[7] * 100,
        response_values=[],
        tid=18,
    )
    source = tmp_path / "sensor.log"
    source.write_text("\n".join(map(json.dumps, [read, write])) + "\n")
    events = load_modbus_log(source)
    for event in events:
        validate_event(event)
        assert event["detail"]["quantity"] in {125, 110}
    read_response, write_request = events[1], events[2]
    assert "response_values" not in read_response["detail"]
    assert read_response["observation"]["truncated_values"] == ["response_values"]
    assert "request_values" not in write_request["detail"]
    assert write_request["observation"]["truncated_values"] == ["request_values"]
    assert "truncated_values" not in events[0]["observation"]


def test_truncation_is_recognized_only_at_the_sensor_limit(tmp_path: Path) -> None:
    from substation.ingest.modbus import load_modbus_log

    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record(quantity=60, response_values=[0] * 50)) + "\n")
    with pytest.raises(SchemaValidationError, match="length differs"):
        load_modbus_log(source)
    events = load_modbus_log(source, container_limit=50)
    assert events[1]["observation"]["truncated_values"] == ["response_values"]


def test_unprojectable_rows_are_skipped_so_they_cannot_hide_a_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    unauthorized = sensor_record(
        func="WRITE_SINGLE_REGISTER",
        address=5,
        quantity=1,
        request_values=[1],
        response_values=[1],
        **{"id.orig_h": "192.0.2.77", "id.resp_h": "10.0.0.50"},
    )
    unanswered = sensor_record(tid=19, matched=False)
    vendor = sensor_record(tid=20, func="ENCAP_INTERFACE_TRANSPORT")
    source = tmp_path / "sensor.log"
    source.write_text("\n".join(map(json.dumps, [unauthorized, unanswered, vendor])) + "\n")
    events = tmp_path / "events.jsonl"

    assert main(["import-modbus", str(source), "--strict", "--out", str(events)]) == 1
    assert not events.exists()

    assert main(["import-modbus", str(source), "--out", str(events)]) == 0
    err = capsys.readouterr().err
    assert "skipped 2 unprojectable row(s)" in err
    assert "1 unmatched transaction" in err
    assert len(events.read_text().splitlines()) == 2
    assert main(["detect", str(events), "--detection", "M1"]) == 0
    hits = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [hit["event_index"] for hit in hits] == [0]


def test_a_log_of_only_unprojectable_rows_imports_as_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record(matched=False)) + "\n")
    assert main(["import-modbus", str(source)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "skipped 1 unprojectable row(s)" in captured.err


def test_import_output_keeps_ordinary_or_existing_permissions(tmp_path: Path) -> None:
    import os
    import stat

    source = tmp_path / "sensor.log"
    source.write_text(json.dumps(sensor_record()) + "\n")
    fresh, existing = tmp_path / "fresh.jsonl", tmp_path / "existing.jsonl"
    existing.write_text("old\n")
    existing.chmod(0o640)
    previous = os.umask(0o022)
    try:
        assert main(["import-modbus", str(source), "--out", str(fresh)]) == 0
        assert main(["import-modbus", str(source), "--out", str(existing)]) == 0
    finally:
        os.umask(previous)
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o644
    assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    assert existing.read_text() == fresh.read_text()
