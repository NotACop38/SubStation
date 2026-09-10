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
