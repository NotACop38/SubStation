"""Tests for the frozen event-log schema and its dependency-free validator.

These tests are the gate's proof: the committed golden events validate, and
representative malformed events are rejected. ``make ci`` additionally runs
``python -m substation.schema`` over ``tests/data/events`` so any emitted event
that violates the schema fails the pipeline (`PRD.md` §6.3).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from substation.schema import (
    EVENT_SCHEMA_PATH,
    SchemaValidationError,
    iter_event_errors,
    iter_jsonl_errors,
    load_event_schema,
    validate_event,
    validate_jsonl_file,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = _REPO_ROOT / "tests" / "data" / "events" / "modbus" / "valid.jsonl"


def _a_valid_read_request() -> dict[str, Any]:
    return {
        "ts": 1717372800.123,
        "uid": "CwT9aQ1z8pPnabc01",
        "conn": {"orig_h": "10.0.0.10", "orig_p": 51234, "resp_h": "10.0.0.50", "resp_p": 502},
        "proto": "modbus",
        "is_orig": True,
        "direction": "request",
        "func_code": 3,
        "func_name": "READ_HOLDING_REGISTERS",
        "action_class": "read",
        "is_exception": False,
        "error": None,
        "detail": {
            "tid": 1,
            "unit": 1,
            "func": "READ_HOLDING_REGISTERS",
            "address": 100,
            "quantity": 10,
        },
    }


def test_schema_file_is_valid_json_and_packaged() -> None:
    assert EVENT_SCHEMA_PATH.exists()
    schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"].startswith("https://json-schema.org/draft/2020-12")
    assert "modbus_detail" in schema["$defs"]


def test_golden_events_all_validate() -> None:
    assert list(iter_jsonl_errors(_GOLDEN)) == []
    validate_jsonl_file(_GOLDEN)  # must not raise


def test_minimal_valid_event_passes() -> None:
    validate_event(_a_valid_read_request())


def test_missing_required_envelope_field_fails() -> None:
    event = _a_valid_read_request()
    del event["proto"]
    errors = list(iter_event_errors(event))
    assert any("proto" in e for e in errors)


def test_unknown_envelope_property_rejected() -> None:
    event = _a_valid_read_request()
    event["bogus"] = 1
    assert any("bogus" in e for e in iter_event_errors(event))


def test_unknown_modbus_detail_property_rejected() -> None:
    event = _a_valid_read_request()
    event["detail"]["not_a_field"] = 5
    assert any("not_a_field" in e for e in iter_event_errors(event))


def test_proto_enum_enforced() -> None:
    event = _a_valid_read_request()
    event["proto"] = "http"
    assert any("enum" in e for e in iter_event_errors(event))


def test_action_class_enum_enforced() -> None:
    event = _a_valid_read_request()
    event["action_class"] = "destroy"
    assert any("action_class" in e for e in iter_event_errors(event))


def test_func_code_range_enforced() -> None:
    event = _a_valid_read_request()
    event["func_code"] = 999
    assert any("maximum" in e for e in iter_event_errors(event))


def test_bool_is_not_an_integer() -> None:
    # bool is a subclass of int in Python; the schema must still reject it.
    event = _a_valid_read_request()
    event["func_code"] = True
    assert any("func_code" in e for e in iter_event_errors(event))


def test_conn_requires_all_endpoints() -> None:
    event = _a_valid_read_request()
    del event["conn"]["resp_p"]
    assert any("resp_p" in e for e in iter_event_errors(event))


def test_modbus_detail_subshape_validated() -> None:
    event = _a_valid_read_request()
    event["detail"]["mask_write"] = {"and_mask": 1, "or_mask": 2, "bad": 3}
    assert any("bad" in e for e in iter_event_errors(event))


def test_validate_event_raises_on_invalid() -> None:
    event = _a_valid_read_request()
    event["uid"] = ""  # minLength 1
    with pytest.raises(SchemaValidationError):
        validate_event(event)


def test_validate_jsonl_reports_line_numbers(tmp_path: Path) -> None:
    good = _a_valid_read_request()
    bad = copy.deepcopy(good)
    bad["proto"] = "nope"
    f = tmp_path / "mixed.jsonl"
    f.write_text(json.dumps(good) + "\n" + json.dumps(bad) + "\n", encoding="utf-8")
    errors = list(iter_jsonl_errors(f))
    assert errors and all(":2:" in e for e in errors)


def test_blank_lines_skipped(tmp_path: Path) -> None:
    f = tmp_path / "blanks.jsonl"
    f.write_text("\n" + json.dumps(_a_valid_read_request()) + "\n\n", encoding="utf-8")
    assert list(iter_jsonl_errors(f)) == []


def test_non_json_line_is_an_error(tmp_path: Path) -> None:
    f = tmp_path / "broken.jsonl"
    f.write_text("{not json\n", encoding="utf-8")
    errors = list(iter_jsonl_errors(f))
    assert errors and "not valid JSON" in errors[0]


def _a_valid_exception() -> dict[str, Any]:
    return {
        "ts": 1717372810.222,
        "uid": "CnXyz93c4lR5ghi03",
        "conn": {"orig_h": "10.0.0.99", "orig_p": 40001, "resp_h": "10.0.0.50", "resp_p": 502},
        "proto": "modbus",
        "is_orig": False,
        "direction": "response",
        "func_code": 132,
        "func_name": "READ_INPUT_REGISTERS_EXCEPTION",
        "action_class": "read",
        "is_exception": True,
        "error": "ILLEGAL_DATA_ADDRESS",
        "detail": {"tid": 7, "unit": 1, "exception_code": "ILLEGAL_DATA_ADDRESS"},
    }


def test_direction_must_match_is_orig_request() -> None:
    event = _a_valid_read_request()  # is_orig True
    event["direction"] = "response"
    assert any("direction" in e for e in iter_event_errors(event))


def test_direction_must_match_is_orig_response() -> None:
    event = _a_valid_exception()  # is_orig False
    event["direction"] = "request"
    assert any("direction" in e for e in iter_event_errors(event))


def test_valid_exception_passes() -> None:
    validate_event(_a_valid_exception())


def test_modbus_exception_requires_error_present() -> None:
    event = _a_valid_exception()
    del event["error"]
    assert any("error" in e for e in iter_event_errors(event))


def test_modbus_exception_rejects_null_error() -> None:
    event = _a_valid_exception()
    event["error"] = None
    assert any("error" in e for e in iter_event_errors(event))


def test_modbus_exception_requires_exception_code() -> None:
    event = _a_valid_exception()
    del event["detail"]["exception_code"]
    assert any("exception_code" in e for e in iter_event_errors(event))


def test_non_exception_does_not_require_error() -> None:
    # The exception constraint must not fire on ordinary events.
    assert list(iter_event_errors(_a_valid_read_request())) == []


def test_nan_constant_rejected_in_jsonl(tmp_path: Path) -> None:
    f = tmp_path / "nan.jsonl"
    event = _a_valid_read_request()
    f.write_text(json.dumps(event).replace('"ts": 1717372800.123', '"ts": NaN'), encoding="utf-8")
    errors = list(iter_jsonl_errors(f))
    assert errors and "not valid JSON" in errors[0]


def test_infinity_constant_rejected_in_jsonl(tmp_path: Path) -> None:
    f = tmp_path / "inf.jsonl"
    event = _a_valid_read_request()
    event["detail"]["address"] = float("inf")  # json.dumps emits bareword Infinity
    f.write_text(json.dumps(event) + "\n", encoding="utf-8")
    errors = list(iter_jsonl_errors(f))
    assert errors and "not valid JSON" in errors[0]


def test_s7_detail_unconstrained_for_now() -> None:
    # S7 detail is not frozen until Phase 4, so it accepts any object; the envelope
    # still applies. (Modbus is frozen in Phase 1, DNP3 in Phase 3 — see below.)
    schema = load_event_schema()
    event = _a_valid_read_request()
    event["proto"] = "s7comm"
    event["detail"] = {"anything": [1, 2, 3]}
    assert list(iter_event_errors(event, schema)) == []


def _a_valid_dnp3_request() -> dict[str, Any]:
    event = _a_valid_read_request()
    event["proto"] = "dnp3"
    event["func_code"] = 1
    event["func_name"] = "READ"
    event["action_class"] = "read"
    event["detail"] = {
        "fc_request": "READ",
        "objects": {"function_code": "READ", "object_type": "Binary Input"},
    }
    return event


def test_dnp3_detail_frozen_accepts_valid() -> None:
    # DNP3 detail is FROZEN (Phase 3): a valid envelope + DNP3 detail passes.
    schema = load_event_schema()
    assert list(iter_event_errors(_a_valid_dnp3_request(), schema)) == []


def test_dnp3_detail_rejects_unknown_property() -> None:
    schema = load_event_schema()
    event = _a_valid_dnp3_request()
    event["detail"]["bogus"] = 1
    errors = list(iter_event_errors(event, schema))
    assert errors and "bogus" in errors[0]


def test_dnp3_detail_rejects_out_of_range_iin() -> None:
    schema = load_event_schema()
    event = _a_valid_dnp3_request()
    event["detail"]["iin"] = 70000  # > 16-bit
    assert list(iter_event_errors(event, schema)) != []
