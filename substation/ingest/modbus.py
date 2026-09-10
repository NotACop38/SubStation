"""Import ICSNPP Modbus detailed transactions, with explicit projection provenance.

The eight core functions require a matched transaction. Unknown raw function
codes are message observations: their high bit identifies exception responses.
Never infer packet timestamps from the transaction timestamp.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import Path
from typing import Any

from substation.protocols.modbus import FUNCTION_NAMES, function_action_class, zeek_function_name
from substation.schema import (
    MAX_JSONL_LINES,
    SchemaValidationError,
    iter_jsonl_lines,
    load_event_schema,
    parse_json_event,
    validate_event,
)

_TYPES = {
    "ts": "time",
    "uid": "string",
    "id.orig_h": "addr",
    "id.orig_p": "port",
    "id.resp_h": "addr",
    "id.resp_p": "port",
    "tid": "count",
    "unit": "count",
    "func": "string",
    "address": "count",
    "quantity": "count",
    "request_values": "vector[count]",
    "response_values": "vector[count]",
    "modbus_detailed_link_id": "string",
    "matched": "bool",
    "request_subfunction_code": "string",
    "response_subfunction_code": "string",
    "request_data": "string",
    "response_data": "string",
    "exception_code": "string",
    "mei_type": "string",
}
_REQUIRED = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "tid", "unit", "func"}
_CODES = {name: code for code, name in FUNCTION_NAMES.items()}
_HEADERS = {
    "separator": r"\x09",
    "set_separator": ",",
    "empty_field": "(empty)",
    "unset_field": "-",
    "path": "modbus_detailed",
}


def _integer(value: Any, maximum: int, field: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{field}: expected integer in 0..{maximum}")
    return int(value)


def _tsv_value(raw: str, kind: str) -> Any:
    if kind == "bool":
        if raw not in {"T", "F"}:
            raise ValueError("expected Zeek boolean T/F")
        return raw == "T"
    if kind in {"count", "port"}:
        if not re.fullmatch(r"[0-9]+", raw):
            raise ValueError("expected unsigned decimal integer")
        return int(raw)
    if kind == "time":
        return float(raw)
    if kind == "vector[count]":
        return [] if raw == "(empty)" else [_tsv_value(v, "count") for v in raw.split(",")]
    if raw == "(empty)":
        return ""
    # Decode Zeek byte escapes without interpreting arbitrary Python escapes.
    if re.search(r"\\(?!x[0-9a-fA-F]{2})", raw):
        raise ValueError("invalid Zeek string escape")
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), raw)


def _project(row: Any, line: int) -> list[dict[str, Any]]:
    if not isinstance(row, dict) or not row.keys() >= _REQUIRED or row.keys() - _TYPES.keys():
        raise ValueError("expected ICSNPP modbus_detailed fields; missing or unknown fields")
    for key, value in row.items():
        kind = _TYPES[key]
        if kind in {"string", "addr"} and not isinstance(value, str):
            raise ValueError(f"{key}: expected string")
        if kind == "bool" and type(value) is not bool:
            raise ValueError(f"{key}: expected boolean")
        if kind == "vector[count]":
            if not isinstance(value, list) or len(value) > 2000:
                raise ValueError(f"{key}: expected bounded vector")
            for item in value:
                _integer(item, 65535, key)
        if kind in {"count", "port"}:
            _integer(value, 255 if key == "unit" else 65535, key)
    conn = {key: row[f"id.{key}"] for key in ("orig_h", "orig_p", "resp_h", "resp_p")}
    for field in ("orig_h", "resp_h"):
        conn[field] = str(ipaddress.ip_address(conn[field]))
    func = row["func"]
    code = _CODES.get(func)
    is_transaction = code is not None
    if code is not None:
        if row.get("matched") is not True:
            raise ValueError("unmatched core transaction: request/response direction is ambiguous")
        if not {"address", "quantity"} <= row.keys():
            raise ValueError("core transaction requires address and quantity")
        quantity = row["quantity"]
        if code in {5, 6} and quantity != 1:
            raise ValueError("single write requires quantity 1")
        is_error = bool(row.get("exception_code"))
        if code in {1, 2, 3, 4} and row.get("request_values"):
            raise ValueError("read request cannot contain write values")
        if code in {5, 6, 15, 16} and len(row.get("request_values", [])) != quantity:
            raise ValueError("request_values length differs from quantity")
        if (
            not is_error
            and code in {1, 2, 3, 4, 5, 6}
            and (not quantity or len(row.get("response_values", [])) != quantity)
        ):
            raise ValueError("response_values length differs from quantity")
        if (is_error or code in {15, 16}) and row.get("response_values"):
            raise ValueError("exception/multiple-write ACK cannot contain response_values")
        if code in {1, 2, 5, 15}:
            for key in ("request_values", "response_values"):
                if any(v not in {0, 1} for v in row.get(key, [])):
                    raise ValueError("coil/discrete values must be 0 or 1")
        directions = [True, False]
    else:
        unknown = re.fullmatch(r"unknown-([0-9]+)", func)
        if unknown is None:
            raise ValueError(
                f"unsupported function {func!r}; only eight core functions and unknown codes"
            )
        code = _integer(int(unknown[1]), 255, "function code")
        if not zeek_function_name(code & 127).startswith("unknown-"):
            raise ValueError("known function mislabeled unknown")
        if any(key in row for key in ("address", "quantity", "request_values", "response_values")):
            raise ValueError("unknown function has unsupported decoded fields")
        if bool(code & 128) != bool(row.get("exception_code")):
            raise ValueError("unknown function high bit and exception outcome disagree")
        directions = [not bool(code & 128)]
    events: list[dict[str, Any]] = []
    for is_orig in directions:
        exception = not is_orig and bool(row.get("exception_code"))
        raw_code = code | 128 if exception else code
        name = zeek_function_name(code & 127) + ("_EXCEPTION" if exception else "")
        detail = {"tid": row["tid"], "unit": row["unit"], "func": name}
        for key in ("address", "quantity", "modbus_detailed_link_id"):
            if key in row:
                detail[key] = row[key]
        values = "request_values" if is_orig else "response_values"
        if row.get(values):
            detail[values] = row[values]
        if not is_orig and is_transaction:
            detail["matched"] = True
        if exception:
            detail["exception_code"] = row["exception_code"]
        event = {
            "ts": row["ts"],
            "uid": row["uid"],
            "conn": conn,
            "proto": "modbus",
            "is_orig": is_orig,
            "direction": "request" if is_orig else "response",
            "func_code": raw_code,
            "func_name": name,
            "action_class": function_action_class(code & 127),
            "is_exception": exception,
            "detail": detail,
            "observation": {
                "source": "icsnpp-modbus",
                "line": line,
                "kind": "transaction_projection" if is_transaction else "message",
                "timestamp": "transaction" if is_transaction else "message",
            },
        }
        if exception:
            event["error"] = row["exception_code"]
        events.append(event)
    return events


def load_modbus_log(path: str | Path) -> list[dict[str, Any]]:
    """Load strict Zeek JSON/TSV; no partial result on unsupported/ambiguous input."""
    events: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    fields: list[str] = []
    types: list[str] = []
    mode: str | None = None
    data_seen = False
    schema = load_event_schema()
    for line, raw in iter_jsonl_lines(path):
        raw = raw.rstrip("\r\n")
        if not raw:
            continue
        try:
            if mode is None:
                mode = "tsv" if raw.startswith("#") else "json"
            if mode == "tsv" and raw.startswith("#"):
                key, _, value = raw[1:].partition(" " if raw.startswith("#separator ") else "\t")
                if key in {"open", "close"}:
                    continue
                if data_seen or key in headers or key not in {*_HEADERS, "fields", "types"}:
                    raise ValueError("duplicate, late or unsupported Zeek header")
                headers[key] = value
                if key in _HEADERS and value != _HEADERS[key]:
                    raise ValueError(f"unsupported Zeek {key}")
                if key == "fields":
                    fields = value.split("\t")
                if key == "types":
                    types = value.split("\t")
                continue
            data_seen = True
            if mode == "json":
                row = parse_json_event(raw)
            else:
                if not _HEADERS.keys() <= headers.keys() or not fields or len(fields) != len(types):
                    raise ValueError("incomplete Zeek TSV header")
                if len(set(fields)) != len(fields) or any(
                    _TYPES.get(f) != t for f, t in zip(fields, types, strict=True)
                ):
                    raise ValueError("unknown/duplicate field or mismatched Zeek type")
                values = raw.split("\t")
                if len(values) != len(fields):
                    raise ValueError("TSV column count differs from header")
                row = {
                    f: _tsv_value(v, t)
                    for f, t, v in zip(fields, types, values, strict=True)
                    if v != "-"
                }
            projected = _project(row, line)
            for event in projected:
                validate_event(event, schema)
            events.extend(projected)
            if len(events) > MAX_JSONL_LINES:
                raise ValueError("projected events exceed the event load cap")
        except (ValueError, TypeError, OverflowError) as exc:
            raise SchemaValidationError(f"{path}:{line}: {exc}") from exc
    if not events:
        raise SchemaValidationError(f"{path}: no supported sensor observations")
    return events


def compare_modbus_events(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]]
) -> list[str]:
    """Compare field multisets, excluding timestamps/UIDs and unobservable fields.

    Read address/quantity are transaction projections. Unknown function PDUs have
    no decoded address/value fields. Timing and packet order are not compared.
    """

    def key(event: dict[str, Any]) -> tuple[Any, ...]:
        detail = event["detail"]
        identity = tuple(event["conn"][f] for f in ("orig_h", "orig_p", "resp_h", "resp_p"))
        identity += tuple(
            event[f] for f in ("is_orig", "func_code", "func_name", "action_class", "is_exception")
        )
        identity += (event.get("error"), detail["tid"], detail["unit"])
        if event["func_code"] & 127 in FUNCTION_NAMES:
            identity += (
                detail.get("address"),
                detail.get("quantity"),
                tuple(detail.get("request_values", [])),
                tuple(detail.get("response_values", [])),
            )
        return identity

    want, got = Counter(map(key, expected)), Counter(map(key, actual))
    return [
        f"{item!r}: expected {want[item]}, observed {got[item]}"
        for item in sorted(want.keys() | got.keys(), key=repr)
        if want[item] != got[item]
    ]
